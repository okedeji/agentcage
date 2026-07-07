"""agentcage reasoner: a reusable reasoning harness.

It serves one MCP tool, `respond(messages)`, that answers a request by running
an LLM tool-use loop over whatever tools it reaches through its USES sub-agents.
It reads AGENTCAGE_USES_*_URL (each a tool server behind the gateway) and
AGENTCAGE_LLM_URL (an OpenAI-compatible endpoint that never exposes a provider
key), so it holds no key of its own and boots fine with zero USES tools.

This file is written into the generated reasoning agent, so it is yours to edit:
tune the loop, change the model handling, or replace it entirely. Nothing here
is agentcage-specific beyond the two environment variables above.
"""

import json
import logging
import os
import re
import sys

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from openai import AsyncOpenAI

# agentcage forwards this container's stderr verbatim, so quiet the libraries'
# default request logging here rather than expecting the platform to.
logging.getLogger("mcp").setLevel(logging.WARNING)
logging.getLogger("httpx").setLevel(logging.WARNING)

# The provider/model is the operator's decision, resolved by the LLM gateway,
# which rewrites the model field on the wire; the value sent here is only a
# placeholder the gateway overrides. The operator's knobs use non-reserved env
# names because the Agentfile parser forbids ENV keys under the AGENTCAGE_
# prefix. MAX_TURNS bounds a runaway tool loop; the per-run budget is the real
# ceiling, enforced by the gateway.
MODEL = "gpt-4o-mini"
MAX_TURNS = int(os.environ.get("REASONER_MAX_TURNS", "12"))
SYSTEM_PROMPT = os.environ.get(
    "REASONER_SYSTEM_PROMPT",
    "You are a helpful agent. Use the available tools to answer the user's request.",
)

mcp = FastMCP("reasoner")


def _root_cause(err: BaseException) -> str:
    # The streamable-HTTP client nests task groups, so a gateway DENY/BAN or a
    # tool error comes back buried inside ExceptionGroups. Unwrap to the message.
    while isinstance(err, BaseExceptionGroup) and err.exceptions:
        err = err.exceptions[0]
    return str(err)


def _uses_urls() -> dict[str, str]:
    """Each USES edge is injected as AGENTCAGE_USES_<ALIAS>_URL. The alias
    labels a tool when two sub-agents serve tools of the same name."""
    out: dict[str, str] = {}
    for key, value in os.environ.items():
        match = re.fullmatch(r"AGENTCAGE_USES_(.+)_URL", key)
        if match and value:
            out[match.group(1).lower()] = value
    return out


def _sanitize(name: str) -> str:
    # OpenAI function names allow [a-zA-Z0-9_-]; keep MCP tool names in range.
    return re.sub(r"[^a-zA-Z0-9_-]", "_", name)


async def _discover(urls: dict[str, str]):
    """List every USES sub-agent's tools and build the OpenAI tool schema plus a
    map from the exposed function name to (url, real tool name). Also returns the
    aliases that could not be reached, so the caller can refuse rather than answer
    with a silently missing tool server."""
    schema: list[dict] = []
    routes: dict[str, tuple[str, str]] = {}
    failed: list[str] = []
    for alias, url in urls.items():
        try:
            async with streamable_http_client(url) as (read, write, _):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    listed = await session.list_tools()
        except BaseException as err:
            print(f"[reasoner] listing tools from {alias} failed: {_root_cause(err)}", file=sys.stderr, flush=True)
            failed.append(alias)
            continue
        for tool in listed.tools:
            exposed = _sanitize(tool.name)
            if exposed in routes:
                exposed = _sanitize(f"{alias}_{tool.name}")
            routes[exposed] = (url, tool.name)
            schema.append(
                {
                    "type": "function",
                    "function": {
                        "name": exposed,
                        "description": tool.description or "",
                        "parameters": tool.inputSchema or {"type": "object", "properties": {}},
                    },
                }
            )
    return schema, routes, failed


async def _dispatch(url: str, tool: str, arguments: dict) -> str:
    async with streamable_http_client(url) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(tool, arguments)
            parts = [c.text for c in result.content if getattr(c, "text", None)]
            return "\n".join(parts) if parts else "(no output)"


@mcp.tool()
async def respond(messages: list[dict] = None) -> str:
    """Answer the user's request, using the available tools as needed."""
    conversation = [{"role": "system", "content": SYSTEM_PROMPT}]
    conversation += messages or []

    uses = _uses_urls()
    tools, routes, failed = await _discover(uses)
    # Refuse if any declared tool server dropped out, rather than answer over a
    # partial toolset and let the model claim it used a tool it never reached.
    # Fail closed on the whole run: a missing capability the agent declares is a
    # failure, not something to paper over. A toolless run is only legitimate
    # when the agent declares no USES at all.
    if failed:
        return "reasoning stopped: could not reach tool server(s): " + ", ".join(sorted(failed)) + ". Refusing rather than answer without a tool this agent declares; check that the sub-agents are healthy and retry."

    client = AsyncOpenAI(base_url=os.environ["AGENTCAGE_LLM_URL"], api_key="unused", timeout=60)

    for _ in range(MAX_TURNS):
        kwargs = {"model": MODEL, "messages": conversation}
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"
        try:
            resp = await client.chat.completions.create(**kwargs)
        except BaseException as err:
            return f"reasoning stopped: {_root_cause(err)}"

        message = resp.choices[0].message
        if not message.tool_calls:
            return message.content or ""

        conversation.append(
            {
                "role": "assistant",
                "content": message.content or "",
                "tool_calls": [
                    {"id": tc.id, "type": "function", "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                    for tc in message.tool_calls
                ],
            }
        )
        for tc in message.tool_calls:
            route = routes.get(tc.function.name)
            try:
                arguments = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError:
                arguments = {}
            if route is None:
                content = f"error: unknown tool {tc.function.name}"
            else:
                url, real = route
                try:
                    content = await _dispatch(url, real, arguments)
                except BaseException as err:
                    content = f"error: {_root_cause(err)}"
            conversation.append({"role": "tool", "tool_call_id": tc.id, "content": content})

    return "reasoning stopped: reached the tool-call limit without a final answer"


if __name__ == "__main__":
    serve = os.environ.get("AGENTCAGE_SERVE_HTTP")
    if serve:
        host, _, port = serve.rpartition(":")
        mcp.settings.host = host or "0.0.0.0"
        mcp.settings.port = int(port)
        # The gateway on a private per-run network is the trust boundary, so the
        # SDK's own DNS-rebinding host check (which 421s the forwarded Host) is
        # redundant here. Turn it off, matching the other sample agents.
        mcp.settings.transport_security = TransportSecuritySettings(enable_dns_rebinding_protection=False)
        mcp.run(transport="streamable-http")
    else:
        mcp.run()
