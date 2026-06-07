"""agentcage Python SDK.

Build an agent that the agentcage runtime executes. The SDK bundles the
official MCP server, an LLM client, sub-agent call helpers, and
runtime metadata proxies in one importable package.

Typical use:

    import agentcage

    agent = agentcage.Agent("hello", "A trivial agent")

    @agent.tool()
    def smart_greet(name: str) -> str:
        return agentcage.llm.complete(
            system="You are friendly.",
            user=f"Greet {name} in one sentence.",
        )

    if __name__ == "__main__":
        agent.run()

Public surface:

    Agent                    MCP server. Re-exports mcp.server.fastmcp.FastMCP.
    llm.complete             Single-turn LLM call. Routes to Anthropic or OpenAI by model name.
    llm.anthropic_client     Preconfigured Anthropic SDK client for advanced features.
    llm.openai_client        Preconfigured OpenAI SDK client for advanced features.
    agents.<name>.<tool>     Call a sub-agent declared in USES.
    run                      Current run metadata: run.id, run.agent_ref.
    budget                   Budget introspection: budget.total, budget.used, budget.remaining_tokens().

Every helper has a standard-library equivalent, so skipping the SDK
and writing against MCP, anthropic, and openai directly does not
change platform behavior.
"""

from mcp.server.fastmcp import FastMCP as Agent

from . import llm
from ._agents import agents
from .runtime import budget, run

__all__ = ["Agent", "agents", "budget", "llm", "run"]
__version__ = "0.1.0"
