# agentcage Python SDK

Convenience layer for building agentcage agents in Python. Every helper
here has a standard-library equivalent so authors who want full control
can opt out without changing what the platform does.

## Install

```bash
pip install agentcage-sdk
```

For local development against this checkout:

```bash
pip install -e ./sdk/python
```

## Quick start

```python
import agentcage

agent = agentcage.Agent("hello", "A trivial agent.")

@agent.main()                              # ← runs when you call `agentcage run`
def respond(messages: list[dict]) -> str:
    # messages = [{"role": "user", "content": "..."}, ...]
    # Same {role, content} shape OpenAI and Anthropic accept.
    return agentcage.llm.complete(
        system="You are friendly and concise.",
        messages=messages,
    )

@agent.tool(expose=True)                   # ← public direct tool
def echo(message: str) -> str:
    return message

@agent.tool()                              # ← private; only respond() can call
def _helper(x: str) -> str:
    return x.strip()

if __name__ == "__main__":
    agent.run()
```

Pair with an `Agentfile`:

```
FROM python:3.12-slim
RUN pip install --no-cache-dir agentcage-sdk
MODEL anthropic/claude-3-5-sonnet
SECRETS anthropic_api_key
NETWORK allow:api.anthropic.com
MAIN respond
EXPOSE echo
META description "A trivial agent."
ENTRYPOINT python3 agent.py
```

## Public surface

| Surface | Purpose |
|---|---|
| `agentcage.Agent` | MCP server subclassing `FastMCP`, adds `@main()` and `expose=` keyword on `@tool()`. |
| `agentcage.llm.complete` | LLM chat completion. Routes to Anthropic or OpenAI by model name (`anthropic/claude-3-5-sonnet`, `openai/gpt-4o`). Pass `user=` for single-turn or `messages=` for multi-turn — same `{role, content}` shape both providers accept. |
| `agentcage.llm.anthropic_client()` | Preconfigured Anthropic SDK client. Reach for this when you need multi-turn, tool use, streaming, vision, or anything else the Anthropic API exposes. |
| `agentcage.llm.openai_client()` | Preconfigured OpenAI SDK client. Same shape as above. |
| `agentcage.agents.<name>.<tool>` | Call a sub-agent declared in your `USES`. |
| `agentcage.run.id` | The current run's ID, useful for logging and trace correlation. |
| `agentcage.run.agent_ref` | The ref this run is executing (e.g. `@org/name:1.0`). |
| `agentcage.budget.total` | Tokens declared in the Agentfile's `BUDGET`. |
| `agentcage.budget.used` | Tokens this run has consumed so far. |
| `agentcage.budget.remaining_tokens()` | What's left. Clamps at 0. |

## Conversation state

The agentcage platform stores nothing about your conversations. Every
`agentcage run` and `agentcage call` is independent. The agent receives
whatever the caller sends and returns a single response.

That keeps the platform small and lets each author pick the memory
strategy that fits their agent:

| Pattern | How |
|---|---|
| Stateless single-turn | Take the last `messages[-1]["content"]`, respond. No memory needed. |
| Client-managed history | The caller (CLI, app, UI) keeps the message array and sends it on every call. The agent just forwards it to the LLM. This is the default `agentcage run "..."` shape — one user turn — extended naturally for multi-turn. |
| Author-managed history | The agent stores conversations itself. Declare `SECRETS db_url` in your Agentfile, connect to whatever store you pick (SQLite, Postgres, Redis, file), key by some session identifier the caller passes. |
| Sub-agent memory | `USES @someorg/memory:1.0` in your Agentfile; call its `recall` / `remember` tools from inside your `respond`. A reusable memory agent on the registry can serve many other agents. |

The `messages: list[dict]` shape your `@agent.main()` accepts is the
same shape OpenAI and Anthropic accept — no transformation needed when
you forward to `agentcage.llm.complete(messages=...)`.

## Opting out

Every helper has a standard-library equivalent. If you don't want the
SDK, none of the platform semantics change.

| Instead of | Use |
|---|---|
| `agentcage.Agent` | `from mcp.server.fastmcp import FastMCP` |
| `agentcage.llm.complete(...)` | `anthropic.Anthropic().messages.create(...)` or `openai.OpenAI().chat.completions.create(...)` |
| `agentcage.llm.anthropic_client()` / `openai_client()` | Construct the native SDK client directly (handle the env var yourself) |
| `agentcage.agents.web_search.search(...)` | Construct an `mcp.ClientSession` against `os.environ["AGENTCAGE_USES_WEB_SEARCH_URL"]` |
| `agentcage.run.*` | Read `AGENTCAGE_RUN_ID`, `AGENTCAGE_AGENT_REF` directly |
| `agentcage.budget.*` | Read `AGENTCAGE_BUDGET`, `AGENTCAGE_BUDGET_USED` directly |

Pick whichever feels right. The platform doesn't care which surface you
build against.

## Development

```bash
pip install -e ./sdk/python[dev]
pytest sdk/python/tests/
```
