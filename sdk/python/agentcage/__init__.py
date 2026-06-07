"""agentcage Python SDK.

Build an agent that the agentcage runtime executes. The SDK bundles the
official MCP server, an LLM client, sub-agent call helpers, and
runtime metadata proxies in one importable package.

Typical use:

    import agentcage

    agent = agentcage.Agent("researcher", "A research assistant")

    @agent.main()                         # ← runs on `agentcage run BUNDLE "..."`
    def respond(prompt: str) -> str:
        return agentcage.llm.complete(
            system="You are a research assistant.",
            user=prompt,
        )

    @agent.tool(expose=True)              # ← public direct tool
    def fetch_paper(doi: str) -> str:
        ...

    @agent.tool()                         # ← private; only respond() can call
    def parse_doi(doi: str) -> dict:
        ...

    if __name__ == "__main__":
        agent.run()

Public surface:

    Agent                    MCP server with @main()/@tool() decorators mirroring the Agentfile.
    llm.complete             Single-turn LLM call. Routes to Anthropic or OpenAI by model name.
    llm.anthropic_client     Preconfigured Anthropic SDK client for advanced features.
    llm.openai_client        Preconfigured OpenAI SDK client for advanced features.
    agents.<name>.<tool>     Call a sub-agent declared in USES.
    run                      Current run metadata: run.id, run.agent_ref.
    budget                   Budget introspection: budget.total, budget.used, budget.remaining_tokens().

The Agentfile is the platform contract for MAIN and EXPOSE. The Python
decorators are sugar — pair every `@agent.main()` with `MAIN <name>`
in the Agentfile, and every `@agent.tool(expose=True)` with
`EXPOSE <name>`. Authors who skip the SDK and write MCP directly just
add the Agentfile directives; the platform reads from there.
"""

from ._agent_class import Agent
from . import llm
from ._agents import agents
from .runtime import budget, run

__all__ = ["Agent", "agents", "budget", "llm", "run"]
__version__ = "0.1.0"
