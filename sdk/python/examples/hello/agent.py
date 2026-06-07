"""A trivial example agent that greets a name warmly via the LLM."""

import agentcage

agent = agentcage.Agent("hello", "A trivial agent that greets warmly.")


@agent.tool()
def greet(name: str) -> str:
    """Greet someone warmly using the LLM."""
    return agentcage.llm.complete(
        system="You are friendly and concise.",
        user=f"Greet {name} in one sentence.",
    )


if __name__ == "__main__":
    agent.run()
