"""A trivial example agent that responds warmly via the LLM."""

import agentcage

agent = agentcage.Agent("hello", "A trivial agent that responds warmly.")


@agent.main()
def respond(prompt: str) -> str:
    """The agent's reasoning entry. Runs when callers do
    `agentcage run hello.agent "..."`. Pair with MAIN respond in the
    Agentfile.
    """
    return agentcage.llm.complete(
        system="You are friendly and concise.",
        user=prompt,
    )


if __name__ == "__main__":
    agent.run()
