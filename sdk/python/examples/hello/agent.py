"""A trivial example agent that responds warmly via the LLM."""

import agentcage

agent = agentcage.Agent("hello", "A trivial agent that responds warmly.")


@agent.main()
def respond(messages: list[dict]) -> str:
    """The agent's reasoning entry. Runs when callers do
    `agentcage run hello.agent "..."`.

    The caller passes a list of {role, content} objects — the same
    shape OpenAI and Anthropic accept. Stateless agents can ignore
    everything except the last user turn; multi-turn agents pass the
    whole list to the LLM and conversation continuity comes from
    whoever sent it (CLI, app, or a memory sub-agent). The platform
    stores nothing about conversations on its own; if you want
    persistence bring your own store via SECRETS, or USES a memory
    agent from the registry.
    """
    return agentcage.llm.complete(
        system="You are friendly and concise.",
        messages=messages,
    )


if __name__ == "__main__":
    agent.run()
