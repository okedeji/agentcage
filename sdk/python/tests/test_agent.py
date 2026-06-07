"""Tests for the Agent class — the FastMCP subclass with MAIN/EXPOSE sugar.

The decorators on Agent are conveniences over the official MCP SDK.
The platform contract for MAIN and EXPOSE lives in the Agentfile;
these tests check that the Python sugar records what authors say,
not that it enforces it at runtime.
"""

import agentcage


def test_agent_is_importable():
    assert agentcage.Agent is not None
    assert agentcage.__version__ == "0.1.0"


def test_agent_construction():
    agent = agentcage.Agent("hello", "A trivial agent")
    assert agent.name == "hello"


def test_agent_subclass_of_fastmcp():
    """Authors who hand the Agent to existing MCP tooling should not be surprised."""
    from mcp.server.fastmcp import FastMCP
    agent = agentcage.Agent("hello", "A trivial agent")
    assert isinstance(agent, FastMCP)


def test_tool_decorator_registers_with_mcp():
    agent = agentcage.Agent("hello", "A trivial agent")

    @agent.tool()
    def greet(name: str) -> str:
        """Greet someone."""
        return f"Hello, {name}!"

    registered = list(agent._tool_manager.list_tools())
    assert any(t.name == "greet" for t in registered), f"greet not registered, got {registered}"


def test_main_decorator_records_tool_name():
    agent = agentcage.Agent("hello", "A trivial agent")

    @agent.main()
    def respond(prompt: str) -> str:
        return prompt

    assert agent._main_tool_name == "respond"


def test_main_decorator_with_explicit_name():
    agent = agentcage.Agent("hello", "A trivial agent")

    @agent.main(name="chat")
    def some_function(prompt: str) -> str:
        return prompt

    assert agent._main_tool_name == "chat"


def test_main_also_registers_as_tool():
    """@main() is sugar — the function still ends up in the MCP tool registry."""
    agent = agentcage.Agent("hello", "A trivial agent")

    @agent.main()
    def respond(prompt: str) -> str:
        return prompt

    registered = list(agent._tool_manager.list_tools())
    assert any(t.name == "respond" for t in registered), (
        f"respond not registered as MCP tool, got {registered}"
    )


def test_tool_decorator_without_expose_is_private():
    agent = agentcage.Agent("hello", "A trivial agent")

    @agent.tool()
    def private_helper(x: int) -> int:
        return x * 2

    assert "private_helper" not in agent._exposed_tool_names


def test_tool_decorator_with_expose_records_name():
    agent = agentcage.Agent("hello", "A trivial agent")

    @agent.tool(expose=True)
    def fetch_paper(doi: str) -> str:
        return f"paper {doi}"

    assert "fetch_paper" in agent._exposed_tool_names


def test_main_and_tools_coexist():
    agent = agentcage.Agent("researcher", "Research assistant")

    @agent.main()
    def respond(prompt: str) -> str:
        return prompt

    @agent.tool(expose=True)
    def fetch_paper(doi: str) -> str:
        return doi

    @agent.tool()
    def parse_doi(doi: str) -> str:
        return doi

    assert agent._main_tool_name == "respond"
    assert agent._exposed_tool_names == {"fetch_paper"}
    registered = {t.name for t in agent._tool_manager.list_tools()}
    assert registered == {"respond", "fetch_paper", "parse_doi"}, (
        f"unexpected tools registered: {registered}"
    )
