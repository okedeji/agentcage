"""Smoke tests for the agentcage.Agent re-export.

The actual MCP plumbing is owned by the official MCP Python SDK. These
tests just confirm that the public surface agent authors will reach for
exists, is importable, and behaves like FastMCP.
"""

import agentcage


def test_agent_is_importable():
    assert agentcage.Agent is not None
    assert agentcage.__version__ == "0.1.0"


def test_agent_construction():
    agent = agentcage.Agent("hello", "A trivial agent")
    assert agent.name == "hello"


def test_agent_registers_tool():
    agent = agentcage.Agent("hello", "A trivial agent")

    @agent.tool()
    def greet(name: str) -> str:
        """Greet someone."""
        return f"Hello, {name}!"

    # FastMCP's internal tool registry. This assertion is intentionally
    # loose: if FastMCP changes its internal storage we want to notice,
    # but we do not want the test to break on a cosmetic refactor.
    registered = list(agent._tool_manager.list_tools())
    assert any(t.name == "greet" for t in registered), f"greet not registered, got {registered}"
