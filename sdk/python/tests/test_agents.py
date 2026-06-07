"""Tests for the sub-agent helpers."""

import pytest

from agentcage import agents
from agentcage._agents import _env_var_for, _SubAgent, _ToolProxy


def test_env_var_dashes_become_underscores():
    assert _env_var_for("web-search") == "AGENTCAGE_USES_WEB_SEARCH_URL"


def test_env_var_already_underscored():
    assert _env_var_for("my_agent") == "AGENTCAGE_USES_MY_AGENT_URL"


def test_sub_agent_raises_clear_error_when_env_missing(monkeypatch):
    monkeypatch.delenv("AGENTCAGE_USES_WEB_SEARCH_URL", raising=False)
    proxy = _SubAgent("web-search")
    with pytest.raises(RuntimeError, match="web-search") as exc:
        proxy._resolve_url()
    assert "USES" in str(exc.value)
    assert "AGENTCAGE_USES_WEB_SEARCH_URL" in str(exc.value)


def test_sub_agent_caches_resolved_url(monkeypatch):
    monkeypatch.setenv("AGENTCAGE_USES_WEB_SEARCH_URL", "http://test")
    proxy = _SubAgent("web-search")
    assert proxy._resolve_url() == "http://test"
    # Second call uses the cached value; even if env changes, the
    # already-resolved URL stays put.
    monkeypatch.setenv("AGENTCAGE_USES_WEB_SEARCH_URL", "http://other")
    assert proxy._resolve_url() == "http://test"


def test_namespace_attribute_access_returns_tool_proxy(monkeypatch):
    monkeypatch.setenv("AGENTCAGE_USES_WEB_SEARCH_URL", "http://test")
    sub = agents.web_search
    assert isinstance(sub, _SubAgent)
    tool = sub.search
    assert isinstance(tool, _ToolProxy)
    assert tool._tool == "search"
    assert tool._agent == "web_search"
