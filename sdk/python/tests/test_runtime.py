"""Tests for runtime metadata proxies."""

from agentcage import budget, run


# ----- agentcage.run --------------------------------------------------------


def test_run_id_when_set(monkeypatch):
    monkeypatch.setenv("AGENTCAGE_RUN_ID", "abc-123")
    assert run.id == "abc-123"


def test_run_id_empty_when_unset(monkeypatch):
    monkeypatch.delenv("AGENTCAGE_RUN_ID", raising=False)
    assert run.id == ""


def test_run_agent_ref_when_set(monkeypatch):
    monkeypatch.setenv("AGENTCAGE_AGENT_REF", "@okedeji/researcher:1.0")
    assert run.agent_ref == "@okedeji/researcher:1.0"


def test_run_agent_ref_empty_when_unset(monkeypatch):
    monkeypatch.delenv("AGENTCAGE_AGENT_REF", raising=False)
    assert run.agent_ref == ""


def test_run_reads_env_at_access_time(monkeypatch):
    """Each attribute access reads the env fresh, so a runtime update
    is reflected without restarting the process."""
    monkeypatch.setenv("AGENTCAGE_RUN_ID", "first")
    assert run.id == "first"
    monkeypatch.setenv("AGENTCAGE_RUN_ID", "second")
    assert run.id == "second"


# ----- agentcage.budget -----------------------------------------------------


def test_budget_total_returns_zero_when_unset(monkeypatch):
    monkeypatch.delenv("AGENTCAGE_BUDGET", raising=False)
    assert budget.total == 0


def test_budget_total_returns_declared_value(monkeypatch):
    monkeypatch.setenv("AGENTCAGE_BUDGET", "100000")
    assert budget.total == 100000


def test_budget_used_returns_zero_when_unset(monkeypatch):
    monkeypatch.delenv("AGENTCAGE_BUDGET_USED", raising=False)
    assert budget.used == 0


def test_budget_used_returns_runtime_value(monkeypatch):
    monkeypatch.setenv("AGENTCAGE_BUDGET_USED", "42000")
    assert budget.used == 42000


def test_budget_remaining_tokens_when_budget_declared(monkeypatch):
    monkeypatch.setenv("AGENTCAGE_BUDGET", "100000")
    monkeypatch.setenv("AGENTCAGE_BUDGET_USED", "30000")
    assert budget.remaining_tokens() == 70000


def test_budget_remaining_tokens_zero_when_no_budget(monkeypatch):
    monkeypatch.delenv("AGENTCAGE_BUDGET", raising=False)
    monkeypatch.delenv("AGENTCAGE_BUDGET_USED", raising=False)
    assert budget.remaining_tokens() == 0


def test_budget_remaining_tokens_clamps_negative(monkeypatch):
    """Tokens used can exceed budget if metering is loose; remaining
    clamps at 0 rather than reporting a negative number."""
    monkeypatch.setenv("AGENTCAGE_BUDGET", "10000")
    monkeypatch.setenv("AGENTCAGE_BUDGET_USED", "15000")
    assert budget.remaining_tokens() == 0


def test_budget_handles_malformed_env_as_zero(monkeypatch):
    monkeypatch.setenv("AGENTCAGE_BUDGET", "not-a-number")
    assert budget.total == 0
