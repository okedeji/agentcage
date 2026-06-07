"""Current-run metadata.

Two proxy objects, agentcage.run and agentcage.budget, read environment
variables the runtime injects into the cage. Each attribute reads at
access time, so values always reflect current state rather than what
was set when the module was imported.

Env vars consumed:

    AGENTCAGE_RUN_ID         The current run's ID.
    AGENTCAGE_AGENT_REF      The ref this run is executing (e.g. @org/name:1.0).
    AGENTCAGE_BUDGET         Max LLM tokens declared in the Agentfile.
    AGENTCAGE_BUDGET_USED    Tokens consumed so far.
"""

from __future__ import annotations

import os


class _Run:
    """Proxy for current-run metadata exposed as agentcage.run."""

    @property
    def id(self) -> str:
        """The current run's ID, or empty string when not in a run."""
        return os.environ.get("AGENTCAGE_RUN_ID", "")

    @property
    def agent_ref(self) -> str:
        """The ref the runtime is executing this run for (e.g. @org/name:1.0)."""
        return os.environ.get("AGENTCAGE_AGENT_REF", "")


class _Budget:
    """Proxy for budget metadata exposed as agentcage.budget."""

    @property
    def total(self) -> int:
        """The BUDGET declared in the Agentfile, 0 when unset."""
        return _safe_int_env("AGENTCAGE_BUDGET")

    @property
    def used(self) -> int:
        """Tokens consumed by this run so far."""
        return _safe_int_env("AGENTCAGE_BUDGET_USED")

    def remaining_tokens(self) -> int:
        """Tokens left in the budget. Returns 0 when no budget was declared
        (callers can disambiguate via the total property).
        """
        total = self.total
        if total == 0:
            return 0
        return max(0, total - self.used)


def _safe_int_env(name: str) -> int:
    """Read an env var as int, returning 0 for unset or malformed values."""
    raw = os.environ.get(name, "")
    if not raw:
        return 0
    try:
        return int(raw)
    except ValueError:
        return 0


# Module-level singletons exposed as agentcage.run and agentcage.budget.
run = _Run()
budget = _Budget()
