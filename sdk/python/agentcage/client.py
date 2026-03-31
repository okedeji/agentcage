"""agentcage Python SDK client."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Iterator

import grpc

from agentcage import proto


@dataclass
class RunConfig:
    """Configuration for starting an assessment."""

    agent: str
    target: list[str]
    token_budget: int = 0
    max_duration: str = ""
    compliance: str = ""


@dataclass
class Finding:
    """A vulnerability finding from an assessment."""

    id: str
    title: str
    severity: str
    vuln_class: str
    endpoint: str
    status: str


@dataclass
class Assessment:
    """Handle to a running or completed assessment."""

    id: str
    _client: Client = field(repr=False)

    def status(self) -> dict:
        """Get current assessment status."""
        resp = self._client._assess.GetAssessment(
            proto.GetAssessmentRequest(assessment_id=self.id)
        )
        return _assessment_info_to_dict(resp.assessment)

    def findings(self, poll_interval: float = 5.0) -> Iterator[Finding]:
        """Stream findings as they arrive. Polls until assessment completes."""
        seen = set()
        while True:
            info = self.status()
            # TODO: Replace with actual findings RPC when available
            if info["status"] in ("approved", "rejected"):
                break
            time.sleep(poll_interval)

    def wait(self, poll_interval: float = 5.0) -> dict:
        """Block until the assessment reaches a terminal state."""
        while True:
            info = self.status()
            if info["status"] in ("approved", "rejected"):
                return info
            time.sleep(poll_interval)


class Client:
    """agentcage SDK client. Connects to an orchestrator via gRPC."""

    def __init__(self, addr: str = "localhost:9090"):
        self._channel = grpc.insecure_channel(addr)
        self._cages = proto.CageServiceStub(self._channel)
        self._assess = proto.AssessmentServiceStub(self._channel)
        self._intervene = proto.InterventionServiceStub(self._channel)
        self._fleet = proto.FleetServiceStub(self._channel)

    def close(self):
        """Close the gRPC connection."""
        self._channel.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def run(
        self,
        agent: str,
        target: list[str],
        token_budget: int = 0,
        max_duration: str = "",
        compliance: str = "",
    ) -> Assessment:
        """Start a new assessment.

        Args:
            agent: Path to .cage bundle.
            target: Target hosts.
            token_budget: LLM token budget (0 = use config default).
            max_duration: Assessment time limit (e.g. "30m", "4h").
            compliance: Compliance framework (e.g. "soc2").

        Returns:
            Assessment handle for tracking progress.
        """
        config = proto.AssessmentConfig(
            scope=proto.TargetScope(hosts=target),
            total_token_budget=token_budget,
        )
        resp = self._assess.CreateAssessment(
            proto.CreateAssessmentRequest(config=config)
        )
        return Assessment(id=resp.assessment_id, _client=self)

    def test(self, agent: str, target: list[str]) -> str:
        """Create a single cage for agent development/debugging.

        Returns:
            Cage ID.
        """
        config = proto.CageConfig(
            type=proto.CAGE_TYPE_DISCOVERY,
            scope=proto.TargetScope(hosts=target),
        )
        resp = self._cages.CreateCage(proto.CreateCageRequest(config=config))
        return resp.cage_id

    def interventions(self) -> list[dict]:
        """List pending interventions."""
        resp = self._intervene.ListInterventions(
            proto.ListInterventionsRequest(
                status_filter=proto.INTERVENTION_STATUS_PENDING
            )
        )
        return [_intervention_to_dict(i) for i in resp.interventions]

    def resolve(self, intervention_id: str, action: str, rationale: str = "") -> None:
        """Resolve a cage intervention.

        Args:
            intervention_id: Intervention ID.
            action: One of "resume", "kill", "allow", "block".
            rationale: Reason for the decision.
        """
        action_map = {
            "resume": proto.INTERVENTION_ACTION_RESUME,
            "kill": proto.INTERVENTION_ACTION_KILL,
            "allow": proto.INTERVENTION_ACTION_ALLOW,
            "block": proto.INTERVENTION_ACTION_BLOCK,
        }
        self._intervene.ResolveCageIntervention(
            proto.ResolveCageInterventionRequest(
                intervention_id=intervention_id,
                action=action_map[action],
                rationale=rationale,
            )
        )

    def fleet_status(self) -> dict:
        """Get current fleet status."""
        resp = self._fleet.GetFleetStatus(proto.GetFleetStatusRequest())
        return {"total_hosts": resp.status.total_hosts}


def _assessment_info_to_dict(info) -> dict:
    return {
        "id": info.assessment_id,
        "customer_id": info.customer_id,
        "status": proto.AssessmentStatus.Name(info.status).lower().replace(
            "assessment_status_", ""
        ),
    }


def _intervention_to_dict(info) -> dict:
    return {
        "id": info.intervention_id,
        "type": info.type,
        "status": info.status,
        "cage_id": info.cage_id,
        "description": info.description,
    }
