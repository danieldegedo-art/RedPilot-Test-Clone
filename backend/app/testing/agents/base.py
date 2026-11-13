"""The agent layer: real Agent objects over the existing bounded capabilities.

Each A-roster agent is a thin, real module that DELEGATES to a capability already
built and tested (the differencer, the specialists, the impact assessor, the fleet
orchestrator, ...) and wraps the result in a uniform `AgentReport`. The layer adds
three things the capabilities alone don't have, all required by the owner's agent
rules ("every agent action traceable, logged, attributable; preserve authorization
and scope context across every agent step"):

  * a uniform interface (`run(**inputs) -> AgentReport`) with a stable id/role;
  * SCOPE PRESERVATION + fail-closed-for-declined: an agent whose roster scope is
    OUT_OF_SCOPE (owner-declined) refuses to run and never touches its capability --
    the single source of truth for scope is `kill_chain_roster`;
  * fault containment: a delegate that raises yields an `error` report, never a crash.

Agents add no capability of their own; they cannot widen what the bounded capability
already allows. Stdlib only; pure (delegates are pure too).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.testing.integrity import kill_chain_roster as roster


@dataclass(frozen=True)
class AgentReport:
    agent_id: str
    name: str
    role: str
    scope_ok: bool              # authorization/scope context preserved + satisfied
    status: str                 # "ok" | "refused_scope" | "error"
    summary: str
    data: dict[str, Any] = field(default_factory=dict)
    leads: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"agent_id": self.agent_id, "name": self.name, "role": self.role, "scope_ok": self.scope_ok,
                "status": self.status, "summary": self.summary, "data": self.data, "leads": list(self.leads)}


class Agent:
    """Base agent. Subclasses implement `_run(**inputs) -> (summary, data, leads)`.
    Scope is read from the kill-chain roster so the roster's owner-decisions are
    enforced here too."""

    agent_id: str = "A?"
    name: str = "agent"
    role: str = "general"

    def __init__(self) -> None:
        a = roster.get(self.agent_id)
        self.scope_status: str = a.scope_status.value if a is not None else "in_scope"

    @property
    def activatable(self) -> bool:
        return self.scope_status != "out_of_scope"

    def run(self, **inputs: Any) -> AgentReport:
        if not self.activatable:
            return AgentReport(self.agent_id, self.name, self.role, scope_ok=False, status="refused_scope",
                               summary=f"{self.agent_id} ({self.name}) is out of scope (owner-declined); not run",
                               data={}, leads=[])
        try:
            summary, data, leads = self._run(**inputs)
            return AgentReport(self.agent_id, self.name, self.role, scope_ok=True, status="ok",
                               summary=summary, data=dict(data), leads=list(leads))
        except Exception as exc:  # a delegate fault must never crash the agent layer
            return AgentReport(self.agent_id, self.name, self.role, scope_ok=True, status="error",
                               summary=f"{self.agent_id} delegate failed: {type(exc).__name__}: {exc}", data={}, leads=[])

    def _run(self, **inputs: Any) -> tuple[str, dict[str, Any], list[str]]:
        raise NotImplementedError
