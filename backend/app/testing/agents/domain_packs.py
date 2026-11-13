"""Domain-pack agents (A31-A36) over the narrowed domain-focus capability.

Each delegates to `domain_focus.focus`, which exposes ONLY the entitlement-verification
slice of its domain (pre-registered oracle classes + public signals) and names the
offensive capability it excludes. Scope is the roster's: A31 (AD Operator) and A32
(Cloud Hunter) are owner-declined, so their agent REFUSES at the base scope gate and
never touches the capability; A33/A34/A35 are in scope and A36 is narrowed.

No agent builds or widens any offensive domain tooling. Stdlib only; pure.
"""
from __future__ import annotations

from typing import Any

from app.testing.agents.base import Agent
from app.testing.integrity import domain_focus


class _DomainPackAgent(Agent):
    def _run(self, **inputs: Any) -> tuple[str, dict[str, Any], list[str]]:
        f = domain_focus.focus(self.agent_id)
        classes = f["oracle_classes"] or ["(authorization/scope confirmation only)"]
        return f"{self.name}: entitlement-verification focus {classes}; excludes {f['excluded']}", f, []


class ADOperatorAgent(_DomainPackAgent):            # owner-declined -> refuses at the gate
    agent_id, name, role = "A31", "AD Operator", "recon"


class CloudHunterAgent(_DomainPackAgent):           # owner-declined -> refuses at the gate
    agent_id, name, role = "A32", "Cloud Hunter", "recon"


class ContractAuditorAgent(_DomainPackAgent):
    agent_id, name, role = "A33", "Contract Auditor", "attack"


class ReverserAgent(_DomainPackAgent):
    agent_id, name, role = "A34", "Reverser", "recon"


class MobileOperatorAgent(_DomainPackAgent):
    agent_id, name, role = "A35", "Mobile Operator", "attack"


class OSINTOperatorAgent(_DomainPackAgent):         # narrowed -> activatable, no oracle exercised
    agent_id, name, role = "A36", "OSINT Operator", "recon"


AGENTS: tuple[Agent, ...] = (
    ADOperatorAgent(), CloudHunterAgent(), ContractAuditorAgent(),
    ReverserAgent(), MobileOperatorAgent(), OSINTOperatorAgent(),
)
