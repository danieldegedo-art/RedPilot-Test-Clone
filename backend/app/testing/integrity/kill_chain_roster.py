"""B37: Kill-Chain Agent Roster.

A fixed, declarative registry of the engagement's agent fleet. It is NOT a spawner:
there is no runtime agent creation, no dynamic capability. Its job is to record, as
enforced data, which agent owns which pre-registered capability, what phase/role it
plays, and -- most importantly -- its SCOPE STATUS, so the owner's turn-1 scope
decisions are encoded where the orchestrator can honour them rather than living only
in docs.

The safety-bearing part is `activatable()`: an OUT_OF_SCOPE agent (the narrowed-away
AD/cloud attack-path operators the owner declined) is never activatable, and a
NARROWED agent carries its boundary in `scope_note`. B33's orchestrator consults this
before scheduling, so a declined capability cannot be run by accident.

The fleet is A1..A39 minus the two cross-cutting capability entries (A5 payment-flow
modeling, A6 entitlement invariants) that belong to the core rather than the fleet;
A1 and A17 are known documentation gaps (RP-005) recorded in `KNOWN_GAPS`, not
invented here. Total declared fleet size is 37.

Stdlib only; pure.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

MODULE_VERSION = "kill-chain-roster/1.0"


class AgentRole(str, Enum):
    PLANNING = "planning"
    RECON = "recon"
    ATTACK = "attack"
    PROOF = "proof"
    LEARNING = "learning"
    ORCHESTRATION = "orchestration"


class ScopeStatus(str, Enum):
    IN_SCOPE = "in_scope"
    NARROWED = "narrowed"          # activatable, but constrained -- see scope_note
    OUT_OF_SCOPE = "out_of_scope"  # owner-declined -> never activatable


@dataclass(frozen=True)
class Agent:
    agent_id: str
    name: str
    role: AgentRole
    domain_pack: bool
    scope_status: ScopeStatus
    owns: tuple[str, ...]
    scope_note: str = ""

    @property
    def activatable(self) -> bool:
        return self.scope_status is not ScopeStatus.OUT_OF_SCOPE

    def to_dict(self) -> dict[str, Any]:
        return {"agent_id": self.agent_id, "name": self.name, "role": self.role.value,
                "domain_pack": self.domain_pack, "scope_status": self.scope_status.value,
                "owns": list(self.owns), "scope_note": self.scope_note, "activatable": self.activatable}


_R, _A, _P, _L, _O, _PL = (AgentRole.RECON, AgentRole.ATTACK, AgentRole.PROOF, AgentRole.LEARNING,
                           AgentRole.ORCHESTRATION, AgentRole.PLANNING)
_IN, _NAR, _OUT = ScopeStatus.IN_SCOPE, ScopeStatus.NARROWED, ScopeStatus.OUT_OF_SCOPE

ROSTER: tuple[Agent, ...] = (
    Agent("A2", "Engagement Planner", _PL, False, _IN, ("B39",)),
    Agent("A3", "Application-Surface Discovery", _R, False, _IN, ()),
    Agent("A4", "Authenticated Workflow Mapper", _R, False, _IN, ()),
    Agent("A7", "API Behavior and Contract", _R, False, _IN, ("B7",)),
    Agent("A8", "Differential Testing", _A, False, _IN, ()),
    Agent("A9", "Business-Logic Hypothesis", _A, False, _IN, ()),
    Agent("A10", "Validation", _P, False, _IN, ()),
    Agent("A11", "Race and State-Transition Analysis", _A, False, _IN, ()),
    Agent("A12", "Evidence-Correlation", _P, False, _IN, ("ZR-005",)),
    Agent("A13", "Severity and Impact-Assessment", _P, False, _IN, ()),
    Agent("A14", "Duplicate and Novelty-Analysis", _P, False, _IN, ("B11",)),
    Agent("A15", "Report-Generation", _P, False, _IN, ()),
    Agent("A16", "Quality-Control and Rejection", _P, False, _IN, ()),
    Agent("A18", "Audit and Forensic-Logging", _O, False, _IN, ()),
    Agent("A19", "Feedback-Learning", _L, False, _IN, ("B16",)),
    Agent("A20", "Orchestrator/Fleet Coordinator", _O, False, _IN, ("B33",)),
    Agent("A21", "Payment-Provider Specialist", _R, False, _IN, ()),
    Agent("A22", "Webhook-Fraud Specialist", _R, False, _IN, ()),
    Agent("A23", "Coupon/Promo-Abuse Specialist", _R, False, _IN, ()),
    Agent("A24", "Subscription-Lifecycle Specialist", _R, False, _IN, ()),
    Agent("A25", "Chain-Composition Agent", _A, False, _IN, ("B32",)),
    Agent("A26", "Twin-Training Supervisor", _A, False, _IN, ("B31",)),
    Agent("A27", "Browser-Execution Agent", _A, False, _IN, ("B35",)),
    Agent("A28", "Impact Quantifier", _P, False, _IN, ()),
    Agent("A29", "Chain-Trace Renderer", _P, False, _IN, ()),
    Agent("A30", "Capability-Synthesis Agent", _L, False, _IN, ("B34",)),
    Agent("A31", "AD Operator", _R, True, _OUT,
          (), "owner-declined (turn 1): AD-backed entitlement verification only was kept in principle, but general "
              "AD attack-path / Kerberoasting / DCSync is out of scope -> not activatable"),
    Agent("A32", "Cloud Hunter", _R, True, _OUT,
          (), "owner-declined (turn 1): cloud-backed entitlement verification only; IAM-escalation / RBAC-escape "
              "hunting is out of scope -> not activatable"),
    Agent("A33", "Contract Auditor", _A, True, _IN, (), "smart-contract auditing (not infrastructure attack paths)"),
    Agent("A34", "Reverser", _R, True, _IN, ("B38",), "owns the Ghidra leg of B38; Sliver/BloodHound legs out of scope"),
    Agent("A35", "Mobile Operator", _A, True, _IN, ()),
    Agent("A36", "OSINT Operator", _R, True, _NAR,
          (), "NARROWED: confirm declared domains belong to the authorized entity; NOT broad employee/breach-data recon"),
    Agent("A37", "Threat-Intel Ingestion Agent", _R, False, _IN, ("B40",)),
    Agent("A38", "Symbolic-Solver Agent", _A, False, _IN, ("B41",)),
    Agent("A39", "Graph-Analyst Agent", _PL, False, _IN, ("B42",)),
)

# A1 and A17 are undocumented in the resolved backlog (RP-005). Recorded, never invented.
KNOWN_GAPS: tuple[str, ...] = ("A1", "A17")
FLEET_SIZE = len(ROSTER) + len(KNOWN_GAPS)

_BY_ID = {a.agent_id: a for a in ROSTER}
assert len(_BY_ID) == len(ROSTER), "duplicate agent id in the roster"
assert FLEET_SIZE == 37, f"declared fleet size should be 37, got {FLEET_SIZE}"


def roster() -> tuple[Agent, ...]:
    return ROSTER


def get(agent_id: str) -> Agent | None:
    return _BY_ID.get(agent_id)


def by_role(role: AgentRole) -> tuple[Agent, ...]:
    return tuple(a for a in ROSTER if a.role is role)


def domain_packs() -> tuple[Agent, ...]:
    return tuple(a for a in ROSTER if a.domain_pack)


def out_of_scope() -> tuple[Agent, ...]:
    return tuple(a for a in ROSTER if a.scope_status is ScopeStatus.OUT_OF_SCOPE)


def is_activatable(agent_id: str) -> bool:
    """False for an unknown agent AND for an owner-declined (OUT_OF_SCOPE) one."""
    a = _BY_ID.get(agent_id)
    return bool(a and a.activatable)


def owner_of(capability_id: str) -> Agent | None:
    return next((a for a in ROSTER if capability_id in a.owns), None)


def roster_payload() -> dict[str, Any]:
    return {"module_version": MODULE_VERSION, "fleet_size": FLEET_SIZE, "documented": len(ROSTER),
            "known_gaps": list(KNOWN_GAPS), "agents": [a.to_dict() for a in ROSTER],
            "out_of_scope": [a.agent_id for a in out_of_scope()],
            "note": "A fixed, declarative roster -- no runtime agent creation. An OUT_OF_SCOPE agent is never "
                    "activatable; the orchestrator (B33) consults this so owner-declined capabilities cannot run."}
