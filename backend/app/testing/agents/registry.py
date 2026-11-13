"""The agent-layer registry: assembles every real Agent wrapper and proves, at import,
that the whole kill-chain roster is accounted for.

Each roster agent is in exactly one of three states:
  * WRAPPED            -- a real Agent module in `app/testing/agents/` (26 agents);
  * CAPABILITY_SATISFIED -- the capability module IS the agent's whole purpose, so no
                           thin wrapper is added (9 agents; each cited in MASTER_BACKLOG);
  * KNOWN_GAPS         -- A1/A17, undocumented ids in the owner's source spec, recorded
                           explicitly in the roster rather than invented (2 agents).

WRAPPED + CAPABILITY_SATISFIED must equal the roster exactly (asserted below), so nothing
is silently missing. Stdlib only; pure.
"""
from __future__ import annotations

from typing import Any

from app.testing.agents import attack, domain_packs, orchestration, proof, recon
from app.testing.agents.base import Agent
from app.testing.integrity import kill_chain_roster as roster

MODULE_VERSION = "agent-registry/1.0"

ALL_AGENTS: tuple[Agent, ...] = (
    recon.AGENTS + attack.AGENTS + proof.AGENTS + orchestration.AGENTS + domain_packs.AGENTS
)
_BY_ID: dict[str, Agent] = {a.agent_id: a for a in ALL_AGENTS}
assert len(_BY_ID) == len(ALL_AGENTS), "duplicate agent wrapper id"

# Roster agents whose capability module directly satisfies them (the overlap rule in
# MASTER_BACKLOG.md): A2=B39 opplan, A7=B7 contract inference, A10=oracle_gate gate,
# A12=evidence graph, A16=Finding enforcement, A18=audit logging, A25=B32 chain,
# A26=B31 twin self-play, A27=B35 browser surface. No thin wrapper is added for these.
CAPABILITY_SATISFIED: tuple[str, ...] = ("A2", "A7", "A10", "A12", "A16", "A18", "A25", "A26", "A27")

_ROSTER_IDS = frozenset(a.agent_id for a in roster.roster())
_WRAPPED_IDS = frozenset(_BY_ID)

# Self-verifying invariants: every wrapper maps to a real roster id; wrappers and
# capability-satisfied ids are disjoint; together they cover the roster exactly.
assert _WRAPPED_IDS <= _ROSTER_IDS, f"wrapper(s) not in roster: {sorted(_WRAPPED_IDS - _ROSTER_IDS)}"
assert not (_WRAPPED_IDS & set(CAPABILITY_SATISFIED)), "an agent is both wrapped and capability-satisfied"
assert _WRAPPED_IDS | set(CAPABILITY_SATISFIED) == _ROSTER_IDS, \
    f"roster not fully accounted for: {sorted(_ROSTER_IDS - _WRAPPED_IDS - set(CAPABILITY_SATISFIED))}"


def get(agent_id: str) -> Agent | None:
    return _BY_ID.get(agent_id)


def wrapped_ids() -> frozenset[str]:
    return _WRAPPED_IDS


def activatable() -> tuple[Agent, ...]:
    """The wrapper agents that are in scope (owner-declined A31/A32 excluded)."""
    return tuple(a for a in ALL_AGENTS if a.activatable)


def coverage() -> dict[str, Any]:
    unaccounted = sorted(_ROSTER_IDS - _WRAPPED_IDS - set(CAPABILITY_SATISFIED))
    return {
        "module_version": MODULE_VERSION,
        "roster_size": len(_ROSTER_IDS),
        "wrapped": sorted(_WRAPPED_IDS, key=lambda s: int(s[1:])),
        "capability_satisfied": list(CAPABILITY_SATISFIED),
        "known_gaps": list(roster.KNOWN_GAPS),
        "activatable": sorted((a.agent_id for a in activatable()), key=lambda s: int(s[1:])),
        "out_of_scope": sorted((a.agent_id for a in ALL_AGENTS if not a.activatable), key=lambda s: int(s[1:])),
        "unaccounted": unaccounted,
        "fully_accounted": not unaccounted,
        "note": "Every kill-chain roster agent is either WRAPPED (a real Agent module), CAPABILITY_SATISFIED "
                "(its capability module is its whole purpose), or a recorded KNOWN_GAP (A1/A17). Nothing silent.",
    }
