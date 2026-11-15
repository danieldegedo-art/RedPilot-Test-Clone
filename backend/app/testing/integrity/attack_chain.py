"""B32 (owns A25): Attack-Chain Composition Engine -- BOUNDED and FAIL-CLOSED.

Commercial authorised-testing platforms compose individual findings into multi-step
chains so a report can show how one weakness enables the next. B32 does that for the
payment-entitlement domain, but it is deliberately built as a COMPOSER OF FIXED,
PRE-REGISTERED STEPS, not a capability generator:

  * BOUNDED to the domain (ZR-036). The only steps it will ever place in a chain
    are the ten pre-registered oracle classes (`findings.EXPERIMENT_CLASSES`), linked
    through a small, documented precondition/effect catalog derived from their specs.
    It does not invent steps, generate code, or emit anything transferable; a chain
    is an ORDERING of existing findings, nothing more. Chain depth is capped.
  * FAIL-CLOSED. Composition is a gated capability: `compose_chains(..., enabled=...)`
    returns an empty FAIL_CLOSED result whenever the enabling control is absent. The
    safety lives in this function itself, not in the (fail-open) control layer -- if
    the control is deleted, the capability turns OFF, it does not turn open.

It also supplies the precondition/effect state that ZR-019's finding schema needs
(`precondition_of` / `effect_of`), so the composer and the schema share one catalog.

A composed chain is a planning/impact narrative over confirmed-or-hypothesised
findings; it is never itself proof and never a new capability. The pre-registered
oracles still confirm every step (ZR-017).

Stdlib only; pure.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from app.testing.integrity.findings import EXPERIMENT_CLASSES

MODULE_VERSION = "attack-chain/1.0"
MAX_DEPTH_CAP = 6
SEARCH_CAP = 1024   # hard ceiling on chains explored, so the search is always bounded

# State atoms true at the start of an authorised engagement (a fresh synthetic identity
# facing a gated feature with a checkout available). Baseline, not a finding.
BASELINE_STATE: frozenset[str] = frozenset({"fresh_identity", "feature_denied_baseline", "checkout_available"})


@dataclass(frozen=True)
class ChainLink:
    """The precondition/effect of one pre-registered oracle, as symbolic state
    atoms. `effect` is the state established ONLY IF that oracle is confirmed."""
    precondition: frozenset[str]
    effect: frozenset[str]


# One link per pre-registered class. Derived from each spec's baseline_state / expected_outcome;
# fixed before any traffic, never generated. PBB-E's effect is a non-authoritative trust signal
# that nothing consumes (a view/server divergence never enables an access step).
LINKS: dict[str, ChainLink] = {
    "PBB-OPEN": ChainLink(frozenset({"feature_denied_baseline"}), frozenset({"gating_is_soft"})),
    "PBB-U": ChainLink(frozenset({"feature_denied_baseline"}), frozenset({"access_without_payment"})),
    "PBB-F": ChainLink(frozenset({"checkout_available"}), frozenset({"tier_without_tier_price"})),
    "PBB-H": ChainLink(frozenset({"checkout_available"}), frozenset({"tier_via_underbilling"})),
    "PBB-C": ChainLink(frozenset({"access_without_payment"}), frozenset({"duplicate_quota_value"})),
    "PBB-X": ChainLink(frozenset({"access_without_payment"}), frozenset({"cross_identity_redemption"})),
    "PBB-G": ChainLink(frozenset({"cross_identity_redemption"}), frozenset({"cross_tenant_benefit"})),
    "PBB-LEAK": ChainLink(frozenset({"access_without_payment"}), frozenset({"unrelated_identity_access"})),
    "PBB-R": ChainLink(frozenset({"access_without_payment"}), frozenset({"retention_after_refund"})),
    "PBB-E": ChainLink(frozenset(), frozenset({"view_server_divergence"})),
    # PBB-D stands alone: a fresh authenticated identity reaches another subject's object directly
    # (no prior payment step). Its effect is a cross-subject access that no payment step consumes.
    "PBB-D": ChainLink(frozenset({"fresh_identity"}), frozenset({"cross_subject_object_access"})),
}
assert set(LINKS) == set(EXPERIMENT_CLASSES), "chain catalog must cover exactly the pre-registered classes"


class ComposeStatus(str, Enum):
    COMPOSED = "COMPOSED"
    NO_CHAIN = "NO_CHAIN"
    FAIL_CLOSED = "FAIL_CLOSED"   # the enabling control was absent -> capability OFF


@dataclass(frozen=True)
class AttackChain:
    steps: tuple[str, ...]            # ordered pre-registered hypothesis ids
    establishes: tuple[str, ...]      # accumulated effect atoms, sorted

    def to_dict(self) -> dict[str, Any]:
        return {"steps": list(self.steps), "establishes": list(self.establishes)}


@dataclass(frozen=True)
class ComposeResult:
    status: ComposeStatus
    goal: str
    chains: tuple[AttackChain, ...]
    note: str

    def to_dict(self) -> dict[str, Any]:
        return {"status": self.status.value, "goal": self.goal, "chains": [c.to_dict() for c in self.chains],
                "note": self.note}


def precondition_of(hypothesis_id: str) -> dict[str, Any]:
    """ZR-019 `precondition`: the state a step needs, as a JSON-safe dict."""
    link = LINKS[hypothesis_id]
    return {"state_atoms": sorted(link.precondition),
            "satisfied_by_baseline": link.precondition <= BASELINE_STATE}


def effect_of(hypothesis_id: str) -> dict[str, Any]:
    """ZR-019 `effect`: the state a step establishes IF confirmed, JSON-safe."""
    return {"state_atoms": sorted(LINKS[hypothesis_id].effect),
            "note": "established only if the oracle confirms this step (ZR-017); not asserted otherwise"}


def compose_chains(goal: str, *, enabled: bool, max_depth: int = 4, max_chains: int = 32) -> ComposeResult:
    """Find precondition-gated orderings of pre-registered steps that reach `goal`
    as their final step, starting from BASELINE_STATE. FAIL-CLOSED: returns an empty
    FAIL_CLOSED result when `enabled` is False (the control is absent)."""
    if goal not in LINKS:
        raise KeyError(f"unknown goal {goal!r} (not a pre-registered oracle class)")
    if not 1 <= max_depth <= MAX_DEPTH_CAP:
        raise ValueError(f"max_depth must be in 1..{MAX_DEPTH_CAP}")
    if not enabled:
        return ComposeResult(ComposeStatus.FAIL_CLOSED, goal, (),
                             "FAIL-CLOSED: chain composition is disabled because its enabling control is absent "
                             "(the capability turns off, not open)")

    found: list[AttackChain] = []

    def dfs(seq: list[str], state: frozenset[str]) -> None:
        if len(found) >= SEARCH_CAP:
            return
        if seq and seq[-1] == goal:               # goal is always terminal (never mid-chain)
            found.append(AttackChain(tuple(seq), tuple(sorted(state))))
            return
        if len(seq) >= max_depth:
            return
        for h in sorted(LINKS):
            if h in seq:
                continue
            if LINKS[h].precondition <= state:
                dfs(seq + [h], state | LINKS[h].effect)

    dfs([], BASELINE_STATE)
    found.sort(key=lambda c: (len(c.steps), c.steps))   # shortest, most useful chains first
    chains = tuple(found[:max_chains])
    if not chains:
        return ComposeResult(ComposeStatus.NO_CHAIN, goal, (),
                             f"no precondition-gated chain of pre-registered steps reaches {goal} within depth "
                             f"{max_depth}")
    return ComposeResult(ComposeStatus.COMPOSED, goal, tuple(chains),
                         f"{len(chains)} bounded chain(s) reaching {goal}; each is an ordering of pre-registered, "
                         f"separately-confirmed findings (a planning/impact narrative, never proof or a new capability)")


def compose_payload(goal: str, *, enabled: bool, max_depth: int = 4, max_chains: int = 32) -> dict[str, Any]:
    res = compose_chains(goal, enabled=enabled, max_depth=max_depth, max_chains=max_chains)
    return {"module_version": MODULE_VERSION, **res.to_dict(),
            "note": "Bounded to the ten pre-registered oracle classes (ZR-036) and FAIL-CLOSED (off without its "
                    "control). A chain orders existing findings; it is never a new capability, never exploit code, "
                    "and never proof -- each step is still confirmed by its own oracle (ZR-017)."}
