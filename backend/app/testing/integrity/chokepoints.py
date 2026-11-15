"""B42 (Section 10.2): Attack-Path Chokepoint Analysis -- the bounded form.

A chokepoint is a single control (an entitlement check / validation step / state
transition) through which the greatest number of payment-integrity failure paths
converge: the node that, if flawed, cascades the widest. Fixing a high-cascade
chokepoint closes several P0 classes at once, so ranking them is remediation
targeting -- which fix buys the most -- not attack generation.

The spec's full B42 runs graph analytics over B36's knowledge graph + B32's
confirmed chains + B1's FSM. Those are later phases, so this is the BOUNDED form
that runs over what already exists: the current run's findings plus a declared
payment control-point model (the smallest reasonable, documented decision, per
ZR-036). CONTROL_POINTS maps each standard payment-integrity control to the
hypotheses whose confirmation would prove that control flawed -- used only for
remediation ranking, never for any verdict. When B36/B32 land, this module's
ranking is replaced by the graph-structural version; the output shape stays.

Ranking: a chokepoint with CONFIRMED findings is a proven-flawed chokepoint
(highest priority -- fixing it is known to close `cascade_width` classes); then
by cascade width; then by attack-distance (how few steps from externally
reachable). Sparse coverage of a chokepoint's region yields a 'provisional'
confidence that SUPPRESSES, never inflates, its weight (spec's confidence rule).

Stdlib only; pure (reads a finished EngineResult)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.testing.integrity.findings import EngineResult
from app.testing.purity.taxonomy import Verdict

# control_id -> (what the control must enforce, the hypotheses that prove it flawed when confirmed)
CONTROL_POINTS: dict[str, tuple[str, frozenset[str]]] = {
    "payment_event_verification": ("Entitlement is granted only on a server-verified payment-provider event, never on the return-flow's claimed status", frozenset({"PBB-U", "PBB-E"})),
    "plan_price_binding": ("The granted tier is derived from the plan/price the provider actually confirmed charged", frozenset({"PBB-F", "PBB-H"})),
    "entitlement_identity_binding": ("Entitlement is bound to the paying identity/tenant and re-checked on every protected request", frozenset({"PBB-G", "PBB-X", "PBB-LEAK"})),
    "grant_idempotency": ("One confirmed payment yields exactly one grant (idempotent per payment id)", frozenset({"PBB-C"})),
    "refund_revocation": ("A confirmed refund revokes entitlement within the declared tolerance", frozenset({"PBB-R"})),
    "entitlement_gating": ("A plan-gated feature is denied to any identity without a valid entitlement", frozenset({"PBB-OPEN"})),
}
# how few steps from externally-reachable state the control's flow sits (0 = entry point). Declared; used only for tie-breaking.
FLOW_DISTANCE: dict[str, int] = {"checkout": 0, "payment": 1, "subscription": 1, "entitlement": 2, "refund": 3}
_FAR = 9

_TESTED = (Verdict.CONFIRMED_P0, Verdict.RULED_OUT, Verdict.PARTIALLY_VALIDATED_PAYMENT_INTEGRITY_ISSUE, Verdict.SUSPECTED_PAYMENT_INTEGRITY_ISSUE)
_AT_RISK = (Verdict.CONFIRMED_P0, Verdict.PARTIALLY_VALIDATED_PAYMENT_INTEGRITY_ISSUE, Verdict.SUSPECTED_PAYMENT_INTEGRITY_ISSUE, Verdict.UNKNOWN)


@dataclass(frozen=True)
class Chokepoint:
    control_id: str
    description: str
    cascade_width: int               # structural blast radius: how many classes this control governs
    attack_distance: int             # fewest flow-steps from externally-reachable state among governed classes
    governed: tuple[str, ...]
    confirmed: tuple[str, ...]        # governed hypotheses CONFIRMED_P0 in this run (proof the control is flawed)
    at_risk: tuple[str, ...]          # confirmed + partial + unknown (not proven safe)
    confidence: str                   # "high" | "provisional" (region coverage density)
    priority_rank: int = 0            # 1 = highest-leverage fix (filled by rank_chokepoints)

    def to_dict(self) -> dict[str, Any]:
        return {"control_id": self.control_id, "description": self.description, "cascade_width": self.cascade_width,
                "attack_distance": self.attack_distance, "governed": list(self.governed), "confirmed": list(self.confirmed),
                "at_risk": list(self.at_risk), "confidence": self.confidence, "priority_rank": self.priority_rank}


def _chokepoint(control_id: str, result: EngineResult) -> Chokepoint:
    desc, hyps = CONTROL_POINTS[control_id]
    by_id = result.by_id()
    present = [by_id[h] for h in sorted(hyps) if h in by_id]
    confirmed = tuple(f.hypothesis_id for f in present if f.verdict == Verdict.CONFIRMED_P0)
    at_risk = tuple(f.hypothesis_id for f in present if f.verdict in _AT_RISK)
    tested = [f for f in present if f.verdict in _TESTED]
    density = (len(tested) / len(hyps)) if hyps else 0.0
    confidence = "high" if density >= 0.5 else "provisional"
    flows = {by_id[h].affected_flow for h in hyps if h in by_id and by_id[h].affected_flow}
    attack_distance = min((FLOW_DISTANCE.get(fl, _FAR) for fl in flows), default=_FAR)
    return Chokepoint(control_id, desc, len(hyps), attack_distance, tuple(sorted(hyps)), confirmed, at_risk, confidence)


def rank_chokepoints(result: EngineResult) -> list[Chokepoint]:
    """Ranked highest-leverage control first: proven-flawed (most confirmed) ->
    widest cascade -> nearest to externally-reachable state. Deterministic."""
    chokepoints = [_chokepoint(cid, result) for cid in CONTROL_POINTS]
    chokepoints.sort(key=lambda c: (-len(c.confirmed), -c.cascade_width, c.attack_distance, c.control_id))
    return [Chokepoint(c.control_id, c.description, c.cascade_width, c.attack_distance, c.governed, c.confirmed, c.at_risk, c.confidence, i + 1)
            for i, c in enumerate(chokepoints)]


def chokepoint_weights(result: EngineResult) -> dict[str, float]:
    """Per-hypothesis information-gain boost for B18/ZR-010 to consume: a hypothesis
    adjacent to a wide-cascade chokepoint is worth testing first. A 'provisional'
    (sparsely-covered) chokepoint's boost is halved, never inflated."""
    weights: dict[str, float] = {}
    for c in rank_chokepoints(result):
        boost = float(c.cascade_width) * (1.0 if c.confidence == "high" else 0.5)
        for h in c.governed:
            weights[h] = boost
    return weights


def chokepoint_report(result: EngineResult) -> dict[str, Any]:
    ranked = rank_chokepoints(result)
    proven = [c for c in ranked if c.confirmed]
    return {
        "chokepoints": [c.to_dict() for c in ranked],
        "weights": chokepoint_weights(result),
        "summary": {
            "total": len(ranked),
            "proven_flawed": [c.control_id for c in proven],
            "highest_leverage_fix": ranked[0].control_id if ranked else None,
            "note": "Bounded form over this run's findings + a declared payment control-point model; full graph-analytics form (over B36/B32/B1) is Phase 4.",
        },
    }
