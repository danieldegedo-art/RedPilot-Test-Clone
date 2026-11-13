"""ZR-010: Next-Best-Action / information-gain planning.

The risk scheduler (prioritization.py, ZR-003/ZR-012) orders experiments by what
is LOST if a flaw is real (business impact). ZR-010 is the orthogonal dimension:
how much a given experiment would RESOLVE -- its expected information gain. The
spec has the two compose (the fleet weighs structural/info-gain value against
risk); this module owns the info-gain side.

BOUNDED (ZR-036): next_best_actions only ever ranks the hypotheses it is given --
the fixed, pre-registered oracle set. It never invents a hypothesis, never skips
one, and produces no verdict; it is an ORDERING/selection aid, exactly like the
risk scheduler.

Information gain per hypothesis = sum of three documented, bounded components
(each 0..1), nothing learned about untested states inferred:

  coverage_gap        COVERED -> 0.0 (already conclusive, nothing to learn),
                      PARTIALLY_COVERED -> 0.5, UNKNOWN or untested -> 1.0,
                      BLOCKED -> 0.0 (cannot learn more without a new capability).
  chokepoint_leverage B42's per-hypothesis weight, normalised to 0..1: testing a
                      hypothesis adjacent to a wide-cascade control informs the
                      most other classes.
  prior_uncertainty   RULED_OUT -> 0.0 (resolved), CONFIRMED_P0 -> 0.3 (regression
                      value only), PARTIAL/SUSPECTED -> 1.0 (closest to a
                      resolution), UNKNOWN / no prior -> 0.7 (unexplored).

Deterministic: ties break by the risk prior (BASE_RISK) then the caller's input
order. Stdlib only; pure.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from app.testing.prioritization import BASE_RISK, DEFAULT_BASE_RISK
from app.testing.purity.taxonomy import Verdict

_COVERAGE_GAP: dict[str, float] = {"COVERED": 0.0, "PARTIALLY_COVERED": 0.5, "UNKNOWN": 1.0, "BLOCKED": 0.0}
_UNTESTED_GAP = 1.0  # a class with no coverage cell at all has the most to learn

_PRIOR_UNCERTAINTY: dict[Verdict, float] = {
    Verdict.RULED_OUT: 0.0,
    Verdict.CONFIRMED_P0: 0.3,
    Verdict.PARTIALLY_VALIDATED_PAYMENT_INTEGRITY_ISSUE: 1.0,
    Verdict.SUSPECTED_PAYMENT_INTEGRITY_ISSUE: 1.0,
    Verdict.UNKNOWN: 0.7,
    Verdict.BLOCKED: 0.7,
}
_NO_PRIOR_UNCERTAINTY = 0.7


@dataclass(frozen=True)
class Action:
    hypothesis_id: str
    information_gain: float
    components: dict[str, float]
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        return {"hypothesis_id": self.hypothesis_id, "information_gain": round(self.information_gain, 4),
                "components": {k: round(v, 4) for k, v in self.components.items()}, "rationale": self.rationale}


def information_gain(
    hypotheses: Sequence[str], *,
    chokepoint_weights: Mapping[str, float] | None = None,
    coverage_by_hypothesis: Mapping[str, str] | None = None,
    prior_verdicts: Mapping[str, Verdict] | None = None,
) -> dict[str, dict[str, float]]:
    """Per-hypothesis info-gain component breakdown, for the given fixed set only."""
    weights = chokepoint_weights or {}
    max_w = max(weights.values()) if weights else 0.0
    coverage = coverage_by_hypothesis or {}
    priors = prior_verdicts or {}
    out: dict[str, dict[str, float]] = {}
    for h in hypotheses:
        cov = coverage.get(h)
        coverage_gap = _COVERAGE_GAP.get(cov, _UNTESTED_GAP) if cov is not None else _UNTESTED_GAP
        leverage = (weights.get(h, 0.0) / max_w) if max_w > 0 else 0.0
        verdict = priors.get(h)
        uncertainty = _PRIOR_UNCERTAINTY.get(verdict, _NO_PRIOR_UNCERTAINTY) if verdict is not None else _NO_PRIOR_UNCERTAINTY
        out[h] = {"coverage_gap": coverage_gap, "chokepoint_leverage": leverage, "prior_uncertainty": uncertainty}
    return out


def next_best_actions(
    hypotheses: Sequence[str], *,
    chokepoint_weights: Mapping[str, float] | None = None,
    coverage_by_hypothesis: Mapping[str, str] | None = None,
    prior_verdicts: Mapping[str, Verdict] | None = None,
) -> list[Action]:
    """Rank the given hypotheses by expected information gain (highest first).
    Ties break by risk prior (BASE_RISK) then input order -- deterministic.
    Returns the full ranked plan; the next best action is the first element."""
    components = information_gain(hypotheses, chokepoint_weights=chokepoint_weights,
                                  coverage_by_hypothesis=coverage_by_hypothesis, prior_verdicts=prior_verdicts)
    actions: list[tuple[int, Action]] = []
    for idx, h in enumerate(hypotheses):
        comp = components[h]
        gain = sum(comp.values())
        top = max(comp, key=lambda k: comp[k]) if any(comp.values()) else "none"
        rationale = f"info-gain {round(gain, 3)} (dominant: {top}); bounded to the fixed hypothesis set -- selection only, never a verdict"
        actions.append((idx, Action(h, gain, dict(comp), rationale)))
    actions.sort(key=lambda p: (-p[1].information_gain, -BASE_RISK.get(p[1].hypothesis_id, DEFAULT_BASE_RISK), p[0]))
    return [a for _, a in actions]


def next_best_actions_payload(actions: Sequence[Action]) -> dict[str, Any]:
    return {"next_best_action": actions[0].hypothesis_id if actions else None,
            "plan": [a.to_dict() for a in actions],
            "note": "Information-gain ordering within the fixed oracle set (ZR-036 bounded); composes with the risk scheduler, never overrides a verdict."}
