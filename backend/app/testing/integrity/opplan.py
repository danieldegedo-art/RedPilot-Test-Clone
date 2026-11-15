"""B39: OPPLAN Engagement Planning Engine (deterministic).

Before execution, an engagement gets an OPPLAN: the goal decomposed into concrete,
testable objectives (one per payment-oracle class), sequenced by information gain
(ZR-010, which already folds in B42 chokepoint leverage + ZR-006 coverage +
priors), each with a budget allocation and explicit abort conditions. It replaces
a flat test list with a decomposed, budgeted, abort-conditioned plan.

BOUNDED (spec §378 rejects B28 self-scope-expansion): objectives are generated
ONLY from the configured hypothesis set and declared B36 cross-engagement leads.
The planner never invents an objective outside that set, never expands scope, and
never decides a verdict -- a lead is a known-technique SEED that still must pass
the engagement's full validation.

DETERMINISTIC: the same hypotheses, budget, ordering signals and seed set produce
the same OPPLAN (and the same version hash); every objective records what it was
derived from. Re-planning is a fresh deterministic build with a new version, never
a silent mutation. Stdlib only; pure.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from app.testing.integrity.findings import EXPERIMENT_CLASSES
from app.testing.integrity.planning import next_best_actions
from app.testing.purity.taxonomy import Verdict

OPPLAN_VERSION_SCHEME = "opplan/1.0"
ABORT_CONDITIONS = (
    "objective budget exhausted",
    "class RULED_OUT with a discriminating oracle (cleared -- stop, do not keep burning budget)",
    "scope/purity denial or kill switch engaged",
    "synthetic identity pool exhausted",
)


@dataclass(frozen=True)
class Objective:
    objective_id: str
    hypothesis_id: str
    p0_class: str
    decomposition_axis: str
    priority_rank: int
    information_gain: float
    budget: int
    source: str
    abort_conditions: tuple[str, ...] = ABORT_CONDITIONS

    def to_dict(self) -> dict[str, Any]:
        return {"objective_id": self.objective_id, "hypothesis_id": self.hypothesis_id, "p0_class": self.p0_class,
                "decomposition_axis": self.decomposition_axis, "priority_rank": self.priority_rank,
                "information_gain": round(self.information_gain, 4), "budget": self.budget, "source": self.source,
                "abort_conditions": list(self.abort_conditions)}


@dataclass(frozen=True)
class OPPLAN:
    engagement_fingerprint: str
    total_budget: int
    objectives: tuple[Objective, ...]
    version: str

    def total_allocated(self) -> int:
        return sum(o.budget for o in self.objectives)

    def to_dict(self) -> dict[str, Any]:
        return {"scheme": OPPLAN_VERSION_SCHEME, "engagement_fingerprint": self.engagement_fingerprint,
                "total_budget": self.total_budget, "total_allocated": self.total_allocated(), "version": self.version,
                "objectives": [o.to_dict() for o in self.objectives],
                "note": "Deterministic, budgeted, abort-conditioned objectives over the configured hypothesis set only (B28 self-scope-expansion rejected); leads are seeds, never proof."}


def _allocate(total: int, weights: Sequence[float]) -> list[int]:
    """Largest-remainder allocation of `total` across objectives by weight, with a
    floor of 1 each when the budget allows (never starve an objective to 0 while
    others have budget -- an objective is re-ordered, never skipped). Deterministic."""
    n = len(weights)
    if n == 0 or total <= 0:
        return [0] * n
    if total >= n:
        base = [1] * n
        remaining = total - n
    else:
        base = [0] * n
        remaining = total
    s = sum(weights)
    if s <= 0:
        raw = [remaining / n] * n
    else:
        raw = [remaining * w / s for w in weights]
    floor = [int(x) for x in raw]
    rem = remaining - sum(floor)
    order = sorted(range(n), key=lambda i: (-(raw[i] - floor[i]), i))
    for i in order[:rem]:
        floor[i] += 1
    return [base[i] + floor[i] for i in range(n)]


def build_opplan(
    hypotheses: Sequence[str], *, total_budget: int,
    chokepoint_weights: Mapping[str, float] | None = None,
    coverage_by_hypothesis: Mapping[str, str] | None = None,
    prior_verdicts: Mapping[str, Verdict] | None = None,
    seeded: set[str] | None = None,
    engagement_fingerprint: str = "",
) -> OPPLAN:
    ranked = next_best_actions(hypotheses, chokepoint_weights=chokepoint_weights,
                               coverage_by_hypothesis=coverage_by_hypothesis, prior_verdicts=prior_verdicts)
    seeds = set(seeded or ())
    weights = [a.information_gain for a in ranked]
    budgets = _allocate(total_budget, weights)
    objectives: list[Objective] = []
    for rank, (action, budget) in enumerate(zip(ranked, budgets), start=1):
        h = action.hypothesis_id
        p0 = EXPERIMENT_CLASSES.get(h, "unknown_class")
        source = ("B36 cross-engagement lead (known-technique seed); must still pass this engagement's full validation"
                  if h in seeds else "configured hypothesis set")
        objectives.append(Objective(
            objective_id=f"OBJ-{rank:02d}-{h}", hypothesis_id=h, p0_class=p0,
            decomposition_axis=f"per_class:{p0}", priority_rank=rank, information_gain=action.information_gain,
            budget=budget, source=source,
        ))
    payload = json.dumps({"hyps": sorted(hypotheses), "budget": total_budget, "seeded": sorted(seeds),
                          "order": [(a.hypothesis_id, round(a.information_gain, 4)) for a in ranked]}, sort_keys=True)
    version = f"{OPPLAN_VERSION_SCHEME}:{hashlib.sha256(payload.encode()).hexdigest()[:16]}"
    return OPPLAN(engagement_fingerprint, total_budget, tuple(objectives), version)
