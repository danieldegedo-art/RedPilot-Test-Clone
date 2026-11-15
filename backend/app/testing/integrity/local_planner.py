"""B13: Local Planner.

The OPPLAN planner (B39) sequences the whole engagement across hypotheses under a
global budget. B13 is its LOCAL counterpart: given where one hypothesis's
investigation currently stands, it picks the next concrete step to take WITHIN
that hypothesis.

What keeps it bounded (ZR-036) is that it never invents a step: the only steps it
will ever return are the ones parsed, in order, from that oracle's OWN
pre-registered `action_sequence` (`findings.SPECS[hyp].action_sequence`, split on
the spec's "->" separator). The sequence is fixed before any traffic, so the local
plan cannot grow new actions from a result.

Disciplines:
  * steps are taken strictly in the pre-registered order, and a step already
    completed is not repeated;
  * a stop signal (the oracle's stop_condition, a scope/purity/kill-switch halt)
    returns STOP immediately -- it HALTS, it never jumps past remaining steps to
    "finish" (the H4 discipline: stopping is not clearing);
  * a local step budget is honoured exactly (never exceeded);
  * it is deterministic and emits no action of its own -- it only names the next
    step for the executor to run under the usual controls.

Stdlib only; pure.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from app.testing.integrity.findings import SPECS

MODULE_VERSION = "local-planner/1.0"


class StepAction(str, Enum):
    PROCEED = "PROCEED"
    STOP = "STOP"


@dataclass(frozen=True)
class LocalStep:
    index: int
    label: str


@dataclass(frozen=True)
class LocalPlan:
    hypothesis_id: str
    action: StepAction
    next_step: LocalStep | None
    remaining_budget: int
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {"hypothesis_id": self.hypothesis_id, "action": self.action.value,
                "next_step": {"index": self.next_step.index, "label": self.next_step.label} if self.next_step else None,
                "remaining_budget": self.remaining_budget, "reason": self.reason}


def local_steps(hypothesis_id: str) -> tuple[LocalStep, ...]:
    """The pre-registered action sequence for this oracle, as ordered steps.
    Derived ONLY from the fixed spec text (split on '->'); nothing is added."""
    if hypothesis_id not in SPECS:
        raise KeyError(f"unknown hypothesis {hypothesis_id!r} (not a pre-registered oracle)")
    raw = SPECS[hypothesis_id].action_sequence
    parts = [p.strip().rstrip(".").strip() for p in raw.split("->")]
    return tuple(LocalStep(i, p) for i, p in enumerate(parts) if p)


def plan_next(hypothesis_id: str, completed_indices: set[int], *, local_budget: int,
              stop_signal: bool = False) -> LocalPlan:
    """Pick the next step for this hypothesis. `completed_indices` are the step
    indices already executed; `local_budget` caps total steps; `stop_signal` is a
    halt from the oracle's stop_condition or a scope/kill-switch denial."""
    if local_budget < 0:
        raise ValueError("local_budget must be >= 0")
    steps = local_steps(hypothesis_id)
    valid = {s.index for s in steps}
    bad = completed_indices - valid
    if bad:
        raise ValueError(f"completed_indices {sorted(bad)} are not steps of {hypothesis_id} (never invented)")

    used = len(completed_indices)
    remaining_budget = max(0, local_budget - used)

    if stop_signal:
        return LocalPlan(hypothesis_id, StepAction.STOP, None, remaining_budget,
                         "STOP: oracle stop_condition / scope-or-kill halt -- the plan halts here and does NOT "
                         "skip the remaining steps (stopping is not clearing)")
    if used >= local_budget:
        return LocalPlan(hypothesis_id, StepAction.STOP, None, 0,
                         f"STOP: local step budget exhausted ({used}/{local_budget})")
    remaining = [s for s in steps if s.index not in completed_indices]
    if not remaining:
        return LocalPlan(hypothesis_id, StepAction.STOP, None, remaining_budget,
                         "STOP: the pre-registered action sequence is complete")
    nxt = remaining[0]
    return LocalPlan(hypothesis_id, StepAction.PROCEED, nxt, remaining_budget,
                     f"PROCEED: next pre-registered step {nxt.index} of {len(steps)}")


def plan_payload(hypothesis_id: str, completed_indices: set[int], *, local_budget: int,
                 stop_signal: bool = False) -> dict[str, Any]:
    plan = plan_next(hypothesis_id, completed_indices, local_budget=local_budget, stop_signal=stop_signal)
    return {"module_version": MODULE_VERSION, "total_steps": len(local_steps(hypothesis_id)),
            "completed": sorted(completed_indices), "plan": plan.to_dict(),
            "note": "Local planning over a single oracle's PRE-REGISTERED action sequence only (ZR-036); the planner "
                    "names the next step, it does not act, invent steps, or expand scope."}
