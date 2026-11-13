"""B10 (prioritization half) / ZR-003 / ZR-012: risk-driven experiment ordering.

WHAT THIS DECIDES, AND WHAT IT NEVER DECIDES
--------------------------------------------
This decides ORDER only: which hypothesis is tested first, so that when the run
budget or the synthetic-identity pool runs out, what's left untested is the
lower-risk end (ZR-012: "payment risk over UI/redirect/cache anomalies"). It
never skips an experiment, never adds one, and never produces or influences a
verdict. B10's description also says its score "gates CONFIRMED_P0"; that half
is deliberately NOT built, because ZR-024/ZR-025 are explicit that a confirmation
only ever comes from ConfirmationGate's AND-gate and that no scoring threshold
may upgrade anything to CONFIRMED_P0. Where B10's wording and ZR-024 disagree,
ZR-024 wins. The rejection/candidate-scoring half of B10 (oracle-strength tier,
reproduction count, evidence completeness, novelty) scores FINDINGS, not
experiments to schedule, and is a separate piece of work.

HOW A SCORE IS BUILT (all of it visible in ScoreBreakdown)
-----------------------------------------------------------
  score = base_risk + prior_adjustment + coverage_adjustment

  base_risk         -- a documented prior per hypothesis class (BASE_RISK): how
                       much is lost if the flaw is real. Configuration, not
                       truth; override per engagement via `weights`.
  prior_adjustment  -- EVIDENCE from an earlier run of the same target. An open
                       lead (PARTIALLY_VALIDATED, SUSPECTED) goes up; a cleared
                       hypothesis (RULED_OUT) goes down. RULED_OUT demotes
                       ORDER only -- it never removes a test, which matters
                       because the spec records a known false-clearance gap in
                       the RULED_OUT branch (H4); a falsely cleared hypothesis
                       still runs, just later.
  coverage_adjustment -- from the compiled FSM(s) (ZR-001): a hypothesis whose
                       flow family was actually observed on this target goes up;
                       one whose flow the engagement expected but recon never
                       found goes down (it would most likely come back BLOCKED
                       or UNKNOWN and shouldn't spend budget first). No FSM, or
                       a flow nobody expected or saw: no adjustment.

HARD CONSTRAINTS (not preferences -- score cannot override them)
-----------------------------------------------------------------
  * schedule() always returns a permutation of its input.
  * DERIVED_HYPOTHESES are held to the end. PBB-E is not run as an experiment:
    PureBlackBoxEngine._derive_e computes it from the view observations every
    OTHER experiment appends to ControlState while it runs. Scheduled early, it
    would see a partial observation set and could report "views agreed with the
    server in all observed states" over states it simply hadn't observed yet --
    a false clearance. The engine enforces this itself as well
    (integrity/engine.py::_apply_prioritizer); the default here makes the safe
    behaviour the one you get without asking for it.

Deterministic: equal scores keep the caller's input order.

Stdlib only.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable, Mapping, Sequence

from app.testing.fsm_compiler import CompiledFSM
from app.testing.purity.taxonomy import Verdict

# Documented priors, highest first. Rationale, in order of how much of a paid
# item's value is lost if the flaw is real:
BASE_RISK: Mapping[str, float] = {
    "PBB-U": 100.0,  # benefit with no valid payment at all
    "PBB-F": 90.0,   # benefit above what was paid for (tier)
    "PBB-H": 90.0,   # benefit at a price below the public price
    "PBB-X": 85.0,   # a payment redeemed by someone other than its owner
    "PBB-G": 85.0,   # a payment benefiting another tenant
    "PBB-R": 80.0,   # benefit retained after a confirmed refund
    "PBB-C": 75.0,   # benefit multiplied by replaying the return flow
    "PBB-E": 40.0,   # presentation disagreeing with the server -- ZR-012's "UI/redirect/cache anomalies"; the engine itself says NOT a P0 on its own
}
DEFAULT_BASE_RISK = 50.0  # a hypothesis with no registered weight: still scheduled, and reported in Schedule.unweighted

PRIOR_ADJUSTMENT: Mapping[Verdict, float] = {
    Verdict.PARTIALLY_VALIDATED_PAYMENT_INTEGRITY_ISSUE: +25.0,  # an open lead, closest to confirmation
    Verdict.SUSPECTED_PAYMENT_INTEGRITY_ISSUE: +15.0,
    Verdict.CONFIRMED_P0: +10.0,  # regression value (is the fix holding?), less urgent than an unresolved lead
    Verdict.UNKNOWN: 0.0,
    Verdict.BLOCKED: 0.0,
    Verdict.RULED_OUT: -30.0,  # cleared on this target: later, never skipped (see module docstring on H4)
}
COVERAGE_OBSERVED = +10.0
COVERAGE_EXPECTED_BUT_MISSING = -20.0

# Hypotheses computed from other experiments' observations rather than run as
# experiments in their own right -- they must come after everything they derive from.
DERIVED_HYPOTHESES: frozenset[str] = frozenset({"PBB-E"})


@dataclass(frozen=True)
class ScoreBreakdown:
    hypothesis_id: str
    base_risk: float
    weighted: bool  # False: no registered weight, DEFAULT_BASE_RISK was used
    prior_verdict: str | None
    prior_adjustment: float
    flow_family: str | None
    coverage_adjustment: float
    score: float
    held_last: bool  # forced to the end by a hard constraint, regardless of score


@dataclass(frozen=True)
class Schedule:
    order: tuple[str, ...]
    breakdowns: tuple[ScoreBreakdown, ...]  # same order as `order`

    @property
    def unweighted(self) -> tuple[str, ...]:
        return tuple(b.hypothesis_id for b in self.breakdowns if not b.weighted)

    @property
    def held_last(self) -> tuple[str, ...]:
        return tuple(b.hypothesis_id for b in self.breakdowns if b.held_last)


def _coverage_adjustment(flow: str | None, fsms: Sequence[CompiledFSM]) -> float:
    if flow is None or not fsms:
        return 0.0
    if any(f.segment(flow) is not None for f in fsms):
        return COVERAGE_OBSERVED
    if any(flow in f.uncovered_flow_types for f in fsms):
        return COVERAGE_EXPECTED_BUT_MISSING
    return 0.0


def schedule(
    hypotheses: Sequence[str], *,
    prior_verdicts: Mapping[str, Verdict] | None = None,
    fsms: Iterable[CompiledFSM] = (),
    flow_of: Mapping[str, str] | None = None,
    weights: Mapping[str, float] | None = None,
    derived_last: Iterable[str] = DERIVED_HYPOTHESES,
) -> Schedule:
    prior = prior_verdicts or {}
    fsm_list = tuple(fsms)
    base = dict(BASE_RISK)
    if weights:
        base.update(weights)
    derived = frozenset(derived_last)

    scored: list[tuple[int, ScoreBreakdown]] = []
    for idx, h in enumerate(hypotheses):
        weighted = h in base
        base_risk = base.get(h, DEFAULT_BASE_RISK)
        verdict = prior.get(h)
        prior_adj = PRIOR_ADJUSTMENT.get(verdict, 0.0) if verdict is not None else 0.0
        flow = flow_of.get(h) if flow_of else None
        cov_adj = _coverage_adjustment(flow, fsm_list)
        scored.append((idx, ScoreBreakdown(
            hypothesis_id=h, base_risk=base_risk, weighted=weighted,
            prior_verdict=verdict.value if verdict is not None else None, prior_adjustment=prior_adj,
            flow_family=flow, coverage_adjustment=cov_adj,
            score=round(base_risk + prior_adj + cov_adj, 4), held_last=h in derived,
        )))

    free = sorted((p for p in scored if not p[1].held_last), key=lambda p: (-p[1].score, p[0]))
    held = [p for p in scored if p[1].held_last]  # input order, regardless of score
    ordered = tuple(b for _, b in free) + tuple(b for _, b in held)
    return Schedule(order=tuple(b.hypothesis_id for b in ordered), breakdowns=ordered)


class Prioritizer:
    """The callable PureBlackBoxEngine accepts (prioritizer=...). Keeps the last
    Schedule so the caller can report WHY the run went in the order it did."""

    def __init__(self, **signals: object) -> None:
        self._signals = signals
        self.last_schedule: Schedule | None = None

    def __call__(self, hypotheses: Sequence[str]) -> list[str]:
        self.last_schedule = schedule(hypotheses, **self._signals)  # type: ignore[arg-type]
        return list(self.last_schedule.order)


PrioritizerFn = Callable[[Sequence[str]], Sequence[str]]
