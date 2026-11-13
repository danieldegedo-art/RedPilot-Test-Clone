"""B16: Feedback Loop.

Closes the loop between what a probe found and what the planners decide next: each
result is folded into the bounded per-hypothesis state that B39 (OPPLAN), B13
(local planner) and ZR-010 (next-best-action) read, so the next decision reflects
the latest evidence instead of the stale prior.

It is a pure, deterministic state-transition -- `apply(state, event) -> state` --
with the bounds that keep a feedback loop from becoming a scope-growth loop:

  * Events may only target an ALREADY-REGISTERED hypothesis. Feedback never
    synthesises a new hypothesis or target from a result (B28 self-scope-expansion
    is rejected here as everywhere).
  * `ruled_out` is monotonic and only DEMOTES: a RULED_OUT signal marks the class
    so the planners deprioritise it, but the hypothesis stays in consideration and
    is never skipped (the H4 false-clearance discipline). Nothing in this module
    removes a hypothesis.
  * Uncertainty moves only within [0, 1]; a conclusive signal lowers it, an
    INCONCLUSIVE signal is not treated as evidence (it never lowers uncertainty).
  * `fold` is idempotent per `event_id`: replaying the same event (a retry, a
    duplicated log) does not double-count.
  * State is class-level (ZR-038): keyed by hypothesis class, never an individual
    identity profile.

Stdlib only; pure.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any

MODULE_VERSION = "feedback-loop/1.0"
_CONCLUSIVE_FACTOR = 0.5


class Signal(str, Enum):
    ALLOWED = "ALLOWED"          # the feature was usable (conclusive observation)
    DENIED = "DENIED"            # the feature was refused (conclusive observation)
    INCONCLUSIVE = "INCONCLUSIVE"  # no usable result -- NOT evidence
    RULED_OUT = "RULED_OUT"      # the oracle's rule_out_condition was met (demote, never skip)

    @property
    def is_conclusive(self) -> bool:
        return self in (Signal.ALLOWED, Signal.DENIED)


@dataclass(frozen=True)
class HypothesisState:
    hypothesis_id: str
    probes: int = 0
    uncertainty: float = 1.0
    ruled_out: bool = False
    last_signal: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"hypothesis_id": self.hypothesis_id, "probes": self.probes,
                "uncertainty": round(self.uncertainty, 6), "ruled_out": self.ruled_out,
                "last_signal": self.last_signal}


@dataclass(frozen=True)
class FeedbackEvent:
    event_id: str
    hypothesis_id: str
    signal: Signal


def initial_state(hypothesis_id: str) -> HypothesisState:
    return HypothesisState(hypothesis_id=hypothesis_id)


def apply(state: HypothesisState, event: FeedbackEvent) -> HypothesisState:
    """Deterministically fold one event into one hypothesis's state."""
    if event.hypothesis_id != state.hypothesis_id:
        raise ValueError(f"event targets {event.hypothesis_id!r} but state is {state.hypothesis_id!r}")
    uncertainty = state.uncertainty
    if event.signal.is_conclusive:
        uncertainty = max(0.0, uncertainty * _CONCLUSIVE_FACTOR)   # a real result lowers uncertainty
    # INCONCLUSIVE / RULED_OUT: uncertainty unchanged (a non-result is not evidence)
    ruled_out = state.ruled_out or (event.signal == Signal.RULED_OUT)  # monotonic; demotes, never skips
    return replace(state, probes=state.probes + 1, uncertainty=uncertainty,
                   ruled_out=ruled_out, last_signal=event.signal.value)


@dataclass
class FoldResult:
    states: dict[str, HypothesisState]
    applied: list[str] = field(default_factory=list)   # event_ids actually applied, in order
    skipped_duplicates: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"states": {k: v.to_dict() for k, v in sorted(self.states.items())},
                "applied": list(self.applied), "skipped_duplicates": list(self.skipped_duplicates)}


def fold(states: dict[str, HypothesisState], events: list[FeedbackEvent], *, registered: set[str]) -> FoldResult:
    """Apply events in order to a copy of `states`. Rejects an event for an
    unregistered hypothesis (never invents a target). Idempotent per event_id."""
    out = dict(states)
    result = FoldResult(states=out)
    seen: set[str] = set()
    for ev in events:
        if ev.hypothesis_id not in registered:
            raise ValueError(f"event for unregistered hypothesis {ev.hypothesis_id!r} "
                             f"(feedback never creates a new target -- B28)")
        if ev.event_id in seen:
            result.skipped_duplicates.append(ev.event_id)
            continue
        seen.add(ev.event_id)
        out[ev.hypothesis_id] = apply(out.get(ev.hypothesis_id, initial_state(ev.hypothesis_id)), ev)
        result.applied.append(ev.event_id)
    return result


def fold_payload(states: dict[str, HypothesisState], events: list[FeedbackEvent], *, registered: set[str]) -> dict[str, Any]:
    res = fold(states, events, registered=registered)
    return {"module_version": MODULE_VERSION, **res.to_dict(),
            "note": "Feedback updates only the bounded per-hypothesis state the planners read; it never creates a "
                    "hypothesis/target (B28), ruled_out only demotes and never skips (H4), and INCONCLUSIVE is not "
                    "treated as evidence."}
