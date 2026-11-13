"""B12: Race-Condition Harness -- the bounded, dependency-free detector half.

A live concurrency harness needs a real target (not available here, and the risky
part), so B12's buildable core is the ANALYSIS: given the observed time intervals of
the quota-granting operations, detect a time-of-check-to-time-of-use (TOCTOU) window
where more grant operations overlap than the paid quota allows -- i.e. concurrent
return-flow repetitions that could yield duplicate paid value.

It is bounded and honest:
  * Pure interval analysis over operations the engine already observed; a hard cap on
    how many operations it will process; deterministic sweep.
  * A detected window is a LEAD to confirm with the pre-registered PBB-C oracle (the
    duplicate-value class), never a finding and never proof on its own (ZR-017).
  * `suggest_probe_concurrency` returns a BOUNDED, capped number of concurrent
    repetitions to probe -- it never suggests unbounded load.

Stdlib only; pure.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

MODULE_VERSION = "race-window/1.0"
MAX_OPS = 10000
MAX_PROBE_CONCURRENCY = 16


class RaceStatus(str, Enum):
    WINDOW_FOUND = "WINDOW_FOUND"   # concurrent grants exceed the quota -> duplicate-value race possible
    NO_WINDOW = "NO_WINDOW"


@dataclass(frozen=True)
class Operation:
    op_id: str
    start: float
    end: float


@dataclass(frozen=True)
class RaceResult:
    status: RaceStatus
    quota: int
    max_concurrent: int
    overlapping: tuple[str, ...]   # op ids active at the densest overlap
    note: str

    def to_dict(self) -> dict[str, Any]:
        return {"status": self.status.value, "quota": self.quota, "max_concurrent": self.max_concurrent,
                "overlapping": list(self.overlapping), "note": self.note}


def _peak(ops: list[Operation]) -> tuple[int, float]:
    """Max number of simultaneously-active intervals, and a time at which it occurs.
    Touching intervals (one ends as another starts) count as concurrent -- the
    conservative choice for race detection."""
    events: list[tuple[float, int]] = []
    for o in ops:
        events.append((o.start, 1))
        events.append((o.end, -1))
    # at equal times, apply +1 before -1 so touching intervals overlap
    events.sort(key=lambda e: (e[0], 0 if e[1] == 1 else 1))
    running = 0
    best = 0
    best_t = ops[0].start if ops else 0.0
    for t, delta in events:
        running += delta
        if running > best:
            best = running
            best_t = t
    return best, best_t


def detect(operations: list[Operation], *, quota: int, max_ops: int = MAX_OPS) -> RaceResult:
    """Detect a duplicate-value race window: a time where more grant operations are
    concurrently active than `quota` permits."""
    if quota < 1:
        raise ValueError("quota must be >= 1")
    if len(operations) > max_ops:
        raise ValueError(f"{len(operations)} operations exceeds the cap of {max_ops}")
    for o in operations:
        if o.end < o.start:
            raise ValueError(f"operation {o.op_id!r} has end < start")
    if not operations:
        return RaceResult(RaceStatus.NO_WINDOW, quota, 0, (), "no operations to analyse")

    max_concurrent, peak_t = _peak(operations)
    active = tuple(sorted(o.op_id for o in operations if o.start <= peak_t <= o.end))

    if max_concurrent > quota:
        return RaceResult(RaceStatus.WINDOW_FOUND, quota, max_concurrent, active,
                          f"LEAD: {max_concurrent} grant operations overlap but the paid quota is {quota}; a "
                          f"duplicate-value race may be possible — confirm with the PBB-C oracle (never a finding here)")
    return RaceResult(RaceStatus.NO_WINDOW, quota, max_concurrent, (),
                      f"max concurrent grants {max_concurrent} <= quota {quota}; no race window observed "
                      f"(absence is not proof the target is safe)")


def suggest_probe_concurrency(quota: int, *, cap: int = MAX_PROBE_CONCURRENCY) -> int:
    """A bounded number of concurrent repetitions to probe: just past the quota, hard-capped."""
    if quota < 1:
        raise ValueError("quota must be >= 1")
    return min(quota + 2, cap)


def detect_payload(operations: list[Operation], *, quota: int, max_ops: int = MAX_OPS) -> dict[str, Any]:
    res = detect(operations, quota=quota, max_ops=max_ops)
    return {"module_version": MODULE_VERSION, **res.to_dict(),
            "suggested_probe_concurrency": suggest_probe_concurrency(quota),
            "note": "TOCTOU race-window detection over observed operation intervals; a window is a LEAD for the "
                    "PBB-C duplicate-value oracle, never proof. Probe concurrency is bounded and capped."}
