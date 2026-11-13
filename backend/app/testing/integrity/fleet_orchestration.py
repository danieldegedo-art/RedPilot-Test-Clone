"""B33: Fleet-Orchestration Layer -- BOUNDED and FAIL-CLOSED.

Schedules the pre-registered oracle hypotheses across a capped worker pool so an
engagement can run them in parallel waves while respecting their dependencies (a
step whose precondition is only met by another step's effect must run after it).

It is a PURE PLANNER, not an executor: it produces an orchestration plan (ordered
waves of hypothesis ids) that the existing engine then runs under its own controls.
B33 itself issues no requests, so it cannot widen what actually runs.

Bounds that keep a "fleet" from becoming open-ended automation:
  * Registered hypotheses only (ZR-036): every item must be a pre-registered oracle
    class (`findings.EXPERIMENT_CLASSES`); an unknown id is rejected.
  * Hard worker-count cap (`MAX_WORKERS_CAP`): concurrency is bounded; a wave never
    exceeds `max_workers`, and `max_workers` itself is capped.
  * Deterministic layering with cycle detection: a dependency cycle raises rather
    than looping; identical inputs give identical plans.
  * FAIL-CLOSED: orchestration is a gated capability -- without its enabling control
    `orchestrate(..., enabled=False)` returns an empty FAIL_CLOSED plan (no work is
    scheduled; the capability turns off, not open).

Dependencies can be supplied explicitly or derived from B32's precondition/effect
catalog (`dependencies_from_catalog`), so the fleet and the chain composer agree on
ordering.

Stdlib only; pure.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from app.testing.integrity.findings import EXPERIMENT_CLASSES

MODULE_VERSION = "fleet-orchestration/1.0"
MAX_WORKERS_CAP = 16


class OrchestrationStatus(str, Enum):
    SCHEDULED = "SCHEDULED"
    EMPTY = "EMPTY"              # nothing to schedule
    FAIL_CLOSED = "FAIL_CLOSED"  # enabling control absent -> capability OFF


@dataclass(frozen=True)
class OrchestrationPlan:
    status: OrchestrationStatus
    waves: tuple[tuple[str, ...], ...]
    max_workers: int
    note: str

    def to_dict(self) -> dict[str, Any]:
        return {"status": self.status.value, "waves": [list(w) for w in self.waves],
                "max_workers": self.max_workers, "note": self.note}


def dependencies_from_catalog(hypotheses: list[str]) -> dict[str, set[str]]:
    """Derive ordering deps from B32's catalog: within the given set, hyp B depends
    on hyp A when A's effect supplies an atom B's precondition needs and the baseline
    does not already provide it. Imported lazily to avoid a hard import cycle."""
    from app.testing.integrity.attack_chain import BASELINE_STATE, LINKS
    hs = [h for h in hypotheses]
    deps: dict[str, set[str]] = {h: set() for h in hs}
    for b in hs:
        needed = LINKS[b].precondition - BASELINE_STATE
        if not needed:
            continue
        for a in hs:
            if a != b and (LINKS[a].effect & needed):
                deps[b].add(a)
    return deps


def orchestrate(hypotheses: list[str], *, enabled: bool, max_workers: int,
                dependencies: dict[str, set[str]] | None = None) -> OrchestrationPlan:
    """Lay `hypotheses` into dependency-respecting waves of at most `max_workers`.
    FAIL-CLOSED when `enabled` is False."""
    if not 1 <= max_workers <= MAX_WORKERS_CAP:
        raise ValueError(f"max_workers must be in 1..{MAX_WORKERS_CAP}")
    unknown = [h for h in hypotheses if h not in EXPERIMENT_CLASSES]
    if unknown:
        raise ValueError(f"unregistered hypotheses {sorted(unknown)} (orchestrates pre-registered oracles only)")
    if len(set(hypotheses)) != len(hypotheses):
        raise ValueError("duplicate hypotheses in the work set")

    if not enabled:
        return OrchestrationPlan(OrchestrationStatus.FAIL_CLOSED, (), max_workers,
                                 "FAIL-CLOSED: fleet orchestration is disabled because its enabling control is "
                                 "absent (no work scheduled; the capability turns off, not open)")
    if not hypotheses:
        return OrchestrationPlan(OrchestrationStatus.EMPTY, (), max_workers, "no hypotheses to schedule")

    work = set(hypotheses)
    deps = {h: set(dependencies.get(h, set()) if dependencies else set()) & work for h in work}
    bad = {d for s in deps.values() for d in s} - work
    if bad:
        raise ValueError(f"dependencies reference hypotheses outside the work set: {sorted(bad)}")

    done: set[str] = set()
    pending = set(work)
    waves: list[tuple[str, ...]] = []
    while pending:
        ready = sorted(h for h in pending if deps[h] <= done)
        if not ready:
            raise ValueError(f"dependency cycle among {sorted(pending)} (orchestration never loops)")
        wave = tuple(ready[:max_workers])
        waves.append(wave)
        done.update(wave)
        pending.difference_update(wave)

    return OrchestrationPlan(OrchestrationStatus.SCHEDULED, tuple(waves), max_workers,
                             f"{len(work)} hypotheses in {len(waves)} wave(s), <= {max_workers} per wave, "
                             f"dependency-ordered; a plan for the engine to run under its own controls (B33 runs nothing)")


def orchestrate_payload(hypotheses: list[str], *, enabled: bool, max_workers: int,
                        dependencies: dict[str, set[str]] | None = None) -> dict[str, Any]:
    plan = orchestrate(hypotheses, enabled=enabled, max_workers=max_workers, dependencies=dependencies)
    return {"module_version": MODULE_VERSION, **plan.to_dict(),
            "note": "Bounded to pre-registered oracles (ZR-036), hard worker cap, deterministic, FAIL-CLOSED. "
                    "B33 only produces a schedule; the engine executes it under the usual controls."}
