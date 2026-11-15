#!/usr/bin/env python3
"""Persistent learning: the prioritizer's learning is stored in the real cross-session
memory layer (cognition.PersistentMemoryStore, SQLite procedural memory), so a brand-new
session starts WARM -- it finds the population's dominant flaw at position ~1 on its very
first target, instead of cold-starting at the static-order position.

    PYTHONPATH=tests/verification_infrastructure/shims:tests/verification_infrastructure:. \
        python3 tests/verification_infrastructure/hardened_benchmark/run_persistent_learning.py
"""
from __future__ import annotations

import asyncio
import pathlib
import uuid

from app.testing.cognition.persistent_memory import PersistentMemoryStore, ProceduralMemory
from app.testing.integrity.engine import EXPERIMENT_ORDER
from hardened_benchmark.learning_curve import LearningPrioritizer, ORDER_INDEX, first_hit_pos, run_one

PROC_TYPE = "exp_class_success"


class PersistentLearningPrioritizer:
    """Same ordering logic as the in-process learner, but its per-class hit/attempt counts
    live in PersistentMemoryStore (procedural memory), loaded on construction and persisted
    on every update -- so it carries between engagements/sessions."""

    def __init__(self, store: PersistentMemoryStore) -> None:
        self.store = store
        existing = {m.best_for.get("class"): m for m in store.get_procedural_by_type(PROC_TYPE)}
        self.proc: dict[str, ProceduralMemory] = {}
        for h in EXPERIMENT_ORDER:
            m = existing.get(h)
            if m is None:
                m = ProceduralMemory(procedure_type=PROC_TYPE, description=f"ordering stat for {h}", best_for={"class": h})
                store.store_procedural(m)
            self.proc[h] = m

    def _score(self, h: str) -> float:
        m = self.proc.get(h)
        used = m.times_used if m else 0
        succ = m.times_successful if m else 0
        return (succ + 1) / (used + 2)

    def __call__(self, wanted: list[str]) -> list[str]:
        return sorted(wanted, key=lambda h: (-self._score(h), ORDER_INDEX.get(h, 99)))

    def update(self, confirmed: set[str], attempted: set[str]) -> None:
        for h in attempted:
            m = self.proc.get(h)
            if m is None:
                continue
            m.times_used += 1
            if h in confirmed:
                m.times_successful += 1
            m.effectiveness = (m.times_successful / m.times_used) if m.times_used else 0.5
            self.store.store_procedural(m)  # persist to SQLite


DOMINANT = {"payment_owner_unchecked": True}  # class X (6th in the static order)


async def _train(store: PersistentMemoryStore, n: int) -> None:
    learner = PersistentLearningPrioritizer(store)
    for _ in range(n):
        order, conf = await run_one(DOMINANT, learner)
        learner.update(conf, set(order))


async def main() -> int:
    path = pathlib.Path("/tmp/claude-0/-home-claude/43a5d656-31be-58f6-b935-55a453242ee3/scratchpad") / f"persist_mem_{uuid.uuid4().hex[:8]}.db"

    # cold baseline: a fresh in-process learner, no memory -> first X-target at the static position
    cold = LearningPrioritizer()
    order, conf = await run_one(DOMINANT, cold)
    cold_first = first_hit_pos(order, conf)

    # session 1: train a persistent learner and let it write to the store
    store1 = PersistentMemoryStore(storage_path=str(path))
    await _train(store1, n=8)

    # session 2: a BRAND-NEW store object on the same path + a brand-new learner -> must load session 1's learning
    store2 = PersistentMemoryStore(storage_path=str(path))
    warm = PersistentLearningPrioritizer(store2)
    loaded = {h: (warm.proc[h].times_successful, warm.proc[h].times_used) for h in EXPERIMENT_ORDER if warm.proc[h].times_used}
    order, conf = await run_one(DOMINANT, warm)
    warm_first = first_hit_pos(order, conf)

    print("== persistent learning: cross-session carry-over ==")
    print(f"  dominant class X sits at static position {ORDER_INDEX['PBB-X'] + 1}")
    print(f"  loaded-from-disk stats in session 2 (succ/used) : {loaded}")
    print(f"  COLD learner, first target first-hit position   : {cold_first}")
    print(f"  WARM (persisted) learner, first target position : {warm_first}")
    print(f"  => carry-over works: {bool(loaded) and warm_first is not None and warm_first < cold_first}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
