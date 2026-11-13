#!/usr/bin/env python3
"""Learning axis: does feedback-driven experiment ordering make the engine find a target
population's dominant flaw SOONER over time?

The engine already accepts an injected prioritizer (it chooses experiment ORDER only; the
engine stays the authority on verdicts). Here a LearningPrioritizer accumulates, across a
stream of targets, which classes actually confirm, and orders by Laplace-smoothed hit-rate.
Metric: the position (1-indexed) of the first CONFIRMED_P0 in the executed experiment order
-- lower = found sooner. We compare static order vs the learner, and show the learner's
first-half vs second-half (the learning curve). Detection itself is unchanged (the engine
still runs every experiment); this measures efficiency/triage speed, and it is injected, so
the default engine is untouched.

    PYTHONPATH=tests/verification_infrastructure/shims:tests/verification_infrastructure:. \
        python3 tests/verification_infrastructure/hardened_benchmark/learning_curve.py
"""
from __future__ import annotations

import asyncio
import random

from app.enterprise_controls.scope import ScopeGuard, ScopePolicy
from app.testing.http_client import QAHttpClient
from app.testing.integrity.brief import ExecutionBrief
from app.testing.integrity.engine import EXPERIMENT_ORDER, PureBlackBoxEngine
from purity_benchmark.customer_target import TargetFlags, start_customer_target
from purity_benchmark.lab import public_brief

ORDER_INDEX = {h: i for i, h in enumerate(EXPERIMENT_ORDER)}


class LearningPrioritizer:
    def __init__(self) -> None:
        self.stat: dict[str, list[int]] = {h: [0, 0] for h in EXPERIMENT_ORDER}

    def _score(self, h: str) -> float:
        hits, att = self.stat.get(h, [0, 0])
        return (hits + 1) / (att + 2)  # Laplace-smoothed observed confirmation rate

    def __call__(self, wanted: list[str]) -> list[str]:
        return sorted(wanted, key=lambda h: (-self._score(h), ORDER_INDEX.get(h, 99)))

    def update(self, confirmed: set[str], attempted: set[str]) -> None:
        for h in attempted:
            self.stat.setdefault(h, [0, 0])[1] += 1
        for h in confirmed:
            self.stat.setdefault(h, [0, 0])[0] += 1


async def run_one(flags: dict, prioritizer):
    target, server, port = await start_customer_target(TargetFlags(**flags))
    base = f"http://127.0.0.1:{port}"
    http = None
    try:
        brief = ExecutionBrief.from_dict(public_brief(base), env={})
        guard = ScopeGuard(ScopePolicy.for_environment(base, max_requests=brief.limits.max_requests,
                                                        max_requests_per_second=brief.limits.max_requests_per_second))
        http = QAHttpClient(base, brief.limits.timeout_seconds, None, {}, "qa-pure-black-box-engine/1.0",
                            max_retries=0, guard=guard, stateless=True)
        engine = PureBlackBoxEngine(http, brief, base_url=base, prioritizer=prioritizer)
        result = await engine.run(None)
        order = list(result.stats["experiment_order"])
        confirmed = {f.hypothesis_id for f in result.findings if f.verdict.value == "CONFIRMED_P0"}
        return order, confirmed
    finally:
        if http is not None and hasattr(http, "aclose"):
            await http.aclose()
        await server.aclose()


def first_hit_pos(order: list[str], confirmed: set[str]):
    for i, h in enumerate(order):
        if h in confirmed:
            return i + 1
    return None


def _mean(xs):
    return round(sum(xs) / len(xs), 2) if xs else None


async def main() -> int:
    stream = ([{"payment_owner_unchecked": True}] * 16   # dominant class X (6th in static order)
              + [{"return_trusts_status_claim": True}] * 4  # class U (1st)
              + [{}] * 4)                                   # clean (no confirmable P0)
    random.Random(7).shuffle(stream)

    static_pos = []
    for flags in stream:
        order, conf = await run_one(flags, None)
        p = first_hit_pos(order, conf)
        if p is not None:
            static_pos.append(p)

    learner = LearningPrioritizer()
    learned_pos = []
    for flags in stream:
        order, conf = await run_one(flags, learner)
        p = first_hit_pos(order, conf)
        if p is not None:
            learned_pos.append(p)
        learner.update(conf, set(order))

    half = len(learned_pos) // 2
    print(f"stream targets={len(stream)}  confirmable={len(static_pos)}  (dominant class X is 6th in static order)")
    print(f"static  mean first-hit position : {_mean(static_pos)}")
    print(f"learned mean first-hit position : {_mean(learned_pos)}")
    print(f"learned curve  first-half={_mean(learned_pos[:half])}  second-half={_mean(learned_pos[half:])}  (drop = learning)")
    if static_pos and learned_pos:
        red = 1 - (sum(learned_pos) / len(learned_pos)) / (sum(static_pos) / len(static_pos))
        print(f"reduction in mean experiments-before-first-hit : {red:.1%}")
    stats = {k: v for k, v in learner.stat.items() if v[1]}
    print(f"learned class hit/attempt stats : {stats}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
