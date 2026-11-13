#!/usr/bin/env python3
"""Run the extreme depth-3 + ordering target against the current engine and diagnose.

    PYTHONPATH=tests/verification_infrastructure/shims:tests/verification_infrastructure:. \
        python3 tests/verification_infrastructure/hardened_benchmark/run_extreme.py
"""
from __future__ import annotations

import asyncio

from app.enterprise_controls.scope import ScopeGuard, ScopePolicy
from app.testing.http_client import QAHttpClient
from app.testing.integrity.brief import ExecutionBrief
from app.testing.integrity.engine import PureBlackBoxEngine
from hardened_benchmark.extreme_target import extreme_brief, probe_extreme_truth, start_extreme_target


async def main() -> int:
    truth = await probe_extreme_truth()
    print("== ground truth (driven through the public API) ==")
    print(f"  unpaid org denied the feature                 : {truth['unpaid_denied']}")
    print(f"  obvious order (credit before schedule) REJECTED: {truth['obvious_order_rejected']}  (ordering is essential)")
    print(f"  correct order (schedule->credit->settle) grants: {truth['correct_order_grants_enterprise']}")
    print(f"  => a real depth-3 + ordering bypass exists     : {truth['bypass_present']}")

    target, server, port = await start_extreme_target()
    base = f"http://127.0.0.1:{port}"
    http = None
    try:
        brief = ExecutionBrief.from_dict(extreme_brief(base), env={})
        guard = ScopeGuard(ScopePolicy.for_environment(base, max_requests=brief.limits.max_requests,
                                                        max_requests_per_second=brief.limits.max_requests_per_second))
        http = QAHttpClient(base, brief.limits.timeout_seconds, None, {}, "qa-pure-black-box-engine/1.0",
                            max_retries=0, guard=guard, stateless=True)
        engine = PureBlackBoxEngine(http, brief, base_url=base, enable_channel_probe=True, enable_chain_probe=True)
        result = await engine.run(None)
    finally:
        if http is not None and hasattr(http, "aclose"):
            await http.aclose()
        await server.aclose()

    confirmed = sorted({f.hypothesis_id for f in result.findings if f.verdict.value == "CONFIRMED_P0"})
    paths = {p for _, p in target.request_log}
    print("\n== engine result (recon + depth-2 chaining enabled) ==")
    print(f"  confirmed P0s          : {confirmed or '- (none)'}")
    print(f"  called /schedule       : {'/v3/subscription/schedule' in paths}")
    print(f"  called a /settle        : {any(p.endswith('/settle') for p in paths)}")
    print(f"  called /credits/grant  : {'/v3/billing/credits/grant' in paths}")

    missed = truth["bypass_present"] and not confirmed
    print("\n== diagnosis ==")
    if missed:
        print("  RESULT: MISS. A real depth-3 + ordering bypass exists and the engine did not find it.")
        print("  WHY: the chain planner composes at most TWO primitives and does not reorder them. This bypass needs")
        print("       THREE composed steps (schedule -> credit -> settle) in a NON-OBVIOUS order, and the planner must")
        print("       LEARN the ordering from the 'stale_credit' rejection (mint the credit AFTER the schedule, then")
        print("       settle). Depth-2 + fixed order cannot express it.")
        print("  NEEDED: depth-3 composition + a bounded reorder search driven by step-rejection feedback (learn the")
        print("          ordering constraint, then retry in the corrected order).")
    else:
        print(f"  RESULT: engine confirmed {confirmed}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
