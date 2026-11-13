#!/usr/bin/env python3
"""Speed: measure the opt-in find-fast triage mode on the enterprise-hard population.
Reports total customer calls with find-fast OFF vs ON, and proves detection-of-presence
and false positives are unchanged (find-fast only stops AFTER a confirmed P0).

    PYTHONPATH=tests/verification_infrastructure/shims:tests/verification_infrastructure:. \
        python3 tests/verification_infrastructure/hardened_benchmark/run_speed.py
"""
from __future__ import annotations

import asyncio

from app.enterprise_controls.scope import ScopeGuard, ScopePolicy
from app.testing.http_client import QAHttpClient
from app.testing.integrity.brief import ExecutionBrief
from app.testing.integrity.engine import PureBlackBoxEngine
from hardened_benchmark.enterprise_hard import hard_population, probe_enterprise_truth, start_enterprise_target
from purity_benchmark.lab import public_brief


async def run(hard, sla: float, find_fast: bool):
    target, server, port = await start_enterprise_target(hard)
    base = f"http://127.0.0.1:{port}"
    http = None
    try:
        brief = ExecutionBrief.from_dict(public_brief(base, {"limits": {"revocation_sla_seconds": sla}}), env={})
        guard = ScopeGuard(ScopePolicy.for_environment(base, max_requests=brief.limits.max_requests,
                                                        max_requests_per_second=brief.limits.max_requests_per_second))
        http = QAHttpClient(base, brief.limits.timeout_seconds, None, {}, "qa-pure-black-box-engine/1.0",
                            max_retries=0, guard=guard, stateless=True)
        engine = PureBlackBoxEngine(http, brief, base_url=base, enable_channel_probe=True, enable_chain_probe=True, find_fast=find_fast)
        result = await engine.run(None)
        confirmed = bool([f for f in result.findings if f.verdict.value == "CONFIRMED_P0"])
        return confirmed, result.stats["customer_level_calls"]
    finally:
        if http is not None and hasattr(http, "aclose"):
            await http.aclose()
        await server.aclose()


async def main() -> int:
    pop = hard_population()
    full_calls = fast_calls = 0
    full_tp = fast_tp = fp_full = fp_fast = present = 0
    flawed_full = flawed_fast = 0
    for name, hard in pop:
        truth = await probe_enterprise_truth(hard)
        cf, nf = await run(hard, hard.sla, find_fast=False)
        cff, nff = await run(hard, hard.sla, find_fast=True)
        full_calls += nf
        fast_calls += nff
        if truth.bypass_present:
            present += 1
            full_tp += int(cf)
            fast_tp += int(cff)
            flawed_full += nf
            flawed_fast += nff
        else:
            fp_full += int(cf)
            fp_fast += int(cff)

    print(f"population={len(pop)}  flawed={present}")
    print(f"detection-of-presence  full={full_tp}/{present}  find-fast={fast_tp}/{present}  (must be equal)")
    print(f"false positives        full={fp_full}            find-fast={fp_fast}            (must be 0)")
    print(f"total customer calls   full={full_calls}  find-fast={fast_calls}  reduction={1 - fast_calls/full_calls:.1%}")
    if flawed_full:
        print(f"calls on FLAWED targets full={flawed_full}  find-fast={flawed_fast}  reduction={1 - flawed_fast/flawed_full:.1%}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
