#!/usr/bin/env python3
"""Honest control: run the current engine (recon + depth-3 chaining) against a target with
the SAME flaw but authored OUTSIDE the planner's conventions. A miss here is the point --
it shows the planner is not magic and the earlier 1.0 reflects author-tailored targets.

    PYTHONPATH=tests/verification_infrastructure/shims:tests/verification_infrastructure:. \
        python3 tests/verification_infrastructure/hardened_benchmark/run_blind.py
"""
from __future__ import annotations

import asyncio

from app.enterprise_controls.scope import ScopeGuard, ScopePolicy
from app.testing.http_client import QAHttpClient
from app.testing.integrity.brief import ExecutionBrief
from app.testing.integrity.engine import PureBlackBoxEngine
from hardened_benchmark.blind_target import blind_brief, probe_blind_truth, start_blind_target


async def main() -> int:
    truth = await probe_blind_truth()
    print("== ground truth ==")
    print(f"  unpaid denied                       : {truth['unpaid_denied']}")
    print(f"  off-convention chain grants max tier: {truth['chain_grants_max']}")
    print(f"  => a real bypass exists             : {truth['bypass_present']}")

    target, server, port = await start_blind_target()
    base = f"http://127.0.0.1:{port}"
    http = None
    try:
        brief = ExecutionBrief.from_dict(blind_brief(base), env={})
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
    print("\n== engine result (recon + depth-3 chaining) ==")
    print(f"  confirmed P0s        : {confirmed or '- (none)'}")
    print(f"  reached /finalize    : {any(p.endswith('/finalize') for p in paths)}")
    print(f"  result: {'DETECTED (planner generalized)' if (truth['bypass_present'] and confirmed) else 'MISS -- the honest boundary: this flaw was authored outside the planner conventions (off-convention op names + remapped data-flow field), so the bounded planner does not compose it'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
