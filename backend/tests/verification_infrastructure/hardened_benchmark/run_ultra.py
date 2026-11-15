#!/usr/bin/env python3
"""Run the ultra-realistic Northwind target against the current engine and diagnose.

    PYTHONPATH=tests/verification_infrastructure/shims:tests/verification_infrastructure:. \
        python3 tests/verification_infrastructure/hardened_benchmark/run_ultra.py
"""
from __future__ import annotations

import asyncio

from app.enterprise_controls.scope import ScopeGuard, ScopePolicy
from app.testing.http_client import QAHttpClient
from app.testing.integrity.brief import ExecutionBrief
from app.testing.integrity.engine import PureBlackBoxEngine
from hardened_benchmark.ultra_target import probe_ultra_truth, start_ultra_target, ultra_brief


async def main() -> int:
    truth = await probe_ultra_truth()
    print("== ground truth (driven through the public API) ==")
    print(f"  unpaid org denied the feature              : {truth['unpaid_denied']}")
    print(f"  voucher alone is harmless                  : {truth['voucher_alone_harmless']}")
    print(f"  activate without voucher/payment harmless  : {truth['activate_without_voucher_harmless']}")
    print(f"  recon + claim + activate -> free enterprise: {truth['chain_grants_enterprise']}")
    print(f"  => a real 2-primitive chain bypass exists  : {truth['bypass_present']}")

    target, server, port = await start_ultra_target()
    base = f"http://127.0.0.1:{port}"
    http = None
    try:
        brief = ExecutionBrief.from_dict(ultra_brief(base), env={})
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
    print("\n== engine result (recon + chaining enabled) ==")
    print(f"  confirmed P0s            : {confirmed or '- (none)'}")
    print(f"  called /vouchers/claim   : {'/api/v2/billing/vouchers/claim' in paths}")
    print(f"  called /subscription/activate : {'/api/v2/billing/subscription/activate' in paths}")
    print(f"  called /billing/catalog  : {'/api/v2/billing/catalog' in paths}")
    print(f"  customer-level calls     : {result.stats['customer_level_calls']}")

    missed = truth["bypass_present"] and not confirmed
    print("\n== diagnosis ==")
    if missed:
        print("  RESULT: MISS. A real 2-primitive chain bypass exists and the engine did not find it.")
        print("  WHY: the chain probe composes only ONE auxiliary primitive around checkout->return. This bypass")
        print("       needs TWO composed primitives in sequence (claim-voucher THEN activate), with the voucher_id")
        print("       flowing from step 1 into step 2 and the ENTERPRISE price_id learned from the catalog (not the")
        print("       first/'recommended' one), and provisioning happens on 'activate', not on 'return'.")
        print("  NEEDED: depth-2 sequence composition with intermediate harvest + catalog-ranked selector values +")
        print("          a feature check after each step (not only after return_flow).")
    else:
        print(f"  RESULT: engine confirmed {confirmed}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
