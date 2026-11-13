#!/usr/bin/env python3
"""Run the chain-only paywall target against the current (recon-enabled) engine and
diagnose the result.

    PYTHONPATH=tests/verification_infrastructure/shims:tests/verification_infrastructure:. \
        python3 tests/verification_infrastructure/hardened_benchmark/run_chain.py
"""
from __future__ import annotations

import asyncio

from app.enterprise_controls.scope import ScopeGuard, ScopePolicy
from app.testing.http_client import QAHttpClient
from app.testing.integrity.brief import ExecutionBrief
from app.testing.integrity.engine import PureBlackBoxEngine
from hardened_benchmark.chain_target import chain_brief, probe_chain_truth, start_chain_target


async def main() -> int:
    truth = await probe_chain_truth()
    print("== ground truth (established by driving the public API) ==")
    print(f"  unpaid identity correctly denied the feature : {truth['unpaid_denied']}")
    print(f"  intent+return alone (no bind/pay) is harmless : {truth['intent_then_return_harmless']}")
    print(f"  recon+chain (intent->bind->return, no pay) grants free enterprise : {truth['chain_bypass_grants_enterprise']}")
    print(f"  => a real chain-only bypass exists           : {truth['bypass_present']}")

    target, server, port = await start_chain_target()
    base = f"http://127.0.0.1:{port}"
    http = None
    try:
        brief = ExecutionBrief.from_dict(chain_brief(base), env={})
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
    paths_hit = {p for _, p in target.request_log}
    bind_hit = any(p.endswith("/bind") for p in paths_hit)
    recon_hit = "/api/v1/orgs/current" in paths_hit

    print("\n== engine result (recon-breadth ENABLED) ==")
    print(f"  confirmed P0s               : {confirmed or '- (none)'}")
    print(f"  engine ever called /bind    : {bind_hit}")
    print(f"  engine ever called /orgs/current : {recon_hit}")
    print(f"  customer-level calls        : {result.stats['customer_level_calls']}")

    missed = truth["bypass_present"] and not confirmed
    print("\n== diagnosis ==")
    if missed:
        print("  RESULT: MISS. A real chain-only bypass exists and the engine did NOT find it.")
        print("  WHY: the engine's experiments are a FIXED set over single declared steps. It verified the")
        print("       normal pay->return flow and the 1-step return-claim tricks (correctly gated here), but it")
        print("       never composed the observed primitives (checkout-intent + bind + return) into the novel")
        print("       no-payment sequence, and it never exercised the /bind primitive at all.")
        print("  NEEDED: a bounded chain-reasoner that treats confirmed-harmless primitives as composable steps")
        print("          (precondition/effect) and tests candidate payment-skipping sequences via the real oracle.")
    else:
        print(f"  RESULT: engine confirmed {confirmed} (chain detected).")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
