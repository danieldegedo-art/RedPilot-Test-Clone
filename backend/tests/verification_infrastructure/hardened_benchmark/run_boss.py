#!/usr/bin/env python3
"""Run the engine against the BOSS 'Aurelia' target and print whether it finds the depth-4 no-payment
enterprise bypass, alongside the independent truth prober. See boss_target.py for the design."""
from __future__ import annotations

import asyncio

from hardened_benchmark import boss_target as B


async def main() -> int:
    truth = await B.probe_boss_truth()
    found, result = await B.run_engine()
    pbbu = next((f for f in result.findings if f.hypothesis_id == "PBB-U"), None)
    print("== BOSS target 'Aurelia' (decoupled billing + most-generous-wins entitlement) ==")
    print(f"  independent truth prober: real no-payment enterprise bypass exists = {truth}")
    print(f"  engine CONFIRMED_P0 (no-payment enterprise)                        = {found}")
    print(f"  PBB-U verdict = {pbbu.verdict.value if pbbu else None}")
    if pbbu and found:
        print(f"  chain = {pbbu.metrics.get('chain')}")
    print(f"  calls used = {result.stats.get('customer_level_calls')}")
    # webhook dead-end must NOT be the confirmation path
    print(f"  (webhook settlement path is HMAC-signed -> unforgeable black-box -> must stay a dead-end)")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
