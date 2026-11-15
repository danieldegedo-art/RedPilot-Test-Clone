#!/usr/bin/env python3
"""Run the engine against the BOSS 'Helios' target (depth-5, reverse-engineered route, two-reference
commit). See boss_helios.py for the design."""
from __future__ import annotations

import asyncio

from hardened_benchmark import boss_helios as H


async def main() -> int:
    truth = await H.probe_helios_truth()
    found, result = await H.run_engine()
    pbbu = next((f for f in result.findings if f.hypothesis_id == "PBB-U"), None)
    print("== BOSS target 'Helios' (reverse-engineered route + one-time-nonce two-reference commit) ==")
    print(f"  independent truth prober: real no-payment enterprise bypass exists = {truth}")
    print(f"  engine CONFIRMED_P0 (no-payment enterprise)                        = {found}")
    print(f"  PBB-U verdict = {pbbu.verdict.value if pbbu else None}")
    if pbbu and found:
        print(f"  chain = {pbbu.metrics.get('chain')}")
    print(f"  calls used = {result.stats.get('customer_level_calls')}")
    print(f"  (webhook settlement path is HMAC-signed -> unforgeable black-box -> must stay a dead-end)")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
