#!/usr/bin/env python3
"""Run the engine against the BOSS 'Aegis' target (depth-8; two freshness-signed steps). See boss_aegis.py."""
from __future__ import annotations

import asyncio

from hardened_benchmark import boss_aegis as A


async def main() -> int:
    truth = await A.probe_aegis_truth()
    found, result = await A.run_engine()
    pbbu = next((f for f in result.findings if f.hypothesis_id == "PBB-U"), None)
    print("== BOSS target 'Aegis' (depth-8; two DPoP-style freshness-signed steps) ==")
    print(f"  independent truth prober: real no-payment enterprise bypass exists = {truth}")
    print(f"  engine CONFIRMED_P0 (no-payment enterprise)                        = {found}")
    print(f"  PBB-U verdict = {pbbu.verdict.value if pbbu else None}")
    if pbbu and found:
        print(f"  chain = {pbbu.metrics.get('chain')}")
    print(f"  calls used = {result.stats.get('customer_level_calls')}")
    print(f"  (webhook settlement path is HMAC-signed with a server secret -> unforgeable -> must stay a dead-end)")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
