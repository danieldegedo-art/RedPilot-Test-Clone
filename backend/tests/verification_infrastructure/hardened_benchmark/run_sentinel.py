#!/usr/bin/env python3
"""Run the engine against the BOSS 'Sentinel' target (depth-12 NEEDLE; single buried algorithm-confusion
flaw at the settlement). Also runs the CONTROL variant (legacy scheme disabled) to prove FP-resistance:
with the one flaw removed the engine must find NOTHING. See boss_sentinel.py."""
from __future__ import annotations

import asyncio

from hardened_benchmark import boss_sentinel as S


async def main() -> int:
    truth = await S.probe_sentinel_truth(legacy_enabled=True)
    ctrl_truth = await S.probe_sentinel_truth(legacy_enabled=False)
    found, result = await S.run_engine(legacy_enabled=True)
    pbbu = next((f for f in result.findings if f.hypothesis_id == "PBB-U"), None)
    c_found, c_result = await S.run_engine(legacy_enabled=False)
    print("== BOSS target 'Sentinel' (depth-12 NEEDLE; single alg-confusion flaw) ==")
    print(f"  independent truth prober: real no-payment enterprise bypass exists = {truth}")
    print(f"  CONTROL truth (legacy scheme disabled) -- must be False            = {ctrl_truth}")
    print(f"  engine CONFIRMED_P0 (no-payment enterprise)                        = {found}")
    print(f"  PBB-U verdict = {pbbu.verdict.value if pbbu else None}")
    if pbbu and found:
        print(f"  chain = {pbbu.metrics.get('chain')}")
    print(f"  calls used = {result.stats.get('customer_level_calls')}")
    print(f"  CONTROL (needle removed): engine CONFIRMED_P0 -- must be False      = {c_found}")
    print(f"  CONTROL calls used = {c_result.stats.get('customer_level_calls')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
