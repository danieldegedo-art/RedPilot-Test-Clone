#!/usr/bin/env python3
"""Run the engine against the BOSS 'Leviathan' target (depth-11; replay-aware forged webhook + fraud/step-up
gates). See boss_leviathan.py."""
from __future__ import annotations

import asyncio

from hardened_benchmark import boss_leviathan as L


async def main() -> int:
    truth = await L.probe_leviathan_truth()
    found, result = await L.run_engine()
    pbbu = next((f for f in result.findings if f.hypothesis_id == "PBB-U"), None)
    print("== BOSS target 'Leviathan' (depth-11; replay-aware forged webhook + fraud/step-up bypass) ==")
    print(f"  independent truth prober: real no-payment enterprise bypass exists = {truth}")
    print(f"  engine CONFIRMED_P0 (no-payment enterprise)                        = {found}")
    print(f"  PBB-U verdict = {pbbu.verdict.value if pbbu else None}")
    if pbbu and found:
        print(f"  chain = {pbbu.metrics.get('chain')}")
    print(f"  calls used = {result.stats.get('customer_level_calls')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
