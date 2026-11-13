#!/usr/bin/env python3
"""Run the engine against the BOSS 'Obsidian' target (depth-6; capability id carried in the Location
header; reverse-engineered route; two-reference stage + commit). See boss_obsidian.py."""
from __future__ import annotations

import asyncio

from hardened_benchmark import boss_obsidian as O


async def main() -> int:
    truth = await O.probe_obsidian_truth()
    found, result = await O.run_engine()
    pbbu = next((f for f in result.findings if f.hypothesis_id == "PBB-U"), None)
    print("== BOSS target 'Obsidian' (Location-header capability + reverse-engineered route + multi-ref commit) ==")
    print(f"  independent truth prober: real no-payment enterprise bypass exists = {truth}")
    print(f"  engine CONFIRMED_P0 (no-payment enterprise)                        = {found}")
    print(f"  PBB-U verdict = {pbbu.verdict.value if pbbu else None}")
    if pbbu and found:
        print(f"  chain = {pbbu.metrics.get('chain')}")
    print(f"  calls used = {result.stats.get('customer_level_calls')}")
    print(f"  (webhook settlement path is Standard-Webhooks HMAC-signed -> unforgeable -> must stay a dead-end)")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
