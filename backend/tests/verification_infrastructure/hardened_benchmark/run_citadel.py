#!/usr/bin/env python3
"""Run the engine against the BOSS 'Citadel' target (depth-7; requires constructing an HMAC request
signature from a provisioned key; zero-trust decoys). See boss_citadel.py."""
from __future__ import annotations

import asyncio

from hardened_benchmark import boss_citadel as C


async def main() -> int:
    truth = await C.probe_citadel_truth()
    found, result = await C.run_engine()
    pbbu = next((f for f in result.findings if f.hypothesis_id == "PBB-U"), None)
    print("== BOSS target 'Citadel' (zero-trust; client-signed request step; depth-7) ==")
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
