#!/usr/bin/env python3
"""Run the engine against the BOSS 'Obelisk' target (depth-10; RFC 9421 content-digest-bound asymmetric
signing). See boss_obelisk.py."""
from __future__ import annotations

import asyncio

from hardened_benchmark import boss_obelisk as O


async def main() -> int:
    truth = await O.probe_obelisk_truth()
    found, result = await O.run_engine()
    pbbu = next((f for f in result.findings if f.hypothesis_id == "PBB-U"), None)
    print("== BOSS target 'Obelisk' (depth-10; RFC 9421 content-digest-bound Ed25519 signing) ==")
    print(f"  independent truth prober: real no-payment enterprise bypass exists = {truth}")
    print(f"  engine CONFIRMED_P0 (no-payment enterprise)                        = {found}")
    print(f"  PBB-U verdict = {pbbu.verdict.value if pbbu else None}")
    if pbbu and found:
        print(f"  chain = {pbbu.metrics.get('chain')}")
    print(f"  calls used = {result.stats.get('customer_level_calls')}")
    print(f"  (webhook is HMAC-signed with a server secret that is NEVER exposed -> unforgeable -> dead-end)")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
