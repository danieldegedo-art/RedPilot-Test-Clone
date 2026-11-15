#!/usr/bin/env python3
"""Run the engine against BOSS 'Olympus' (depth-16, two services, SSRF hop). Proves: (a) the engine FINDS the
depth-16 cross-service composite; (b) removing ANY one of the five flaws -> engine finds nothing (each
load-bearing); (c) all-correct -> 0 (zero false-alarm). See boss_olympus.py."""
from __future__ import annotations

import asyncio
import sys

from hardened_benchmark import boss_olympus as O

FULL = {"ssrf_open": True, "legacy_enabled": True, "reveal_authz_broken": True, "mandate_lax": True, "credit_lax": True}
SINGLE_REMOVED = {
    "no-ssrf-hop":     {**FULL, "ssrf_open": False},
    "no-alg-confusion": {**FULL, "legacy_enabled": False},
    "no-detokenize":    {**FULL, "reveal_authz_broken": False},
    "no-mandate-flaw":  {**FULL, "mandate_lax": False},
    "no-dunning-flaw":  {**FULL, "credit_lax": False},
}
ALL_CORRECT = {k: False for k in FULL}


async def main() -> int:
    controls = "--controls" in sys.argv
    truth = await O.probe_olympus_truth(**FULL)
    found, result = await O.run_engine(FULL)
    pbbu = next((f for f in result.findings if f.hypothesis_id == "PBB-U"), None)
    print("== BOSS target 'Olympus' (depth-16, two services, SSRF hop; five load-bearing flaws) ==")
    print(f"  independent truth prober: real no-payment bypass exists = {truth}")
    print(f"  engine CONFIRMED_P0 (no-payment enterprise)             = {found}")
    print(f"  PBB-U verdict = {pbbu.verdict.value if pbbu else None}")
    if pbbu and found:
        print(f"  chain ({len(pbbu.metrics.get('chain') or [])} steps) = {pbbu.metrics.get('chain')}")
    print(f"  calls used = {result.stats.get('customer_level_calls')}")
    print(f"  internal-service (B) hits = {getattr(result, 'stats', {}).get('internal_hits', 'n/a')}")
    if controls:
        print("  -- per-flaw controls (each MUST be truth=False and engine=False: the flaw is load-bearing) --")
        for name, flags in SINGLE_REMOVED.items():
            t = await O.probe_olympus_truth(**flags)
            f, r = await O.run_engine(flags)
            print(f"    {name:16s} truth={t!s:5s} engine_confirmed={f!s:5s} calls={r.stats.get('customer_level_calls')}")
        t0 = await O.probe_olympus_truth(**ALL_CORRECT)
        f0, r0 = await O.run_engine(ALL_CORRECT)
        print(f"  ALL-CORRECT control: truth={t0} engine_confirmed={f0} (MUST be False/False) calls={r0.stats.get('customer_level_calls')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
