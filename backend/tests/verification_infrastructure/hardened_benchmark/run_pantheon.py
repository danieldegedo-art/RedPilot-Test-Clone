#!/usr/bin/env python3
"""Run the engine against BOSS 'Pantheon' (depth-14 deny-by-default maze; four load-bearing buried flaws +
reverse-engineered 3-fragment capability-URL settlement route). Proves: (a) the engine FINDS the depth-14
composite; (b) removing ANY one flaw -> engine finds NOTHING (each flaw load-bearing); (c) the all-correct
variant -> 0 (zero false-alarm on the denied maze). See boss_pantheon.py."""
from __future__ import annotations

import asyncio

from hardened_benchmark import boss_pantheon as P

FULL = {"legacy_enabled": True, "reveal_authz_broken": True, "mandate_lax": True, "credit_lax": True}
SINGLE_REMOVED = {
    "no-alg-confusion": {**FULL, "legacy_enabled": False},
    "no-detokenize":    {**FULL, "reveal_authz_broken": False},
    "no-mandate-flaw":  {**FULL, "mandate_lax": False},
    "no-dunning-flaw":  {**FULL, "credit_lax": False},
}
ALL_CORRECT = {"legacy_enabled": False, "reveal_authz_broken": False, "mandate_lax": False, "credit_lax": False}


async def main() -> int:
    truth = await P.probe_pantheon_truth(**FULL)
    found, result = await P.run_engine(FULL)
    pbbu = next((f for f in result.findings if f.hypothesis_id == "PBB-U"), None)
    print("== BOSS target 'Pantheon' (depth-14 deny-by-default maze; 4 load-bearing flaws + hidden route) ==")
    print(f"  independent truth prober: real no-payment bypass exists = {truth}")
    print(f"  engine CONFIRMED_P0 (no-payment enterprise)             = {found}")
    print(f"  PBB-U verdict = {pbbu.verdict.value if pbbu else None}")
    if pbbu and found:
        print(f"  chain ({len(pbbu.metrics.get('chain') or [])} steps) = {pbbu.metrics.get('chain')}")
    print(f"  calls used = {result.stats.get('customer_level_calls')}")
    print("  -- per-flaw controls (each MUST be truth=False and engine=False: the flaw is load-bearing) --")
    for name, flags in SINGLE_REMOVED.items():
        t = await P.probe_pantheon_truth(**flags)
        f, r = await P.run_engine(flags)
        print(f"    {name:16s} truth={t!s:5s} engine_confirmed={f!s:5s} calls={r.stats.get('customer_level_calls')}")
    t0 = await P.probe_pantheon_truth(**ALL_CORRECT)
    f0, r0 = await P.run_engine(ALL_CORRECT)
    print(f"  ALL-CORRECT control: truth={t0} engine_confirmed={f0} (MUST be False/False) calls={r0.stats.get('customer_level_calls')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
