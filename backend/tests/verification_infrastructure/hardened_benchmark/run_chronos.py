#!/usr/bin/env python3
"""Run the engine against BOSS 'Chronos' (depth-22, double async-callback forge prefix + a DEEP in-chain TOCTOU
race gating the terminal grant). Proves:
(a) the engine FINDS the depth-22 chain, establishing the ~21-step forge prefix (numeric + BOLA + corr-1/corr-2)
    and then overrunning the terminal one-shot `claim_settlement_slot` with a bounded concurrent burst;
(b) removing ANY one of the eight flaws -> 0 (each load-bearing, the deep race included);
(c) all-correct -> 0 (zero false-alarm);
(d) the ATOMIC boundary: a correct (atomic) one-shot is unbeaten even with the race probe on.

    PYTHONPATH=tests/verification_infrastructure/shims:tests/verification_infrastructure:. \
        python3 tests/verification_infrastructure/hardened_benchmark/run_chronos.py [--controls]
"""
from __future__ import annotations

import asyncio
import sys

from hardened_benchmark import boss_chronos as C

FLAGS = ["ssrf_open", "callback_secret_leaked", "reveal_authz_broken", "mandate_lax", "credit_lax",
         "numeric_trusts_client", "bola_open", "race_window"]
FULL = {k: True for k in FLAGS}
SINGLE_REMOVED = {
    "no-ssrf-hop":          {**FULL, "ssrf_open": False},
    "no-leaked-callback":   {**FULL, "callback_secret_leaked": False},
    "no-detokenize":        {**FULL, "reveal_authz_broken": False},
    "no-mandate-flaw":      {**FULL, "mandate_lax": False},
    "no-dunning-flaw":      {**FULL, "credit_lax": False},
    "no-numeric-flaw":      {**FULL, "numeric_trusts_client": False},
    "no-bola-flaw":         {**FULL, "bola_open": False},
    "no-deep-race (atomic)": {**FULL, "race_window": False},
}
ALL_CORRECT = {k: False for k in FLAGS}


async def main() -> int:
    controls = "--controls" in sys.argv
    truth = await C.probe_chronos_truth(**FULL)
    found, result = await C.run_engine(FULL, race=True)
    pbbu = next((f for f in result.findings if f.hypothesis_id == "PBB-U"), None)
    print("== BOSS target 'Chronos' (depth-22, double async-callback forge prefix + DEEP in-chain TOCTOU race) ==")
    print(f"  independent truth prober: real no-payment bypass exists = {truth}")
    print(f"  engine CONFIRMED_P0 (no-payment enterprise)             = {found}")
    print(f"  PBB-U verdict = {pbbu.verdict.value if pbbu else None}")
    if pbbu and found:
        m = pbbu.metrics or {}
        chain = m.get("chain") or []
        print(f"  chain ({len(chain)} steps) = {chain}")
        print(f"  deep race: step={m.get('race_step')} depth={m.get('depth')} burst={m.get('burst')} prefix_len={len(m.get('prefix') or [])}")
    print(f"  calls used = {result.stats.get('customer_level_calls')}")
    if controls:
        print("  -- per-flaw controls (each MUST be truth=False and engine=False: the flaw is load-bearing) --")
        for name, flags in SINGLE_REMOVED.items():
            t = await C.probe_chronos_truth(**flags)
            f, r = await C.run_engine(flags, race=True)
            print(f"    {name:22s} truth={t!s:5s} engine_confirmed={f!s:5s} calls={r.stats.get('customer_level_calls')}")
        t0 = await C.probe_chronos_truth(**ALL_CORRECT)
        f0, r0 = await C.run_engine(ALL_CORRECT, race=True)
        print(f"  ALL-CORRECT control: truth={t0} engine_confirmed={f0} (MUST be False/False) calls={r0.stats.get('customer_level_calls')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
