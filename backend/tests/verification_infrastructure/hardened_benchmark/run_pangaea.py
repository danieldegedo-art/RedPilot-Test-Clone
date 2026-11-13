#!/usr/bin/env python3
"""Run the engine against BOSS 'Pangaea' (depth-20, double async-callback hop callback -> reconciler -> settlement
with TWO correlation bindings, and the reconciler gated by the three genuinely-new engine capabilities). Proves:
(a) the engine FINDS the depth-20 chain, forging BOTH correlation hops and folding in NUMERIC business-logic
    (net adjust <= 0 -> free) and MULTI-IDENTITY BOLA (a victim's beneficiary_ref) at the reconciler;
(b) removing ANY one of the seven chain flaws -> 0 (each load-bearing);
(c) all-correct -> 0 (zero false-alarm);
(d) the CONCURRENCY/TOCTOU race is a real flaw in this same target found by the opt-in bounded-burst pass
    (chain closed, race window open -> found), and an atomic (correct) slot stays unbeaten (-> 0).

Honest scope: two of the three new capabilities (numeric, BOLA) are exercised IN the depth-20 chain; the third
(race) is exercised against this target via the standalone bounded-burst pass -- a deep per-identity TOCTOU is
out of scope because it would need K concurrent full-chain prefixes and blow the 5000-call RoE budget. See
boss_pangaea.py. Run:

    PYTHONPATH=tests/verification_infrastructure/shims:tests/verification_infrastructure:. \
        python3 tests/verification_infrastructure/hardened_benchmark/run_pangaea.py [--controls]
"""
from __future__ import annotations

import asyncio
import sys

from hardened_benchmark import boss_pangaea as P

CHAIN_FLAGS = ["ssrf_open", "callback_secret_leaked", "reveal_authz_broken", "mandate_lax", "credit_lax",
               "numeric_trusts_client", "bola_open"]
FULL = {k: True for k in CHAIN_FLAGS}  # race_window defaults True in the target too
SINGLE_REMOVED = {
    "no-ssrf-hop":          {**FULL, "ssrf_open": False},
    "no-leaked-callback":   {**FULL, "callback_secret_leaked": False},
    "no-detokenize":        {**FULL, "reveal_authz_broken": False},
    "no-mandate-flaw":      {**FULL, "mandate_lax": False},
    "no-dunning-flaw":      {**FULL, "credit_lax": False},
    "no-numeric-flaw":      {**FULL, "numeric_trusts_client": False},
    "no-bola-flaw":         {**FULL, "bola_open": False},
}
ALL_CORRECT = {k: False for k in CHAIN_FLAGS}


async def main() -> int:
    controls = "--controls" in sys.argv
    truth = await P.probe_pangaea_truth(**FULL)
    found, result = await P.run_engine(FULL, race=False)
    pbbu = next((f for f in result.findings if f.hypothesis_id == "PBB-U"), None)
    print("== BOSS target 'Pangaea' (depth-20, double async-callback hop + numeric + BOLA + race; seven chain flaws) ==")
    print(f"  independent truth prober: real no-payment bypass exists = {truth}")
    print(f"  engine CONFIRMED_P0 (no-payment enterprise)             = {found}")
    print(f"  PBB-U verdict = {pbbu.verdict.value if pbbu else None}")
    if pbbu and found:
        chain = pbbu.metrics.get("chain") or []
        print(f"  chain ({len(chain)} steps) = {chain}")
    print(f"  calls used = {result.stats.get('customer_level_calls')}")
    if controls:
        print("  -- per-flaw controls (each MUST be truth=False and engine=False: the flaw is load-bearing) --")
        for name, flags in SINGLE_REMOVED.items():
            t = await P.probe_pangaea_truth(**flags)
            f, r = await P.run_engine(flags, race=False)
            print(f"    {name:18s} truth={t!s:5s} engine_confirmed={f!s:5s} calls={r.stats.get('customer_level_calls')}")
        t0 = await P.probe_pangaea_truth(**ALL_CORRECT)
        f0, r0 = await P.run_engine(ALL_CORRECT, race=False)
        print(f"  ALL-CORRECT control: truth={t0} engine_confirmed={f0} (MUST be False/False) calls={r0.stats.get('customer_level_calls')}")
        print("  -- race capability against this target (opt-in bounded burst) --")
        fr, rr = await P.run_engine({**FULL, "numeric_trusts_client": False}, race=True)
        rm = {}
        for f in rr.findings:
            if f.verdict.value == "CONFIRMED_P0":
                rm = {k: v for k, v in (f.metrics or {}).items() if "race" in k or "burst" in k}
        print(f"    race-only  (chain closed, window OPEN,  probe ON) engine_confirmed={fr!s:5s} race_metrics={rm}  (MUST be True)")
        fb, rb = await P.run_engine({**FULL, "numeric_trusts_client": False, "race_window": False}, race=True)
        print(f"    race-bound (chain closed, window ATOMIC, probe ON) engine_confirmed={fb!s:5s}  (MUST be False)")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
