#!/usr/bin/env python3
"""Run the engine against BOSS 'ABRAXAS' and walk the full cycle: Harder Boss -> Clean MISS -> Fix -> FIND -> Upgrade.

ABRAXAS (see boss_abraxas.py) is the apex above NYX: it keeps EVERY correct guard NYX has (all Stripe guards done
right, opaque 422s that never name a field) and adds THREE orthogonal, load-bearing hard axes -- each a class that
public analyses report autonomous web agents (the XBOW family) struggle with, in the payment domain:
  (1) a DEPENDENCY-ORDERED mint DAG (later attestations consume earlier branches' capabilities),
  (2) a TOCTOU settlement window (the only route to $0 is to amend the rates INSIDE the capture gap: a race), and
  (3) a higher-fan-in DECOY convergence step that correctly recomputes server-side and never grants.
It proves:
  (a) the CURRENT engine (channel + chain + race + B49 convergence ON, fabric OFF) cleanly MISSES;
  (b) the UPGRADED engine (B50 fabric probe ON) FINDS the no-payment enterprise bypass and reproduces it;
  (c) each of the four flaws is load-bearing: remove any one -> truth=False AND engine=False;
  (d) all-correct -> False/False (no false alarm);
  (e) each NEW capability (DAG scheduling, the interleaved race, the multi-candidate search) is load-bearing.

    PYTHONPATH=tests/verification_infrastructure/shims:tests/verification_infrastructure:. \
        python3 tests/verification_infrastructure/hardened_benchmark/run_abraxas.py [--controls]
"""
from __future__ import annotations

import asyncio
import sys

from hardened_benchmark import boss_abraxas as A

FLAWS = ["ledger_open", "risk_open", "fabric_toctou", "fabric_rate_trust"]
FULL = {k: True for k in FLAWS}  # difficulty flags default to the HARD setting
SINGLE_REMOVED = {
    "no-ledger-flaw":     {**FULL, "ledger_open": False},
    "no-risk-flaw":       {**FULL, "risk_open": False},
    "no-toctou-flaw":     {**FULL, "fabric_toctou": False},
    "no-rate-trust-flaw": {**FULL, "fabric_rate_trust": False},
}
ALL_CORRECT = {k: False for k in FLAWS}


def _ans(target) -> str:
    if not target.calls_total:
        return "n/a"
    gr = 100.0 * target.grants_total / target.calls_total
    return (f"{100.0 * target.calls_error / target.calls_total:.1f}% non-2xx, access granted on "
            f"{gr:.2f}% ({target.grants_total}/{target.calls_total}), internal/mesh hits={target.internal_hits}")


async def main() -> int:
    controls = "--controls" in sys.argv
    truth = await A.probe_abraxas_truth(**FULL)
    miss_found, miss_res, miss_tgt = await A.run_engine(FULL, fabric=False)   # CURRENT engine (B49)
    find_found, find_res, find_tgt = await A.run_engine(FULL, fabric=True)    # UPGRADED engine (B50)
    pbbu = next((f for f in find_res.findings if f.hypothesis_id == "PBB-U"), None)

    hrate, herr, hgrants, htot = await A.abraxas_hostility(3000)
    print("== BOSS target 'ABRAXAS' (enterprise fabric: full signed/attested/scoped guard set, all correct; dependency-ordered mint DAG + TOCTOU window + honeytoken decoy mesh + short-lived step-up challenge; four load-bearing flaws) ==")
    print(f"  hardening under a {htot}-probe adversarial sweep: {hrate:.2f}% errors ({herr}/{htot}), access granted = {hgrants}")
    print(f"  independent truth prober: real no-payment enterprise bypass exists = {truth}")
    print("  -- Harder Boss -> Clean MISS (current engine: channel+chain+race+B49-convergence ON, fabric OFF) --")
    print(f"     engine CONFIRMED_P0 = {miss_found}   (MUST be False: the DAG busts the flat burst, the decoy starves single-candidate, the window needs a race)")
    print(f"     target answered     = {_ans(miss_tgt)}")
    print("  -- Fix -> FIND (upgraded engine: B50 settlement-fabric probe ON) --")
    print(f"     engine CONFIRMED_P0 = {find_found}   (MUST be True)")
    print(f"     PBB-U verdict       = {pbbu.verdict.value if pbbu else None}")
    if pbbu and find_found:
        print(f"     convergence step    = {pbbu.metrics.get('convergence_step')}")
        print(f"     capabilities        = {pbbu.metrics.get('capabilities')}")
        print(f"     candidates tried    = {pbbu.metrics.get('candidates_considered')}  (highest fan-in first; the decoy is backtracked)")
        print(f"     race used           = {pbbu.metrics.get('race_used')}")
        for i, layer in enumerate(pbbu.metrics.get("dag_layers", [])):
            print(f"       DAG layer {i}        = {' + '.join(layer)}  (fired concurrently)")
    print(f"     calls used          = {find_res.stats.get('customer_level_calls')}")
    print(f"     target answered     = {_ans(find_tgt)}")

    if controls:
        print("  -- per-flaw controls (each MUST be truth=False and engine=False: the flaw is load-bearing) --")
        for name, flags in SINGLE_REMOVED.items():
            t = await A.probe_abraxas_truth(**flags)
            f, _r, _tg = await A.run_engine(flags, fabric=True)
            print(f"     {name:20s} truth={t!s:5s} engine_confirmed={f!s:5s}")
        t0 = await A.probe_abraxas_truth(**ALL_CORRECT)
        f0, _r0, _tg0 = await A.run_engine(ALL_CORRECT, fabric=True)
        print(f"     ALL-CORRECT          truth={t0!s:5s} engine_confirmed={f0!s:5s} (MUST be False/False: no false alarm)")
        print("  -- current-engine necessity (B49 cannot find ABRAXAS under any difficulty relaxation short of trivial) --")
        c1, _r, _t = await A.run_engine(FULL, fabric=False)
        c2, _r, _t = await A.run_engine({**FULL, "dag_cross_deps": False}, fabric=False)
        c3, _r, _t = await A.run_engine({**FULL, "dag_cross_deps": False, "decoy_present": False}, fabric=False)
        c4, _r, _t = await A.run_engine({**FULL, "dag_cross_deps": False, "decoy_present": False, "toctou_window": False}, fabric=False)
        c5, _r, _t = await A.run_engine({**FULL, "dag_cross_deps": False, "decoy_present": False, "toctou_window": False, "fresh_challenge": False}, fabric=False)
        print(f"     B49, all HARD                                engine_confirmed={c1!s:5s} (MUST be False)")
        print(f"     B49, no DAG depth                            engine_confirmed={c2!s:5s} (MUST be False: decoy + window + challenge still defeat it)")
        print(f"     B49, no DAG depth, no decoy                  engine_confirmed={c3!s:5s} (MUST be False: no amend/race capability)")
        print(f"     B49, no DAG depth/decoy/window               engine_confirmed={c4!s:5s} (MUST be False: B49 never lowers a rate)")
        print(f"     B49, no DAG depth/decoy/window/challenge     engine_confirmed={c5!s:5s} (MUST be False: B49 still never lowers a rate)")
        print("  -- new-capability ablations (each NEW capability is individually load-bearing; target stays HARD) --")
        fd, _r, _t = await A.run_engine(FULL, fabric=True, fabric_use_dag=False)
        fr, _r, _t = await A.run_engine(FULL, fabric=True, fabric_use_race=False)
        fm, _r, _t = await A.run_engine(FULL, fabric=True, fabric_multi_candidate=False)
        fc, _r, _t = await A.run_engine(FULL, fabric=True, fabric_fresh_challenge=False)
        ff, _r, _t = await A.run_engine(FULL, fabric=True)
        print(f"     B50, DAG scheduling OFF (flat burst)         engine_confirmed={fd!s:5s} (MUST be False: dependent mints fire before their inputs)")
        print(f"     B50, interleaved race OFF (sequential amend) engine_confirmed={fr!s:5s} (MUST be False: the stale-attestation check turns it away)")
        print(f"     B50, multi-candidate OFF (decoy only)        engine_confirmed={fm!s:5s} (MUST be False: it commits to the decoy)")
        print(f"     B50, fresh-challenge late-binding OFF        engine_confirmed={fc!s:5s} (MUST be False: the step-up nonce expires before settlement)")
        print(f"     B50, full capability                         engine_confirmed={ff!s:5s} (MUST be True)")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
