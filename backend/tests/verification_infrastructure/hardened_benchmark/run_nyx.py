#!/usr/bin/env python3
"""Run the engine against BOSS 'NYX' and walk the full cycle: Harder Boss -> Clean MISS -> Fix -> FIND -> Upgrade.

NYX is the apex target (see boss_nyx.py): all Stripe guards implemented CORRECTLY, opaque errors (never names a
field -> ~99.9% errors to a prober), and a no-payment ENTERPRISE bypass that requires converging a QUORUM of three
independent, freshness-windowed capabilities. It proves:
  (a) the CURRENT engine (chain + race + channel probes on, convergence OFF) cleanly MISSES -- opacity blinds its
      error-driven field learning and the sequential spine busts the freshness window;
  (b) the UPGRADED engine (convergence probe ON) FINDS the no-payment enterprise bypass and reproduces it;
  (c) each of the four flaws is load-bearing: remove any one -> truth=False AND engine=False;
  (d) all-correct -> False/False (no false alarm);
  (e) each NEW capability is load-bearing for DETECTION: the OLD engine finds it only when BOTH opacity and the
      freshness window are off; with either on, only the upgraded engine finds it.

    PYTHONPATH=tests/verification_infrastructure/shims:tests/verification_infrastructure:. \
        python3 tests/verification_infrastructure/hardened_benchmark/run_nyx.py [--controls]
"""
from __future__ import annotations

import asyncio
import sys

from hardened_benchmark import boss_nyx as N

CHAIN_FLAWS = ["ledger_open", "risk_open", "mandate_open", "quorum_trusts_rates"]
FULL = {k: True for k in CHAIN_FLAWS}  # opaque_errors + sync_window default True (the HARD setting)
SINGLE_REMOVED = {
    "no-ledger-flaw":   {**FULL, "ledger_open": False},
    "no-risk-flaw":     {**FULL, "risk_open": False},
    "no-mandate-flaw":  {**FULL, "mandate_open": False},
    "no-quorum-flaw":   {**FULL, "quorum_trusts_rates": False},
}
ALL_CORRECT = {k: False for k in CHAIN_FLAWS}


def _err_rate(target) -> str:
    if not target.calls_total:
        return "n/a"
    gr = 100.0 * target.grants_total / target.calls_total
    return (f"{100.0 * target.calls_error / target.calls_total:.1f}% non-2xx, access granted on "
            f"{gr:.2f}% ({target.grants_total}/{target.calls_total}), internal/mesh hits={target.internal_hits}")


async def main() -> int:
    controls = "--controls" in sys.argv
    truth = await N.probe_nyx_truth(**FULL)
    miss_found, miss_res, miss_tgt = await N.run_engine(FULL, converge=False)   # CURRENT engine
    find_found, find_res, find_tgt = await N.run_engine(FULL, converge=True)    # UPGRADED engine
    pbbu = next((f for f in find_res.findings if f.hypothesis_id == "PBB-U"), None)

    hrate, herr, hgrants, htot = await N.nyx_hostility(3000)
    print("== BOSS target 'NYX' (opaque errors + freshness-windowed 3-capability quorum; four load-bearing flaws) ==")
    print(f"  hardening under a {htot}-probe adversarial sweep: {hrate:.2f}% errors ({herr}/{htot}), access granted = {hgrants}")
    print(f"  independent truth prober: real no-payment enterprise bypass exists = {truth}")
    print("  -- Harder Boss -> Clean MISS (current engine: chain+race+channel ON, convergence OFF) --")
    print(f"     engine CONFIRMED_P0 = {miss_found}   (MUST be False: opacity blinds learning, window busts the spine)")
    print(f"     target answered     = {_err_rate(miss_tgt)}")
    print("  -- Fix -> FIND (upgraded engine: convergence probe ON) --")
    print(f"     engine CONFIRMED_P0 = {find_found}   (MUST be True)")
    print(f"     PBB-U verdict       = {pbbu.verdict.value if pbbu else None}")
    if pbbu and find_found:
        print(f"     convergence step    = {pbbu.metrics.get('convergence_step')}")
        print(f"     capabilities        = {pbbu.metrics.get('capabilities')}")
        for br in pbbu.metrics.get("branches", []):
            print(f"       branch {br['capability']:11s} = {' -> '.join(br['sub_chain'])}")
    print(f"     calls used          = {find_res.stats.get('customer_level_calls')}")
    print(f"     target answered     = {_err_rate(find_tgt)}")

    if controls:
        print("  -- per-flaw controls (each MUST be truth=False and engine=False: the flaw is load-bearing) --")
        for name, flags in SINGLE_REMOVED.items():
            t = await N.probe_nyx_truth(**flags)
            f, _r, _tg = await N.run_engine(flags, converge=True)
            print(f"     {name:16s} truth={t!s:5s} engine_confirmed={f!s:5s}")
        t0 = await N.probe_nyx_truth(**ALL_CORRECT)
        f0, _r0, _tg0 = await N.run_engine(ALL_CORRECT, converge=True)
        print(f"     ALL-CORRECT       truth={t0!s:5s} engine_confirmed={f0!s:5s} (MUST be False/False: no false alarm)")
        print("  -- current-engine necessity (the CURRENT engine cannot find NYX under any difficulty setting) --")
        fo1, _r, _t = await N.run_engine({**FULL, "opaque_errors": True, "sync_window": True}, converge=False)
        fo2, _r, _t = await N.run_engine({**FULL, "opaque_errors": False, "sync_window": True}, converge=False)
        fo3, _r, _t = await N.run_engine({**FULL, "opaque_errors": False, "sync_window": False}, converge=False)
        print(f"     OLD engine, opacity ON  / window ON   engine_confirmed={fo1!s:5s} (MUST be False)")
        print(f"     OLD engine, opacity OFF / window ON   engine_confirmed={fo2!s:5s} (MUST be False)")
        print(f"     OLD engine, opacity OFF / window OFF  engine_confirmed={fo3!s:5s} (MUST be False: too large for the brute spine's budget)")
        print("  -- new-capability ablations (each NEW capability is individually load-bearing; target stays HARD) --")
        fs, _r, _t = await N.run_engine(FULL, converge=True, convergence_use_schema=False)
        fc, _r, _t = await N.run_engine(FULL, converge=True, convergence_concurrent=False)
        ff, _r, _t = await N.run_engine(FULL, converge=True)
        print(f"     NEW engine, schema-satisfaction OFF   engine_confirmed={fs!s:5s} (MUST be False: opacity then blinds it)")
        print(f"     NEW engine, concurrent-mint OFF       engine_confirmed={fc!s:5s} (MUST be False: freshness window then busts it)")
        print(f"     NEW engine, full capability           engine_confirmed={ff!s:5s} (MUST be True)")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
