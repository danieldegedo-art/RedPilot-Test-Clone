#!/usr/bin/env python3
"""Run the engine against BOSS 'PLEROMA' and walk the full cycle: Harder Boss -> Clean MISS -> Fix -> FIND -> Upgrade.

PLEROMA (see boss_pleroma.py) is the apex above ABRAXAS. It keeps ABRAXAS's ENTIRE enterprise crypto/attestation/
scope perimeter -- implemented CORRECTLY, so every signed/attested/convergence route is an unforgeable dead-end that
NEVER grants -- and adds the domain the previous bosses never modelled: the asynchronous MULTI-AUTHORITY USAGE-
METERING + ENTITLEMENT-RECONCILIATION business logic (Orb query-based billing + read-path overlay + closed-period
catch-up; Stripe/Metronome amend/credit; Microsoft base-blind metering). The one load-bearing no-payment ENTERPRISE
bypass lives in the reconciliation gap: a client-declared zero-rate credit overlay on an open billing period, locked
in by the close, is trusted by settlement reconciliation as the authoritative net due and finalises an enterprise
grant with no captured payment.

It proves:
  (a) the CURRENT engine (channel + chain + race + B49 convergence + B50 fabric ON, reconciliation OFF) cleanly
      MISSES -- the grant step consumes a single period handle, not a >=2-capability convergence, and the win is a
      sealed-before-settled ORDER, not a race, so the fabric composer never even selects it;
  (b) the UPGRADED engine (B52 reconciliation probe ON) FINDS the bypass and reproduces it in a clean session;
  (c) each of the four flaws is load-bearing: remove any one -> truth=False AND engine=False;
  (d) all-correct -> False/False (no false alarm);
  (e) each NEW capability (lifecycle reconstruction, the credit overlay, the seal-before-settle order) is load-bearing.

    PYTHONPATH=tests/verification_infrastructure/shims:tests/verification_infrastructure:. \
        python3 tests/verification_infrastructure/hardened_benchmark/run_pleroma.py [--controls]
"""
from __future__ import annotations

import asyncio
import sys

from hardened_benchmark import boss_pleroma as P

FLAWS = ["overlay_unbacked", "close_locks_overlay", "reconcile_trusts_aggregate", "reconcile_grants_without_basis"]
FULL = {k: True for k in FLAWS}
SINGLE_REMOVED = {
    "no-overlay-trust-flaw":   {**FULL, "overlay_unbacked": False},
    "no-close-lock-flaw":      {**FULL, "close_locks_overlay": False},
    "no-reconcile-trust-flaw": {**FULL, "reconcile_trusts_aggregate": False},
    "no-basis-free-grant-flaw": {**FULL, "reconcile_grants_without_basis": False},
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
    truth = await P.probe_pleroma_truth(**FULL)
    miss_found, miss_res, miss_tgt = await P.run_engine(FULL, reconciliation=False)   # CURRENT engine (through B50)
    find_found, find_res, find_tgt = await P.run_engine(FULL, reconciliation=True)    # UPGRADED engine (B52)
    pbbu = next((f for f in find_res.findings if f.hypothesis_id == "PBB-U"), None)

    hrate, herr, hgrants, htot = await P.pleroma_hostility(3000)
    print("== BOSS target 'PLEROMA' (full ABRAXAS perimeter, all correct; asynchronous multi-authority usage-metering + entitlement reconciliation; four load-bearing flaws in the reconciliation gap) ==")
    print(f"  hardening under a {htot}-probe adversarial sweep: {hrate:.2f}% errors ({herr}/{htot}), access granted = {hgrants}")
    print(f"  independent truth prober: real no-payment enterprise bypass exists = {truth}")
    print("  -- Harder Boss -> Clean MISS (current engine: channel+chain+race+B49-convergence+B50-fabric ON, reconciliation OFF) --")
    print(f"     engine CONFIRMED_P0 = {miss_found}   (MUST be False: the grant is a single-handle reconciliation, not a >=2-cap convergence; the win is a sealed-before-settled order, not a race)")
    print(f"     target answered     = {_ans(miss_tgt)}")
    print("  -- Fix -> FIND (upgraded engine: B52 reconciliation-gap probe ON) --")
    print(f"     engine CONFIRMED_P0 = {find_found}   (MUST be True)")
    print(f"     PBB-U verdict       = {pbbu.verdict.value if pbbu else None}")
    if pbbu and find_found:
        print(f"     lifecycle           = {' -> '.join(pbbu.metrics.get('lifecycle', []))}")
        print(f"     order               = {pbbu.metrics.get('order')}  (overlay at rate={pbbu.metrics.get('overlay_rate')})")
    print(f"     calls used          = {find_res.stats.get('customer_level_calls')}")
    print(f"     target answered     = {_ans(find_tgt)}")

    if controls:
        print("  -- per-flaw controls (each MUST be truth=False and engine=False: the flaw is load-bearing) --")
        for name, flags in SINGLE_REMOVED.items():
            t = await P.probe_pleroma_truth(**flags)
            f, _r, _tg = await P.run_engine(flags, reconciliation=True)
            print(f"     {name:26s} truth={t!s:5s} engine_confirmed={f!s:5s}")
        t0 = await P.probe_pleroma_truth(**ALL_CORRECT)
        f0, _r0, _tg0 = await P.run_engine(ALL_CORRECT, reconciliation=True)
        print(f"     ALL-CORRECT                truth={t0!s:5s} engine_confirmed={f0!s:5s} (MUST be False/False: no false alarm)")
        print("  -- current-engine necessity (the B50 fabric engine cannot find PLEROMA under any difficulty relaxation) --")
        c1, _r, _t = await P.run_engine(FULL, reconciliation=False)
        c2, _r, _t = await P.run_engine({**FULL, "opaque_errors": False}, reconciliation=False)
        c3, _r, _t = await P.run_engine({**FULL, "opaque_errors": False, "reconcile_requires_close": False}, reconciliation=False)
        print(f"     B50, all HARD                                engine_confirmed={c1!s:5s} (MUST be False)")
        print(f"     B50, opaque errors OFF                       engine_confirmed={c2!s:5s} (MUST be False: no >=2-cap convergence to compose)")
        print(f"     B50, opaque OFF + reconcile-any-state        engine_confirmed={c3!s:5s} (MUST be False: still a stateful lifecycle, not a convergence)")
        print("  -- new-capability ablations (each NEW capability is individually load-bearing; target stays HARD) --")
        fl, _r, _t = await P.run_engine(FULL, reconciliation=True, recon_use_lifecycle=False)
        fo, _r, _t = await P.run_engine(FULL, reconciliation=True, recon_use_overlay=False)
        fs, _r, _t = await P.run_engine(FULL, reconciliation=True, recon_use_sequence=False)
        ff, _r, _t = await P.run_engine(FULL, reconciliation=True)
        print(f"     B52, lifecycle reconstruction OFF            engine_confirmed={fl!s:5s} (MUST be False: no owned closed period to reconcile)")
        print(f"     B52, credit overlay OFF                      engine_confirmed={fo!s:5s} (MUST be False: authoritative net due stays the full commitment)")
        print(f"     B52, seal-before-settle order OFF            engine_confirmed={fs!s:5s} (MUST be False: overlay after close is rejected, nothing locked in)")
        print(f"     B52, full capability                         engine_confirmed={ff!s:5s} (MUST be True)")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
