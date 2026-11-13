#!/usr/bin/env python3
"""Run the engine against BOSS 'DEMIURGE' and walk the full cycle: Harder Boss -> Clean MISS -> Fix -> FIND -> Upgrade.

DEMIURGE (see boss_demiurge.py and docs/DEMIURGE_BOSS_CYCLE.md) is the first boss that is a DISTRIBUTED FEDERATION:
one edge fronting eight archon services, archon surface UNDECLARED (only in the public reference), and one no-payment
ENTERPRISE bypass that is a CONFUSED DEPUTY across four trust edges carried by an opaque packed correlation token.

It proves:
  (a) the CURRENT engine (channel+chain+race+B49+B50+B52 ON, federation OFF) cleanly MISSES -- even when handed every
      archon op (ops_declared) and even with opaque errors off (structural: two produced roots + a cross-service
      credit + an opaque token, which no single-session composer assembles);
  (b) the UPGRADED engine (federation probe ON) FINDS the bypass and reproduces it in a clean session;
  (c) each of the FIVE flaws is load-bearing: remove any one -> truth=False AND engine=False;
  (d) all-correct -> False/False (no false alarm);
  (e) each of the FOUR new capability CLASSES (B53 discovery, B54 token RE, B55 trust-graph, B56 orchestration) is
      individually load-bearing (ablate any one -> engine misses, target stays HARD).

    PYTHONPATH=tests/verification_infrastructure/shims:tests/verification_infrastructure:. \
        python3 tests/verification_infrastructure/hardened_benchmark/run_demiurge.py [--controls]
"""
from __future__ import annotations

import asyncio
import sys

from hardened_benchmark import boss_demiurge as D

# the CORRECT value of each flaw flag (removing a flaw = setting it here). mac_covers_basis is correct when True;
# the other four are correct when False. The flawed/HARD setting (FULL) is the inverse.
CORRECT = {"mac_covers_basis": True, "disputes_trust_correlation": False, "reconcile_locks_credit": False,
           "settlement_trusts_aggregate": False, "settlement_grants_without_capture": False}
FULL = {k: not v for k, v in CORRECT.items()}
SINGLE_REMOVED = {f"no-{k}": {**FULL, k: CORRECT[k]} for k in CORRECT}
ALL_CORRECT = dict(CORRECT)


def _ans(target) -> str:
    if not target.calls_total:
        return "n/a"
    gr = 100.0 * target.grants_total / target.calls_total
    return (f"{100.0 * target.calls_error / target.calls_total:.1f}% non-2xx, access granted on "
            f"{gr:.2f}% ({target.grants_total}/{target.calls_total}), internal/mesh hits={target.internal_hits}")


async def main() -> int:
    controls = "--controls" in sys.argv
    truth = await D.probe_demiurge_truth(**FULL)
    miss_found, miss_res, miss_tgt = await D.run_engine(FULL)                        # CURRENT engine (through B52)
    find_found, find_res, find_tgt = await D.run_engine(FULL, enable_federation=True)  # UPGRADED engine (B53-B56)
    pbbu = next((f for f in find_res.findings if f.hypothesis_id == "PBB-U"), None)

    hrate, herr, hgrants, htot = await D.demiurge_hostility(3000)
    print("== BOSS target 'DEMIURGE' (payment FEDERATION: one edge fronting 8 archons, all correct; the archon surface "
          "is UNDECLARED; one load-bearing no-payment ENTERPRISE bypass = a cross-service confused deputy carried by an "
          "opaque packed correlation token) ==")
    print(f"  hardening under a {htot}-probe adversarial sweep: {hrate:.2f}% errors ({herr}/{htot}), access granted = {hgrants}")
    print(f"  independent truth prober: real no-payment enterprise bypass exists = {truth}")
    print("  -- Harder Boss -> Clean MISS (current engine through B52, federation OFF) --")
    print(f"     engine CONFIRMED_P0 = {miss_found}   (MUST be False: the archon surface is undeclared; and even declared it is a two-root cross-service confused deputy no single-session composer assembles)")
    print(f"     target answered     = {_ans(miss_tgt)}")
    print("  -- Fix -> FIND (upgraded engine: B53 discovery + B54 token RE + B55 trust-graph + B56 orchestration ON) --")
    print(f"     engine CONFIRMED_P0 = {find_found}   (MUST be True)")
    print(f"     PBB-U verdict       = {pbbu.verdict.value if pbbu else None}")
    if pbbu and find_found:
        m = pbbu.metrics or {}
        print(f"     discovered roles    = {m.get('roles')}")
        print(f"     token amount_offset = {m.get('amount_offset')}  (found by differential diffing, no key)")
        print(f"     cross-service chain = {' -> '.join(m.get('chain', []))}")
    print(f"     calls used          = {find_res.stats.get('customer_level_calls')}")
    print(f"     target answered     = {_ans(find_tgt)}")

    if controls:
        print("  -- current-engine necessity (the B52 engine cannot find DEMIURGE even handed the whole surface) --")
        c1, _r, _t = await D.run_engine(FULL)
        c2, _r, _t = await D.run_engine(FULL, ops_declared=True)
        c3, _r, _t = await D.run_engine({**FULL, "opaque_errors": False}, ops_declared=True)
        print(f"     B52, archon ops undeclared                   engine_confirmed={c1!s:5s} (MUST be False: no discovery)")
        print(f"     B52, ops_declared (handed every archon op)   engine_confirmed={c2!s:5s} (MUST be False: structural -- two roots + cross-service credit + opaque token)")
        print(f"     B52, ops_declared + opaque errors OFF        engine_confirmed={c3!s:5s} (MUST be False: it is a confused-deputy order, not a field-learning problem)")
        print("  -- per-flaw controls (each MUST be truth=False and engine=False: the flaw is load-bearing) --")
        for name, flags in SINGLE_REMOVED.items():
            t = await D.probe_demiurge_truth(**flags)
            f, _r, _tg = await D.run_engine(flags, enable_federation=True)
            print(f"     {name:36s} truth={t!s:5s} engine_confirmed={f!s:5s}")
        t0 = await D.probe_demiurge_truth(**ALL_CORRECT)
        f0, _r0, _tg0 = await D.run_engine(ALL_CORRECT, enable_federation=True)
        print(f"     ALL-CORRECT                          truth={t0!s:5s} engine_confirmed={f0!s:5s} (MUST be False/False: no false alarm)")
        print("  -- new-capability ablations (FIVE load-bearing classes + one HONEST efficiency-only rider) --")
        fd, _r, _t = await D.run_engine(FULL, enable_federation=True, fed_use_discovery=False)
        fr, _r, _t = await D.run_engine(FULL, enable_federation=True, fed_use_token_re=False)
        fg, _r, _t = await D.run_engine(FULL, enable_federation=True, fed_use_trust_graph=False)
        fo, _r, _t = await D.run_engine(FULL, enable_federation=True, fed_use_orchestration=False)
        fa, _r, _t = await D.run_engine(FULL, enable_federation=True, fed_use_analogy=False)
        fi, rifi, _t = await D.run_engine(FULL, enable_federation=True, fed_use_infogain=False)
        ff, rff, _t = await D.run_engine(FULL, enable_federation=True)
        print(f"     B53 discovery OFF                            engine_confirmed={fd!s:5s} (MUST be False: no archon surface synthesised)")
        print(f"     B54 token-RE OFF                             engine_confirmed={fr!s:5s} (MUST be False: honest token -> zero credit -> net due stays full)")
        print(f"     B55 trust-graph OFF                          engine_confirmed={fg!s:5s} (MUST be False: the cross-service order is not composed)")
        print(f"     B56 orchestration OFF                        engine_confirmed={fo!s:5s} (MUST be False: the fresh step-up is not late-bound)")
        print(f"     B59 analogy OFF                              engine_confirmed={fa!s:5s} (MUST be False: the token is never presented to the credit step)")
        print(f"     full capability                              engine_confirmed={ff!s:5s} (MUST be True)")
        print(f"     B58 info-gain OFF (EFFICIENCY, not load-bearing): engine_confirmed={fi!s:5s} (still True); calls {rifi.stats.get('customer_level_calls')} vs {rff.stats.get('customer_level_calls')} with it -- ranking avoids wasted decoy probes")
        print("  -- roster dispatch (the probe runs each step only while its OWNING kill-chain agent is activatable) --")
        for aid, cap in [("A3", "surface discovery"), ("A34", "token reverse-engineering"), ("A39", "trust-graph"),
                         ("A20", "orchestration"), ("A30", "analogy/capability-synthesis")]:
            fx, _r, _t = await D.run_engine(FULL, enable_federation=True, disabled_agents=frozenset({aid}))
            print(f"     disable {aid} ({cap:28s}) engine_confirmed={fx!s:5s} (MUST be False: load-bearing agent)")
        fn, _r, _t = await D.run_engine(FULL, enable_federation=True, disabled_agents=frozenset({"A21"}))
        print(f"     disable A21 (payment-provider specialist, non-owning) engine_confirmed={fn!s:5s} (MUST be True: honestly NOT load-bearing for this find)")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
