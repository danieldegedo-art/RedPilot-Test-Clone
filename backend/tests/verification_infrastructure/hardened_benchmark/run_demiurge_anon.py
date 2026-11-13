#!/usr/bin/env python3
"""DEMIURGE anonymization-insensitivity experiment -- RedPilot's structural edge over LLM agents.

AnonVul's headline is that restoring software IDENTITY lifts LLM-agent discovery from 21.25% -> 40.83% (+19.58pp):
LLM agents lean on memorized provider knowledge. RedPilot has NO LLM and NO training corpus, so its find should be
IDENTITY-INVARIANT. This runs the same seeded federation twice -- archon service names ANONYMIZED (generic) vs.
DE-ANONYMIZED (real provider names: stripe / orb / adyen / apple ...), with the ACTION segments (and therefore the
semantics the engine binds on) identical -- and reports the find-rate delta.

    PYTHONPATH=tests/verification_infrastructure/shims:tests/verification_infrastructure:. \
        python3 tests/verification_infrastructure/hardened_benchmark/run_demiurge_anon.py [N]
"""
from __future__ import annotations

import asyncio
import random
import sys

from hardened_benchmark import boss_demiurge as D

PFX = D.PFX
FULL = {"mac_covers_basis": False, "disputes_trust_correlation": True, "reconcile_locks_credit": True,
        "settlement_trusts_aggregate": True, "settlement_grants_without_capture": True}
# the role -> ACTION segment the engine binds on (identical across both namings, so only IDENTITY differs)
ACT = {"mint": "correlation", "open": "open", "credit": "credit", "close": "close", "stepup": "stepup",
       "finalize": "finalize", "atomic": "atomic", "consortium": "consortium", "attestation": "purchase",
       "entitlement": "state"}
ANON = {r: f"svc-{i}" for i, r in enumerate(ACT)}                      # generic, identity-free service names
REAL = {"mint": "stripe-vault", "open": "orb-metering", "credit": "metronome-disputes", "close": "orb-reconciler",
        "stepup": "stripe-radar", "finalize": "adyen-settlement", "atomic": "adyen-settlement",
        "consortium": "swift-netclear", "attestation": "apple-appattest", "entitlement": "stripe-entitlements"}


def routes(names: dict[str, str]) -> dict[str, str]:
    return {r: f"{PFX}/{names[r]}/{ACT[r]}" for r in ACT}


async def main() -> int:
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 6
    anon_found = real_found = 0
    for seed in range(n):
        order = ["ver", "tenant", "ts", "basis", "amount"]
        random.Random(seed * 97 + 13).shuffle(order)
        flags = {**FULL, "tok_order": tuple(order)}
        fa, _r, _t = await D.run_engine({**flags, "routes": routes(ANON)}, enable_federation=True)
        fr, _r, _t = await D.run_engine({**flags, "routes": routes(REAL)}, enable_federation=True)
        anon_found += int(fa)
        real_found += int(fr)
    a, r = 100.0 * anon_found / n, 100.0 * real_found / n
    print("== DEMIURGE anonymization-insensitivity (same federations; archon identity hidden vs. real provider names) ==")
    print(f"  anonymized  : engine FOUND {anon_found}/{n} ({a:.1f}%)")
    print(f"  de-anonymized: engine FOUND {real_found}/{n} ({r:.1f}%)")
    print(f"  delta = {r - a:+.1f}pp   (MUST be ~0: RedPilot has no LLM/memorized-provider channel; cf. AnonVul's +19.58pp for LLM agents)")
    print(f"  RESULT: {'PASS -- identity-invariant discovery' if abs(r - a) < 1e-6 else 'NONZERO -- investigate provider-keyed logic (itself a finding)'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
