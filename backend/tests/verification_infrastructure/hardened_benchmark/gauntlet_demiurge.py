#!/usr/bin/env python3
"""Held-out DEMIURGE family -- SEEDED federation instances the engine never saw, randomized INDEPENDENTLY of it, to
prove the federation capability GENERALISES (discovery, not memorization -- the AnonVul bar), carried out-of-sample.

Each seed keeps the FULL maximal archon federation but randomizes:
  * the archon ROUTES -- service + action path segments drawn from role-carrying pools (so B53 must re-discover an
    unseen surface and bind roles SEMANTICALLY, not by DEMIURGE's exact spelling);
  * the opaque token LAYOUT -- a random permutation of the five packed fields (so the amount field's byte offset
    differs per seed and B54's differential field inference must actually re-derive it, never a hard-coded offset).

Three instance kinds (the same discipline as the other gauntlet families):
  * solvable   -- the full load-bearing flaw set is present  -> truth True  -> the engine MUST FIND (detect)
  * unsolvable -- exactly ONE flaw is flipped CORRECT         -> truth False -> the engine MUST stay 0 (honest boundary)
  * clean      -- every flaw is correct                       -> truth False -> the engine MUST stay 0 (no false positive)

    PYTHONPATH=tests/verification_infrastructure/shims:tests/verification_infrastructure:. \
        python3 tests/verification_infrastructure/hardened_benchmark/gauntlet_demiurge.py
"""
from __future__ import annotations

import asyncio
import random
import sys

from hardened_benchmark import boss_demiurge as D

PFX = D.PFX

# role-carrying (service, action) pools. Every entry contains a keyword the engine's SEMANTIC role-binder matches, and
# the sets are disjoint across roles, so a renamed surface still binds exactly one path per role.
POOLS = {
    "mint":        [("vault", "correlation"), ("custodian", "mint"), ("tokenizer", "issue"), ("vault", "token")],
    "open":        [("metering", "open"), ("usage", "cycle"), ("billing", "meter"), ("metering", "usage")],
    "credit":      [("disputes", "credit"), ("rebates", "rebate"), ("chargebacks", "adjust"), ("disputes", "chargeback")],
    "close":       [("reconciler", "close"), ("lockbox", "lock"), ("sealer", "seal"), ("reconciler", "reconcile")],
    "finalize":    [("settlement", "finalize"), ("clearing", "clear"), ("disbursement", "disburse"), ("payouts", "payout")],
    "stepup":      [("radar", "stepup"), ("otpguard", "otp"), ("challenger", "challenge"), ("verifier", "verify")],
    "attestation": [("attestation", "purchase"), ("deviceauth", "attest")],
    "entitlement": [("entitlement", "state"), ("permits", "record")],
    "atomic":      [("settlement", "atomic"), ("clearing", "pvp")],
    "consortium":  [("settlement", "consortium"), ("netclear", "batch")],
}
CORRECT = {"mac_covers_basis": True, "disputes_trust_correlation": False, "reconcile_locks_credit": False,
           "settlement_trusts_aggregate": False, "settlement_grants_without_capture": False}
FULL = {k: not v for k, v in CORRECT.items()}


def gen_spec(seed: int, kind: str) -> dict:
    rng = random.Random(seed * 131 + (hash(kind) % 997))
    routes = {}
    for role, pool in POOLS.items():
        svc, act = rng.choice(pool)
        routes[role] = f"{PFX}/{svc}-{rng.randrange(16 ** 4):04x}/{act}"
    order = ["ver", "tenant", "ts", "basis", "amount"]
    rng.shuffle(order)
    flaws = dict(FULL)
    if kind == "unsolvable":
        flip = rng.choice(list(CORRECT))
        flaws[flip] = CORRECT[flip]
    elif kind == "clean":
        flaws = dict(CORRECT)
    return {**flaws, "routes": routes, "tok_order": tuple(order)}


async def main() -> int:
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 6
    res: dict[str, list[tuple[bool, bool]]] = {"solvable": [], "unsolvable": [], "clean": []}
    for kind in res:
        for seed in range(n):
            flags = gen_spec(seed, kind)
            truth = await D.probe_demiurge_truth(**flags)
            found, _r, _t = await D.run_engine(flags, enable_federation=True)
            res[kind].append((truth, found))

    sol_found = sum(1 for t, f in res["solvable"] if f)
    sol_truth = sum(1 for t, f in res["solvable"] if t)
    uns_truth = sum(1 for t, f in res["unsolvable"] if t)
    uns_found = sum(1 for t, f in res["unsolvable"] if f)
    cln_found = sum(1 for t, f in res["clean"] if f)
    print("== Held-out DEMIURGE family (seeded federations; randomized archon paths + token layout; full 8-archon set) ==")
    print(f"  solvable   (n={n}): truth True on {sol_truth}/{n}; engine FOUND {sol_found}/{n}   (MUST be {n}/{n} and {n}/{n})")
    print(f"  unsolvable (n={n}): truth True on {uns_truth}/{n} (MUST be 0); engine found {uns_found}/{n}   (MUST be 0 -- honest boundary)")
    print(f"  clean      (n={n}): engine found {cln_found}/{n}   (MUST be 0 -- no false positive)")
    ok = sol_found == n and sol_truth == n and uns_found == 0 and cln_found == 0
    print(f"  RESULT: {'PASS -- the federation capability generalises out-of-sample' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
