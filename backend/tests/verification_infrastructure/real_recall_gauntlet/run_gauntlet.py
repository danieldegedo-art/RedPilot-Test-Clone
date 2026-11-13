#!/usr/bin/env python3
"""Blind runner for the Real-Glue-Code Recall Gauntlet.

For every manifest instance it (1) runs the INDEPENDENT truth prober on a fresh target to
establish ground truth, and (2) runs TODAY's full engine BLIND (brief + URL only) against a
separate fresh target over a real socket, then classifies the outcome. The engine is never
told the class, the target, or whether the flaw is on.

    PYTHONPATH=tests/verification_infrastructure/shims:tests/verification_infrastructure:\
tests/verification_infrastructure/real_recall_gauntlet:\
tests/verification_infrastructure/real_recall_gauntlet/targets:. \
        python3 tests/verification_infrastructure/real_recall_gauntlet/run_gauntlet.py [--split test|dev|all] [--json PATH]
"""
from __future__ import annotations

import argparse
import asyncio
import importlib
import json
import os
import sys

import manifest as MAN
from harness import run_engine_blind
from surface import Scheme


async def run_instance(family: str, seed: int, split: str, scope: str) -> dict:
    M = importlib.import_module(f"targets.{family}")
    rec: dict = {"family": family, "seed": seed, "split": split, "scope": scope,
                 "advisory": MAN.PROVENANCE[family]["advisory"], "class": MAN.PROVENANCE[family]["engine_class"]}

    # ---- independent ground truth (flaw on vs patched), engine NOT involved -------------
    truth_on = await M.probe_truth(Scheme(family, seed), True)
    truth_off = await M.probe_truth(Scheme(family, seed), False)
    rec["truth_flaw_on"] = bool(truth_on)
    rec["truth_patched"] = bool(truth_off)
    rec["dual_oracle_valid"] = bool(truth_on) and not bool(truth_off)

    # ---- engine BLIND on the flaw-on target ---------------------------------------------
    scheme = Scheme(family, seed)
    plog: set = set()
    tgt = M.make(scheme, True, path_log=plog)

    async def handle(method, path, body, headers):
        return await tgt.handle(method, path, body, headers)

    rr_on = await run_engine_blind(lambda base: M.brief(base, scheme), handle, path_log=plog)
    rec["engine_confirmed_flaw_on"] = rr_on.confirmed
    rec["engine_calls"] = rr_on.stats.get("customer_level_calls")
    rec["internal_hits"] = tgt.internal_hits  # purity: must be 0

    # ---- engine BLIND on the patched target (false-positive control) --------------------
    scheme2 = Scheme(family, seed)
    tgt2 = M.make(scheme2, False)

    async def handle2(method, path, body, headers):
        return await tgt2.handle(method, path, body, headers)

    rr_off = await run_engine_blind(lambda base: M.brief(base, scheme2), handle2)
    rec["engine_confirmed_patched"] = rr_off.confirmed
    rec["internal_hits"] += tgt2.internal_hits

    # ---- classify ------------------------------------------------------------------------
    found_on = bool(rr_on.confirmed)
    found_off = bool(rr_off.confirmed)
    if scope == "ceiling":
        rec["positive_outcome"] = "CEILING_BREACH(engine forged?!)" if found_on else "CEILING_ABSTAIN(correct)"
    else:
        rec["positive_outcome"] = "TP" if found_on else "FN"
    rec["negative_outcome"] = "FP" if found_off else "TN"
    return rec


def aggregate(records: list[dict], split: str) -> dict:
    rows = [r for r in records if r["split"] == split] if split != "all" else records
    insc = [r for r in rows if r["scope"] == "in_scope"]
    ceil = [r for r in rows if r["scope"] == "ceiling"]
    tp = sum(r["positive_outcome"] == "TP" for r in insc)
    fn = sum(r["positive_outcome"] == "FN" for r in insc)
    fp = sum(r["negative_outcome"] == "FP" for r in rows)
    tn = sum(r["negative_outcome"] == "TN" for r in rows)
    positives = tp + fn
    invalid = [f"{r['family']}#{r['seed']}" for r in insc if not r["dual_oracle_valid"]]
    return {
        "split": split,
        "in_scope_positives": positives,
        "true_positives": tp, "false_negatives": fn,
        "recall": round(tp / positives, 4) if positives else None,
        "negatives": tp + fn + len(ceil),  # one patched control per instance
        "false_positives": fp, "true_negatives": tn,
        "precision": round(tp / (tp + fp), 4) if (tp + fp) else None,
        "false_positive_rate": round(fp / (len(rows)) , 4) if rows else None,
        "ceiling_instances": len(ceil),
        "ceiling_abstained": sum("ABSTAIN" in r["positive_outcome"] for r in ceil),
        "internal_route_hits_total": sum(r["internal_hits"] for r in rows),
        "dual_oracle_invalid": invalid,
    }


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", choices=["test", "dev", "all"], default="all")
    ap.add_argument("--json", default=None)
    args = ap.parse_args()

    insts = {"test": MAN.TEST, "dev": MAN.DEV, "all": MAN.ALL}[args.split]
    records = [await run_instance(*i) for i in insts]

    print("== Real-Glue-Code Recall Gauntlet (engine run BLIND over a real socket) ==\n")
    hdr = f"{'family':24s} {'seed':>4s} {'split':5s} {'scope':9s} {'truth':5s} {'pos':4s} {'neg':3s}  confirmed(flaw_on)"
    print(hdr)
    print("-" * len(hdr))
    for r in sorted(records, key=lambda r: (r["split"], r["scope"], r["family"])):
        print(f"{r['family']:24s} {r['seed']:>4d} {r['split']:5s} {r['scope']:9s} "
              f"{str(r['truth_flaw_on']):5s} {r['positive_outcome'][:4]:4s} {r['negative_outcome']:3s}  {r['engine_confirmed_flaw_on']}")

    print("\n== aggregates ==")
    out = {"records": records, "aggregate": {}}
    for split in (["test", "dev"] if args.split == "all" else [args.split]):
        agg = aggregate(records, split)
        out["aggregate"][split] = agg
        if agg["in_scope_positives"]:
            print(f"[{split.upper()}] recall={agg['recall']} ({agg['true_positives']}/{agg['in_scope_positives']}) "
                  f"precision={agg['precision']} FP={agg['false_positives']} FPrate={agg['false_positive_rate']} "
                  f"ceiling_abstained={agg['ceiling_abstained']}/{agg['ceiling_instances']} "
                  f"internal_hits={agg['internal_route_hits_total']}"
                  + (f"  !! INVALID DUAL ORACLE: {agg['dual_oracle_invalid']}" if agg["dual_oracle_invalid"] else ""))

    if args.json:
        os.makedirs(os.path.dirname(args.json) or ".", exist_ok=True)
        with open(args.json, "w") as fh:
            json.dump(out, fh, indent=2, default=str)
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
