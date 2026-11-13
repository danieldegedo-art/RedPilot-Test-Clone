#!/usr/bin/env python3
"""Run the hardened purity benchmark: a large randomized population, truth from the
independent prober, verdicts from the real PureBlackBoxEngine, scored by the base
scorer. Writes docs/HARDENED_SCORECARD.md + docs/hardened_scorecard.json.

    PYTHONPATH=tests/verification_infrastructure/shims:tests/verification_infrastructure:. \
        python3 tests/verification_infrastructure/hardened_benchmark/run_hardened.py [N] [test|tuning]
"""
from __future__ import annotations

import asyncio
import collections
import json
import pathlib
import sys
import time
from datetime import datetime, timezone

RESULTS = pathlib.Path(__file__).resolve().parent / "results"  # stays inside the audited hardened_benchmark/ tree

from hardened_benchmark import sampler                               # noqa: E402
from hardened_benchmark.ground_truth import EXPERIMENTS, probe_truth  # noqa: E402
from purity_benchmark.customer_target import TargetFlags             # noqa: E402
from purity_benchmark.lab import run_scenario                        # noqa: E402
from purity_benchmark.scenarios import Scenario                      # noqa: E402
from purity_benchmark.scorer import score                            # noqa: E402


def _sla(inst) -> float:
    return float(inst.brief_overrides.get("limits", {}).get("revocation_sla_seconds", 1.0))


def fmt(v) -> str:
    return "n/a" if v is None else (f"{v:.4f}".rstrip("0").rstrip(".") if isinstance(v, float) else str(v))


async def main() -> int:
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 60
    split = sys.argv[2] if len(sys.argv) > 2 else "test"
    population = sampler.held_out(n) if split == "test" else sampler.tuning(n)

    started = time.perf_counter()
    runs = []
    errors = []
    truth_tally = collections.Counter()
    for k, inst in enumerate(population):
        flags = TargetFlags(**inst.flags)
        try:
            gt = await probe_truth(flags, sla=_sla(inst))
            for e in EXPERIMENTS:
                truth_tally[gt.truth[e]] += 1
            scenario = Scenario(
                name=inst.name, flags=inst.flags, truth=gt.truth,
                brief_overrides=inst.brief_overrides,
                expects_open_finding=gt.open_present, expects_leak_finding=gt.leak_present,
                emits_hints=bool(inst.flags.get("emit_debug_hints")),
                unprobed_flaws=("coupon_grants_top_tier",) if inst.flags.get("coupon_grants_top_tier") else (),
                description=f"category={inst.category}",
            )
            run = await run_scenario(scenario)
            runs.append((inst, run))
            print(f"  {k+1:3d}/{len(population)} {inst.name} {inst.category:20s} "
                  f"P0={sum(1 for e in EXPERIMENTS if gt.truth[e]=='P0')} calls={run.result.stats['customer_level_calls']}", flush=True)
        except Exception as exc:  # noqa: BLE001 - record and continue; a crash on one instance must not void the run
            errors.append(f"{inst.name} ({inst.category}): {type(exc).__name__}: {exc}")
            print(f"  {k+1:3d}/{len(population)} {inst.name} ERROR {type(exc).__name__}: {exc}", flush=True)

    scoreruns = [r for _, r in runs]
    s = score(scoreruns)
    elapsed = round(time.perf_counter() - started, 1)

    # --- speed baseline: requests and engine wall-clock (under fixed scope caps) ---
    import statistics as _stats
    calls = [r.result.stats["customer_level_calls"] for _, r in runs]
    engine_secs = [r.elapsed_s for _, r in runs]
    overhead_calls = [r.result.stats["customer_level_calls"] for inst, r in runs
                      if inst.category.split(":")[0] in ("clean", "unk")]
    tp = s["outcome_counts"]["TP"]
    speed = {
        "total_customer_calls": sum(calls),
        "median_calls_per_target": _stats.median(calls) if calls else 0,
        "calls_per_confirmed_p0": round(sum(calls) / tp, 2) if tp else None,
        "median_overhead_calls_on_clean_or_unk": _stats.median(overhead_calls) if overhead_calls else 0,
        "total_engine_wall_clock_s": round(sum(engine_secs), 1),
        "median_engine_s_per_target": round(_stats.median(engine_secs), 3) if engine_secs else 0,
    }

    # per-category confusion from the scored pairs
    by_cat: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    inst_by_name = {inst.name: inst for inst, _ in runs}
    for p in s["pairs_detail"]:
        cat = inst_by_name[p["scenario"]].category.split(":")[0]
        by_cat[cat][p["outcome"]] += 1

    internal_hits = s["internal_route_hits_total"]
    data = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "split": split, "population": len(population), "scored": len(runs), "errors": errors,
        "elapsed_s": elapsed, "truth_tally": dict(truth_tally),
        "scores": {k: v for k, v in s.items() if k != "pairs_detail"},
        "speed": speed,
        "per_category": {c: dict(v) for c, v in by_cat.items()},
    }
    RESULTS.mkdir(exist_ok=True)
    (RESULTS / "hardened_scorecard.json").write_text(json.dumps(data, indent=1, sort_keys=True))
    (RESULTS / "HARDENED_SCORECARD.md").write_text(render(data))

    print(f"\n[hardened:{split}] n={len(runs)}/{len(population)} ({elapsed}s)  "
          f"detection={fmt(s['seeded_p0_detection_rate'])} FP={fmt(s['false_positive_rate'])} "
          f"false_assurance={fmt(s['false_assurance_rate'])} unknown_honesty={fmt(s['unknown_honesty_rate'])} "
          f"safe_ruled_out={fmt(s['safe_ruled_out_rate'])} div_resist={fmt(s['ui_only_false_positive_resistance'])} "
          f"internal_hits={internal_hits}")
    print(f"[hardened:{split}] speed: {speed['total_customer_calls']} calls, "
          f"{fmt(speed['calls_per_confirmed_p0'])} calls/confirmed-P0, "
          f"median {speed['median_calls_per_target']} calls/target, "
          f"median overhead {speed['median_overhead_calls_on_clean_or_unk']} calls on clean/unk, "
          f"engine {speed['total_engine_wall_clock_s']}s total")
    if errors:
        print(f"ERRORS on {len(errors)} instance(s):")
        for e in errors:
            print("  -", e)
    return 1 if errors else 0


def render(d: dict) -> str:
    s = d["scores"]
    oc = s["outcome_counts"]
    tc = s["truth_counts"]
    lines = [
        "# Hardened Black-Box Purity Benchmark Scorecard",
        "",
        f"Generated {d['generated_at']} by `hardened_benchmark/run_hardened.py` -- split=`{d['split']}`, "
        f"{d['scored']}/{d['population']} randomized targets scored in {d['elapsed_s']}s. Every number MEASURED by running the code.",
        "",
        "**What is hardened vs. the base scorecard:** (1) TRUTH is computed by an independent prober that drives each "
        "target's public API as an attacker (`ground_truth.py`), with no reference to the engine or the seeded flags -- "
        "validated 21/21 against the base hand-labels; (2) the population is a large RANDOMIZED mix (single flaws, 2-4 "
        "flaw combinations, FP-bait decoys with lying debug hints / UI-only badges / within-SLA refund lag, opacity/UNK "
        "cases, and out-of-model coupon blind spots).",
        "",
        "**Residual limits (unchanged, stated plainly):** loopback timing only; the target's flaw *mechanisms* are still "
        "the base fixture's code (mechanism-variant and surface-vocabulary randomization are the next hardening step); "
        "provider-event authenticity remains black-box-unprovable and is out of this population.",
        "",
        f"Truth distribution over {sum(tc.values())} (target x experiment) pairs: "
        f"P0={tc['P0']}, SAFE={tc['SAFE']}, UNK={tc['UNK']}, DIV={tc['DIV']}.",
        "",
        "| Metric | Value | Numerator / denominator |",
        "|---|---|---|",
        f"| seeded_p0_detection_rate | {fmt(s['seeded_p0_detection_rate'])} | TP {oc['TP']} / P0 {tc['P0']} |",
        f"| false_positive_rate | {fmt(s['false_positive_rate'])} | FP {oc['FP']} / (SAFE+UNK+DIV) {tc['SAFE']+tc['UNK']+tc['DIV']} |",
        f"| false_assurance_rate | {fmt(s['false_assurance_rate'])} | FA {oc['FALSE_ASSURANCE']+oc['FALSE_ASSURANCE_UNPROVABLE']} / (P0+UNK) {tc['P0']+tc['UNK']} |",
        f"| missed_as_unknown_rate | {fmt(s['missed_as_unknown_rate'])} | MISSED {oc['MISSED_AS_UNKNOWN']} / P0 {tc['P0']} |",
        f"| unknown_honesty_rate | {fmt(s['unknown_honesty_rate'])} | HONEST_UNKNOWN {oc['HONEST_UNKNOWN']} / UNK {tc['UNK']} |",
        f"| safe_ruled_out_rate | {fmt(s['safe_ruled_out_rate'])} | TN {oc['TN']} / SAFE {tc['SAFE']} |",
        f"| ui_only_false_positive_resistance | {fmt(s['ui_only_false_positive_resistance'])} | DIV_OK {oc['DIV_OK']} / DIV {tc['DIV']} |",
        f"| internal_route_hits_total | {s['internal_route_hits_total']} | engine requests to /internal,/admin,/__benchmark__ |",
        f"| purity_gate_denials_caused_by_engine | {s['purity_gate_denials_caused_by_engine']} | engine addressing a non-customer surface |",
        f"| evidence_integrity (unredacted/bad-hash) | {s['evidence_integrity']['unredacted_identifiers_or_tokens']}/{s['evidence_integrity']['bad_hash']} | over {s['evidence_integrity']['artifacts']} artifacts |",
        f"| blind_spot_flaws_listed_as_gap | {s['blind_spot_flaws_listed_as_gap']}/{s['blind_spot_flaws_total']} | out-of-model coupon reported as BLOCKED gap |",
        "",
        "## Speed baseline (under the fixed scope caps; loopback)",
        "",
        "| Speed metric | Value |",
        "|---|---|",
        f"| total customer-level calls | {d['speed']['total_customer_calls']} |",
        f"| calls per confirmed P0 | {fmt(d['speed']['calls_per_confirmed_p0'])} |",
        f"| median calls / target | {d['speed']['median_calls_per_target']} |",
        f"| median overhead calls on a clean/UNK target | {d['speed']['median_overhead_calls_on_clean_or_unk']} |",
        f"| total engine wall-clock | {d['speed']['total_engine_wall_clock_s']}s |",
        f"| median engine time / target | {d['speed']['median_engine_s_per_target']}s |",
        "",
        "## Per-category outcome counts",
        "",
        "| Category | TP | FP | FA | TN | HONEST_UNKNOWN | DIV_OK | other |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for cat, c in sorted(d["per_category"].items()):
        other = sum(v for k, v in c.items() if k not in ("TP", "FP", "FALSE_ASSURANCE", "FALSE_ASSURANCE_UNPROVABLE", "TN", "HONEST_UNKNOWN", "DIV_OK"))
        lines.append(f"| {cat} | {c.get('TP',0)} | {c.get('FP',0)} | {c.get('FALSE_ASSURANCE',0)+c.get('FALSE_ASSURANCE_UNPROVABLE',0)} | {c.get('TN',0)} | {c.get('HONEST_UNKNOWN',0)} | {c.get('DIV_OK',0)} | {other} |")
    if d["errors"]:
        lines += ["", f"## Errors ({len(d['errors'])})", ""] + [f"- {e}" for e in d["errors"]]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
