#!/usr/bin/env python3
"""Run the ENTERPRISE-HARD benchmark against the current engine and score it honestly.

Per-target outcome (target-level, because novel-channel bypasses are not in the base
8-class vocabulary):
  bypass truly present + engine CONFIRMED something -> TP
  bypass truly present + engine confirmed nothing   -> MISS (false assurance)
  no real bypass       + engine CONFIRMED something -> FP (fooled by a decoy)
  no real bypass       + engine confirmed nothing   -> TN

    PYTHONPATH=tests/verification_infrastructure/shims:tests/verification_infrastructure:. \
        python3 tests/verification_infrastructure/hardened_benchmark/run_enterprise.py
"""
from __future__ import annotations

import asyncio
import json
import pathlib
import time
from datetime import datetime, timezone

from app.enterprise_controls.scope import ScopeGuard, ScopePolicy
from app.testing.http_client import QAHttpClient
from app.testing.integrity.brief import ExecutionBrief
from app.testing.integrity.engine import PureBlackBoxEngine
from hardened_benchmark.enterprise_hard import hard_population, probe_enterprise_truth, start_enterprise_target
from purity_benchmark.lab import public_brief

RESULTS = pathlib.Path(__file__).resolve().parent / "results"


async def engine_run(hard, sla: float):
    target, server, port = await start_enterprise_target(hard)
    base = f"http://127.0.0.1:{port}"
    http = None
    try:
        brief_dict = public_brief(base, {"limits": {"revocation_sla_seconds": sla}})
        brief = ExecutionBrief.from_dict(brief_dict, env={})
        guard = ScopeGuard(ScopePolicy.for_environment(base, max_requests=brief.limits.max_requests,
                                                        max_requests_per_second=brief.limits.max_requests_per_second))
        http = QAHttpClient(base, brief.limits.timeout_seconds, None, {}, "qa-pure-black-box-engine/1.0",
                            max_retries=0, guard=guard, stateless=True)
        engine = PureBlackBoxEngine(http, brief, base_url=base, enable_channel_probe=True, enable_chain_probe=True)
        result = await engine.run(None)
        confirmed = sorted({f.hypothesis_id for f in result.findings if f.verdict.value == "CONFIRMED_P0"})
        calls = result.stats["customer_level_calls"]
        return confirmed, calls
    finally:
        if http is not None and hasattr(http, "aclose"):
            await http.aclose()
        await server.aclose()


async def main() -> int:
    pop = hard_population()
    started = time.perf_counter()
    rows = []
    tp = miss = fp = tn = 0
    for name, hard in pop:
        truth = await probe_enterprise_truth(hard)
        confirmed, calls = await engine_run(hard, hard.sla)
        engine_flagged = bool(confirmed)
        if truth.bypass_present and engine_flagged:
            outcome = "TP"; tp += 1
        elif truth.bypass_present and not engine_flagged:
            outcome = "MISS"; miss += 1
        elif not truth.bypass_present and engine_flagged:
            outcome = "FP"; fp += 1
        else:
            outcome = "TN"; tn += 1
        rows.append({"name": name, "bypass_present": truth.bypass_present, "novel_channel": truth.novel_channel,
                     "base_p0": truth.base_p0, "engine_confirmed": confirmed, "outcome": outcome, "calls": calls})
        print(f"  {outcome:4s} {name:34s} truth_bypass={truth.bypass_present!s:5s} "
              f"novel={truth.novel_channel!s:5s} engine={confirmed or '-'}", flush=True)

    present = tp + miss
    absent = fp + tn
    detection = round(tp / present, 4) if present else None
    fp_rate = round(fp / absent, 4) if absent else None
    elapsed = round(time.perf_counter() - started, 1)

    # novel-channel-only detection (the headroom the owner asked to expose)
    novel_rows = [r for r in rows if r["novel_channel"]]
    novel_detected = sum(1 for r in novel_rows if r["outcome"] == "TP")
    buried_rows = [r for r in rows if r["name"].startswith("buried:")]
    buried_detected = sum(1 for r in buried_rows if r["outcome"] == "TP")

    data = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "population": len(pop), "elapsed_s": elapsed,
        "target_detection_rate": detection, "false_positive_rate": fp_rate,
        "counts": {"TP": tp, "MISS": miss, "FP": fp, "TN": tn},
        "novel_channel_detection": f"{novel_detected}/{len(novel_rows)}",
        "base_flaw_buried_in_decoys_detection": f"{buried_detected}/{len(buried_rows)}",
        "rows": rows,
    }
    RESULTS.mkdir(exist_ok=True)
    (RESULTS / "enterprise_hard_scorecard.json").write_text(json.dumps(data, indent=1, sort_keys=True))
    (RESULTS / "ENTERPRISE_HARD_SCORECARD.md").write_text(render(data))

    print(f"\n[enterprise-hard] n={len(pop)} ({elapsed}s)  detection={detection} FP_rate={fp_rate}  "
          f"TP={tp} MISS={miss} FP={fp} TN={tn}")
    print(f"[enterprise-hard] novel-channel detection: {novel_detected}/{len(novel_rows)}  |  "
          f"base-flaw-buried-in-decoys: {buried_detected}/{len(buried_rows)}")
    return 0


def render(d: dict) -> str:
    c = d["counts"]
    lines = [
        "# Enterprise-Hard Benchmark Scorecard",
        "",
        f"Generated {d['generated_at']} -- {d['population']} adversarial targets in {d['elapsed_s']}s. "
        "Real bypasses hidden behind recon-only channels and buried under hard decoys (shadow endpoint, "
        "flapping badge, cosmetic entitled-fields, lying hints). Truth is independent (every channel probed).",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| target detection rate | {d['target_detection_rate']} (TP {c['TP']} / present {c['TP']+c['MISS']}) |",
        f"| false-positive rate (fooled by a decoy) | {d['false_positive_rate']} (FP {c['FP']} / absent {c['FP']+c['TN']}) |",
        f"| novel-channel (recon-only) detection | {d['novel_channel_detection']} |",
        f"| base flaw buried in decoys, still detected | {d['base_flaw_buried_in_decoys_detection']} |",
        "",
        "## Per-target",
        "",
        "| Outcome | Target | Real bypass? | Novel channel? | Engine confirmed |",
        "|---|---|---|---|---|",
    ]
    for r in d["rows"]:
        lines.append(f"| {r['outcome']} | {r['name']} | {r['bypass_present']} | {r['novel_channel']} | {', '.join(r['engine_confirmed']) or '-'} |")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
