#!/usr/bin/env python3
"""Standalone CLI for the pure black-box Protected-Feature Oracle engine: Execution Brief in, evidence-backed verdicts out.

    python3 scripts/run_pure_engine.py --brief qa_integrity/brief.json --base-url https://staging.shop.example [--experiments PBB-U,PBB-F] [--out report.json]

Identity tokens are read from the environment variables NAMED in the brief (token_env); the brief itself never contains a secret. Exit codes:
0 = no confirmed P0 (NOT 'no P0 exists': see the capability gaps), 1 = at least one CONFIRMED_P0, 2 = brief rejected / unreadable / target not authorised (no request sent).
"""
from __future__ import annotations

import argparse
import asyncio
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from app.core.control_port import BriefRejected, get_control_adapter  # noqa: E402
from app.testing.http_client import QAHttpClient  # noqa: E402
from app.testing.integrity.brief import ExecutionBrief  # noqa: E402
from app.testing.integrity.engine import PureBlackBoxEngine  # noqa: E402
from app.testing.integrity.gaps import capability_gaps, unknown_exposures  # noqa: E402
from app.testing.integrity.regression import build_regression_spec  # noqa: E402
from app.testing.modules.payment_integrity import host_permitted  # noqa: E402


async def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--brief", required=True)
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--experiments", default=None, help="comma separated subset, e.g. PBB-U,PBB-F (default: all)")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    try:
        raw = json.loads(pathlib.Path(args.brief).read_text(encoding="utf-8"))
        brief = ExecutionBrief.from_dict(raw)
    except (OSError, ValueError) as exc:
        print(f"BRIEF UNREADABLE ({type(exc).__name__}); no request was sent.", file=sys.stderr)
        return 2
    except BriefRejected as exc:
        print("BRIEF REJECTED (fail closed); no request was sent:", *[f"  - {r}" for r in exc.reasons], sep="\n", file=sys.stderr)
        return 2
    if not host_permitted(args.base_url, brief.allowed_hosts):
        print(f"TARGET NOT AUTHORISED: {args.base_url} is not covered by the brief's allowed_hosts; no request was sent.", file=sys.stderr)
        return 2
    controls = get_control_adapter()
    guard = controls.create_run_guard(controls.build_scope_policy(args.base_url, max_requests=brief.limits.max_requests, max_requests_per_second=brief.limits.max_requests_per_second))
    http = QAHttpClient(args.base_url, brief.limits.timeout_seconds, None, {}, "qa-pure-black-box-engine/1.0", max_retries=0, guard=guard, stateless=True)
    try:
        result = await PureBlackBoxEngine(http, brief, base_url=args.base_url).run(args.experiments.split(",") if args.experiments else None)
    finally:
        await http.aclose()
    rows = capability_gaps(brief, result)
    report = {**result.to_dict(), "capability_gaps": [r.to_dict() for r in unknown_exposures(rows)], "regression_spec": build_regression_spec(result, brief),
              "note": "No confirmed P0 does not mean no P0 exists: every capability gap above is UNKNOWN/BLOCKED, not safe."}
    for f in result.findings:
        print(f"{f.hypothesis_id:9s} {f.verdict.value:46s} {f.summary[:120]}")
    print(f"\n{len(unknown_exposures(rows))} of {len(rows)} P0 classes are NOT covered (UNKNOWN/BLOCKED).")
    if args.out:
        pathlib.Path(args.out).write_text(json.dumps(report, indent=1, default=str))
    return 1 if result.confirmed() else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
