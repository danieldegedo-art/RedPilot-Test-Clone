#!/usr/bin/env python3
"""Run a payment-integrity engagement twice against the SAME target -- once
with the static EXPERIMENT_ORDER, once with prioritize_experiments on -- and
diff the two. This is the one thing this session's sandbox could not do (no
real HTTP target, no Postgres); everything it exercises has its own unit
tests already (test_prioritization.py, test_run_memory.py,
test_prioritizer_settings_wiring.py). This script is for confirming those
units are correctly wired together against a real brief and a real database,
not for re-testing their logic.

Usage:
    python3 scripts/compare_prioritized_run.py <base_url> <brief.json>

What a healthy result looks like:
  * "order changed: True" the SECOND time this is run against a target with
    at least one prior finding on record (the first run has no history to
    prioritize from, so order is expected to be unchanged there).
  * "verdicts identical: True", always -- see the check below. If this is ever
    False, STOP: scheduling changed a verdict, which must never happen
    (ZR-024/ZR-025: only ConfirmationGate may produce or change one), and is
    a real bug in the wiring, not a passing variation.
  * No "could not build the experiment prioritizer" or "prior findings
    unavailable" line in this script's stderr/log output (both are logged by
    build_prioritizer, modules/payment_integrity.py) -- either means the
    "after" run silently fell back to the static order, so the comparison
    below is not actually testing what it claims to. Nothing currently
    surfaces that into a structured field this script can check instead of
    the log; that would be a reasonable follow-up to run_memory.py.

Needs: a running instance of this project (real sqlalchemy/httpx/fastapi
installed) and network access to <base_url>. Does not touch the API server or
the dashboard -- it drives TestRunner directly, the same object
api/v1/runs.py uses, so no server process needs to be running.
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


async def _run(base_url: str, brief_raw: dict, *, prioritize: bool) -> dict:
    from app.testing.context import EndpointMap, RunSettings
    from app.testing.enums import TestScope
    from app.testing.event_bus import EventBus
    from app.testing.runner import TestRunner

    settings = RunSettings(enabled_modules={"payment_integrity"}, prioritize_experiments=prioritize)
    settings.integrity_brief = brief_raw  # see RunSettings.integrity_brief in context.py
    runner = TestRunner(run_id=f"compare-{'after' if prioritize else 'before'}", base_url=base_url,
                        scope=TestScope.COMPREHENSIVE, settings=settings, endpoints=EndpointMap(), event_bus=EventBus())
    await runner.execute()
    summary = next(r for r in runner.collector.results if r.test_case_id == "PI-SUMMARY")
    return {
        "verdict_counts": summary.input_parameters["verdict_counts"],
        "experiment_order": summary.input_parameters["engine_stats"]["experiment_order"],
    }


async def main(base_url: str, brief_path: str) -> int:
    brief_raw = json.loads(Path(brief_path).read_text())

    before = await _run(base_url, brief_raw, prioritize=False)
    after = await _run(base_url, brief_raw, prioritize=True)

    verdicts_match = before["verdict_counts"] == after["verdict_counts"]
    order_changed = before["experiment_order"] != after["experiment_order"]
    print(f"before order:    {before['experiment_order']}")
    print(f"after  order:    {after['experiment_order']}")
    print(f"order changed:   {order_changed}")
    print(f"before verdicts: {before['verdict_counts']}")
    print(f"after  verdicts: {after['verdict_counts']}")
    print(f"verdicts identical: {verdicts_match}")
    if not verdicts_match:
        print("\nSTOP: scheduling changed a verdict. This is a bug -- see the module docstring.", file=sys.stderr)
        return 1
    if not order_changed:
        print("\nOrder did not change. Expected on a target with no prior findings yet "
              "(this run's own two findings don't count as history for each other) -- "
              "run this script again against the same target/brief to see the second "
              "run pick up what the first one just wrote.")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(2)
    sys.exit(asyncio.run(main(sys.argv[1], sys.argv[2])))
