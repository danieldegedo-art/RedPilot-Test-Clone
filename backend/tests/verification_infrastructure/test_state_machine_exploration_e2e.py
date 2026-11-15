"""End-to-end verification of modules/state_machine_exploration.py against
a real (if local) HTTP target -- see README.md in this directory for what
this does and does not prove.

Run directly (pytest is not installable in the sandbox this was written
in either -- see tests/test_state_exploration.py's docstring for the same
constraint elsewhere in this project):

    PYTHONPATH=tests/verification_infrastructure/shims:. python3 \\
        tests/verification_infrastructure/test_state_machine_exploration_e2e.py
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from reference_target import start_reference_target  # noqa: E402

from app.testing.context import RunSettings, TestContext  # noqa: E402
from app.testing.endpoints import EndpointMap, EndpointSpec  # noqa: E402
from app.testing.enums import TestScope  # noqa: E402
from app.testing.http_client import QAHttpClient  # noqa: E402
from app.testing.modules.state_machine_exploration import StateMachineExplorationModule  # noqa: E402

# capture_payment/cancel_payment are NOT in EndpointMap's built-in default
# vocabulary (only create_payment/get_payment/create_refund are -- see
# endpoints.py) -- this override is exactly the mechanism a real target
# with separate capture/cancel endpoints needs configured, the same
# pattern additional_webhook_security.py already establishes for other
# target-specific extension. Without it, this module does not guess a
# path; see StateMachineExplorationModule.get_last_run_scope_report.
REFERENCE_TARGET_OVERRIDES = EndpointMap(
    overrides={
        "capture_payment": EndpointSpec("POST", "/api/v1/payments/{payment_id}/capture"),
        "cancel_payment": EndpointSpec("POST", "/api/v1/payments/{payment_id}/cancel"),
    }
)


async def run_against_reference_target() -> tuple[list, dict]:
    target, server, port = await start_reference_target()
    base_url = f"http://127.0.0.1:{port}"
    http_client = QAHttpClient(
        base_url=base_url, timeout_seconds=5.0, proxy_url=None, headers={}, user_agent="QA-Suite-Verify/1.0"
    )
    results: list = []

    async def collect(result) -> None:
        results.append(result)

    context = TestContext(
        run_id="e2e-verify",
        base_url=base_url,
        entry_url=base_url,
        scope=TestScope.FULL_REGRESSION,
        settings=RunSettings(),
        endpoints=REFERENCE_TARGET_OVERRIDES,
        http=http_client,
    )
    module = StateMachineExplorationModule(context, collect)
    await module.run()
    scope_report = module.get_last_run_scope_report()

    await http_client.aclose()
    server.close()
    await server.wait_closed()
    return results, scope_report


def test_generates_and_executes_real_scenarios_with_nothing_skipped() -> None:
    results, scope_report = asyncio.run(run_against_reference_target())
    assert len(results) == 14, f"expected 14 generated+executed scenarios against this reference target, got {len(results)}"
    assert scope_report["skipped_count"] == 0, f"expected nothing skipped once capture_payment/cancel_payment are overridden, got {scope_report}"


def test_finds_exactly_the_two_planted_illegal_transition_bugs() -> None:
    """Reference target's Bug 1 (capture() checks the wrong precondition)
    manifests as BOTH cancelled->captured and partially_refunded->captured
    wrongly succeeding -- two distinct generated cases catching the same
    root cause, which is itself worth knowing (a fix to capture()'s
    precondition check fixes both at once)."""
    results, _ = asyncio.run(run_against_reference_target())
    failed_names = {r.name for r in results if r.status == "FAIL"}
    assert "Illegal transition rejected: cancelled -> captured" in failed_names
    assert "Illegal transition rejected: partially_refunded -> captured" in failed_names


def test_finds_the_planted_concurrency_bug_via_real_asyncio_interleaving() -> None:
    """Bug 2 (refund's TOCTOU window) is caught by the ONE race pair where
    both operations are refunds and their combined amount exceeds the
    captured amount -- state_machine_exploration.py correctly routes this
    through check_refund_sum_within_capture rather than treating it as a
    "mutually exclusive" pair (see the "not mutually exclusive" test
    below for why that distinction matters)."""
    results, _ = asyncio.run(run_against_reference_target())
    race = next(r for r in results if r.name == "Concurrent race: partially_refunded vs refunded from captured")
    assert race.status == "FAIL", "the TOCTOU refund race must be caught"


def test_does_not_false_positive_when_one_outcome_enables_the_other() -> None:
    """REGRESSION TEST for a real false positive found while building this
    module: capture and refund from "authorized" were originally both
    treated as "mutually exclusive, at most one may succeed" purely
    because both are legal exits from the same from_state. Running this
    against the reference target showed that assumption is wrong --
    capturing legitimately ENABLES a subsequent refund; they are not
    competing outcomes. Fixed by checking graph reachability between the
    two target states before applying the exclusivity rule (see
    state_machine_exploration.py's _run_one_race)."""
    results, _ = asyncio.run(run_against_reference_target())
    race = next(r for r in results if r.name == "Concurrent race: captured vs refunded from authorized")
    assert race.status == "PASS", (
        "capture enabling a subsequent refund is legitimate sequencing, not a bug -- "
        f"got status={race.status}, actual={race.actual}"
    )


def test_deterministic_pass_fail_pattern_across_repeated_real_runs() -> None:
    """Runs the full real-socket, real-asyncio-concurrency scenario 5
    times and requires an identical PASS/FAIL pattern per case every
    time -- payment ids are random per run, so this compares
    (test_case_id, status) pairs, not raw output. See the project's
    before/after report for a larger (30-run, multiple simulated
    latencies) version of this same check."""
    patterns = set()
    for _ in range(5):
        results, _ = asyncio.run(run_against_reference_target())
        patterns.add(tuple(sorted((r.test_case_id, r.status) for r in results)))
    assert len(patterns) == 1, f"expected one stable PASS/FAIL pattern across 5 real runs, got {len(patterns)} distinct patterns"


def test_completes_within_its_runtime_budget() -> None:
    """Axis 3's own requirement ("define a runtime budget and verify it
    holds"), applied to this module specifically: against a local
    reference target with realistic (10ms) simulated per-refund DB
    latency, this module's 14 generated-and-executed scenarios,
    parallelized (module_concurrency, default 4), must complete within
    500ms -- generously above the ~55-60ms this actually measures locally
    (see the project's before/after report), leaving headroom for a
    slower CI machine while still catching a real regression (e.g.
    someone accidentally serializing the parallel loop again, or a
    scenario count that grows without the concurrency limit growing to
    match)."""
    import time

    start = time.perf_counter()
    asyncio.run(run_against_reference_target())
    elapsed = time.perf_counter() - start
    assert elapsed < 0.5, f"runtime budget exceeded: {elapsed:.3f}s (budget: 0.5s)"


def _run(fn) -> None:
    try:
        fn()
        print(f"[PASS] {fn.__name__}")
    except AssertionError as exc:
        print(f"[FAIL] {fn.__name__}: {exc}")
        raise


if __name__ == "__main__":
    for _name, _fn in list(globals().items()):
        if _name.startswith("test_") and callable(_fn):
            _run(_fn)
    print("Alle State-Machine-Exploration-E2E-Tests bestanden (echte Sockets, echtes Modul, echtes Target).")
