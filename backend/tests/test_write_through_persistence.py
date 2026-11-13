"""ZR-009: a result must be durable the moment it's produced, not only in a
single batch after the whole run finishes (see runner.py's PersistResultFn /
_persist_one_result and api/v1/runs.py's _persist_result_db).

Exercises TestRunner directly with a FAKE persist_result function -- this is
possible, and deliberately so, because the real SQLAlchemy-backed
implementation is injected by api/v1/runs.py rather than imported by
runner.py itself (see runner.py's module-level PersistResultFn docstring for
why). No sqlalchemy needed to verify the sequencing/crash-survival/
error-handling behaviour; only the pydantic shim, for TestResult itself.

Runs under pytest AND as a plain script, same convention as
test_control_adapter.py.
"""
from __future__ import annotations

import asyncio
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.testing.context import RunSettings  # noqa: E402
from app.testing.endpoints import EndpointMap  # noqa: E402
from app.testing.enums import ResultStatus, TestCategory, TestScope  # noqa: E402
from app.testing.event_bus import EventBus  # noqa: E402
from app.testing.models import TestResult  # noqa: E402
from app.testing.runner import TestRunner, _noop_persist_result  # noqa: E402


def _result(test_case_id: str = "tc-1", status=ResultStatus.PASS) -> TestResult:
    now = datetime.now(timezone.utc)
    return TestResult(
        test_case_id=test_case_id, category=TestCategory.FUNCTIONAL, name="n",
        description="d", expected="e", actual="a", status=status,
        started_at=now, finished_at=now, duration_ms=1.0,
    )


def _runner(persist_result=None) -> TestRunner:
    return TestRunner(
        run_id="run-1", base_url="https://shop.example.test", scope=TestScope.COMPREHENSIVE,
        settings=RunSettings(enabled_modules=set()), endpoints=EndpointMap(),
        event_bus=EventBus(), persist_result=persist_result,
    )


def test_default_construction_is_backward_compatible_noop():
    """Every existing TestRunner(...) call site that predates this fix (all 7
    of them -- grep TestRunner( across backend/tests) doesn't pass
    persist_result and must keep working exactly as before: nothing
    persisted, nothing raised, nothing required to change in those files."""
    runner = _runner()
    assert runner._persist_result is _noop_persist_result
    asyncio.run(runner._emit_result(_result()))
    assert runner.persist_failures == []


def test_emit_result_calls_the_injected_persist_function_with_run_id_and_result():
    calls = []

    async def fake_persist(run_id, result):
        calls.append((run_id, result.test_case_id))

    runner = _runner(persist_result=fake_persist)
    r = _result(test_case_id="tc-42")
    asyncio.run(runner._emit_result(r))

    assert calls == [("run-1", "tc-42")]
    assert runner.persist_failures == []
    # persistence is additive -- the in-memory/live-stream copy still exists too
    assert runner.collector.results[-1].test_case_id == "tc-42"


def test_a_crash_partway_through_still_leaves_everything_emitted_so_far_durable():
    """The actual ZR-009 scenario: execute() raises after some results were
    already produced (container restart, OOM kill, any unhandled exception).
    Everything emitted before the crash must already be in the durable store
    -- it must not depend on a final, never-reached commit at the end of the
    run, which is exactly what the pre-fix design required."""
    durable_store = []

    async def fake_persist(run_id, result):
        durable_store.append(result.test_case_id)

    async def crash_partway():
        runner = _runner(persist_result=fake_persist)
        await runner._emit_result(_result("tc-1"))
        await runner._emit_result(_result("tc-2"))
        raise RuntimeError("simulated crash, e.g. OOM kill, mid-run")

    try:
        asyncio.run(crash_partway())
        raise AssertionError("expected the simulated crash to propagate")
    except RuntimeError:
        pass

    assert durable_store == ["tc-1", "tc-2"], (
        f"both results emitted before the crash must already be durable, got {durable_store}"
    )


def test_a_persist_failure_is_caught_logged_and_recorded_not_raised():
    async def always_fails(run_id, result):
        raise ConnectionError("simulated transient DB error")

    runner = _runner(persist_result=always_fails)
    r = _result("tc-flaky")
    asyncio.run(runner._emit_result(r))  # must not raise

    assert runner.persist_failures == [str(r.id)]
    assert runner.collector.results[-1].test_case_id == "tc-flaky"


def test_skip_result_path_also_goes_through_persistence():
    """Regression guard: _run_one_module's module-not-registered SKIP path
    used to duplicate _emit_result's body (collector.add + event_bus.publish)
    instead of calling it, silently bypassing whatever _emit_result does --
    persistence included. Exercised directly since it needs no live target."""
    calls = []

    async def fake_persist(run_id, result):
        calls.append(result.test_case_id)

    async def go():
        runner = _runner(persist_result=fake_persist)
        await runner._run_one_module(object(), "definitely-not-a-registered-module-id", announce=False)

    asyncio.run(go())
    assert calls == ["SKIP-definitely-not-a-registered-module-id"]


if __name__ == "__main__":
    import traceback
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = failed = 0
    for t in tests:
        try:
            t()
            print(f"PASS {t.__name__}")
            passed += 1
        except Exception:
            print(f"FAIL {t.__name__}")
            traceback.print_exc()
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
