"""Regression tests for the fault-isolation pass (see
CHANGELOG_COGNITIVE_UPGRADE.md and the accompanying hardening report):

1. DiscoveryEngine._run_analyzers isolates each of the nine analyzers --
   one raising must not discard the other eight's findings.
2. api/v1/runs.py's _execute_and_persist survives an exception from
   TestRunner.execute() by persisting a real RunStatus.FAILED with
   whatever the run's ResultCollector already gathered, instead of the
   pre-fix behavior (nothing persisted at all; the row silently stuck at
   its last status forever).

NOTE ON THIS SANDBOX: like test_http_client_resilience.py, this needs
pydantic (TestResult/Finding's TestResult conversion) and, for
TestExecuteAndPersistSurvivesACrash specifically, sqlalchemy/fastapi --
none installable here (see that file's note, and README.md's "A note on
this build"). Written and reviewed against the real source and
syntax-checked (`ast.parse`); run with the real dependencies installed
before relying on it.
"""
from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest

from app.testing.discovery.engine import DiscoveryEngine
from app.testing.enums import ResultStatus, TestCategory
from app.testing.models import RequestEvidence, ResponseEvidence, TestResult


def _module_result(test_case_id: str = "FUNC-001", status: ResultStatus = ResultStatus.PASS) -> TestResult:
    now = datetime.now(timezone.utc)
    return TestResult(
        test_case_id=test_case_id,
        category=TestCategory.FUNCTIONAL,
        name="stub result",
        description="stub",
        expected="stub",
        actual="stub",
        status=status,
        request=RequestEvidence(method="GET", url="https://target.example/x"),
        response=ResponseEvidence(status_code=200, body={}, elapsed_ms=5.0),
        started_at=now,
        finished_at=now,
        duration_ms=5.0,
    )


class TestDiscoveryAnalyzerIsolation:
    @pytest.mark.asyncio
    async def test_one_raising_analyzer_does_not_suppress_the_others(self):
        """The exact bug this fixes: before it, an exception anywhere in
        _run_analyzers propagated out of DiscoveryEngine.run entirely,
        which -- combined with the matching runner.py fix -- used to mean
        losing every finding, from every analyzer, not just the broken
        one."""
        results = [_module_result()]
        engine = DiscoveryEngine(results, function_map=None)

        with patch(
            "app.testing.discovery.engine.analyze_timing_outliers", side_effect=ValueError("boom")
        ), patch(
            "app.testing.discovery.engine.analyze_sensitive_data",
            return_value=[],
        ):
            emitted: list[TestResult] = []

            async def emit(result: TestResult) -> None:
                emitted.append(result)

            await engine.run(emit)

        test_case_ids = [r.test_case_id for r in emitted]
        assert "DISCOVERY-ANALYZER-ERROR" in test_case_ids, "the failure must be visible in the run's own evidence"
        error_result = next(r for r in emitted if r.test_case_id == "DISCOVERY-ANALYZER-ERROR")
        assert error_result.status == ResultStatus.WARNING
        assert "timing_outliers" in error_result.actual
        # The other eight analyzers must still have run to completion --
        # verified indirectly: a DISCOVERY-SUMMARY (or the "no finding"
        # DISCOVERY-000, depending on what the other eight found against
        # this minimal fixture) must still be present, proving run()
        # continued past the failing analyzer rather than aborting.
        assert any(r.test_case_id in ("DISCOVERY-SUMMARY", "DISCOVERY-000") for r in emitted)

    @pytest.mark.asyncio
    async def test_no_analyzer_errors_means_no_error_result_emitted(self):
        """Negative case, so the WARNING above can't be a false-positive
        that fires on every run regardless of whether anything failed."""
        results = [_module_result()]
        engine = DiscoveryEngine(results, function_map=None)
        emitted: list[TestResult] = []

        async def emit(result: TestResult) -> None:
            emitted.append(result)

        await engine.run(emit)
        assert "DISCOVERY-ANALYZER-ERROR" not in [r.test_case_id for r in emitted]


class TestExecuteAndPersistSurvivesACrash:
    """api/v1/runs.py's _execute_and_persist. Uses a minimal in-memory fake
    for SessionLocal/RunRecord instead of a real Postgres connection --
    the real SQLAlchemy model classes aren't needed to prove this
    function's own control flow (does it call session.commit() with a
    FAILED status and the partial results, or not), which is what this
    fix actually changed."""

    @pytest.mark.asyncio
    async def test_crash_in_execute_still_persists_failed_status_and_partial_results(self):
        from app.api.v1 import runs as runs_module
        from app.testing.collector import ResultCollector
        from app.testing.enums import RunStatus

        class FakeRecord:
            def __init__(self):
                self.status = "running"
                self.finished_at = None
                self.summary_json = None
                self.cognitive_snapshot_json = None
                self.error_message = None

        class FakeSession:
            def __init__(self, record):
                self._record = record
                self.added = []
                self.committed = False

            async def get(self, model, run_id):
                return self._record

            def add(self, obj):
                self.added.append(obj)

            async def commit(self):
                self.committed = True

            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc_info):
                return False

        fake_record = FakeRecord()
        fake_session = FakeSession(fake_record)

        class FakeRunner:
            run_id = "run-123"
            cognitive_snapshot = None

            def __init__(self):
                self.status = RunStatus.RUNNING
                self.collector = ResultCollector(run_id="run-123")

            async def execute(self):
                # Simulate a module having already reported one real result
                # before the crash -- this is what must NOT be lost.
                await self.collector.add(_module_result("PARTIAL-001"))
                raise RuntimeError("simulated unhandled exception deep in execute()")

        with patch.object(runs_module, "SessionLocal", return_value=fake_session), patch.object(
            runs_module.db_models, "TestResultRecord", side_effect=lambda **kwargs: kwargs
        ):
            await runs_module._execute_and_persist(FakeRunner())

        assert fake_record.status == "failed", "must be a real, visible terminal status -- not left at its prior value"
        assert fake_record.error_message and "RuntimeError" in fake_record.error_message
        assert fake_record.finished_at is not None
        assert fake_session.committed is True
        assert len(fake_session.added) == 1, "the one result collected before the crash must still be persisted"
        assert fake_session.added[0]["test_case_id"] == "PARTIAL-001"
        assert "run-123" not in runs_module.active_runners

    @pytest.mark.asyncio
    async def test_successful_execute_is_unaffected(self):
        """The success path must behave exactly as before this fix --
        this fix only changes what happens on an exception."""
        from app.api.v1 import runs as runs_module
        from app.testing.collector import ResultCollector
        from app.testing.enums import RunStatus

        class FakeRecord:
            def __init__(self):
                self.status = "running"
                self.finished_at = None
                self.summary_json = None
                self.cognitive_snapshot_json = None
                self.error_message = None

        class FakeSession:
            def __init__(self, record):
                self._record = record
                self.added = []
                self.committed = False

            async def get(self, model, run_id):
                return self._record

            def add(self, obj):
                self.added.append(obj)

            async def commit(self):
                self.committed = True

            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc_info):
                return False

        fake_record = FakeRecord()
        fake_session = FakeSession(fake_record)

        class FakeRunner:
            run_id = "run-456"
            cognitive_snapshot = {"hypotheses": []}

            def __init__(self):
                self.status = RunStatus.COMPLETED

            async def execute(self):
                collector = ResultCollector(run_id="run-456")
                await collector.add(_module_result("FUNC-001"))
                return collector

        with patch.object(runs_module, "SessionLocal", return_value=fake_session), patch.object(
            runs_module.db_models, "TestResultRecord", side_effect=lambda **kwargs: kwargs
        ):
            await runs_module._execute_and_persist(FakeRunner())

        assert fake_record.status == "completed"
        assert fake_record.error_message is None
        assert len(fake_session.added) == 1
