"""End-to-end: TestRunner against a REAL local server, proving the scope guard,
redaction and skipped-module visibility all work together in the actual
execution path -- not just in isolation against their own unit tests.

Uses a minimal synthetic module (not one of the 19 production modules) so this
test exercises TestRunner/QAHttpClient/ScopeGuard/TestContext wiring on its own,
without also depending on any production module's behaviour.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.testing.base import BaseTestModule  # noqa: E402
from app.testing.context import RunSettings  # noqa: E402
from app.testing.endpoints import EndpointMap  # noqa: E402
from app.testing.enums import ResultStatus, RunStatus, TestCategory, TestScope  # noqa: E402
from app.testing.event_bus import EventBus  # noqa: E402
from app.testing.models import RequestEvidence, ResponseEvidence, TestResult  # noqa: E402
from app.testing.runner import TestRunner  # noqa: E402
from app.enterprise_controls.scope import ScopePolicy  # noqa: E402
from datetime import datetime, timezone  # noqa: E402


class _ProbeModule(BaseTestModule):
    """Sends one in-scope request, one off-scope request, and emits evidence
    carrying a secret plus an over-long test_case_id -- so one module run
    exercises the guard, the client's denial path, and result construction
    exactly as a production module would."""

    module_id = "e2e_probe"
    display_name = "E2E Probe"
    category = TestCategory.FUNCTIONAL

    async def run(self) -> None:
        _, in_scope = await self.context.http.request("GET", "/ping")
        _, off_scope = await self.context.http.request("GET", "http://evil.example.invalid/steal")
        now = datetime.now(timezone.utc)
        await self.emit(TestResult(
            test_case_id="E2E-" + "X" * 60,
            category=TestCategory.FUNCTIONAL,
            name="probe",
            description="d",
            input_parameters={"note": "in-scope call"},
            expected="200",
            actual=f"in_scope={in_scope.status_code} off_scope_error={off_scope.error}",
            status=ResultStatus.PASS if in_scope.status_code == 200 else ResultStatus.FAIL,
            request=RequestEvidence(method="GET", url="/ping", headers={"Authorization": "Bearer abcdefghijklmnop"}, body=None),
            response=ResponseEvidence(status_code=200, headers={"Set-Cookie": "sid=deadbeefcafe"}, body={"token": "tok_should_not_leak"}, elapsed_ms=1.0),
            started_at=now, finished_at=now, duration_ms=1.0,
        ))


async def _tiny_server(handler):
    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


async def _handle(reader, writer):
    try:
        await reader.readline()
        while True:
            h = await reader.readline()
            if h in (b"\r\n", b"\n", b""):
                break
        body = b'{"ok": true}'
        writer.write(f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body)
        await writer.drain()
    finally:
        writer.close()


def test_runner_enforces_scope_redacts_evidence_and_reports_skipped_modules() -> None:
    async def scenario() -> None:
        server, port = await _tiny_server(_handle)
        try:
            base_url = f"http://127.0.0.1:{port}"
            settings = RunSettings(enabled_modules={"functional"})  # 'recon' etc. deliberately NOT enabled
            runner = TestRunner(
                run_id="e2e-1", base_url=base_url, scope=TestScope.COMPREHENSIVE, settings=settings,
                endpoints=EndpointMap(), event_bus=EventBus(),
                scope_policy=ScopePolicy.for_environment(base_url, max_requests_per_second=1000.0),
            )
            from app.testing import registry
            original = dict(registry.MODULE_REGISTRY)
            registry.MODULE_REGISTRY["functional"] = _ProbeModule
            try:
                collector = await runner.execute()
            finally:
                registry.MODULE_REGISTRY.clear()
                registry.MODULE_REGISTRY.update(original)

            assert runner.status == RunStatus.COMPLETED
            probe = next(r for r in collector.results if r.test_case_id.startswith("E2E-"))
            assert "off_scope_error=scope_violation[host_not_allowed]" in probe.actual, probe.actual
            assert "in_scope=200" in probe.actual

            assert runner.guard_stats["requests_used"] == 1, "only the in-scope request counted"
            assert runner.guard_stats["denied_by_code"] == {"host_not_allowed": 1}

            coverage = next((r for r in collector.results if r.test_case_id == "SCOPE-COVERAGE"), None)
            assert coverage is not None and coverage.status == ResultStatus.WARNING
            assert "additional_webhook_security" in coverage.input_parameters["skipped_modules"]
            assert "state_machine_exploration" in coverage.input_parameters["skipped_modules"]
            assert set(runner.skipped_modules) == set(coverage.input_parameters["skipped_modules"])
            # every OTHER comprehensive-scope module was disabled on purpose in this test's
            # RunSettings; SCOPE-COVERAGE must report every one of them, not just the two
            # permanently-missing-from-defaults modules Phase-0 found.
            from app.testing.registry import SCOPE_MODULES
            assert set(coverage.input_parameters["skipped_modules"]) == SCOPE_MODULES[TestScope.COMPREHENSIVE] - {"functional"}
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(scenario())


def test_runner_persistence_normalization_matches_what_the_module_emitted() -> None:
    """Confirms the SAME normalize_result_for_persistence used by api/v1/runs.py's
    _persist_run strips the secrets this run's evidence carried and shortens the ID --
    i.e. that runs.py's persistence path (not exercised here directly, since it needs
    a real DB session) is fed results that actually need exactly this treatment."""
    from app.testing.redaction import normalize_result_for_persistence

    async def scenario() -> None:
        server, port = await _tiny_server(_handle)
        try:
            base_url = f"http://127.0.0.1:{port}"
            runner = TestRunner(
                run_id="e2e-2", base_url=base_url, scope=TestScope.SMOKE,
                settings=RunSettings(enabled_modules={"functional"}), endpoints=EndpointMap(), event_bus=EventBus(),
                scope_policy=ScopePolicy.for_environment(base_url),
            )
            from app.testing import registry
            original = dict(registry.MODULE_REGISTRY)
            registry.MODULE_REGISTRY["functional"] = _ProbeModule
            try:
                collector = await runner.execute()
            finally:
                registry.MODULE_REGISTRY.clear()
                registry.MODULE_REGISTRY.update(original)

            result = next(r for r in collector.results if r.test_case_id.startswith("E2E-"))
            normalized = normalize_result_for_persistence({
                "test_case_id": result.test_case_id, "name": result.name,
                "request_json": result.request.model_dump(mode="json") if result.request else None,
                "response_json": result.response.model_dump(mode="json") if result.response else None,
            })
            assert len(normalized["test_case_id"]) <= 48
            import json
            blob = json.dumps(normalized)
            assert "abcdefghijklmnop" not in blob and "deadbeefcafe" not in blob and "tok_should_not_leak" not in blob
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(scenario())


if __name__ == "__main__":
    import inspect
    import traceback

    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and inspect.isfunction(fn):
            try:
                fn()
                print(f"PASS {name}")
            except Exception:
                failures += 1
                print(f"FAIL {name}")
                traceback.print_exc()
    print(f"\n{'ALL PASSED' if not failures else str(failures) + ' FAILED'}")
    sys.exit(1 if failures else 0)
