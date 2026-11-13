"""Abstract base class for every test module.

A test module is independently runnable: it takes a TestContext (where/how
to send requests) and an `emit` callback (where results go), and executes
its test cases. `execute_case()` is a helper that covers the common
single-request-then-evaluate pattern (used heavily by NegativeTestModule);
modules that need multi-step flows (create-then-verify, polling, etc.) call
`self.context.http.request(...)` directly and build a TestResult by hand
(see FunctionalTestModule).
"""
from __future__ import annotations

import abc
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

from app.testing.context import TestContext
from app.testing.dynamic_values import DiscoveredValues
from app.testing.enums import ResultStatus, TestCategory
from app.testing.models import ResponseEvidence, TestResult

EvaluateFn = Callable[[ResponseEvidence], tuple[ResultStatus, str]]


class BaseTestModule(abc.ABC):
    module_id: str
    display_name: str
    category: TestCategory

    def __init__(self, context: TestContext, emit: Callable[[TestResult], Awaitable[None]]) -> None:
        self.context = context
        self._emit_fn = emit

    @abc.abstractmethod
    async def run(self) -> None:
        """Execute every test case in this module, calling self.emit(result) for each."""
        raise NotImplementedError

    async def emit(self, result: TestResult) -> None:
        await self._emit_fn(result)

    def resolve_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Returns `payload` with any field Recon observed a real value for
        this run (any nesting depth, exact name match) replaced by that
        real value -- see dynamic_values.py. Falls back to `payload`
        unchanged (same object) if Recon didn't run or found nothing
        usable, so this is always safe to call unconditionally."""
        discovered = self.context.shared_state.get("discovered_values")
        if not isinstance(discovered, DiscoveredValues) or not discovered.by_field_name:
            return payload
        return discovered.resolve(payload)

    async def execute_case(
        self,
        *,
        test_case_id: str,
        name: str,
        description: str,
        method: str,
        path: str,
        expected: str,
        evaluate: EvaluateFn,
        input_parameters: dict[str, Any] | None = None,
        raw_body: bytes | None = None,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        recommendation: str | None = None,
        probe_class: str | None = None,
    ) -> TestResult:
        """Send one request, time it, evaluate the response, emit + return a TestResult.

        `evaluate` receives the captured ResponseEvidence and returns
        (status, actual_description). It is only called when the request
        completed at the transport level; transport failures are reported
        as ResultStatus.ERROR automatically.

        Does NOT resolve `input_parameters` against Recon's discovered
        values itself -- resolving here, after a case has already applied
        its own deliberate override (e.g. NEG-001's amount=0 spread on top
        of a base payload), would silently replace that deliberate value
        with a real discovered one and invert what the test is checking.
        Call `self.resolve_payload()` on a payload TEMPLATE before any
        case-specific override is applied to it instead (see
        modules/negative.py's `base_payload` for the pattern every module
        follows).
        """
        started = datetime.now(timezone.utc)
        request_evidence, response_evidence = await self.context.http.request(
            method, path, json_body=input_parameters, raw_body=raw_body, params=params, extra_headers=headers,
            probe_class=probe_class,
        )
        finished = datetime.now(timezone.utc)

        if response_evidence.error is not None:
            status, actual = ResultStatus.ERROR, f"Transport error: {response_evidence.error}"
        else:
            status, actual = evaluate(response_evidence)

        result = TestResult(
            test_case_id=test_case_id,
            category=self.category,
            name=name,
            description=description,
            input_parameters=input_parameters or {},
            expected=expected,
            actual=actual,
            status=status,
            request=request_evidence,
            response=response_evidence,
            recommendation=recommendation if status in (ResultStatus.FAIL, ResultStatus.ERROR) else None,
            started_at=started,
            finished_at=finished,
            duration_ms=(finished - started).total_seconds() * 1000,
        )
        await self.emit(result)
        return result
