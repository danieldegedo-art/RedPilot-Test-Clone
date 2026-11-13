"""ResultCollector: aggregates TestResults for one run and produces summary stats.

The collector is intentionally dumb -- it just accumulates results and
computes counts. All intelligence (grouping, deduplication, correlation)
lives in the test modules themselves and the discovery/cognition layers.
"""
from __future__ import annotations

from collections import Counter
from typing import Any

from app.testing.enums import ResultStatus, RunStatus
from app.testing.models import TestResult


class ResultCollector:
    def __init__(self, run_id: str) -> None:
        self.run_id = run_id
        self.results: list[TestResult] = []

    async def add(self, result: TestResult) -> None:
        self.results.append(result)

    def summary(self) -> dict[str, Any]:
        status_counts = Counter(
            r.status if isinstance(r.status, str) else r.status.value
            for r in self.results
        )
        total = len(self.results)
        passed = status_counts.get(ResultStatus.PASS.value, 0)
        failed = status_counts.get(ResultStatus.FAIL.value, 0)
        warnings = status_counts.get(ResultStatus.WARNING.value, 0)
        info = status_counts.get(ResultStatus.INFO.value, 0)
        errors = status_counts.get(ResultStatus.ERROR.value, 0)

        pass_rate = (passed / total * 100) if total > 0 else 0.0

        # Detect likely session expiry: broad spread of 401/403 responses
        auth_failure_count = sum(
            1 for r in self.results
            if r.response is not None
            and r.response.status_code in (401, 403)
        )
        likely_session_expired = (
            auth_failure_count >= 3
            and total > 0
            and auth_failure_count / total >= 0.25
        )

        return {
            "total": total,
            "passed": passed,
            "failed": failed,
            "warnings": warnings,
            "info": info,
            "errors": errors,
            "pass_rate": round(pass_rate, 1),
            "likely_session_expired": likely_session_expired,
            "status_counts": dict(status_counts),
        }
