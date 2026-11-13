"""Pydantic data models for test evidence and test results.

These models are the single source of truth for a test case's outcome. They
are used directly by the test modules (to emit results), the WebSocket layer
(serialized to JSON for live streaming), the database layer (persisted after
a run completes) and the reporter (JSON / CSV / PDF export).
"""
from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from app.testing.enums import ResultStatus, TestCategory


class RequestEvidence(BaseModel):
    """Exact request sent to the system under test, captured for evidence."""

    method: str
    url: str
    headers: dict[str, str] = Field(default_factory=dict)
    body: Any = None


class ResponseEvidence(BaseModel):
    """Exact response received from the system under test, captured for evidence.

    `error` is populated instead of `status_code`/`body` when the request
    failed at the transport level (timeout, connection refused, DNS failure).
    """

    status_code: int | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    body: Any = None
    elapsed_ms: float | None = None
    error: str | None = None


class TestResult(BaseModel):
    """The full record of a single executed test case.

    Field names intentionally mirror the required dashboard output format:
    Category / Description / Input / Expected / Actual / Result / Evidence /
    Recommendation.
    """

    model_config = ConfigDict(use_enum_values=True)

    id: UUID = Field(default_factory=uuid4)
    test_case_id: str
    category: TestCategory
    name: str
    description: str
    input_parameters: dict[str, Any] = Field(default_factory=dict)
    expected: str
    actual: str
    status: ResultStatus
    request: RequestEvidence | None = None
    response: ResponseEvidence | None = None
    recommendation: str | None = None
    started_at: datetime
    finished_at: datetime
    duration_ms: float
