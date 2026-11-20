"""Pydantic request/response schemas for the /runs API."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, HttpUrl

from app.testing.enums import ResultStatus, RunStatus, TestCategory, TestScope
from app.testing.schema_version import SCHEMA_VERSION


class ScanRequest(BaseModel):
    """TEST CLONE: dead-simple cold-domain input. Paste a URL, press run.
    Optionally provide a twin_url for dual-target mode: all probes run against both."""
    url: HttpUrl
    twin_url: HttpUrl | None = None
    session_cookies: str | None = None


class RunCreateRequest(BaseModel):
    environment_url: HttpUrl
    scope: TestScope = TestScope.FULL_REGRESSION
    # Additional hosts this run is authorised to call beyond environment_url's
    # own host (e.g. a separate checkout/API subdomain the flow redirects
    # through). The environment_url host is ALWAYS in scope; this only adds
    # to it -- see testing/scope_guard.py's ScopePolicy.for_environment. Never
    # a way to widen scope beyond what the caller explicitly lists here.
    extra_allowed_hosts: list[str] = Field(default_factory=list)


class RequestEvidenceSchema(BaseModel):
    method: str
    url: str
    headers: dict[str, str] = Field(default_factory=dict)
    body: Any = None


class ResponseEvidenceSchema(BaseModel):
    status_code: int | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    body: Any = None
    elapsed_ms: float | None = None
    error: str | None = None


class TestResultSchema(BaseModel):
    id: str | None = None
    test_case_id: str
    category: TestCategory
    name: str
    description: str
    input_parameters: dict[str, Any] = Field(default_factory=dict)
    expected: str
    actual: str
    status: ResultStatus
    request: RequestEvidenceSchema | None = None
    response: ResponseEvidenceSchema | None = None
    recommendation: str | None = None
    started_at: datetime
    finished_at: datetime
    duration_ms: float


class RunSummarySchema(BaseModel):
    schema_version: str = SCHEMA_VERSION
    run_id: str
    status: RunStatus
    environment_url: str
    scope: TestScope
    started_at: datetime
    finished_at: datetime | None = None
    summary: dict[str, Any] | None = None
    # Only set when status == "failed" -- see db/models.py's RunRecord.error_message.
    error_message: str | None = None


class RunDetailSchema(BaseModel):
    schema_version: str = SCHEMA_VERSION
    run_id: str
    status: RunStatus
    environment_url: str
    scope: TestScope
    started_at: datetime
    finished_at: datetime | None = None
    summary: dict[str, Any] | None = None
    cognitive_snapshot: dict[str, Any] | None = None
    results: list[TestResultSchema] = Field(default_factory=list)
    error_message: str | None = None
