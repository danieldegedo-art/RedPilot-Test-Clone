"""The internal representation an analyzer produces, before
discovery/engine.py converts it into a TestResult for the dashboard."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.testing.enums import ResultStatus


@dataclass
class Finding:
    finding_id: str  # stable-ish within a run; used as the TestResult's test_case_id
    title: str
    description: str  # methodology: what this analyzer looks for and why
    status: ResultStatus
    observation: str  # what was actually observed this run (-> TestResult.actual)
    standard_reference: str  # e.g. "OWASP API3:2023; PCI-DSS Req. 3.4"
    source_test_case_ids: list[str] = field(default_factory=list)
    recommendation: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)  # -> TestResult.input_parameters
