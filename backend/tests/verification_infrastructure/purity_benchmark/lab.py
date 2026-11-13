"""Blind benchmark runner: the engine gets a base URL and a customer-level Execution Brief -- never flags, scenario names, truth or fixture metadata."""
from __future__ import annotations

import copy
import time
from dataclasses import dataclass
from typing import Any

from app.testing.http_client import QAHttpClient
from app.testing.integrity.brief import ExecutionBrief
from app.testing.integrity.engine import PureBlackBoxEngine
from app.testing.integrity.findings import EngineResult
from app.enterprise_controls.blindness import BlindnessMonitor
from app.enterprise_controls.scope import ScopeGuard, ScopePolicy
from purity_benchmark.customer_target import CustomerLevelTarget, TargetFlags, start_customer_target
from purity_benchmark.scenarios import Scenario, secret_tokens

BASE_BRIEF: dict[str, Any] = {
    "authorization_ref": "BENCH-AUTH-001", "authorized_by": "qa-benchmark-owner", "environment": "benchmark", "target_kind": "controlled_benchmark",
    "attested_synthetic_data": True, "attested_sandbox_payments": True, "allow_signup": True, "primary_currency": "USD",
    "surface": {
        "signup": {"method": "POST", "path": "/api/v1/account/signup", "observed_via": "product_ui"},
        "start_checkout": {"method": "POST", "path": "/api/v1/checkout", "observed_via": "authorized_browser_trace"},
        "sandbox_pay": {"method": "POST", "path": "/api/v1/checkout/{payment_id}/sandbox-pay", "observed_via": "authorized_browser_trace"},
        "return_flow": {"method": "GET", "path": "/api/v1/checkout/return", "observed_via": "authorized_browser_trace"},
        "subscription_view": {"method": "GET", "path": "/api/v1/account/subscription", "observed_via": "product_ui"},
        "request_refund": {"method": "POST", "path": "/api/v1/account/refund", "observed_via": "product_ui"},
    },
    "plans": {"basic": {"prices": {"USD": 9.0, "JPY": 1300.0}}, "enterprise": {"prices": {"USD": 99.0, "JPY": 14500.0}}},
    "features": {
        "premium_export": {"method": "POST", "path": "/api/v1/premium/export", "proof_field": "export_id", "requires_plan": "basic", "observed_via": "product_ui"},
        "credits_use": {"method": "POST", "path": "/api/v1/premium/credits/use", "proof_field": "credit_used", "requires_plan": "basic", "consumes_quota": True, "observed_via": "product_ui"},
        "enterprise_report": {"method": "GET", "path": "/api/v1/premium/enterprise-report", "proof_field": "report_id", "requires_plan": "enterprise", "observed_via": "product_ui"},
    },
    "declared_paid_features": ["premium_export", "credits_use", "enterprise_report"],
    "limits": {"max_requests": 600, "max_requests_per_second": 25, "revocation_sla_seconds": 1.0, "revocation_poll_schedule_s": [0.0, 0.1, 0.25, 0.5], "quota_probe_cap": 6, "timeout_seconds": 10},
}


def public_brief(base_url: str, overrides: dict[str, Any] | None = None) -> dict[str, Any]:
    """The customer-level brief: only what an authorised external tester can see/do. Overrides may only touch declared limits (e.g. the SLA)."""
    brief = copy.deepcopy(BASE_BRIEF)
    brief["allowed_hosts"] = [base_url.split("//", 1)[1]]
    for key, value in (overrides or {}).items():
        if isinstance(value, dict) and isinstance(brief.get(key), dict):
            brief[key].update(value)
        else:
            brief[key] = value
    return brief


@dataclass
class ScenarioRun:
    scenario: Scenario
    result: EngineResult
    target: CustomerLevelTarget
    elapsed_s: float
    brief_dict: dict[str, Any]
    request_count_at_target: int
    internal_hits: int
    blindness_checks: int
    ledger: Any = None  # the engine's EvidenceLedger (scorer-side verification of hashes/redaction)
    brief: ExecutionBrief | None = None


async def run_scenario(scenario: Scenario, *, experiments: list[str] | None = None) -> ScenarioRun:
    target, server, port = await start_customer_target(TargetFlags(**scenario.flags))
    base_url = f"http://127.0.0.1:{port}"
    http: QAHttpClient | None = None
    try:
        brief_dict = public_brief(base_url, scenario.brief_overrides)
        monitor = BlindnessMonitor(secret_tokens(scenario))
        monitor.assert_blind(brief_dict, where="the execution brief handed to the engine")
        brief = ExecutionBrief.from_dict(brief_dict, env={})
        monitor.assert_blind(brief.to_public_dict(), where="the engine's brief view")
        guard = ScopeGuard(ScopePolicy.for_environment(base_url, max_requests=brief.limits.max_requests, max_requests_per_second=brief.limits.max_requests_per_second))
        http = QAHttpClient(base_url, brief.limits.timeout_seconds, None, {}, "qa-pure-black-box-engine/1.0", max_retries=0, guard=guard, stateless=True)
        engine = PureBlackBoxEngine(http, brief, base_url=base_url)
        started = time.perf_counter()
        result = await engine.run(experiments)
        elapsed = time.perf_counter() - started
        # post-run blindness audit from the TARGET side: the engine must never have SENT a ground-truth token
        monitor.assert_blind({"paths": [p for _, p in target.request_log], "headers": target.request_headers_seen}, where="requests the target received")
        monitor.assert_blind(result.to_dict()["evidence"], where="the evidence ledger summary")
        return ScenarioRun(scenario, result, target, elapsed, brief_dict, len(target.request_log), target.internal_hits, monitor.checks, ledger=engine.ledger, brief=brief)
    finally:
        if http is not None and hasattr(http, "aclose"):
            await http.aclose()
        await server.aclose()
