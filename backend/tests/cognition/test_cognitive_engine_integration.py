"""End-to-end integration test across the observation -> process_observation
-> LLMReplacementLayer pipeline.

This exists because of the single most consequential bug found during
this audit: LLMReplacementLayer was correctly built and correctly wired
into CognitiveEngine, matching its documented contract exactly -- but
app/testing/runner.py's observation dict never included "body" or
"headers" at all, so in the real run flow the analyzer could never
actually see any response content. A live secret key in a response body
produced severity="none" until that one-line gap was fixed. Unit-testing
LLMReplacementLayer in isolation (see test_llm_replacement_layer.py)
would never have caught this -- only exercising the full pipeline does.
"""
from __future__ import annotations

import pytest

from app.testing.cognition.engine import CognitiveEngine


@pytest.mark.asyncio
async def test_clean_observation_produces_no_llm_finding(tmp_path):
    engine = CognitiveEngine(
        storage_path=str(tmp_path / "qa_cognition" / "t1"),
        coverage_db_path=str(tmp_path / "qa_cognition" / "t1" / "coverage.db"),
        enable_persistence=True,
        enable_event_bus=False,
        enable_sub_second=False,
    )
    engine.initialize({"run_id": "r1", "base_url": "https://staging.acme.com"})

    observation = {
        "test_case_id": "ROLE-002-00", "category": "role_based_access", "status": "pass",
        "endpoint": "https://staging.acme.com/api/v1/orders/1", "method": "GET",
        "status_code": 200, "elapsed_ms": 45.0,
        "body": {"id": 1, "status": "completed", "amount": 1999, "currency": "usd"},
        "headers": {"content-type": "application/json"},
        "duration_ms": 45.0, "name": "x", "actual": "ok", "recommendation": "",
    }
    result = await engine.process_observation(observation)
    assert result["llm_insights"]["severity"] == "none"
    if engine.memory_store:
        engine.memory_store.close()


@pytest.mark.asyncio
async def test_leaked_secret_in_response_body_is_caught_end_to_end(tmp_path):
    """The regression test for the body/headers wiring bug specifically:
    this exact scenario produced severity='none' before the fix, purely
    because the secret never reached the analyzer at all."""
    engine = CognitiveEngine(
        storage_path=str(tmp_path / "qa_cognition" / "t1"),
        coverage_db_path=str(tmp_path / "qa_cognition" / "t1" / "coverage.db"),
        enable_persistence=True,
        enable_event_bus=False,
        enable_sub_second=False,
    )
    engine.initialize({"run_id": "r1", "base_url": "https://staging.acme.com"})

    observation = {
        "test_case_id": "ROLE-002-01", "category": "role_based_access", "status": "info",
        "endpoint": "https://staging.acme.com/api/v1/payments/1/confirm", "method": "POST",
        "status_code": 500, "elapsed_ms": 30.0,
        "body": {"error": "upstream failed", "debug_context": "sk_live_51Hh2eZAbCdEfGhIjKlMnOpQrStUvWx"},
        "headers": {},
        "duration_ms": 30.0, "name": "x", "actual": "processed", "recommendation": "",
    }
    result = await engine.process_observation(observation)

    assert result["llm_insights"]["severity"] == "critical", (
        "a live secret key in the response body must be caught end-to-end via the real "
        "runner.py observation shape, not just when calling LLMReplacementLayer directly"
    )
    assert result["llm_insights"]["suspicious_fields"] >= 1
    if engine.memory_store:
        engine.memory_store.close()


@pytest.mark.asyncio
async def test_full_run_lifecycle_produces_a_snapshot(tmp_path):
    """Smoke test for the whole per-observation lifecycle
    (record_outcome + learn_from_execution + process_observation) plus
    end_session/get_snapshot, matching how runner.py actually drives the
    engine across a run."""
    engine = CognitiveEngine(
        storage_path=str(tmp_path / "qa_cognition" / "t1"),
        coverage_db_path=str(tmp_path / "qa_cognition" / "t1" / "coverage.db"),
        enable_persistence=True,
        enable_event_bus=False,
        enable_sub_second=False,
    )
    engine.initialize({"run_id": "r1", "base_url": "https://staging.acme.com"})

    for i in range(3):
        test_result = {
            "test_case_id": f"PROC-00{i}", "status": "pass", "category": "processing_integrity",
            "actual": "ok", "recommendation": "", "duration_ms": 10.0,
            "request": {"url": f"https://staging.acme.com/api/v1/payments/{i}", "method": "GET"},
        }
        await engine.record_outcome(test_result)
        await engine.learn_from_execution(test_result)

    engine.end_session({"total_results": 3, "total_findings": 0})
    snapshot = engine.get_snapshot()

    assert snapshot["memory_store"]["total_episodic"] == 6  # 2 writes per result (record_outcome + learn_from_execution)
    assert snapshot["coverage"]["total_endpoints"] == 3
    assert isinstance(snapshot["top_hypotheses"], list)
    assert snapshot["llm_replacement_active"] is True

    import json
    json.dumps(snapshot)  # the whole point: this must be directly API-serializable

    if engine.memory_store:
        engine.memory_store.close()
