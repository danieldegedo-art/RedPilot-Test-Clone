"""Tests for benchmark.llm_replacement_layer.LLMReplacementLayer.

The structural-anomaly component went through several failed designs
before landing here (see the module's own docstring for the full
reasoning) -- IsolationForest's contamination="auto" and percentile-based
calibration against the model's own score distribution both produced
false positives on genuinely clean, uniform traffic. The clean-traffic
tests below exist specifically so that class of regression can't silently
come back.
"""
from __future__ import annotations

import random

from benchmark.llm_replacement_layer import LLMReplacementLayer


def _obs(url="https://staging.acme.com/api/v1/orders/1", method="GET", status=200, body=None, elapsed=45.0, headers=None):
    return {
        "request_data": {"url": url, "method": method},
        "response_data": {"status_code": status, "body": body, "headers": headers or {"content-type": "application/json"}, "elapsed_ms": elapsed},
    }


def test_clean_uniform_traffic_produces_no_findings():
    """80 near-identical observations (only a growing numeric id and
    small timing jitter differ) must never be flagged. This specific
    shape -- an id crossing from 1 to 2 digits -- is exactly what
    triggered false positives in three earlier design iterations."""
    layer = LLMReplacementLayer()
    random.seed(42)
    false_positives = []
    for i in range(80):
        body = {"id": i, "status": "completed", "amount": 1999, "currency": "usd", "items": [{"sku": "abc", "qty": 1}]}
        result = layer.analyze_observation(_obs(
            url=f"https://staging.acme.com/api/v1/orders/{i}",
            elapsed=40 + random.uniform(-5, 5),
            body=body,
        ))
        if result.overall_severity != "none":
            false_positives.append((i, result.to_dict()))
    assert not false_positives, f"false positives on clean traffic: {false_positives}"


def test_leaked_live_secret_on_payment_route_is_critical():
    layer = LLMReplacementLayer()
    result = layer.analyze_observation(_obs(
        url="https://staging.acme.com/api/v1/payments/21/confirm", method="POST", status=500,
        body={"error": "upstream failed", "debug_context": "sk_live_51Hh2eZAbCdEfGhIjKlMnOpQrStUvWx"},
    ))
    assert result.overall_severity == "critical"
    assert any(f["category"] == "critical_secret" for f in result.zero_shot_findings)
    assert result.suspicious_fields


def test_card_number_on_payment_route_is_critical():
    layer = LLMReplacementLayer()
    result = layer.analyze_observation(_obs(
        url="https://staging.acme.com/api/v1/payments/22", method="POST", status=200,
        body={"status": "ok", "echo": "4111 1111 1111 1111"},
    ))
    assert result.overall_severity == "critical"
    assert any(f["category"] == "possible_card_number" for f in result.zero_shot_findings)


def test_card_number_on_non_payment_route_is_flagged_but_lower():
    """Same zero-shot finding, different context -- contextual weighting
    should still flag it, but not floor it to critical the way the
    payment-route case is."""
    layer = LLMReplacementLayer()
    result = layer.analyze_observation(_obs(
        url="https://staging.acme.com/api/v1/support/tickets/5", method="GET", status=200,
        body={"note": "customer quoted 4111 1111 1111 1111 in the ticket"},
    ))
    assert result.overall_severity not in ("none", "critical")


def test_structurally_anomalous_response_is_flagged():
    """A response wildly larger/deeper/slower than everything else in
    the run should register as a structural anomaly even with no
    pattern-level finding at all."""
    layer = LLMReplacementLayer()
    random.seed(1)
    for i in range(30):
        body = {"id": i, "status": "completed", "amount": 1999, "currency": "usd"}
        layer.analyze_observation(_obs(url=f"https://staging.acme.com/api/v1/orders/{i}", elapsed=40 + random.uniform(-5, 5), body=body))

    weird_body = {"a": {"b": {"c": {"d": [{"x": i, "y": str(i) * 40} for i in range(200)]}}}}
    result = layer.analyze_observation(_obs(
        url="https://staging.acme.com/api/v1/catalog/999", status=200, body=weird_body, elapsed=850.0,
    ))
    assert result.structural_anomaly is True
    assert result.overall_severity != "none"


def test_baseline_recovers_after_one_anomaly():
    """A single weird response shouldn't permanently poison the
    baseline -- the next normal observation should read as clean again."""
    layer = LLMReplacementLayer()
    random.seed(7)
    for i in range(30):
        body = {"id": i, "status": "completed", "amount": 1999, "currency": "usd"}
        layer.analyze_observation(_obs(url=f"https://staging.acme.com/api/v1/orders/{i}", elapsed=40 + random.uniform(-5, 5), body=body))

    weird_body = {"a": {"b": {"c": {"d": [{"x": i} for i in range(200)]}}}}
    layer.analyze_observation(_obs(body=weird_body, elapsed=900.0))

    normal_again = layer.analyze_observation(_obs(
        body={"id": 999, "status": "completed", "amount": 1999, "currency": "usd"}, elapsed=41.0,
    ))
    assert normal_again.overall_severity == "none"


def test_missing_body_handled_gracefully():
    layer = LLMReplacementLayer()
    result = layer.analyze_observation(_obs(body=None))
    assert result.overall_severity == "none"
    assert result.suspicious_fields == []


def test_result_is_json_serializable():
    import json

    layer = LLMReplacementLayer()
    result = layer.analyze_observation(_obs(body={"a": 1}))
    json.dumps(result.to_dict())  # raises if not serializable


def test_statistics_reflect_observations_analyzed():
    layer = LLMReplacementLayer()
    for _ in range(5):
        layer.analyze_observation(_obs())
    stats = layer.get_statistics()
    assert stats["observations_analyzed"] == 5
