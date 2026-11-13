"""Tests for benchmark/ambiguous_case_resolution.py -- the local
replacement for the former optional real-model escalation
(benchmark/llm_escalation.py, removed). See that module's docstring for
the full "kept vs. dropped" rationale.

Unlike the old test_llm_escalation.py, nothing here injects a fake HTTP
transport, because there is no transport left to fake -- every test below
exercises the real code path directly. Runnable both under pytest and
directly via `python3 tests/test_ambiguous_case_resolution.py` (see
test_state_exploration.py's module docstring for why that matters in this
sandbox).
"""
from __future__ import annotations

import asyncio

from benchmark.ambiguous_case_resolution import (
    AmbiguousAnomalyResolver,
    AmbiguousResolutionConfig,
    build_ambiguous_resolution_config_from_settings,
    redact_url,
)
from benchmark.llm_replacement_layer import LLMReplacementResult


def _run_async(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Redaction -- unchanged behavior from the removed module; pinned here so a
# future edit can't silently weaken it.
# ---------------------------------------------------------------------------


def test_redact_url_strips_query_string():
    assert redact_url("/api/v1/customers/1?token=abc123") == "/api/v1/customers/<id>"


def test_redact_url_masks_all_digit_segments_regardless_of_length():
    assert redact_url("/api/v1/page/2") == "/api/v1/page/<id>"
    assert redact_url("/api/v1/accounts/12345678") == "/api/v1/accounts/<id>"


def test_redact_url_masks_long_opaque_alphanumeric_segments():
    assert redact_url("/api/v1/sessions/tok_live_ab12cd34ef56gh78") == "/api/v1/sessions/<id>"


def test_redact_url_keeps_route_vocabulary():
    assert redact_url("/api/v1/customers/cards") == "/api/v1/customers/cards"


# ---------------------------------------------------------------------------
# No network capability at all: the entire point of this rewrite.
# ---------------------------------------------------------------------------


def test_module_has_no_httpx_import_and_no_network_call():
    """Structural guard via AST, not a raw text search: the module's own
    docstring legitimately DISCUSSES httpx/api_key/the old provider URL
    (explaining what was removed and why), so a naive substring search
    over the whole file text would false-positive on its own
    documentation. What actually matters, and what this checks precisely,
    is that no `import httpx` (or `from httpx import ...`) statement
    exists, and no function call anywhere in the module targets an
    `AsyncClient`/`.post(`-shaped call -- i.e. the CAPABILITY is gone,
    not just the word."""
    import ast

    import benchmark.ambiguous_case_resolution as mod

    tree = ast.parse(open(mod.__file__, encoding="utf-8").read())

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert not any(alias.name.split(".")[0] == "httpx" for alias in node.names), "found `import httpx`"
        if isinstance(node, ast.ImportFrom):
            assert node.module != "httpx", "found `from httpx import ...`"
        if isinstance(node, ast.Attribute) and node.attr in ("AsyncClient", "post", "request"):
            raise AssertionError(f"found a call-shaped attribute access `.{node.attr}` that looks like an HTTP client call")

    # Config must not carry the fields that made a real call possible.
    cfg = AmbiguousResolutionConfig()
    assert not hasattr(cfg, "api_key")
    assert not hasattr(cfg, "fast_model")
    assert not hasattr(cfg, "deep_model")


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


def test_config_defaults_to_enabled_with_no_network_fields():
    cfg = AmbiguousResolutionConfig()
    assert cfg.enabled is True
    assert not hasattr(cfg, "api_key")
    assert not hasattr(cfg, "fast_model")


def test_config_from_settings_reads_explicit_values():
    class FakeSettings:
        enable_ambiguous_case_resolution = False
        ambiguous_resolution_memory_context_items = 9

    cfg = build_ambiguous_resolution_config_from_settings(FakeSettings())
    assert cfg.enabled is False
    assert cfg.memory_context_items == 9


def test_config_from_settings_defaults_when_attributes_missing():
    class EmptySettings:
        pass

    cfg = build_ambiguous_resolution_config_from_settings(EmptySettings())
    assert cfg.enabled is True
    assert cfg.memory_context_items == 3


# ---------------------------------------------------------------------------
# Resolution policy (same rule as the removed _should_escalate)
# ---------------------------------------------------------------------------


def test_severity_none_is_never_resolved_further():
    resolver = AmbiguousAnomalyResolver(AmbiguousResolutionConfig())
    heuristic = LLMReplacementResult(overall_severity="none")

    async def go():
        return await resolver.resolve_ambiguous_case({"url": "/api/v1/health", "method": "GET"}, {"status_code": 200}, heuristic)

    result = _run_async(go())
    assert result is heuristic


def test_low_severity_on_non_payment_route_is_not_resolved_further():
    resolver = AmbiguousAnomalyResolver(AmbiguousResolutionConfig())
    heuristic = LLMReplacementResult(overall_severity="low", overall_suspicion_score=0.1)

    async def go():
        return await resolver.resolve_ambiguous_case({"url": "/api/v1/products", "method": "GET"}, {"status_code": 200}, heuristic)

    result = _run_async(go())
    assert result is heuristic


def test_structural_only_anomaly_is_resolved_and_local_judgment_fully_determines_severity():
    resolver = AmbiguousAnomalyResolver(AmbiguousResolutionConfig())
    heuristic = LLMReplacementResult(
        overall_severity="medium", overall_suspicion_score=0.5,
        structural_anomaly=True, structural_score=0.72, zero_shot_findings=[],
    )
    req = {"url": "/api/v1/payments/pay_abcdef0123456789/capture", "method": "POST"}
    resp = {"status_code": 200, "body": {"ok": True}, "headers": {}, "elapsed_ms": 900}

    result = _run_async(resolver.resolve_ambiguous_case(req, resp, heuristic))
    assert result.assessment_source == "local_resolver"
    assert 0.0 <= result.overall_suspicion_score <= 1.0
    assert "Local resolver" in result.contextual_notes[-1]


def test_concrete_finding_on_payment_route_can_only_raise_never_lower_severity():
    resolver = AmbiguousAnomalyResolver(AmbiguousResolutionConfig())
    heuristic = LLMReplacementResult(
        overall_severity="high", overall_suspicion_score=0.65,
        structural_anomaly=False, structural_score=0.1,
        zero_shot_findings=[{"category": "critical_secret", "field": "<response body>", "detail": "stripe_secret_key"}],
    )
    req = {"url": "/api/v1/payments/pay_1/capture", "method": "POST"}
    resp = {"status_code": 200, "body": {}, "headers": {}, "elapsed_ms": 50}

    result = _run_async(resolver.resolve_ambiguous_case(req, resp, heuristic))
    assert result.overall_severity in ("high", "critical")


# ---------------------------------------------------------------------------
# Novelty discount -- the genuinely new local-judgment behavior this module
# introduces in place of "ask a model".
# ---------------------------------------------------------------------------


def test_repeated_identical_anomaly_confidence_decays_via_novelty_discount():
    resolver = AmbiguousAnomalyResolver(AmbiguousResolutionConfig())
    heuristic = LLMReplacementResult(
        overall_severity="medium", overall_suspicion_score=0.5,
        structural_anomaly=True, structural_score=0.72, zero_shot_findings=[],
    )
    req = {"url": "/api/v1/payments/pay_1/capture", "method": "POST"}
    resp = {"status_code": 200, "body": {}, "headers": {}, "elapsed_ms": 900}

    async def three_sightings():
        first = await resolver.resolve_ambiguous_case(req, resp, heuristic)
        second = await resolver.resolve_ambiguous_case(req, resp, heuristic)
        third = await resolver.resolve_ambiguous_case(req, resp, heuristic)
        return first, second, third

    first, second, third = _run_async(three_sightings())
    assert first.overall_suspicion_score > second.overall_suspicion_score > third.overall_suspicion_score


def test_different_route_shapes_do_not_share_a_novelty_discount():
    resolver = AmbiguousAnomalyResolver(AmbiguousResolutionConfig())
    heuristic = LLMReplacementResult(
        overall_severity="medium", overall_suspicion_score=0.5,
        structural_anomaly=True, structural_score=0.72, zero_shot_findings=[],
    )
    resp = {"status_code": 200, "body": {}, "headers": {}, "elapsed_ms": 900}

    async def go():
        a = await resolver.resolve_ambiguous_case({"url": "/api/v1/payments/pay_1/capture", "method": "POST"}, resp, heuristic)
        b = await resolver.resolve_ambiguous_case({"url": "/api/v1/refunds/ref_1", "method": "POST"}, resp, heuristic)
        return a, b

    a, b = _run_async(go())
    assert a.overall_suspicion_score == b.overall_suspicion_score, "first sighting of two DIFFERENT route shapes must score identically"


# ---------------------------------------------------------------------------
# Safe defaults / failure handling
# ---------------------------------------------------------------------------


def test_disabled_config_never_touches_the_heuristic():
    resolver = AmbiguousAnomalyResolver(AmbiguousResolutionConfig(enabled=False))
    heuristic = LLMReplacementResult(
        overall_severity="high", overall_suspicion_score=0.9, structural_anomaly=True, structural_score=0.9,
    )
    req = {"url": "/api/v1/payments/pay_1/capture", "method": "POST"}
    resp = {"status_code": 200, "body": {}, "headers": {}, "elapsed_ms": 50}

    result = _run_async(resolver.resolve_ambiguous_case(req, resp, heuristic))
    assert result is heuristic
    assert resolver.active is False


def test_a_broken_memory_store_degrades_to_heuristic_never_raises():
    """memory_store.query_episodic raising must not propagate -- same
    "never break the hot path" guarantee the removed module had for a
    failed network call, now applied to the one remaining I/O dependency."""

    class BrokenMemoryStore:
        def query_episodic(self, **kwargs):
            raise RuntimeError("db is down")

        def store_episodic(self, **kwargs):
            raise RuntimeError("db is down")

    resolver = AmbiguousAnomalyResolver(AmbiguousResolutionConfig())
    heuristic = LLMReplacementResult(
        overall_severity="medium", overall_suspicion_score=0.5,
        structural_anomaly=True, structural_score=0.72, zero_shot_findings=[],
    )
    req = {"url": "/api/v1/payments/pay_1/capture", "method": "POST"}
    resp = {"status_code": 200, "body": {}, "headers": {}, "elapsed_ms": 900}

    result = _run_async(resolver.resolve_ambiguous_case(req, resp, heuristic, memory_store=BrokenMemoryStore()))
    assert result.assessment_source == "local_resolver"  # resolution still completed; only memory grounding was skipped


def test_statistics_report_expected_shape_with_no_network_fields():
    resolver = AmbiguousAnomalyResolver(AmbiguousResolutionConfig())
    stats = resolver.get_statistics()
    assert set(stats.keys()) == {
        "enabled", "active", "resolutions_computed", "skipped_not_applicable", "errors", "distinct_route_shapes_seen",
    }


def _run(fn):
    try:
        fn()
        print(f"[PASS] {fn.__name__}")
    except AssertionError as exc:
        print(f"[FAIL] {fn.__name__}: {exc}")
        raise


if __name__ == "__main__":
    for _name, _fn in list(globals().items()):
        if _name.startswith("test_") and callable(_fn):
            _run(_fn)
    print("Alle ambiguous_case_resolution-Tests bestanden.")
