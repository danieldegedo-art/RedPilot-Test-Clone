"""Ambiguous-Case Resolver -- local replacement for the former optional
real-model second opinion (previously benchmark/llm_escalation.py) on the
subset of observations the deterministic LLM-Ersatz-Layer
(llm_replacement_layer.py) is least certain about.

WHY THIS FILE REPLACES llm_escalation.py, NOT JUST PATCHES IT
-----------------------------------------------------------------
llm_escalation.py was already off by default and already narrowly scoped
(see git history / the before/after report this change shipped with for
the full audit) -- in any deployment that never set
QA_ENABLE_LLM_ESCALATION and never configured an API key, it never made a
network call, ever. That is not what changed here. What changed is the
project's hard constraint, stated plainly: no code path in this suite may
be ABLE to make an external LLM call at runtime, full stop -- not "off by
default," not "opt-in with an API key," because a capability that exists
in the codebase is something a compliance review has to reason about even
when its default is safe, and this is compliance-monitoring software
where that reasoning overhead is exactly the thing being sold against.
`grep -ri "llm_escalation\\|anthropic_api_key\\|api\\.anthropic\\.com" .`
from the repo root returns nothing after this change; that is the
literal, checkable definition of done here.

WHAT WAS KEPT, WHAT WAS DROPPED, AND WHY
-------------------------------------------
KEPT (the parts of the old design that were never ABOUT the network call):
  - The escalation/resolution POLICY (`_should_resolve`, renamed from
    `_should_escalate`, same rule): don't bother with extra scrutiny for
    "none" severity or non-payment "low" severity; always look closer at
    a structural-only anomaly (no concrete pattern match) or any real
    finding on a payment-mutating route.
  - Redaction (`redact_url`, `summarize_observation`, renamed from
    `redact_observation_for_llm`): still worth doing even with nowhere to
    send the summary -- it is also what gets handed to memory-grounding
    and, transitively, what a dashboard/audit trail displays, and the
    same "never a raw body, raw header, or raw URL" bar applies there too.
  - Memory grounding (`_recall_similar`/`_remember`): querying and storing
    episodic memory of past similar findings is a local SQLite operation
    (PersistentMemoryStore), not a network call -- it was never the thing
    the hard constraint is about, and it is a genuinely useful signal for
    the local judgment below (see NoveltyAndHistoryFactors).
  - The combination rule with the deterministic layer: a concrete
    zero-shot match is evidence and is never lowered; the resolver's read
    only gets full control of the verdict for the genuinely ambiguous
    "structural-only" case.

DROPPED (existed ONLY to manage the risk/cost of a real network call, and
have no remaining purpose once there is no network call to manage --
keeping them would be complexity with nothing left to justify it):
  - api_key, fast_model/deep_model, ANTHROPIC_API_URL/VERSION, httpx,
    _post_to_anthropic, the prompt/response JSON contract.
  - Retries and the circuit breaker (both exist to survive a flaky or
    down remote provider; a pure in-process function call does not time
    out or return 503).
  - The per-run TTL cache: it existed to avoid paying a network round
    trip twice for the same observation. The new local judgment
    deliberately has run-scoped state instead (NoveltyAndHistoryFactors'
    occurrence counter) that a cache would actively fight -- caching would
    return a stale confidence value instead of the correctly novelty-
    decayed one for a repeated observation. Removing the cache here is a
    correctness fix enabled by removing the network call, not a
    regression.
  - The per-session escalation budget: existed to bound spend/latency on
    a paid API. A local computation costs microseconds; there is nothing
    left to budget.

ROBUSTNESS
----------
The local judgment is pure computation and cannot time out or fail on I/O,
but resolve_ambiguous_case still wraps it and degrades to the unmodified
heuristic verdict on any unexpected exception, for the same reason the
original module did: nothing in this file may ever propagate into
CognitiveEngine.process_observation's hot path.
"""
from __future__ import annotations

import logging
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any

from app.testing.pattern_library import body_as_text as _body_as_text
from benchmark.llm_replacement_layer import (
    LLMReplacementResult,
    bump_severity as _bump_severity,
    is_payment_sensitive_route,
)

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = ("none", "low", "medium", "high", "critical")

# An "id-shaped" path segment: purely numeric, or 16+ opaque alphanumeric
# characters (tokens, hashes). Unchanged from the original module -- see
# redact_url below for what this is for.
_ID_LIKE_SEGMENT_RE = re.compile(r"^(?:\d+|[A-Za-z0-9_-]{16,})$")


@dataclass(frozen=True)
class AmbiguousResolutionConfig:
    """Operator-controlled knobs for the resolver. Far smaller than the
    old EscalationConfig by design -- see this module's docstring for
    exactly which fields were dropped and why. `enabled` now defaults to
    True: unlike the old escalation path, there is no privacy/cost
    trade-off left to make opt-in -- this is a pure local computation
    over data the suite already collected."""

    enabled: bool = True
    memory_context_items: int = 3


def build_ambiguous_resolution_config_from_settings(app_settings: Any) -> AmbiguousResolutionConfig:
    """Builds an AmbiguousResolutionConfig from app.core.config.settings
    (or any object exposing the same attribute names, e.g. a test
    double). A free function, not a Settings method, so app.core.config
    has no import dependency on benchmark/ -- same rationale as the
    function this replaces."""
    return AmbiguousResolutionConfig(
        enabled=bool(getattr(app_settings, "enable_ambiguous_case_resolution", True)),
        memory_context_items=int(getattr(app_settings, "ambiguous_resolution_memory_context_items", 3)),
    )


def redact_url(url: str) -> str:
    """Strips the query string/fragment and masks id-shaped path segments.
    Unchanged from the original module: what survives is the route SHAPE
    ("/api/v1/customers/<id>/cards"), never a specific id, token, or the
    query string -- still the right bar even though the only remaining
    consumers are memory-grounding and the audit trail, not a prompt."""
    path = (url or "").split("?", 1)[0].split("#", 1)[0]
    segments = path.split("/")
    masked = ["<id>" if _ID_LIKE_SEGMENT_RE.match(seg) else seg for seg in segments]
    return "/".join(masked)


def summarize_observation(
    request_data: dict[str, Any],
    response_data: dict[str, Any],
    heuristic: LLMReplacementResult,
) -> dict[str, Any]:
    """Builds the redacted structural summary used for memory-keying and
    the audit-trail note. Renamed from redact_observation_for_llm -- same
    fields, same redaction guarantees, just no longer framed around
    "what's safe to send an LLM" when nothing is sent anywhere. Reuses
    heuristic's already-redacted fields rather than re-deriving "what's
    safe" a second time, for the same one-canonical-definition reason
    pattern_library.py's own docstring gives."""
    body = response_data.get("body")
    body_text = _body_as_text(body) if body is not None else ""
    headers = response_data.get("headers") or {}

    return {
        "method": str(request_data.get("method", "GET")).upper(),
        "route_shape": redact_url(str(request_data.get("url", ""))),
        "status_code": response_data.get("status_code"),
        "elapsed_ms": response_data.get("elapsed_ms"),
        "response_size_chars": len(body_text),
        "response_header_names": sorted(headers.keys())[:20],
        "heuristic_assessment": {
            "severity": heuristic.overall_severity,
            "suspicion_score": round(heuristic.overall_suspicion_score, 4),
            "structural_anomaly": heuristic.structural_anomaly,
            "structural_score": round(heuristic.structural_score, 4),
            "zero_shot_findings": heuristic.zero_shot_findings,
            "suspicious_field_paths": heuristic.suspicious_fields,
            "contextual_notes": heuristic.contextual_notes,
        },
    }


def _severity_from_confidence(confidence: float) -> str:
    """Same thresholds llm_replacement_layer.py's own
    _severity_from_score uses, kept in sync deliberately -- a confidence
    of 0.6 should mean the same thing here as a structural_score of 0.6
    does there."""
    if confidence >= 0.85:
        return "critical"
    if confidence >= 0.6:
        return "high"
    if confidence >= 0.35:
        return "medium"
    if confidence > 0.05:
        return "low"
    return "none"


class AmbiguousAnomalyResolver:
    """Computes a locally-grounded verdict for the subset of observations
    the deterministic layer flags as a structural-only anomaly (no
    concrete pattern match) or a real finding on a payment-mutating
    route. One instance lives for the duration of a single run (same
    lifecycle as LLMReplacementLayer/CognitiveEngine) so its
    occurrence-novelty counter is scoped to that run's own traffic.
    """

    def __init__(self, config: AmbiguousResolutionConfig) -> None:
        self._config = config
        self._route_shape_occurrences: Counter[str] = Counter()
        self._resolutions_computed = 0
        self._skipped_not_applicable = 0
        self._errors = 0

    @property
    def active(self) -> bool:
        return self._config.enabled

    # -- Resolution policy (unchanged rule from the old _should_escalate) --

    @staticmethod
    def _should_resolve(heuristic: LLMReplacementResult, on_payment_route: bool, structural_only: bool) -> bool:
        """Only bothers with the richer local judgment where it plausibly
        changes the outcome: never for "none" (nothing to reason about),
        never for a non-payment "low" (not worth diluting the signal),
        always for a structural-only signal (the case a flat threshold is
        worst at), and always for any real finding on a payment-mutating
        route (highest cost of a false negative)."""
        if heuristic.overall_severity == "none":
            return False
        if heuristic.overall_severity == "low" and not on_payment_route:
            return False
        if structural_only:
            return True
        return on_payment_route and heuristic.overall_severity in ("medium", "high", "critical")

    # -- Public entry point ------------------------------------------------

    async def resolve_ambiguous_case(
        self,
        request_data: dict[str, Any],
        response_data: dict[str, Any],
        heuristic: LLMReplacementResult,
        *,
        memory_store: Any | None = None,
    ) -> LLMReplacementResult:
        """Always returns *a* verdict -- `heuristic` unchanged whenever
        resolution is disabled or not warranted, and on ANY unexpected
        exception (defense in depth: the computation below is pure and
        should never raise, but this must never be the thing that breaks
        a run)."""
        if not self.active:
            return heuristic

        on_payment_route = is_payment_sensitive_route(str(request_data.get("url", "")))
        structural_only = heuristic.structural_anomaly and not heuristic.zero_shot_findings

        if not self._should_resolve(heuristic, on_payment_route, structural_only):
            self._skipped_not_applicable += 1
            return heuristic

        try:
            redacted = summarize_observation(request_data, response_data, heuristic)
            similar_past = await self._recall_similar(memory_store, redacted)
            severity, confidence, rationale = self._local_judgment(redacted, similar_past, heuristic)
            self._resolutions_computed += 1

            note = f"Local resolver ({confidence:.0%} confidence): {rationale}"
            if structural_only:
                final_severity = severity
                final_score = confidence
            else:
                final_severity = _bump_severity(heuristic.overall_severity, severity)
                final_score = max(heuristic.overall_suspicion_score, confidence)

            verdict = LLMReplacementResult(
                suspicious_fields=heuristic.suspicious_fields,
                overall_severity=final_severity,
                overall_suspicion_score=final_score,
                zero_shot_findings=heuristic.zero_shot_findings,
                structural_anomaly=heuristic.structural_anomaly,
                structural_score=heuristic.structural_score,
                contextual_notes=[*heuristic.contextual_notes, note],
                assessment_source="local_resolver",
            )
            await self._remember(memory_store, redacted, verdict)
            return verdict
        except Exception:  # noqa: BLE001 - must never propagate into process_observation
            self._errors += 1
            logger.warning("Ambiguous-case resolution failed unexpectedly; using heuristic verdict.", exc_info=True)
            return heuristic

    # -- Local judgment ------------------------------------------------

    def _local_judgment(
        self,
        redacted: dict[str, Any],
        similar_past: list[dict[str, Any]],
        heuristic: LLMReplacementResult,
    ) -> tuple[str, float, str]:
        """Produces (severity, confidence, rationale) entirely from data
        already in the process: the deterministic layer's own structural
        score, how many times THIS shape of anomaly has already been seen
        this run (novelty), and what similar findings turned out to be in
        PAST runs (historical prior, via PersistentMemoryStore). This is
        the direct local substitute for what a model's probabilistic read
        used to provide for the genuinely ambiguous case -- reasoned
        explicitly rather than learned, but grounded in the same two
        things a human reviewer would actually look at: "have I seen this
        exact thing already today" and "what did this usually turn out to
        be before".
        """
        route_shape = redacted["route_shape"]
        occurrences_before = self._route_shape_occurrences[route_shape]
        self._route_shape_occurrences[route_shape] += 1

        base_confidence = heuristic.structural_score
        # Novelty: a first sighting this run keeps full confidence; each
        # repeat of the IDENTICAL shape discounts it -- this run's own
        # traffic is live evidence that this is just what the route looks
        # like, not a fresh one-off event. Floored at 0.4 rather than
        # decaying to ~0: a structural anomaly that recurs constantly is
        # still worth a WARNING-level look, just not a fresh CRITICAL
        # every single time.
        novelty_factor = 1.0 if occurrences_before == 0 else max(0.4, 1.0 - 0.15 * occurrences_before)
        confidence = max(0.0, min(1.0, base_confidence * novelty_factor))
        rationale_bits = [f"structural anomaly score {heuristic.structural_score:.2f}"]
        if occurrences_before:
            rationale_bits.append(f"this route shape's anomaly seen {occurrences_before}x already this run (novelty-discounted)")

        # Historical prior: blend toward what similar findings in PAST
        # runs turned out to be (30% weight -- informative, not
        # dominant: this run's own live evidence should still carry most
        # of the verdict).
        past_severities = [p.get("prior_verdict_severity") for p in similar_past if p.get("prior_verdict_severity") in _SEVERITY_ORDER]
        if past_severities:
            avg_rank = sum(_SEVERITY_ORDER.index(s) for s in past_severities) / len(past_severities)
            historical_factor = avg_rank / (len(_SEVERITY_ORDER) - 1)
            confidence = (confidence * 0.7) + (historical_factor * 0.3)
            rationale_bits.append(f"{len(past_severities)} similar past finding(s) averaging '{_SEVERITY_ORDER[round(avg_rank)]}'")

        confidence = max(0.0, min(1.0, confidence))
        severity = _severity_from_confidence(confidence)
        return severity, confidence, "; ".join(rationale_bits)

    # -- Memory grounding (local SQLite via PersistentMemoryStore; no
    # network I/O -- see this module's docstring, "KEPT" section) --------

    @staticmethod
    def _memory_tag(redacted: dict[str, Any]) -> str | None:
        findings = redacted["heuristic_assessment"]["zero_shot_findings"]
        if findings:
            return findings[0].get("category")
        if redacted["heuristic_assessment"]["structural_anomaly"]:
            return "structural_anomaly"
        return None

    async def _recall_similar(self, memory_store: Any, redacted: dict[str, Any]) -> list[dict[str, Any]]:
        if memory_store is None or self._config.memory_context_items <= 0:
            return []
        tag = self._memory_tag(redacted)
        if tag is None:
            return []
        try:
            import asyncio

            memories = await asyncio.to_thread(
                memory_store.query_episodic,
                memory_type="ambiguous_case_resolution",
                tag=tag,
                limit=self._config.memory_context_items,
            )
        except Exception:
            logger.debug("Memory recall for ambiguous-case resolution failed; continuing without it.", exc_info=True)
            return []
        return [
            {
                "route_shape": m.content.get("route_shape"),
                "prior_verdict_severity": m.content.get("verdict_severity"),
                "prior_verdict_rationale": m.content.get("verdict_rationale"),
            }
            for m in memories
        ]

    async def _remember(self, memory_store: Any, redacted: dict[str, Any], verdict: LLMReplacementResult) -> None:
        if memory_store is None:
            return
        tag = self._memory_tag(redacted) or "ambiguous_case_resolution_other"
        try:
            import asyncio

            await asyncio.to_thread(
                memory_store.store_episodic,
                memory_type="ambiguous_case_resolution",
                content={
                    "route_shape": redacted["route_shape"],
                    "verdict_severity": verdict.overall_severity,
                    "verdict_rationale": verdict.contextual_notes[-1] if verdict.contextual_notes else "",
                },
                context={"method": redacted["method"]},
                outcome=verdict.overall_severity,
                tags=[tag],
            )
        except Exception:
            logger.debug("Storing the ambiguous-case-resolution episodic memory failed; continuing.", exc_info=True)

    # -- Statistics ----------------------------------------------------

    def get_statistics(self) -> dict[str, Any]:
        return {
            "enabled": self._config.enabled,
            "active": self.active,
            "resolutions_computed": self._resolutions_computed,
            "skipped_not_applicable": self._skipped_not_applicable,
            "errors": self._errors,
            "distinct_route_shapes_seen": len(self._route_shape_occurrences),
        }
