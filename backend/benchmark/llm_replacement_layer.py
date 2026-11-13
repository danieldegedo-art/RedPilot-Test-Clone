"""LLM-Ersatz-Layer / LLM Replacement Layer.

Referenced from `app.testing.cognition.engine.CognitiveEngine`
(`from benchmark.llm_replacement_layer import LLMReplacementLayer`,
wrapped in try/except ImportError, gracefully degrading to
`self.llm_replacement = None`) but never actually shipped in this
codebase -- the module simply didn't exist. This is that missing piece.

"LLM replacement" because the intent -- per engine.py's own architecture
docstring, "19. LLMReplacementLayer -- Zero-shot + structural +
contextual" -- is to give the cognitive engine an LLM-shaped judgment
call ("does this observation look wrong, and how badly") using fast,
deterministic, fully offline techniques instead of an actual model call:
no added latency per observation, no external API dependency or cost,
and no risk of response bodies from a PAYMENT system ever leaving the
process as part of a "let me just ask an LLM" step. Three complementary
passes, mirroring how such a call would actually be justified:

- Zero-shot: known-bad-shape pattern matching (leaked secrets, stack
  traces, card numbers) that needs no target-specific training data --
  reuses the SAME pattern definitions as
  app.testing.discovery.analyzers.analyze_sensitive_data, both sourced
  from app.testing.pattern_library (a small, dependency-free leaf module)
  rather than each maintaining its own copy of "what does a leaked
  Stripe key look like".
- Structural: unsupervised anomaly scoring (scikit-learn IsolationForest)
  over shape features of the response (size, field count, nesting depth,
  latency, status code, method). Bootstraps entirely from the run in
  progress -- no pre-existing training data -- and stays inert until it
  has seen enough of this run's own traffic to make "unusual" mean
  something. Catches what pattern matching can't: a response that
  doesn't *contain* a known-bad string but doesn't look like the rest of
  this target's traffic either (an endpoint suddenly returning a much
  larger or much slower response than its peers, for instance).
- Contextual: rule-based severity adjustment using what kind of
  endpoint/method this is -- the same leaked secret is a bigger deal on
  a payment-mutating route than on a health check, and gets floored to
  at least that severity regardless of the raw pattern-match/anomaly
  score alone.

Falls back to zero-shot + contextual only (no structural component) when
scikit-learn/numpy aren't importable -- matches the graceful-degradation
pattern already used throughout cognition/ (see event_bus.py's redis
handling, memory_compressor.py's sentence-transformers handling) rather
than making the whole layer hard-depend on an ML stack.
"""
from __future__ import annotations

import re
import statistics
from dataclasses import dataclass, field
from typing import Any

from app.testing.pattern_library import (
    CARD_NUMBER_RE as _CARD_NUMBER_RE,
    SECRET_PATTERNS as _SECRET_PATTERNS,
    body_as_text as _body_as_text,
    luhn_valid as _luhn_valid,
    scan_field_names as _scan_field_names,
)

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest

    SKLEARN_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised by the no-sklearn test
    SKLEARN_AVAILABLE = False


_SEVERITY_ORDER = ["none", "low", "medium", "high", "critical"]
_SEVERITY_FLOOR_SCORE = {"none": 0.0, "low": 0.1, "medium": 0.35, "high": 0.6, "critical": 0.85}

_PAYMENT_SENSITIVE_PATH_RE = re.compile(
    r"(payment|charge|checkout|refund|subscription|card|invoice|payout|balance|transfer)",
    re.IGNORECASE,
)
_MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def is_payment_sensitive_route(url: str) -> bool:
    """Public wrapper around the payment-route heuristic so other modules
    (see benchmark.ambiguous_case_resolution's resolution policy) can reuse
    the exact same definition of "payment-sensitive" instead of re-deriving
    their own -- same rationale as pattern_library.py's "one canonical
    definition"."""
    return bool(_PAYMENT_SENSITIVE_PATH_RE.search(url or ""))


def _bump_severity(current: str, at_least: str) -> str:
    """Raises `current` to `at_least` if `at_least` is more severe; never
    lowers it. Same "floor, don't override" logic the discovery layer
    uses for combining independent severity signals."""
    if _SEVERITY_ORDER.index(at_least) > _SEVERITY_ORDER.index(current):
        return at_least
    return current


def bump_severity(current: str, at_least: str) -> str:
    """Public wrapper around `_bump_severity` -- see
    `is_payment_sensitive_route` above for why this stays a thin wrapper
    around the private implementation rather than a second copy of it.
    Used by benchmark.ambiguous_case_resolution to combine the local
    resolver's severity read with a concrete, deterministic pattern
    match: the resolver may raise the floor further, never lower a
    concretely-evidenced finding
    beneath it."""
    return _bump_severity(current, at_least)


def _severity_from_score(score: float) -> str:
    if score >= 0.85:
        return "critical"
    if score >= 0.6:
        return "high"
    if score >= 0.35:
        return "medium"
    if score > 0.05:
        return "low"
    return "none"


@dataclass
class ZeroShotFinding:
    category: str
    field: str
    detail: str


@dataclass
class LLMReplacementResult:
    """Contract consumed by CognitiveEngine.process_observation: it reads
    `.suspicious_fields` and `.overall_severity` directly, and reports
    `.overall_suspicion_score` in its decision summary. The rest is kept
    on the result for anyone inspecting it more closely (the new
    Cognitive Insights API/dashboard, or a regression test) without
    forcing every caller to reconstruct it from scratch.
    """

    suspicious_fields: list[str] = field(default_factory=list)
    overall_severity: str = "none"  # none|low|medium|high|critical
    overall_suspicion_score: float = 0.0
    zero_shot_findings: list[dict[str, str]] = field(default_factory=list)
    structural_anomaly: bool = False
    structural_score: float = 0.0
    contextual_notes: list[str] = field(default_factory=list)
    # "heuristic" (default -- every existing call site that never sets this
    # keeps working unchanged) | "local_resolver".
    # Set by benchmark.ambiguous_case_resolution when the local resolver
    # (formerly an optional real-model escalation path, since removed) is
    # enabled and applicable; purely informational for anyone inspecting
    # how a given severity was actually arrived at (dashboard, audit
    # trail) -- nothing in this file reads or branches on it.
    assessment_source: str = "heuristic"

    def to_dict(self) -> dict[str, Any]:
        return {
            "suspicious_fields": self.suspicious_fields,
            "overall_severity": self.overall_severity,
            "overall_suspicion_score": round(self.overall_suspicion_score, 4),
            "zero_shot_findings": self.zero_shot_findings,
            "structural_anomaly": self.structural_anomaly,
            "structural_score": round(self.structural_score, 4),
            "contextual_notes": self.contextual_notes,
            "assessment_source": self.assessment_source,
        }


def _count_fields(body: Any) -> int:
    if isinstance(body, dict):
        return len(body) + sum(_count_fields(v) for v in body.values())
    if isinstance(body, list):
        return len(body) + sum(_count_fields(v) for v in body)
    return 0


def _max_depth(body: Any, current: int = 0) -> int:
    if isinstance(body, dict) and body:
        return max(_max_depth(v, current + 1) for v in body.values())
    if isinstance(body, list) and body:
        return max(_max_depth(v, current + 1) for v in body)
    return current


def _extract_features(request_data: dict[str, Any], response_data: dict[str, Any]) -> list[float]:
    """Shape features for the structural anomaly detector. Deliberately
    content-blind (no field values feature in here, only shape/size/
    timing) -- zero-shot already handles content, and keeping this
    layer content-blind means it can't itself become a way payment data
    ends up somewhere it shouldn't (a logged feature vector, say)."""
    body = response_data.get("body")
    body_text = _body_as_text(body) if body is not None else ""
    status = response_data.get("status_code") or 0
    elapsed = response_data.get("elapsed_ms") or 0
    headers = response_data.get("headers") or {}
    method = str(request_data.get("method", "GET")).upper()

    return [
        float(status),
        float(elapsed),
        float(len(body_text)),
        float(_count_fields(body)),
        float(_max_depth(body)),
        float(len(headers)),
        1.0 if method in _MUTATING_METHODS else 0.0,
    ]


class _StructuralBaseline:
    """Maintains a rolling feature buffer scoped to ONE LLMReplacementLayer
    instance -- i.e. one run, since CognitiveEngine creates exactly one --
    so responses are scored against what THIS run's traffic normally
    looks like, rather than a fixed, target-agnostic threshold. Needs no
    pre-existing training data: it bootstraps entirely from the run in
    progress, and stays inert (never flags an anomaly) until it has seen
    enough samples for "unusual" to mean anything.

    Two signals, deliberately not left to just one:
    - The anomaly GATE is a per-feature Iglewicz-Hoaglin modified z-score
      (median/MAD, not mean/stdev) against threshold 3.5 -- the exact
      technique and cutoff this project's own timing-outlier detector
      already uses elsewhere, chosen here for the same reason: robust
      against the training buffer itself containing a couple of odd
      points, and its trigger condition is easy to reason about and
      verify. An earlier version of this class gated purely on
      IsolationForest's own score_samples()/predict(); both produced
      false positives on genuinely uniform data during validation
      (contamination="auto" always classifies *some* fraction of any
      batch as anomalous, and percentile-anchoring against a score
      distribution's own tails has the same problem by construction) --
      this per-feature z-score gate does not have that failure mode.
    - IsolationForest still does real work: once the gate has fired, its
      decision_function (a genuinely multivariate signal a single
      feature's z-score can't see -- an unusual *combination* of
      otherwise-ordinary feature values) sets how far above the minimum
      the suspicion score lands, rather than every anomaly reading as a
      flat "just barely over threshold".
    """

    MIN_SAMPLES_TO_FIT = 15
    REFIT_EVERY = 10
    Z_ANOMALY_THRESHOLD = 3.5  # Iglewicz & Hoaglin's conventional cutoff
    # A feature whose training MAD is below this has shown essentially no
    # natural variation yet (in the extreme, and easy to hit in practice:
    # a byte-count feature differing by exactly 1 across a minority of
    # the window -- e.g. a numeric id crossing from 1 digit to 2 -- can
    # give a median-based MAD of exactly 0 even though *some* real
    # variation exists). Dividing by a near-zero MAD turns a trivial,
    # meaningless difference into an enormous z-score; a feature this
    # close to constant doesn't have enough evidence about its own
    # spread to judge deviations against, so it's excluded from the max()
    # below rather than allowed to dominate it. Confirmed empirically
    # during validation: without this floor, exactly this scenario
    # produced false positives on genuinely clean, uniform traffic.
    MIN_MEANINGFUL_MAD = 1.0

    def __init__(self) -> None:
        self._feature_buffer: list[list[float]] = []
        self._model: Any = None
        self._since_last_fit = 0
        self._feature_medians: list[float] = []
        self._feature_mads: list[float] = []

    @property
    def is_fitted(self) -> bool:
        return bool(self._feature_medians)

    @property
    def sample_count(self) -> int:
        return len(self._feature_buffer)

    def _maybe_fit(self) -> None:
        if len(self._feature_buffer) < self.MIN_SAMPLES_TO_FIT:
            return
        if self._feature_medians and self._since_last_fit < self.REFIT_EVERY:
            return

        columns = list(zip(*self._feature_buffer))
        self._feature_medians = [statistics.median(col) for col in columns]
        self._feature_mads = [statistics.median([abs(v - med) for v in col]) for col, med in zip(columns, self._feature_medians)]
        self._since_last_fit = 0

        if SKLEARN_AVAILABLE:
            x = np.array(self._feature_buffer, dtype=float)
            n_estimators = min(100, max(16, len(x) * 2))
            model = IsolationForest(n_estimators=n_estimators, contamination="auto", random_state=42, n_jobs=1)
            model.fit(x)
            self._model = model

    def score(self, features: list[float]) -> tuple[bool, float]:
        """Returns (is_anomaly, suspicion in [0, 1]). Also feeds
        `features` into the rolling baseline, so the model keeps adapting
        as the run progresses."""
        self._feature_buffer.append(features)
        self._since_last_fit += 1
        self._maybe_fit()

        if not self._feature_medians:
            return False, 0.0

        z_scores = [
            (0.6745 * abs(f - med) / mad) if mad >= self.MIN_MEANINGFUL_MAD else 0.0
            for f, med, mad in zip(features, self._feature_medians, self._feature_mads)
        ]
        max_z = max(z_scores)
        is_anomaly = max_z > self.Z_ANOMALY_THRESHOLD

        forest_component = 0.0
        if self._model is not None:
            x = np.array([features], dtype=float)
            # sklearn convention: negative decision_function = anomalous,
            # roughly -0.5..0.5 in practice for a well-formed forest.
            decision = float(self._model.decision_function(x)[0])
            forest_component = max(0.0, min(1.0, -decision * 2))

        z_component = min(1.0, max_z / (2 * self.Z_ANOMALY_THRESHOLD))
        suspicion = max(z_component, forest_component) if is_anomaly else 0.0
        return is_anomaly, suspicion


def _zero_shot_scan(response_data: dict[str, Any]) -> list[ZeroShotFinding]:
    """Known-bad-shape pattern matching -- no target-specific training
    needed. Reuses app.testing.pattern_library's definitions directly
    rather than re-declaring "what does a leaked Stripe key look like" a
    second time in a second file."""
    body = response_data.get("body")
    if body is None:
        return []
    text = _body_as_text(body)

    findings: list[ZeroShotFinding] = []

    for name, pattern, is_critical in _SECRET_PATTERNS:
        if pattern.search(text):
            findings.append(ZeroShotFinding(
                category="critical_secret" if is_critical else "credential_shaped_token",
                field="<response body>",
                detail=name,
            ))

    for field_path, key, _value in _scan_field_names(body):
        findings.append(ZeroShotFinding(category="sensitive_field_name", field=field_path, detail=key))

    for match in _CARD_NUMBER_RE.finditer(text):
        digits = re.sub(r"[ -]", "", match.group())
        if 13 <= len(digits) <= 19 and _luhn_valid(digits):
            findings.append(ZeroShotFinding(
                category="possible_card_number",
                field="<response body>",
                detail=f"{len(digits)}-digit Luhn-valid sequence",
            ))

    return findings


def _contextual_notes_and_floor(
    request_data: dict[str, Any],
    zero_shot: list[ZeroShotFinding],
) -> tuple[list[str], str]:
    """Rule-based severity weighting by endpoint context. Returns
    (human-readable notes, minimum severity this observation should be
    floored to) -- the same leaked secret is a bigger deal on a
    payment-mutating route than on a health check."""
    notes: list[str] = []
    floor = "none"

    url = str(request_data.get("url", ""))
    method = str(request_data.get("method", "GET")).upper()
    on_payment_route = bool(_PAYMENT_SENSITIVE_PATH_RE.search(url))
    is_mutating = method in _MUTATING_METHODS

    if zero_shot:
        critical_hits = [f for f in zero_shot if f.category in ("critical_secret", "possible_card_number")]
        if critical_hits and on_payment_route:
            notes.append(
                f"{critical_hits[0].category.replace('_', ' ')} on a payment-mutating route "
                f"({method} {url or 'unknown path'}) -- floored to critical regardless of the raw "
                f"pattern match alone."
            )
            floor = "critical"
        elif critical_hits:
            floor = "high"
        else:
            floor = "medium"
    elif on_payment_route and is_mutating:
        notes.append(
            "Payment-mutating route with no pattern-level findings -- any structural signal below "
            "is the only lead here."
        )

    return notes, floor


class LLMReplacementLayer:
    """Ties the three passes together. One instance is meant to live for
    the duration of a single run (CognitiveEngine creates exactly one in
    its __init__) so the structural baseline calibrates against that
    run's own traffic rather than being shared/reset unpredictably.
    """

    def __init__(self) -> None:
        self._baseline = _StructuralBaseline()
        self._observations_analyzed = 0
        self._findings_by_severity: dict[str, int] = {s: 0 for s in _SEVERITY_ORDER}

    def analyze_observation(self, observation: dict[str, Any]) -> LLMReplacementResult:
        """observation: {"request_data": {"url", "method"},
        "response_data": {"status_code", "body", "headers", "elapsed_ms"}}
        -- see CognitiveEngine.process_observation, which builds exactly
        this shape from its own `observation` dict before calling here.
        """
        self._observations_analyzed += 1
        request_data = observation.get("request_data") or {}
        response_data = observation.get("response_data") or {}

        zero_shot = _zero_shot_scan(response_data)

        features = _extract_features(request_data, response_data)
        structural_anomaly, structural_score = self._baseline.score(features)

        contextual_notes, severity_floor = _contextual_notes_and_floor(request_data, zero_shot)

        # Combine: a matched zero-shot pattern is concrete evidence and
        # dominates; a structural anomaly alone is only "this looks
        # unusual compared to this run's other traffic" -- directionally
        # useful, but weaker evidence, so it's weighted down further when
        # not corroborated by anything content-based.
        zero_shot_component = min(1.0, 0.3 * len(zero_shot))
        structural_component = structural_score * (0.6 if structural_anomaly else 0.15)
        overall_score = max(zero_shot_component, structural_component)

        severity = _bump_severity(_severity_from_score(overall_score), severity_floor)
        overall_score = max(overall_score, _SEVERITY_FLOOR_SCORE[severity])
        overall_score = max(0.0, min(1.0, overall_score))

        self._findings_by_severity[severity] += 1

        return LLMReplacementResult(
            suspicious_fields=[f.field for f in zero_shot],
            overall_severity=severity,
            overall_suspicion_score=overall_score,
            zero_shot_findings=[{"category": f.category, "field": f.field, "detail": f.detail} for f in zero_shot],
            structural_anomaly=structural_anomaly,
            structural_score=structural_score,
            contextual_notes=contextual_notes,
        )

    def get_statistics(self) -> dict[str, Any]:
        return {
            "observations_analyzed": self._observations_analyzed,
            "sklearn_available": SKLEARN_AVAILABLE,
            "structural_baseline_fitted": self._baseline.is_fitted,
            "structural_baseline_samples": self._baseline.sample_count,
            "findings_by_severity": dict(self._findings_by_severity),
        }
