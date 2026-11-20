"""LLM-Ersatz-Layer / LLM Replacement Layer -- v2 Major Upgrade.

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
process as part of a "let me just ask an LLM" step.

v2 upgrade adds eleven reasoning engines that together reproduce the
multi-step analysis pipelines of leading cyber-focused AI models -- all
in pure, deterministic code with ZERO external calls:

  1. Zero-shot         -- known-bad-shape pattern matching (secrets, traces)
  2. Structural        -- IsolationForest anomaly over shape features
  3. Chain-of-Thought  -- deterministic multi-step reasoning chains
  4. Multi-Perspective -- red-team / blue-team / auditor viewpoints
  5. Hypothesis        -- Bayesian-style hypothesis generation & scoring
  6. Evidence Correlator -- cross-observation pattern correlation
  7. Reverse Engineering -- infer server-side rules from I/O patterns
  8. Brainstorm        -- divergent/convergent attack ideation
  9. Monte Carlo Risk  -- probabilistic attack-success simulation
 10. Attack Tree       -- goal-oriented AND/OR attack decomposition
 11. Contextual        -- payment-provider & SaaS entitlement context

Falls back gracefully when scikit-learn/numpy aren't importable.
Stdlib only for all engines except #2.
"""
from __future__ import annotations

import hashlib
import math
import random
import re
import statistics
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from app.testing.pattern_library import (
    BUSINESS_LOGIC_ARTIFACTS,
    CARD_NUMBER_RE as _CARD_NUMBER_RE,
    CORS_ARTIFACTS,
    HEADER_SECURITY_PATTERNS,
    INFO_DISCLOSURE_PATTERNS,
    JWT_ABUSE_ARTIFACTS,
    RACE_CONDITION_ARTIFACTS,
    SECRET_PATTERNS as _SECRET_PATTERNS,
    SQL_INJECTION_ARTIFACTS,
    SSRF_ARTIFACTS,
    XSS_ARTIFACTS,
    body_as_text as _body_as_text,
    luhn_valid as _luhn_valid,
    scan_field_names as _scan_field_names,
    scan_injection_artifacts as _scan_injection_artifacts,
)

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest

    SKLEARN_AVAILABLE = True
except ImportError:  # pragma: no cover
    SKLEARN_AVAILABLE = False


# ============================================================================
# Constants
# ============================================================================

_SEVERITY_ORDER = ["none", "low", "medium", "high", "critical"]
_SEVERITY_FLOOR_SCORE = {
    "none": 0.0,
    "low": 0.1,
    "medium": 0.35,
    "high": 0.6,
    "critical": 0.85,
}

_PAYMENT_SENSITIVE_PATH_RE = re.compile(
    r"(payment|charge|checkout|refund|subscription|card|invoice|payout|balance|transfer"
    r"|billing|purchase|order|cart|price|coupon|discount|plan|entitlement|trial"
    r"|stripe|paypal|braintree|adyen|klarna|affirm)",
    re.IGNORECASE,
)
_AUTH_PATH_RE = re.compile(
    r"(login|signin|auth|token|oauth|saml|sso|mfa|2fa|verify|session|api[_-]?key"
    r"|register|signup|password|reset|forgot|confirm|activate)",
    re.IGNORECASE,
)
_ADMIN_PATH_RE = re.compile(
    r"(admin|dashboard|manage|internal|system|config|settings|control|staff|super)",
    re.IGNORECASE,
)
_WEBHOOK_PATH_RE = re.compile(
    r"(webhook|callback|hook|notify|ipn|event|listen|sink)",
    re.IGNORECASE,
)
_USER_DATA_PATH_RE = re.compile(
    r"(user|account|profile|customer|member|person|identity|tenant)",
    re.IGNORECASE,
)
_API_PATH_RE = re.compile(r"(api|graphql|rest|v\d+)", re.IGNORECASE)

_MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

_STRIPE_OBJECT_RE = re.compile(
    r'"object"\s*:\s*"(checkout\.session|payment_intent|subscription'
    r"|invoice|charge|refund|customer|plan|product|price"
    r"|coupon|promotion_code|setup_intent|transfer|payout"
    r'|balance_transaction|connect\.account)"',
    re.IGNORECASE,
)
_STRIPE_STATUS_RE = re.compile(
    r'"status"\s*:\s*"(succeeded|pending|failed|canceled|requires_action'
    r"|requires_payment_method|processing|incomplete|trialing|active"
    r'|past_due|unpaid|incomplete_expired|paused)"',
    re.IGNORECASE,
)

_PROVIDER_SIGNATURES: dict[str, list[re.Pattern[str]]] = {
    "stripe": [
        re.compile(r"(?:sk_live_|pk_live_|sk_test_|pk_test_|whsec_|pi_|cs_|sub_|in_|ch_|re_|cus_|price_)", re.I),
        re.compile(r'"object"\s*:\s*"(?:payment_intent|checkout\.session|subscription|invoice|charge)"', re.I),
    ],
    "paypal": [
        re.compile(r"(?:paypal\.com|PAYPAL-|paypal_client_id|paypal_secret)", re.I),
        re.compile(r'"(?:payer_id|payee|purchase_units|paypal_order_id)"', re.I),
    ],
    "braintree": [
        re.compile(r"(?:braintreegateway|braintree_merchant|bt_)", re.I),
        re.compile(r'"(?:nonce|payment_method_nonce|braintree_transaction)"', re.I),
    ],
    "adyen": [
        re.compile(r"(?:adyen\.com|x-api-key.*adyen|adyen_merchant)", re.I),
        re.compile(r'"(?:pspReference|merchantReference|additionalData|shopperReference)"', re.I),
    ],
}

_ENTITLEMENT_TIER_RE = re.compile(
    r'"(?:plan|tier|subscription|product|plan_id|plan_name|subscription_type|access_level)"'
    r'\s*:\s*"([^"]+)"',
    re.I,
)
_PREMIUM_TIERS = {
    "premium", "enterprise", "pro", "business", "unlimited",
    "professional", "team", "growth", "platinum", "diamond", "ultimate",
}
_UNPAID_STATUSES = {
    "trialing", "trial", "unpaid", "past_due", "canceled", "cancelled",
    "inactive", "free", "incomplete", "paused", "expired", "suspended",
}


# ============================================================================
# Public helpers (re-exported for other modules)
# ============================================================================

def is_payment_sensitive_route(url: str) -> bool:
    return bool(_PAYMENT_SENSITIVE_PATH_RE.search(url or ""))


def bump_severity(current: str, at_least: str) -> str:
    if _SEVERITY_ORDER.index(at_least) > _SEVERITY_ORDER.index(current):
        return at_least
    return current


_bump_severity = bump_severity


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


# ============================================================================
# Data classes
# ============================================================================

@dataclass
class ZeroShotFinding:
    category: str
    field: str
    detail: str
    severity_hint: str = "medium"
    cwe: str = ""


@dataclass
class Hypothesis:
    hypothesis_id: str
    description: str
    category: str
    prior: float
    evidence_for: list[str] = field(default_factory=list)
    evidence_against: list[str] = field(default_factory=list)
    posterior: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.hypothesis_id,
            "description": self.description,
            "category": self.category,
            "prior": round(self.prior, 4),
            "posterior": round(self.posterior, 4),
            "evidence_for": self.evidence_for,
            "evidence_against": self.evidence_against,
        }


@dataclass
class AttackTreeNode:
    goal: str
    node_type: str  # "AND" | "OR" | "LEAF"
    probability: float = 0.0
    children: list[AttackTreeNode] = field(default_factory=list)
    finding_ref: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "goal": self.goal,
            "type": self.node_type,
            "probability": round(self.probability, 4),
        }
        if self.finding_ref:
            d["finding_ref"] = self.finding_ref
        if self.children:
            d["children"] = [c.to_dict() for c in self.children]
        return d


@dataclass
class LLMReplacementResult:
    """Contract consumed by CognitiveEngine.process_observation."""

    suspicious_fields: list[str] = field(default_factory=list)
    overall_severity: str = "none"
    overall_suspicion_score: float = 0.0
    zero_shot_findings: list[dict[str, str]] = field(default_factory=list)
    structural_anomaly: bool = False
    structural_score: float = 0.0
    contextual_notes: list[str] = field(default_factory=list)
    assessment_source: str = "heuristic"

    # --- v2 chain-of-thought reasoning ---
    reasoning_chain: list[str] = field(default_factory=list)
    hypotheses: list[dict] = field(default_factory=list)
    attack_paths: list[dict] = field(default_factory=list)
    brainstorm_results: list[dict] = field(default_factory=list)
    reverse_engineering_findings: list[dict] = field(default_factory=list)
    confidence_calibration: dict = field(default_factory=dict)
    multi_perspective_scores: dict = field(default_factory=dict)
    evidence_correlation: list[dict] = field(default_factory=list)
    anomaly_explanation: str = ""
    risk_monte_carlo: dict = field(default_factory=dict)

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
            "reasoning_chain": self.reasoning_chain,
            "hypotheses": self.hypotheses,
            "attack_paths": self.attack_paths,
            "brainstorm_results": self.brainstorm_results,
            "reverse_engineering_findings": self.reverse_engineering_findings,
            "confidence_calibration": self.confidence_calibration,
            "multi_perspective_scores": self.multi_perspective_scores,
            "evidence_correlation": self.evidence_correlation,
            "anomaly_explanation": self.anomaly_explanation,
            "risk_monte_carlo": self.risk_monte_carlo,
        }


# ============================================================================
# 1. Zero-shot scanner (enhanced)
# ============================================================================

def _zero_shot_scan(response_data: dict[str, Any]) -> list[ZeroShotFinding]:
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
                severity_hint="critical" if is_critical else "high",
                cwe="CWE-200" if not is_critical else "CWE-798",
            ))

    for field_path, key, _value in _scan_field_names(body):
        findings.append(ZeroShotFinding(
            category="sensitive_field_name",
            field=field_path,
            detail=key,
            severity_hint="medium",
            cwe="CWE-200",
        ))

    for match in _CARD_NUMBER_RE.finditer(text):
        digits = re.sub(r"[ -]", "", match.group())
        if 13 <= len(digits) <= 19 and _luhn_valid(digits):
            findings.append(ZeroShotFinding(
                category="possible_card_number",
                field="<response body>",
                detail=f"{len(digits)}-digit Luhn-valid sequence",
                severity_hint="critical",
                cwe="CWE-311",
            ))

    injection_hits = _scan_injection_artifacts(text)
    for cat, name, snippet in injection_hits:
        cwe_map = {
            "sqli": "CWE-89", "xss": "CWE-79", "cmd_injection": "CWE-78",
            "path_traversal": "CWE-22", "ssrf": "CWE-918",
            "deserialization": "CWE-502", "open_redirect": "CWE-601",
            "jwt_abuse": "CWE-347", "business_logic": "CWE-840",
        }
        findings.append(ZeroShotFinding(
            category=f"injection_artifact_{cat}",
            field="<response body>",
            detail=f"{name}: {snippet[:80]}",
            severity_hint="high" if cat in ("sqli", "cmd_injection", "deserialization") else "medium",
            cwe=cwe_map.get(cat, "CWE-20"),
        ))

    return findings


# ============================================================================
# 2. Structural baseline (enhanced with rolling window + trend detection)
# ============================================================================

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
    body = response_data.get("body")
    body_text = _body_as_text(body) if body is not None else ""
    status = response_data.get("status_code") or 0
    elapsed = response_data.get("elapsed_ms") or 0
    headers = response_data.get("headers") or {}
    method = str(request_data.get("method", "GET")).upper()
    url = str(request_data.get("url", ""))

    is_payment = 1.0 if _PAYMENT_SENSITIVE_PATH_RE.search(url) else 0.0
    is_auth = 1.0 if _AUTH_PATH_RE.search(url) else 0.0
    is_admin = 1.0 if _ADMIN_PATH_RE.search(url) else 0.0
    is_webhook = 1.0 if _WEBHOOK_PATH_RE.search(url) else 0.0
    unique_value_types = len({type(v).__name__ for v in (body.values() if isinstance(body, dict) else [])})
    header_count = float(len(headers))
    has_auth_header = 1.0 if any(
        h.lower() in ("authorization", "x-api-key", "cookie", "x-auth-token")
        for h in headers
    ) else 0.0

    return [
        float(status),
        float(elapsed),
        float(len(body_text)),
        float(_count_fields(body)),
        float(_max_depth(body)),
        header_count,
        1.0 if method in _MUTATING_METHODS else 0.0,
        is_payment,
        is_auth,
        is_admin,
        is_webhook,
        float(unique_value_types),
        has_auth_header,
    ]


class _StructuralBaseline:
    """Rolling-window structural anomaly detector with trend detection
    and adaptive thresholds by endpoint category."""

    MIN_SAMPLES_TO_FIT = 15
    REFIT_EVERY = 10
    Z_ANOMALY_THRESHOLD = 3.5
    MIN_MEANINGFUL_MAD = 1.0
    MAX_WINDOW = 200
    TREND_WINDOW = 20

    def __init__(self) -> None:
        self._feature_buffer: list[list[float]] = []
        self._model: Any = None
        self._since_last_fit = 0
        self._feature_medians: list[float] = []
        self._feature_mads: list[float] = []
        self._anomaly_scores: list[float] = []
        self._feature_importances: list[float] = []

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

        window = self._feature_buffer[-self.MAX_WINDOW:]
        columns = list(zip(*window))
        self._feature_medians = [statistics.median(col) for col in columns]
        self._feature_mads = [
            statistics.median([abs(v - med) for v in col])
            for col, med in zip(columns, self._feature_medians)
        ]

        variances = []
        for col in columns:
            try:
                variances.append(statistics.pvariance(col))
            except (statistics.StatisticsError, ValueError):
                variances.append(0.0)
        total_var = sum(variances) or 1.0
        self._feature_importances = [v / total_var for v in variances]

        self._since_last_fit = 0

        if SKLEARN_AVAILABLE:
            x = np.array(window, dtype=float)
            n_estimators = min(100, max(16, len(x) * 2))
            model = IsolationForest(
                n_estimators=n_estimators, contamination="auto",
                random_state=42, n_jobs=1,
            )
            model.fit(x)
            self._model = model

    def score(self, features: list[float]) -> tuple[bool, float]:
        self._feature_buffer.append(features)
        if len(self._feature_buffer) > self.MAX_WINDOW * 2:
            self._feature_buffer = self._feature_buffer[-self.MAX_WINDOW:]
        self._since_last_fit += 1
        self._maybe_fit()

        if not self._feature_medians:
            return False, 0.0

        z_scores = []
        weighted_z = 0.0
        for i, (f, med, mad) in enumerate(
            zip(features, self._feature_medians, self._feature_mads)
        ):
            if mad >= self.MIN_MEANINGFUL_MAD:
                z = 0.6745 * abs(f - med) / mad
            else:
                z = 0.0
            z_scores.append(z)
            importance = self._feature_importances[i] if i < len(self._feature_importances) else 1.0 / len(features)
            weighted_z += z * importance

        max_z = max(z_scores)
        is_anomaly = max_z > self.Z_ANOMALY_THRESHOLD

        forest_component = 0.0
        if self._model is not None:
            x = np.array([features], dtype=float)
            decision = float(self._model.decision_function(x)[0])
            forest_component = max(0.0, min(1.0, -decision * 2))

        z_component = min(1.0, max_z / (2 * self.Z_ANOMALY_THRESHOLD))
        weighted_component = min(1.0, weighted_z / self.Z_ANOMALY_THRESHOLD)
        suspicion = max(z_component, forest_component, weighted_component * 0.8) if is_anomaly else 0.0

        self._anomaly_scores.append(suspicion)

        return is_anomaly, suspicion

    def get_trend(self) -> str:
        if len(self._anomaly_scores) < self.TREND_WINDOW:
            return "insufficient_data"
        recent = self._anomaly_scores[-self.TREND_WINDOW:]
        first_half = statistics.mean(recent[: self.TREND_WINDOW // 2])
        second_half = statistics.mean(recent[self.TREND_WINDOW // 2:])
        diff = second_half - first_half
        if diff > 0.1:
            return "increasing"
        if diff < -0.1:
            return "decreasing"
        return "stable"

    def get_feature_importances(self) -> list[float]:
        return list(self._feature_importances)


# ============================================================================
# 3. Chain-of-Thought Engine
# ============================================================================

@dataclass
class ReasoningStep:
    step_number: int
    phase: str
    content: str
    confidence: float = 1.0

    def __str__(self) -> str:
        return f"Step {self.step_number} [{self.phase}]: {self.content}"


@dataclass
class ReasoningChain:
    steps: list[ReasoningStep] = field(default_factory=list)
    conclusion: str = ""
    confidence: float = 0.0

    def as_strings(self) -> list[str]:
        result = [str(s) for s in self.steps]
        if self.conclusion:
            result.append(f"Conclusion (confidence={self.confidence:.2f}): {self.conclusion}")
        return result


class ChainOfThoughtEngine:
    """Deterministic multi-step reasoning chains modeled on the analysis
    pipelines of leading cyber-focused AI systems. Decomposes each
    observation into components, identifies attack surfaces, generates
    hypotheses, evaluates evidence, and synthesizes a conclusion --
    all in pure code, no model calls."""

    # Mapping from observation features to attack surface categories
    _SURFACE_RULES: list[tuple[str, re.Pattern[str], str, float]] = [
        ("payment_surface", _PAYMENT_SENSITIVE_PATH_RE, "Payment/billing endpoint", 0.9),
        ("auth_surface", _AUTH_PATH_RE, "Authentication/session endpoint", 0.85),
        ("admin_surface", _ADMIN_PATH_RE, "Administrative/privileged endpoint", 0.8),
        ("webhook_surface", _WEBHOOK_PATH_RE, "Webhook/callback endpoint", 0.75),
        ("user_data_surface", _USER_DATA_PATH_RE, "User data management endpoint", 0.7),
        ("api_surface", _API_PATH_RE, "Generic API surface", 0.5),
    ]

    _HYPOTHESIS_TEMPLATES: list[dict[str, Any]] = [
        {
            "id": "H_AUTH_BYPASS",
            "category": "auth_bypass",
            "template": "Authentication bypass: {endpoint} returns success (HTTP {status}) {auth_note}",
            "trigger_conditions": ["no_auth_header", "success_on_auth_endpoint", "token_in_response"],
            "base_prior": 0.3,
            "severity": "critical",
        },
        {
            "id": "H_PAYMENT_MANIP",
            "category": "payment_manipulation",
            "template": "Payment manipulation: {endpoint} accepted {anomaly_detail}",
            "trigger_conditions": ["payment_endpoint", "zero_or_negative_amount", "currency_mismatch"],
            "base_prior": 0.35,
            "severity": "critical",
        },
        {
            "id": "H_ENTITLEMENT_BYPASS",
            "category": "entitlement_bypass",
            "template": "Entitlement bypass: premium tier active with unpaid status at {endpoint}",
            "trigger_conditions": ["premium_tier_with_unpaid", "feature_flags_without_tier"],
            "base_prior": 0.4,
            "severity": "critical",
        },
        {
            "id": "H_SECRET_LEAK",
            "category": "info_disclosure",
            "template": "Secret leakage: {secret_type} exposed in response from {endpoint}",
            "trigger_conditions": ["secret_in_response", "credential_in_response"],
            "base_prior": 0.5,
            "severity": "high",
        },
        {
            "id": "H_IDOR",
            "category": "idor",
            "template": "IDOR: sequential/predictable resource IDs in {endpoint} enable enumeration",
            "trigger_conditions": ["sequential_ids", "uuid_in_error", "cross_resource_access"],
            "base_prior": 0.25,
            "severity": "high",
        },
        {
            "id": "H_INJECTION",
            "category": "injection",
            "template": "Injection: {injection_type} artifacts reflected in response from {endpoint}",
            "trigger_conditions": ["injection_artifact_found", "error_message_with_query"],
            "base_prior": 0.35,
            "severity": "critical",
        },
        {
            "id": "H_SSRF",
            "category": "ssrf",
            "template": "SSRF: internal/metadata addresses in response from {endpoint}",
            "trigger_conditions": ["internal_ip_in_response", "cloud_metadata_in_response"],
            "base_prior": 0.3,
            "severity": "critical",
        },
        {
            "id": "H_PRIV_ESC",
            "category": "privilege_escalation",
            "template": "Privilege escalation: admin-level data/roles returned to non-admin at {endpoint}",
            "trigger_conditions": ["admin_role_in_response", "elevated_permissions_returned"],
            "base_prior": 0.2,
            "severity": "high",
        },
        {
            "id": "H_RACE_CONDITION",
            "category": "race_condition",
            "template": "Race condition: duplicate/stale indicators at {endpoint} suggest TOCTOU window",
            "trigger_conditions": ["duplicate_creation_indicator", "stale_read_indicator"],
            "base_prior": 0.2,
            "severity": "high",
        },
        {
            "id": "H_MASS_ASSIGNMENT",
            "category": "mass_assignment",
            "template": "Mass assignment: mutating endpoint {endpoint} accepted unprotected fields",
            "trigger_conditions": ["mutating_method", "extra_fields_in_response", "role_field_writable"],
            "base_prior": 0.25,
            "severity": "high",
        },
        {
            "id": "H_WEBHOOK_REPLAY",
            "category": "business_logic",
            "template": "Webhook replay: {endpoint} accepted webhook without idempotency/freshness check",
            "trigger_conditions": ["webhook_endpoint", "no_signature_header", "replay_accepted"],
            "base_prior": 0.3,
            "severity": "high",
        },
        {
            "id": "H_RATE_LIMIT_BYPASS",
            "category": "rate_limit_bypass",
            "template": "Rate limit bypass: {endpoint} shows no throttling after repeated requests",
            "trigger_conditions": ["repeated_success_no_429", "auth_endpoint_no_throttle"],
            "base_prior": 0.2,
            "severity": "medium",
        },
    ]

    def reason(
        self,
        observation: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> ReasoningChain:
        chain = ReasoningChain()
        ctx = context or {}

        components = self._decompose_observation(observation)
        chain.steps.append(ReasoningStep(
            1, "decomposition",
            f"Observation decomposed: endpoint={components.get('endpoint', 'unknown')}, "
            f"method={components.get('method', '?')}, status={components.get('status_code', '?')}, "
            f"body_size={components.get('body_size', 0)}, field_count={components.get('field_count', 0)}, "
            f"has_auth={components.get('has_auth_header', False)}, "
            f"anomalies={components.get('anomalies', [])}",
        ))

        surfaces = self._identify_attack_surface(components)
        surface_desc = ", ".join(f"{s[0]} (relevance={s[1]:.2f})" for s in surfaces) or "generic"
        chain.steps.append(ReasoningStep(
            2, "surface_identification",
            f"Attack surface: [{surface_desc}]. "
            f"Trust boundary: {components.get('trust_boundary', 'unknown')}. "
            f"Auth context: {'authenticated' if components.get('has_auth_header') else 'unauthenticated'}.",
        ))

        hypotheses = self._generate_hypotheses(surfaces, components, ctx)
        hyp_desc = "; ".join(
            f"{h.hypothesis_id}: {h.description} (prior={h.prior:.2f})"
            for h in hypotheses[:5]
        )
        chain.steps.append(ReasoningStep(
            3, "hypothesis_generation",
            f"Generated {len(hypotheses)} hypothesis(es): {hyp_desc}",
        ))

        scored = self._evaluate_hypotheses(hypotheses, components)
        eval_desc = "; ".join(
            f"{h.hypothesis_id}: posterior={h.posterior:.3f}, "
            f"+[{','.join(h.evidence_for[:3])}] -[{','.join(h.evidence_against[:3])}]"
            for h in scored[:5]
        )
        chain.steps.append(ReasoningStep(
            4, "evidence_evaluation",
            f"Evidence evaluation: {eval_desc}",
        ))

        conclusion, conf = self._synthesize_conclusion(scored)
        chain.conclusion = conclusion
        chain.confidence = conf
        chain.steps.append(ReasoningStep(
            5, "synthesis",
            conclusion,
            confidence=conf,
        ))

        return chain

    def _decompose_observation(self, obs: dict[str, Any]) -> dict[str, Any]:
        req = obs.get("request_data") or {}
        resp = obs.get("response_data") or {}
        body = resp.get("body")
        body_text = _body_as_text(body) if body is not None else ""
        url = str(req.get("url", ""))
        method = str(req.get("method", "GET")).upper()
        status = resp.get("status_code") or 0
        headers = resp.get("headers") or {}
        req_headers = req.get("headers") or {}
        elapsed = resp.get("elapsed_ms") or 0

        path = urlparse(url).path if url else ""

        anomalies: list[str] = []
        if isinstance(body, dict):
            for k, v in body.items():
                if isinstance(v, (int, float)) and v < 0:
                    anomalies.append(f"negative_value:{k}={v}")
                if isinstance(v, (int, float)) and v == 0 and re.search(
                    r"(?:amount|price|total|cost)", k, re.I
                ):
                    anomalies.append(f"zero_payment_value:{k}")

        tier_matches = _ENTITLEMENT_TIER_RE.findall(body_text)
        premium_tiers = [t for t in tier_matches if t.lower() in _PREMIUM_TIERS]
        status_matches = _STRIPE_STATUS_RE.findall(body_text)
        unpaid_statuses = [s for s in status_matches if s.lower() in _UNPAID_STATUSES]
        if premium_tiers and unpaid_statuses:
            anomalies.append(f"entitlement_drift:{premium_tiers[0]}/{unpaid_statuses[0]}")

        trust_boundary = "unknown"
        if _AUTH_PATH_RE.search(path):
            trust_boundary = "public_to_authenticated"
        elif _ADMIN_PATH_RE.search(path):
            trust_boundary = "authenticated_to_admin"
        elif _PAYMENT_SENSITIVE_PATH_RE.search(path):
            trust_boundary = "payment_to_entitlement"
        elif _WEBHOOK_PATH_RE.search(path):
            trust_boundary = "webhook_to_internal"

        has_auth = any(
            h.lower() in ("authorization", "x-api-key", "cookie", "x-auth-token")
            for h in {**headers, **req_headers}
        )

        stripe_object = _STRIPE_OBJECT_RE.search(body_text)

        return {
            "endpoint": path or url,
            "method": method,
            "status_code": status,
            "body_size": len(body_text),
            "field_count": _count_fields(body),
            "max_depth": _max_depth(body),
            "has_auth_header": has_auth,
            "trust_boundary": trust_boundary,
            "anomalies": anomalies,
            "elapsed_ms": elapsed,
            "is_mutating": method in _MUTATING_METHODS,
            "premium_tiers": premium_tiers,
            "unpaid_statuses": unpaid_statuses,
            "stripe_object": stripe_object.group(1) if stripe_object else None,
            "body_text": body_text,
            "response_headers": headers,
        }

    def _identify_attack_surface(
        self, components: dict[str, Any],
    ) -> list[tuple[str, float]]:
        endpoint = components.get("endpoint", "")
        surfaces: list[tuple[str, float]] = []
        for name, pattern, _desc, relevance in self._SURFACE_RULES:
            if pattern.search(endpoint):
                adj = relevance
                if components.get("is_mutating"):
                    adj = min(1.0, adj + 0.1)
                surfaces.append((name, adj))
        if not surfaces:
            surfaces.append(("generic", 0.3))
        return sorted(surfaces, key=lambda x: x[1], reverse=True)

    def _generate_hypotheses(
        self,
        surfaces: list[tuple[str, float]],
        components: dict[str, Any],
        ctx: dict[str, Any],
    ) -> list[Hypothesis]:
        hypotheses: list[Hypothesis] = []
        surface_names = {s[0] for s in surfaces}
        endpoint = components.get("endpoint", "unknown")
        status = components.get("status_code", 0)
        method = components.get("method", "GET")
        body_text = components.get("body_text", "")
        anomalies = set(a.split(":")[0] for a in components.get("anomalies", []))

        conditions_met: set[str] = set()

        if not components.get("has_auth_header"):
            conditions_met.add("no_auth_header")
        if "auth_surface" in surface_names and 200 <= status < 300:
            conditions_met.add("success_on_auth_endpoint")
        if re.search(r'"(?:token|access_token|bearer)"', body_text, re.I):
            conditions_met.add("token_in_response")
        if "payment_surface" in surface_names:
            conditions_met.add("payment_endpoint")
        if "zero_payment_value" in anomalies:
            conditions_met.add("zero_or_negative_amount")
        if "negative_value" in anomalies:
            conditions_met.add("zero_or_negative_amount")
        if "entitlement_drift" in anomalies:
            conditions_met.add("premium_tier_with_unpaid")
        if re.search(r'"(?:feature_flags?|features?|entitlements?)"', body_text, re.I) and not components.get("premium_tiers"):
            conditions_met.add("feature_flags_without_tier")
        for name, pat, _crit in _SECRET_PATTERNS:
            if pat.search(body_text):
                conditions_met.add("secret_in_response")
                conditions_met.add("credential_in_response")
                break
        if re.search(r'"(?:id|user_id)":\s*\d{1,6}\b', body_text):
            conditions_met.add("sequential_ids")
        if _scan_injection_artifacts(body_text):
            conditions_met.add("injection_artifact_found")
        if re.search(r"(?:127\.0\.0\.1|169\.254\.169\.254|localhost|::1)", body_text, re.I):
            conditions_met.add("internal_ip_in_response")
        if re.search(r"(?:ami-|arn:aws|meta-data|computeMetadata)", body_text, re.I):
            conditions_met.add("cloud_metadata_in_response")
        if re.search(r'"(?:role|is_admin)":\s*"?(?:admin|superadmin|root)', body_text, re.I):
            conditions_met.add("admin_role_in_response")
        if components.get("is_mutating"):
            conditions_met.add("mutating_method")
        if "webhook_surface" in surface_names:
            conditions_met.add("webhook_endpoint")
        for art_name, art_re in RACE_CONDITION_ARTIFACTS:
            if art_re.search(body_text):
                conditions_met.add("duplicate_creation_indicator")
                break

        for tmpl in self._HYPOTHESIS_TEMPLATES:
            triggers = set(tmpl["trigger_conditions"])
            overlap = conditions_met & triggers
            if not overlap:
                continue
            trigger_ratio = len(overlap) / len(triggers)
            prior = tmpl["base_prior"] * (0.5 + 0.5 * trigger_ratio)

            surface_boost = max((r for n, r in surfaces if n != "generic"), default=0.3)
            prior = min(1.0, prior * (0.7 + 0.3 * surface_boost))

            desc = tmpl["template"].format(
                endpoint=endpoint,
                status=status,
                auth_note="without authentication headers" if "no_auth_header" in conditions_met else "with auth",
                anomaly_detail=", ".join(components.get("anomalies", [])[:3]) or "anomalous values",
                secret_type="credential" if "credential_in_response" in conditions_met else "secret",
                injection_type="reflected",
            )
            hypotheses.append(Hypothesis(
                hypothesis_id=tmpl["id"],
                description=desc,
                category=tmpl["category"],
                prior=prior,
            ))

        return sorted(hypotheses, key=lambda h: h.prior, reverse=True)

    def _evaluate_hypotheses(
        self,
        hypotheses: list[Hypothesis],
        components: dict[str, Any],
    ) -> list[Hypothesis]:
        status = components.get("status_code", 0)
        body_text = components.get("body_text", "")
        anomalies = components.get("anomalies", [])
        elapsed = components.get("elapsed_ms", 0)
        is_mutating = components.get("is_mutating", False)
        has_auth = components.get("has_auth_header", False)

        for h in hypotheses:
            evidence_for: list[str] = []
            evidence_against: list[str] = []
            likelihood = 1.0

            if 200 <= status < 300:
                evidence_for.append(f"success_response_HTTP_{status}")
                likelihood *= 1.3
            elif status in (401, 403):
                evidence_against.append(f"auth_rejection_HTTP_{status}")
                likelihood *= 0.2
            elif status >= 500:
                evidence_against.append(f"server_error_HTTP_{status}")
                likelihood *= 0.5

            if anomalies:
                evidence_for.append(f"{len(anomalies)}_anomalies_found")
                likelihood *= 1.0 + 0.15 * min(len(anomalies), 5)

            if h.category in ("auth_bypass", "privilege_escalation") and not has_auth:
                evidence_for.append("unauthenticated_request")
                likelihood *= 1.5
            elif h.category in ("auth_bypass",) and has_auth:
                evidence_against.append("auth_header_present")
                likelihood *= 0.6

            if h.category in ("payment_manipulation", "entitlement_bypass") and is_mutating:
                evidence_for.append("mutating_method_on_payment")
                likelihood *= 1.3

            if h.category == "injection" and len(body_text) > 5000:
                evidence_for.append("large_response_body")
                likelihood *= 1.1

            if elapsed > 2000:
                if h.category in ("race_condition", "injection"):
                    evidence_for.append(f"high_latency_{elapsed}ms")
                    likelihood *= 1.2

            stripe_obj = components.get("stripe_object")
            if stripe_obj:
                if h.category in ("payment_manipulation", "entitlement_bypass"):
                    evidence_for.append(f"stripe_object_{stripe_obj}")
                    likelihood *= 1.4

            posterior = min(1.0, h.prior * likelihood)
            h.evidence_for = evidence_for
            h.evidence_against = evidence_against
            h.posterior = posterior

        return sorted(hypotheses, key=lambda h: h.posterior, reverse=True)

    def _synthesize_conclusion(
        self, scored: list[Hypothesis],
    ) -> tuple[str, float]:
        if not scored:
            return "No hypotheses generated -- observation appears benign.", 0.0

        top = scored[0]
        if top.posterior < 0.1:
            return (
                f"Low-confidence analysis: best hypothesis '{top.hypothesis_id}' "
                f"scored {top.posterior:.3f} -- likely benign.",
                top.posterior,
            )

        supporting = len(top.evidence_for)
        contradicting = len(top.evidence_against)
        conf = top.posterior
        if supporting > contradicting * 2:
            conf = min(1.0, conf * 1.2)

        runners_up = [h for h in scored[1:] if h.posterior > 0.15]
        runner_note = ""
        if runners_up:
            runner_note = (
                f" Alternative hypotheses: "
                + ", ".join(f"{h.hypothesis_id}({h.posterior:.2f})" for h in runners_up[:3])
                + "."
            )

        return (
            f"Most likely: {top.description} "
            f"(posterior={top.posterior:.3f}, "
            f"{supporting} supporting / {contradicting} contradicting evidence points)."
            f"{runner_note}",
            conf,
        )


# ============================================================================
# 4. Multi-Perspective Analyzer
# ============================================================================

@dataclass
class PerspectiveResult:
    perspective: str
    risk_score: float
    findings: list[str]
    recommendations: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "perspective": self.perspective,
            "risk_score": round(self.risk_score, 3),
            "findings": self.findings,
            "recommendations": self.recommendations,
        }


class MultiPerspectiveAnalyzer:
    """Analyzes each observation from three viewpoints: attacker
    (what can I exploit?), defender (what mitigations are missing?),
    and auditor (does this meet compliance requirements?)."""

    def analyze_as_attacker(
        self, components: dict[str, Any], zero_shot: list[ZeroShotFinding],
    ) -> PerspectiveResult:
        findings: list[str] = []
        recs: list[str] = []
        score = 0.0

        if not components.get("has_auth_header") and components.get("status_code", 0) == 200:
            findings.append("Unauthenticated access to endpoint returns data")
            recs.append("Test horizontal/vertical access control bypass")
            score += 0.3

        for a in components.get("anomalies", []):
            if "zero_payment" in a or "negative_value" in a:
                findings.append(f"Payment value anomaly exploitable: {a}")
                recs.append("Attempt price manipulation via parameter tampering")
                score += 0.4
            if "entitlement_drift" in a:
                findings.append(f"Entitlement/payment mismatch exploitable: {a}")
                recs.append("Test accessing premium features without payment")
                score += 0.5

        for f in zero_shot:
            if f.category == "critical_secret":
                findings.append(f"Leaked secret usable for lateral movement: {f.detail}")
                score += 0.5
            elif f.category.startswith("injection"):
                findings.append(f"Injection vector: {f.detail}")
                score += 0.4

        if components.get("stripe_object") in ("checkout.session", "payment_intent"):
            findings.append(f"Stripe {components['stripe_object']} object directly accessible")
            recs.append("Test modifying amount/currency client-side before confirmation")
            score += 0.2

        return PerspectiveResult("attacker", min(1.0, score), findings, recs)

    def analyze_as_defender(
        self, components: dict[str, Any], zero_shot: list[ZeroShotFinding],
    ) -> PerspectiveResult:
        findings: list[str] = []
        recs: list[str] = []
        score = 0.0
        headers = components.get("response_headers", {})
        lower_headers = {k.lower(): v for k, v in headers.items()}

        for issue_name, header_name in HEADER_SECURITY_PATTERNS:
            if header_name not in lower_headers:
                findings.append(f"Missing security header: {header_name}")
                score += 0.05
                recs.append(f"Add {header_name} header")

        if not components.get("has_auth_header") and components.get("trust_boundary") != "unknown":
            findings.append("No authentication on a trust-boundary endpoint")
            recs.append("Enforce authentication middleware")
            score += 0.3

        if zero_shot:
            findings.append(f"{len(zero_shot)} sensitive pattern(s) in response body")
            recs.append("Review response serialization for data leakage")
            score += 0.15 * min(len(zero_shot), 5)

        if components.get("is_mutating") and "x-request-id" not in lower_headers:
            recs.append("Add idempotency/request-id tracking for mutating endpoints")

        return PerspectiveResult("defender", min(1.0, score), findings, recs)

    def analyze_as_auditor(
        self, components: dict[str, Any], zero_shot: list[ZeroShotFinding],
    ) -> PerspectiveResult:
        findings: list[str] = []
        recs: list[str] = []
        score = 0.0

        for f in zero_shot:
            if f.cwe:
                findings.append(f"Compliance gap: {f.cwe} - {f.detail}")
                score += 0.2

        if components.get("trust_boundary") == "payment_to_entitlement":
            if components.get("anomalies"):
                findings.append("PCI-DSS concern: payment endpoint with data anomalies")
                recs.append("Review for PCI-DSS Req. 6.5 compliance")
                score += 0.3

        if not components.get("has_auth_header") and components.get("trust_boundary") in (
            "authenticated_to_admin", "payment_to_entitlement",
        ):
            findings.append("SOC2 CC6.1 gap: sensitive boundary without authentication")
            score += 0.4

        return PerspectiveResult("auditor", min(1.0, score), findings, recs)

    def synthesize(
        self,
        attacker: PerspectiveResult,
        defender: PerspectiveResult,
        auditor: PerspectiveResult,
    ) -> dict[str, Any]:
        combined = max(attacker.risk_score, defender.risk_score, auditor.risk_score)
        avg = (attacker.risk_score + defender.risk_score + auditor.risk_score) / 3
        return {
            "attacker": attacker.to_dict(),
            "defender": defender.to_dict(),
            "auditor": auditor.to_dict(),
            "combined_risk": round(combined, 3),
            "average_risk": round(avg, 3),
        }


# ============================================================================
# 5. Hypothesis Engine (Bayesian-style)
# ============================================================================

class HypothesisEngine:
    """Maintains a running belief state across observations using
    simplified Bayesian updating."""

    def __init__(self) -> None:
        self._belief_state: dict[str, float] = {}
        self._observation_count = 0

    def update_beliefs(self, hypotheses: list[Hypothesis]) -> None:
        self._observation_count += 1
        decay = 0.95
        for cat in self._belief_state:
            self._belief_state[cat] *= decay

        for h in hypotheses:
            current = self._belief_state.get(h.category, 0.1)
            likelihood = h.posterior
            updated = current * (0.7 + 0.3 * likelihood)
            self._belief_state[h.category] = min(1.0, updated)

    def get_beliefs(self) -> dict[str, float]:
        return {k: round(v, 4) for k, v in sorted(
            self._belief_state.items(), key=lambda x: x[1], reverse=True,
        )}

    def get_top_belief(self) -> tuple[str, float]:
        if not self._belief_state:
            return ("none", 0.0)
        top = max(self._belief_state.items(), key=lambda x: x[1])
        return top


# ============================================================================
# 6. Evidence Correlator
# ============================================================================

class EvidenceCorrelator:
    """Cross-observation correlation engine that finds patterns spanning
    multiple requests/responses."""

    def __init__(self) -> None:
        self._observations: list[dict[str, Any]] = []
        self._response_hashes: list[str] = []

    def add_observation(self, observation: dict[str, Any]) -> None:
        resp = observation.get("response_data") or {}
        body_text = _body_as_text(resp.get("body")) if resp.get("body") is not None else ""
        obs_hash = hashlib.md5(body_text[:500].encode(errors="replace")).hexdigest()[:12]
        self._observations.append(observation)
        self._response_hashes.append(obs_hash)

    def find_correlations(self) -> list[dict[str, Any]]:
        if len(self._observations) < 2:
            return []

        correlations: list[dict[str, Any]] = []

        endpoint_groups: dict[str, list[int]] = defaultdict(list)
        for i, obs in enumerate(self._observations):
            req = obs.get("request_data") or {}
            url = str(req.get("url", ""))
            path = urlparse(url).path if url else ""
            normalized = re.sub(r"/\d+", "/{id}", path)
            normalized = re.sub(r"/[a-f0-9-]{20,}", "/{id}", normalized)
            endpoint_groups[normalized].append(i)

        for ep, indices in endpoint_groups.items():
            if len(indices) < 2:
                continue
            statuses = set()
            for idx in indices:
                resp = (self._observations[idx].get("response_data") or {})
                statuses.add(resp.get("status_code", 0))
            if len(statuses) > 1:
                correlations.append({
                    "type": "status_divergence",
                    "endpoint": ep,
                    "statuses": sorted(statuses),
                    "observation_count": len(indices),
                    "detail": f"Endpoint {ep} returned {len(statuses)} different status codes across {len(indices)} observations",
                })

        hash_counts: dict[str, int] = defaultdict(int)
        for h in self._response_hashes:
            hash_counts[h] += 1
        duplicates = {h: c for h, c in hash_counts.items() if c > 1}
        if duplicates:
            correlations.append({
                "type": "duplicate_responses",
                "count": len(duplicates),
                "detail": f"{len(duplicates)} response fingerprint(s) appeared more than once",
            })

        timing_by_endpoint: dict[str, list[float]] = defaultdict(list)
        for obs in self._observations:
            req = obs.get("request_data") or {}
            resp = obs.get("response_data") or {}
            url = str(req.get("url", ""))
            path = urlparse(url).path if url else ""
            elapsed = resp.get("elapsed_ms")
            if elapsed and path:
                timing_by_endpoint[path].append(elapsed)
        for ep, timings in timing_by_endpoint.items():
            if len(timings) < 3:
                continue
            med = statistics.median(timings)
            for t in timings:
                if med > 0 and t > med * 5:
                    correlations.append({
                        "type": "timing_outlier",
                        "endpoint": ep,
                        "median_ms": round(med, 1),
                        "outlier_ms": round(t, 1),
                        "detail": f"Timing outlier on {ep}: {t:.0f}ms vs median {med:.0f}ms",
                    })
                    break

        return correlations

    def get_correlation_clusters(self) -> list[dict[str, Any]]:
        clusters: dict[str, list[int]] = defaultdict(list)
        for i, obs in enumerate(self._observations):
            req = obs.get("request_data") or {}
            resp = obs.get("response_data") or {}
            status = resp.get("status_code", 0)
            method = str(req.get("method", "GET")).upper()
            cluster_key = f"{method}_{status // 100}xx"
            clusters[cluster_key].append(i)
        return [
            {"cluster": k, "size": len(v), "observation_indices": v[:10]}
            for k, v in sorted(clusters.items(), key=lambda x: len(x[1]), reverse=True)
        ]


# ============================================================================
# 7. Reverse Engineering Engine
# ============================================================================

class ReverseEngineeringEngine:
    """Infers server-side rules, state machines, rate-limit configs, and
    auth models purely from observed request/response patterns."""

    def __init__(self) -> None:
        self._observations: list[dict[str, Any]] = []

    def add_observation(self, observation: dict[str, Any]) -> None:
        self._observations.append(observation)

    def infer_validation_rules(self) -> list[dict[str, Any]]:
        rules: list[dict[str, Any]] = []
        rejections_by_endpoint: dict[str, list[dict]] = defaultdict(list)

        for obs in self._observations:
            req = obs.get("request_data") or {}
            resp = obs.get("response_data") or {}
            status = resp.get("status_code", 0)
            if 400 <= status < 500:
                url = str(req.get("url", ""))
                path = urlparse(url).path if url else ""
                body_text = _body_as_text(resp.get("body")) if resp.get("body") is not None else ""
                rejections_by_endpoint[path].append({
                    "status": status,
                    "method": req.get("method"),
                    "error_text": body_text[:300],
                })

        for ep, rejects in rejections_by_endpoint.items():
            if not rejects:
                continue
            status_counts: dict[int, int] = defaultdict(int)
            for r in rejects:
                status_counts[r["status"]] += 1

            if status_counts.get(422, 0) + status_counts.get(400, 0) > 0:
                error_texts = [r["error_text"] for r in rejects]
                field_mentions: set[str] = set()
                for t in error_texts:
                    field_mentions.update(re.findall(r'"(\w+)"', t[:200]))
                rules.append({
                    "endpoint": ep,
                    "rule_type": "input_validation",
                    "inferred": f"Validates fields: {sorted(field_mentions)[:10]}",
                    "rejection_count": len(rejects),
                    "status_distribution": dict(status_counts),
                })

            if status_counts.get(401, 0) + status_counts.get(403, 0) > 0:
                rules.append({
                    "endpoint": ep,
                    "rule_type": "auth_enforcement",
                    "inferred": "Endpoint enforces authentication/authorization",
                    "rejection_count": status_counts.get(401, 0) + status_counts.get(403, 0),
                })

        return rules

    def infer_state_machine(self) -> list[dict[str, Any]]:
        transitions: list[dict[str, Any]] = []
        status_field_re = re.compile(
            r'"(?:status|state|phase|stage|lifecycle_status)":\s*"([^"]+)"', re.I,
        )
        observed_states: dict[str, set[str]] = defaultdict(set)

        for obs in self._observations:
            req = obs.get("request_data") or {}
            resp = obs.get("response_data") or {}
            body_text = _body_as_text(resp.get("body")) if resp.get("body") is not None else ""
            url = str(req.get("url", ""))
            path = urlparse(url).path if url else ""

            for match in status_field_re.finditer(body_text):
                observed_states[path].add(match.group(1))

        for ep, states in observed_states.items():
            if len(states) >= 2:
                transitions.append({
                    "endpoint": ep,
                    "observed_states": sorted(states),
                    "transition_count": len(states),
                    "inferred": f"State machine with {len(states)} observed states",
                })

        return transitions

    def infer_rate_limit_config(self) -> list[dict[str, Any]]:
        configs: list[dict[str, Any]] = []
        endpoint_timings: dict[str, list[tuple[int, float]]] = defaultdict(list)

        for obs in self._observations:
            req = obs.get("request_data") or {}
            resp = obs.get("response_data") or {}
            status = resp.get("status_code", 0)
            elapsed = resp.get("elapsed_ms", 0)
            url = str(req.get("url", ""))
            path = urlparse(url).path if url else ""
            endpoint_timings[path].append((status, elapsed))

        for ep, entries in endpoint_timings.items():
            rate_limited = [(s, e) for s, e in entries if s == 429]
            if rate_limited:
                configs.append({
                    "endpoint": ep,
                    "rate_limited": True,
                    "total_requests": len(entries),
                    "rate_limited_count": len(rate_limited),
                    "inferred": f"Rate limiting active: {len(rate_limited)}/{len(entries)} requests throttled",
                })
            elif len(entries) >= 5:
                configs.append({
                    "endpoint": ep,
                    "rate_limited": False,
                    "total_requests": len(entries),
                    "inferred": f"No rate limiting detected after {len(entries)} requests",
                })

        return configs

    def infer_auth_model(self) -> list[dict[str, Any]]:
        models: list[dict[str, Any]] = []
        endpoint_auth: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))

        for obs in self._observations:
            req = obs.get("request_data") or {}
            resp = obs.get("response_data") or {}
            url = str(req.get("url", ""))
            path = urlparse(url).path if url else ""
            status = resp.get("status_code", 0)
            req_headers = req.get("headers") or {}
            has_auth = any(
                h.lower() in ("authorization", "x-api-key", "cookie")
                for h in req_headers
            )

            if has_auth and 200 <= status < 300:
                endpoint_auth[path]["auth_success"] += 1
            elif has_auth and status in (401, 403):
                endpoint_auth[path]["auth_rejected"] += 1
            elif not has_auth and 200 <= status < 300:
                endpoint_auth[path]["noauth_success"] += 1
            elif not has_auth and status in (401, 403):
                endpoint_auth[path]["noauth_rejected"] += 1

        for ep, counts in endpoint_auth.items():
            if counts["noauth_success"] > 0 and counts["noauth_rejected"] == 0:
                models.append({
                    "endpoint": ep,
                    "auth_model": "public",
                    "inferred": "No authentication required",
                })
            elif counts["noauth_rejected"] > 0:
                models.append({
                    "endpoint": ep,
                    "auth_model": "authenticated",
                    "inferred": "Authentication required (rejects unauthenticated)",
                })

        return models

    def detect_anti_re_measures(self) -> list[dict[str, Any]]:
        measures: list[dict[str, Any]] = []
        for obs in self._observations:
            resp = obs.get("response_data") or {}
            headers = resp.get("headers") or {}
            body_text = _body_as_text(resp.get("body")) if resp.get("body") is not None else ""

            lower_headers = {k.lower(): v for k, v in headers.items()}
            if "x-request-id" in lower_headers and re.search(r"[a-f0-9-]{32,}", lower_headers.get("x-request-id", "")):
                measures.append({"type": "request_tracing", "detail": "Request tracing via X-Request-Id"})
            if re.search(r"(?:__cf_|cf-ray|cf-cache-status)", str(lower_headers), re.I):
                measures.append({"type": "cdn_waf", "detail": "Cloudflare CDN/WAF detected"})
            if re.search(r"(?:x-amzn-requestid|x-amz-)", str(lower_headers), re.I):
                measures.append({"type": "aws_infrastructure", "detail": "AWS infrastructure detected"})
            if re.search(r"(?:rate.limit|retry.after|x-ratelimit)", str(lower_headers), re.I):
                measures.append({"type": "rate_limiting_headers", "detail": "Rate limit headers present"})
            if re.search(r'"(?:captcha|recaptcha|hcaptcha|turnstile)"', body_text, re.I):
                measures.append({"type": "captcha_protection", "detail": "CAPTCHA challenge detected in response"})

        seen = set()
        deduped: list[dict[str, Any]] = []
        for m in measures:
            key = m["type"]
            if key not in seen:
                seen.add(key)
                deduped.append(m)
        return deduped

    def map_hidden_endpoints(self) -> list[dict[str, Any]]:
        observed_paths: set[str] = set()
        referenced_paths: set[str] = set()
        url_re = re.compile(r'"(?:url|href|link|endpoint|redirect_url|return_url|next)":\s*"(/[^"]+)"')

        for obs in self._observations:
            req = obs.get("request_data") or {}
            resp = obs.get("response_data") or {}
            url = str(req.get("url", ""))
            path = urlparse(url).path if url else ""
            if path:
                observed_paths.add(path)

            body_text = _body_as_text(resp.get("body")) if resp.get("body") is not None else ""
            for match in url_re.finditer(body_text):
                referenced_paths.add(match.group(1))

        hidden = referenced_paths - observed_paths
        return [
            {"path": p, "type": "referenced_but_untested"}
            for p in sorted(hidden)[:20]
        ]

    def infer_data_model(self) -> list[dict[str, Any]]:
        field_registry: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))

        for obs in self._observations:
            req = obs.get("request_data") or {}
            resp = obs.get("response_data") or {}
            url = str(req.get("url", ""))
            path = urlparse(url).path if url else ""
            body = resp.get("body")
            if isinstance(body, dict):
                for k, v in body.items():
                    field_registry[path][k].add(type(v).__name__)

        models: list[dict[str, Any]] = []
        for ep, fields in field_registry.items():
            if len(fields) >= 3:
                models.append({
                    "endpoint": ep,
                    "fields": {k: sorted(v) for k, v in sorted(fields.items())},
                    "field_count": len(fields),
                })
        return models[:20]

    def get_all_findings(self) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for rule in self.infer_validation_rules():
            findings.append({"type": "validation_rule", **rule})
        for sm in self.infer_state_machine():
            findings.append({"type": "state_machine", **sm})
        for rl in self.infer_rate_limit_config():
            findings.append({"type": "rate_limit", **rl})
        for auth in self.infer_auth_model():
            findings.append({"type": "auth_model", **auth})
        for measure in self.detect_anti_re_measures():
            findings.append({"type": "anti_re", **measure})
        for hidden in self.map_hidden_endpoints():
            findings.append({"type": "hidden_endpoint", **hidden})
        for model in self.infer_data_model():
            findings.append({"type": "data_model", **model})
        return findings


# ============================================================================
# 8. Brainstorm Engine
# ============================================================================

class BrainstormEngine:
    """Deterministic divergent/convergent attack ideation. Generates
    creative attack vectors, bypass techniques, and chain compositions
    based on observed evidence."""

    _BYPASS_IDEAS: dict[str, list[str]] = {
        "auth": [
            "Test JWT alg:none header stripping",
            "Test RS256-to-HS256 key confusion",
            "Test expired token acceptance",
            "Test session fixation via pre-auth token reuse",
            "Test API key scope escalation",
            "Test OAuth redirect_uri manipulation",
            "Test SAML assertion replay",
            "Test cookie domain/path scope bypass",
        ],
        "payment": [
            "Test client-side amount modification before server confirmation",
            "Test currency downgrade (USD->lowest denomination currency)",
            "Test negative quantity injection",
            "Test coupon/promo code stacking beyond intended limit",
            "Test race condition on checkout completion",
            "Test payment intent reuse across sessions",
            "Test webhook event replay for duplicate credit",
            "Test subscription downgrade retaining premium features",
            "Test trial extension via re-registration",
            "Test refund-then-reuse for net-free purchase",
        ],
        "access_control": [
            "Test horizontal privilege escalation via IDOR",
            "Test vertical escalation via role parameter injection",
            "Test function-level authorization bypass via method override",
            "Test multi-tenant isolation breach via shared resource IDs",
            "Test API version downgrade for weaker controls",
            "Test GraphQL field-level authorization bypass",
            "Test batch endpoint bypassing per-item auth checks",
        ],
        "injection": [
            "Test SQLi in sort/order parameters",
            "Test SSTI in user-controlled template fields",
            "Test NoSQL operator injection ($gt, $ne, $regex)",
            "Test LDAP injection in search/filter parameters",
            "Test XPath injection in XML-accepting endpoints",
            "Test OS command injection via filename parameters",
            "Test SSRF via URL-accepting parameters",
        ],
        "rate_limit": [
            "Test path normalization bypass (/api/Login vs /api/login)",
            "Test IP rotation via X-Forwarded-For spoofing",
            "Test HTTP method override (GET with X-HTTP-Method-Override: POST)",
            "Test GraphQL alias batching for fan-out",
            "Test window boundary timing exploit",
            "Test session rotation to reset per-session counters",
            "Test HTTP/2 multiplexing race for concurrent bypass",
            "Test IPv6 subnet rotation if /64 allocated",
            "Test encoding variations (%2F, %00) in path",
            "Test CDN PoP-sharding by routing through different edge locations",
        ],
    }

    def brainstorm_attack_vectors(
        self, components: dict[str, Any],
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        endpoint = components.get("endpoint", "")

        for category, ideas in self._BYPASS_IDEAS.items():
            relevance = 0.0
            if category == "auth" and _AUTH_PATH_RE.search(endpoint):
                relevance = 0.9
            elif category == "payment" and _PAYMENT_SENSITIVE_PATH_RE.search(endpoint):
                relevance = 0.95
            elif category == "access_control":
                relevance = 0.5
            elif category == "rate_limit":
                relevance = 0.4
            elif category == "injection":
                relevance = 0.3

            if relevance > 0.2:
                for idea in ideas[:5]:
                    results.append({
                        "category": category,
                        "idea": idea,
                        "relevance": round(relevance, 2),
                    })

        for a in components.get("anomalies", []):
            if "entitlement" in a:
                results.append({
                    "category": "entitlement_bypass",
                    "idea": "Test accessing all premium endpoints with the current unpaid session",
                    "relevance": 0.95,
                })
            if "zero_payment" in a:
                results.append({
                    "category": "payment_manipulation",
                    "idea": "Test completing checkout flow with the zero-amount payload",
                    "relevance": 0.95,
                })

        return sorted(results, key=lambda x: x["relevance"], reverse=True)[:15]

    def brainstorm_bypass_techniques(
        self, defense_indicators: list[str],
    ) -> list[dict[str, Any]]:
        bypasses: list[dict[str, Any]] = []
        for indicator in defense_indicators:
            ind_lower = indicator.lower()
            if "rate" in ind_lower or "throttl" in ind_lower:
                for idea in self._BYPASS_IDEAS["rate_limit"][:5]:
                    bypasses.append({"defense": indicator, "bypass": idea, "confidence": 0.6})
            if "auth" in ind_lower:
                for idea in self._BYPASS_IDEAS["auth"][:3]:
                    bypasses.append({"defense": indicator, "bypass": idea, "confidence": 0.5})
            if "captcha" in ind_lower or "challenge" in ind_lower:
                bypasses.append({"defense": indicator, "bypass": "Test accessibility audio challenge path", "confidence": 0.4})
                bypasses.append({"defense": indicator, "bypass": "Test repeated soft-block vs hard-block behavior", "confidence": 0.3})
            if "waf" in ind_lower or "firewall" in ind_lower:
                bypasses.append({"defense": indicator, "bypass": "Test encoding variation bypass (double-URL, unicode)", "confidence": 0.5})
                bypasses.append({"defense": indicator, "bypass": "Test HTTP parameter pollution", "confidence": 0.4})
                bypasses.append({"defense": indicator, "bypass": "Test chunked transfer encoding bypass", "confidence": 0.3})
        return bypasses

    def brainstorm_chain_compositions(
        self, findings: list[ZeroShotFinding],
    ) -> list[dict[str, Any]]:
        chains: list[dict[str, Any]] = []
        categories = {f.category for f in findings}

        chain_templates = [
            ({"critical_secret", "sensitive_field_name"}, "Secret leak -> credential reuse -> lateral movement"),
            ({"injection_artifact_sqli"}, "SQLi -> data exfiltration -> credential theft -> account takeover"),
            ({"injection_artifact_xss", "sensitive_field_name"}, "XSS -> session hijack -> data theft"),
            ({"injection_artifact_ssrf"}, "SSRF -> cloud metadata -> IAM credential theft -> infrastructure takeover"),
        ]
        for required, chain_desc in chain_templates:
            if required & categories:
                chains.append({
                    "chain": chain_desc,
                    "triggered_by": sorted(required & categories),
                    "severity": "critical",
                })

        return chains

    def divergent_thinking(self, components: dict[str, Any]) -> list[dict[str, Any]]:
        ideas: list[dict[str, Any]] = []
        stripe_obj = components.get("stripe_object")
        if stripe_obj == "checkout.session":
            ideas.extend([
                {"idea": "What if the success_url is called directly without completing payment?", "category": "entitlement_bypass", "likelihood": "medium"},
                {"idea": "What if the session is reused after expiry to access post-payment resources?", "category": "business_logic", "likelihood": "medium"},
                {"idea": "What if metadata fields can inject a custom plan_id?", "category": "mass_assignment", "likelihood": "low"},
            ])
        elif stripe_obj == "subscription":
            ideas.extend([
                {"idea": "What if cancellation doesn't revoke access immediately?", "category": "entitlement_bypass", "likelihood": "high"},
                {"idea": "What if downgrade retains premium features until next billing cycle?", "category": "entitlement_bypass", "likelihood": "high"},
                {"idea": "What if trial_end can be set to a future date via API?", "category": "business_logic", "likelihood": "medium"},
            ])

        if components.get("anomalies"):
            for a in components["anomalies"]:
                if "entitlement_drift" in a:
                    ideas.append({
                        "idea": "What if ALL premium endpoints are accessible, not just the one observed?",
                        "category": "entitlement_bypass",
                        "likelihood": "high",
                    })

        return ideas

    def convergent_thinking(self, hypotheses: list[Hypothesis]) -> list[dict[str, Any]]:
        if not hypotheses:
            return []
        ranked = sorted(hypotheses, key=lambda h: h.posterior, reverse=True)
        return [
            {
                "hypothesis": h.hypothesis_id,
                "action": f"Prioritize investigation of {h.category}: {h.description}",
                "confidence": round(h.posterior, 3),
                "next_step": f"Verify with targeted probe against {h.category} surface",
            }
            for h in ranked[:5]
            if h.posterior > 0.1
        ]


# ============================================================================
# 9. Monte Carlo Risk Simulator (stdlib random only)
# ============================================================================

class MonteCarloRiskSimulator:
    """Probabilistic risk estimation using Monte Carlo simulation.
    Stdlib random only -- no numpy required."""

    def __init__(self, seed: int = 42) -> None:
        self._rng = random.Random(seed)

    def simulate_attack_success(
        self,
        finding_probabilities: list[float],
        n_simulations: int = 1000,
    ) -> dict[str, Any]:
        if not finding_probabilities:
            return {"success_rate": 0.0, "simulations": 0, "mean_steps": 0}

        n_simulations = min(n_simulations, 5000)
        successes = 0
        total_steps: list[int] = []

        for _ in range(n_simulations):
            steps = 0
            for prob in finding_probabilities:
                steps += 1
                if self._rng.random() < prob:
                    successes += 1
                    total_steps.append(steps)
                    break

        success_rate = successes / n_simulations if n_simulations > 0 else 0.0
        mean_steps = statistics.mean(total_steps) if total_steps else 0.0

        return {
            "success_rate": round(success_rate, 4),
            "simulations": n_simulations,
            "mean_steps_to_success": round(mean_steps, 2),
            "findings_tested": len(finding_probabilities),
        }

    def estimate_blast_radius(
        self,
        severity: str,
        is_payment: bool,
        is_auth: bool,
        chain_length: int = 1,
    ) -> dict[str, Any]:
        base_impact = {
            "critical": 0.9, "high": 0.7, "medium": 0.4, "low": 0.2, "none": 0.0,
        }.get(severity, 0.0)

        if is_payment:
            base_impact = min(1.0, base_impact * 1.4)
        if is_auth:
            base_impact = min(1.0, base_impact * 1.3)
        chain_multiplier = min(2.0, 1.0 + 0.3 * (chain_length - 1))
        final_impact = min(1.0, base_impact * chain_multiplier)

        scope = "single_user"
        if final_impact > 0.8:
            scope = "all_users"
        elif final_impact > 0.5:
            scope = "multi_tenant"
        elif final_impact > 0.3:
            scope = "single_tenant"

        return {
            "impact_score": round(final_impact, 3),
            "scope": scope,
            "chain_multiplier": round(chain_multiplier, 2),
            "is_payment_critical": is_payment and final_impact > 0.5,
        }

    def compute_risk_distribution(
        self,
        severity_scores: list[float],
        n_simulations: int = 1000,
    ) -> dict[str, Any]:
        if not severity_scores:
            return {"mean": 0.0, "p50": 0.0, "p90": 0.0, "p99": 0.0}

        n_simulations = min(n_simulations, 5000)
        samples: list[float] = []
        for _ in range(n_simulations):
            sample = sum(
                s * (0.5 + self._rng.random()) for s in severity_scores
            ) / len(severity_scores)
            samples.append(min(1.0, sample))

        samples.sort()
        p50_idx = int(len(samples) * 0.5)
        p90_idx = int(len(samples) * 0.9)
        p99_idx = min(int(len(samples) * 0.99), len(samples) - 1)

        return {
            "mean": round(statistics.mean(samples), 4),
            "p50": round(samples[p50_idx], 4),
            "p90": round(samples[p90_idx], 4),
            "p99": round(samples[p99_idx], 4),
            "sample_count": n_simulations,
        }


# ============================================================================
# 10. Attack Tree Generator
# ============================================================================

class AttackTreeGenerator:
    """Goal-oriented AND/OR attack tree decomposition."""

    _GOAL_TEMPLATES: dict[str, list[dict[str, Any]]] = {
        "access_without_payment": {
            "node_type": "OR",
            "children": [
                {
                    "goal": "Direct entitlement bypass",
                    "node_type": "OR",
                    "children": [
                        {"goal": "Manipulate subscription status to active without payment", "node_type": "LEAF", "category": "entitlement_bypass"},
                        {"goal": "Exploit trial extension to retain premium access", "node_type": "LEAF", "category": "entitlement_bypass"},
                        {"goal": "Access premium endpoints without subscription check", "node_type": "LEAF", "category": "broken_access_control"},
                    ],
                },
                {
                    "goal": "Payment manipulation chain",
                    "node_type": "AND",
                    "children": [
                        {"goal": "Modify payment amount to zero", "node_type": "LEAF", "category": "payment_manipulation"},
                        {"goal": "Complete checkout with zero-amount payment", "node_type": "LEAF", "category": "business_logic"},
                        {"goal": "Receive entitlement for zero payment", "node_type": "LEAF", "category": "entitlement_bypass"},
                    ],
                },
                {
                    "goal": "Webhook abuse chain",
                    "node_type": "AND",
                    "children": [
                        {"goal": "Forge or replay successful payment webhook", "node_type": "LEAF", "category": "auth_bypass"},
                        {"goal": "System grants entitlement from forged webhook", "node_type": "LEAF", "category": "entitlement_bypass"},
                    ],
                },
                {
                    "goal": "Race condition exploitation",
                    "node_type": "AND",
                    "children": [
                        {"goal": "Initiate payment and access simultaneously", "node_type": "LEAF", "category": "race_condition"},
                        {"goal": "Access granted before payment confirmation", "node_type": "LEAF", "category": "entitlement_bypass"},
                    ],
                },
            ],
        },
    }

    def generate_tree(
        self,
        target_goal: str,
        available_findings: list[ZeroShotFinding],
    ) -> AttackTreeNode:
        template = self._GOAL_TEMPLATES.get(target_goal)
        if not template:
            return AttackTreeNode(goal=target_goal, node_type="LEAF", probability=0.0)

        finding_categories = {f.category for f in available_findings}
        return self._build_node(template, finding_categories)

    def _build_node(
        self,
        template: dict[str, Any],
        available_cats: set[str],
    ) -> AttackTreeNode:
        node = AttackTreeNode(
            goal=template.get("goal", ""),
            node_type=template.get("node_type", "LEAF"),
        )

        if node.node_type == "LEAF":
            category = template.get("category", "")
            has_evidence = any(category in cat for cat in available_cats)
            node.probability = 0.6 if has_evidence else 0.1
            node.finding_ref = category
            return node

        children = []
        for child_tmpl in template.get("children", []):
            child = self._build_node(child_tmpl, available_cats)
            children.append(child)
        node.children = children

        if node.node_type == "AND":
            node.probability = math.prod(c.probability for c in children) if children else 0.0
        elif node.node_type == "OR":
            node.probability = 1.0 - math.prod(1.0 - c.probability for c in children) if children else 0.0

        return node

    def find_critical_path(self, tree: AttackTreeNode) -> list[str]:
        if tree.node_type == "LEAF":
            return [tree.goal]

        if not tree.children:
            return [tree.goal]

        if tree.node_type == "OR":
            best = max(tree.children, key=lambda c: c.probability)
            return [tree.goal] + self.find_critical_path(best)

        path = [tree.goal]
        for child in tree.children:
            path.extend(self.find_critical_path(child))
        return path


# ============================================================================
# 11. Enhanced contextual analysis
# ============================================================================

def _contextual_notes_and_floor(
    request_data: dict[str, Any],
    zero_shot: list[ZeroShotFinding],
    components: dict[str, Any] | None = None,
) -> tuple[list[str], str]:
    notes: list[str] = []
    floor = "none"

    url = str(request_data.get("url", ""))
    method = str(request_data.get("method", "GET")).upper()
    on_payment_route = bool(_PAYMENT_SENSITIVE_PATH_RE.search(url))
    on_auth_route = bool(_AUTH_PATH_RE.search(url))
    on_admin_route = bool(_ADMIN_PATH_RE.search(url))
    is_mutating = method in _MUTATING_METHODS
    body_text = ""
    if components:
        body_text = components.get("body_text", "")

    provider = "unknown"
    for prov_name, patterns in _PROVIDER_SIGNATURES.items():
        if any(p.search(body_text or url) for p in patterns):
            provider = prov_name
            break
    if provider != "unknown":
        notes.append(f"Payment provider detected: {provider}")

    if zero_shot:
        critical_hits = [
            f for f in zero_shot
            if f.category in ("critical_secret", "possible_card_number")
        ]
        if critical_hits and on_payment_route:
            notes.append(
                f"{critical_hits[0].category.replace('_', ' ')} on a {provider} payment-mutating route "
                f"({method} {url or 'unknown path'}) -- floored to critical."
            )
            floor = "critical"
        elif critical_hits:
            floor = "high"
        elif on_payment_route and is_mutating:
            floor = _bump_severity(floor, "medium")
            notes.append("Pattern match on payment-mutating route -- floor raised to medium.")
        else:
            floor = "medium"
    elif on_payment_route and is_mutating:
        notes.append("Payment-mutating route with no pattern-level findings.")

    if on_auth_route and not components.get("has_auth_header") if components else False:
        floor = _bump_severity(floor, "medium")
        notes.append("Auth route accessed without credentials -- floor raised.")

    if on_admin_route:
        floor = _bump_severity(floor, "medium")
        notes.append("Administrative route -- severity floor raised.")

    if components and components.get("anomalies"):
        anomaly_list = components["anomalies"]
        for a in anomaly_list:
            if "entitlement_drift" in a:
                floor = _bump_severity(floor, "critical")
                notes.append(f"Entitlement drift detected ({a}) -- floor raised to critical.")
            elif "zero_payment" in a:
                floor = _bump_severity(floor, "high")
                notes.append(f"Zero payment value ({a}) -- floor raised to high.")
            elif "negative_value" in a:
                floor = _bump_severity(floor, "high")
                notes.append(f"Negative value ({a}) -- floor raised to high.")

    if provider == "stripe":
        stripe_obj = components.get("stripe_object") if components else None
        if stripe_obj in ("checkout.session", "payment_intent", "subscription"):
            notes.append(f"Stripe {stripe_obj} object -- applying Stripe-specific context rules.")
            if stripe_obj == "checkout.session" and is_mutating:
                floor = _bump_severity(floor, "high")
            elif stripe_obj == "subscription":
                tiers = components.get("premium_tiers", []) if components else []
                statuses = components.get("unpaid_statuses", []) if components else []
                if tiers and statuses:
                    floor = _bump_severity(floor, "critical")
                    notes.append(f"Stripe subscription with premium tier '{tiers[0]}' but unpaid status '{statuses[0]}'.")

    return notes, floor


# ============================================================================
# Main LLMReplacementLayer (orchestrates all engines)
# ============================================================================

class LLMReplacementLayer:
    """Ties all eleven reasoning engines together. One instance per run."""

    def __init__(self) -> None:
        self._baseline = _StructuralBaseline()
        self._observations_analyzed = 0
        self._findings_by_severity: dict[str, int] = {s: 0 for s in _SEVERITY_ORDER}
        self._cot_engine = ChainOfThoughtEngine()
        self._perspective_analyzer = MultiPerspectiveAnalyzer()
        self._hypothesis_engine = HypothesisEngine()
        self._evidence_correlator = EvidenceCorrelator()
        self._re_engine = ReverseEngineeringEngine()
        self._brainstorm_engine = BrainstormEngine()
        self._monte_carlo = MonteCarloRiskSimulator(seed=42)
        self._attack_tree_gen = AttackTreeGenerator()

    def analyze_observation(self, observation: dict[str, Any]) -> LLMReplacementResult:
        self._observations_analyzed += 1
        request_data = observation.get("request_data") or {}
        response_data = observation.get("response_data") or {}

        # --- Engine 1: Zero-shot ---
        zero_shot = _zero_shot_scan(response_data)

        # --- Engine 2: Structural ---
        features = _extract_features(request_data, response_data)
        structural_anomaly, structural_score = self._baseline.score(features)

        # --- Engine 3: Chain-of-thought ---
        reasoning = self._cot_engine.reason(observation)
        components = self._cot_engine._decompose_observation(observation)

        # --- Engine 4: Multi-perspective ---
        attacker_view = self._perspective_analyzer.analyze_as_attacker(components, zero_shot)
        defender_view = self._perspective_analyzer.analyze_as_defender(components, zero_shot)
        auditor_view = self._perspective_analyzer.analyze_as_auditor(components, zero_shot)
        perspectives = self._perspective_analyzer.synthesize(attacker_view, defender_view, auditor_view)

        # --- Engine 5: Hypothesis ---
        surfaces = self._cot_engine._identify_attack_surface(components)
        hypotheses = self._cot_engine._generate_hypotheses(surfaces, components, {})
        scored_hypotheses = self._cot_engine._evaluate_hypotheses(hypotheses, components)
        self._hypothesis_engine.update_beliefs(scored_hypotheses)

        # --- Engine 6: Evidence correlation ---
        self._evidence_correlator.add_observation(observation)
        correlations = self._evidence_correlator.find_correlations() if self._observations_analyzed % 5 == 0 else []

        # --- Engine 7: Reverse engineering ---
        self._re_engine.add_observation(observation)
        re_findings = self._re_engine.get_all_findings() if self._observations_analyzed % 10 == 0 else []

        # --- Engine 8: Brainstorm ---
        brainstorm_vectors = self._brainstorm_engine.brainstorm_attack_vectors(components)
        brainstorm_chains = self._brainstorm_engine.brainstorm_chain_compositions(zero_shot)
        divergent = self._brainstorm_engine.divergent_thinking(components)

        # --- Engine 9: Monte Carlo ---
        finding_probs = [h.posterior for h in scored_hypotheses if h.posterior > 0.1]
        mc_result = self._monte_carlo.simulate_attack_success(finding_probs)
        severity_scores = [_SEVERITY_FLOOR_SCORE.get(h.category, 0.3) for h in scored_hypotheses]
        mc_risk_dist = self._monte_carlo.compute_risk_distribution(severity_scores)

        # --- Engine 10: Attack tree ---
        attack_tree = self._attack_tree_gen.generate_tree("access_without_payment", zero_shot)
        critical_path = self._attack_tree_gen.find_critical_path(attack_tree)

        # --- Engine 11: Contextual ---
        contextual_notes, severity_floor = _contextual_notes_and_floor(
            request_data, zero_shot, components,
        )

        # --- Synthesis: combine all signals ---
        zero_shot_component = min(1.0, 0.3 * len(zero_shot))
        structural_component = structural_score * (0.6 if structural_anomaly else 0.15)
        cot_component = reasoning.confidence * 0.3
        perspective_component = perspectives.get("combined_risk", 0.0) * 0.25
        hypothesis_component = scored_hypotheses[0].posterior * 0.2 if scored_hypotheses else 0.0
        mc_component = mc_result.get("success_rate", 0.0) * 0.15
        tree_component = attack_tree.probability * 0.1

        overall_score = max(
            zero_shot_component,
            structural_component,
            cot_component,
            perspective_component,
            hypothesis_component,
            mc_component,
            tree_component,
        )

        severity = _bump_severity(_severity_from_score(overall_score), severity_floor)
        overall_score = max(overall_score, _SEVERITY_FLOOR_SCORE[severity])
        overall_score = max(0.0, min(1.0, overall_score))

        self._findings_by_severity[severity] += 1

        anomaly_explanation = ""
        if structural_anomaly:
            trend = self._baseline.get_trend()
            anomaly_explanation = (
                f"Structural anomaly detected (score={structural_score:.3f}, trend={trend}). "
                f"Response deviates from this run's baseline in shape/timing features."
            )
        if reasoning.conclusion:
            anomaly_explanation += f" CoT analysis: {reasoning.conclusion}"

        confidence_calibration = {
            "raw_score": round(overall_score, 4),
            "zero_shot_component": round(zero_shot_component, 4),
            "structural_component": round(structural_component, 4),
            "cot_component": round(cot_component, 4),
            "perspective_component": round(perspective_component, 4),
            "hypothesis_component": round(hypothesis_component, 4),
            "severity_floor_applied": severity_floor,
            "final_severity": severity,
            "belief_state": self._hypothesis_engine.get_beliefs(),
        }

        return LLMReplacementResult(
            suspicious_fields=[f.field for f in zero_shot],
            overall_severity=severity,
            overall_suspicion_score=overall_score,
            zero_shot_findings=[
                {"category": f.category, "field": f.field, "detail": f.detail, "cwe": f.cwe}
                for f in zero_shot
            ],
            structural_anomaly=structural_anomaly,
            structural_score=structural_score,
            contextual_notes=contextual_notes,
            reasoning_chain=reasoning.as_strings(),
            hypotheses=[h.to_dict() for h in scored_hypotheses[:10]],
            attack_paths=[{
                "tree": attack_tree.to_dict(),
                "critical_path": critical_path,
                "success_probability": round(attack_tree.probability, 4),
            }],
            brainstorm_results=(
                brainstorm_vectors[:10]
                + [{"type": "chain_composition", **c} for c in brainstorm_chains]
                + [{"type": "divergent", **d} for d in divergent]
            ),
            reverse_engineering_findings=re_findings[:20],
            confidence_calibration=confidence_calibration,
            multi_perspective_scores=perspectives,
            evidence_correlation=correlations[:10],
            anomaly_explanation=anomaly_explanation,
            risk_monte_carlo={**mc_result, "risk_distribution": mc_risk_dist},
        )

    def get_statistics(self) -> dict[str, Any]:
        return {
            "observations_analyzed": self._observations_analyzed,
            "sklearn_available": SKLEARN_AVAILABLE,
            "structural_baseline_fitted": self._baseline.is_fitted,
            "structural_baseline_samples": self._baseline.sample_count,
            "structural_trend": self._baseline.get_trend(),
            "findings_by_severity": dict(self._findings_by_severity),
            "belief_state": self._hypothesis_engine.get_beliefs(),
            "correlation_clusters": self._evidence_correlator.get_correlation_clusters(),
            "feature_importances": self._baseline.get_feature_importances(),
        }
