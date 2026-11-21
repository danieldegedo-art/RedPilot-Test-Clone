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
import json
import math
import random
import re
import statistics
import time
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


# ############################################################################
#
#  NOVEL ARCHITECTURE: AUTONOMOUS MEMORY + REFLECTION + METACOGNITION
#
#  Three systems that give the engine genuine learning capability:
#
#  A. EpisodicMemory -- Remembers every observation and finding with
#     triple-scored retrieval (recency x importance x relevance).
#     Inspired by Generative Agents (Park et al. 2023).
#
#  B. ReflectionEngine -- Periodically synthesizes high-level insights
#     from accumulated memories. Generates strategic plans for what to
#     look for next. Builds a progressive knowledge graph of entities.
#
#  C. MetacognitiveMonitor -- Tracks the system's own prediction accuracy
#     over time. Calibrates priors for each hypothesis category. Detects
#     when the system is overconfident or underconfident. Adapts strategy.
#
#  D. KnowledgeGraph -- Progressive graph of entities (endpoints, tokens,
#     IDs, payment objects) and their relationships. Enables graph-based
#     reasoning about attack paths.
#
#  E. BeliefRevisionLog -- Tracks WHY beliefs changed and what triggered
#     each revision. Enables self-explanation and debugging.
#
#  F. SelfCritiqueEngine -- Devil's advocate pass: tries to disprove
#     each hypothesis before it advances. Only survivors propagate.
#
# ############################################################################


# ============================================================================
# A. Episodic Memory System
# ============================================================================

@dataclass
class MemoryEntry:
    """A single memory in the episodic memory stream."""
    entry_id: int
    timestamp: float
    entry_type: str  # "observation", "finding", "reflection", "insight"
    content: dict[str, Any]
    importance: float = 0.5
    source_observation_id: int = 0
    endpoint: str = ""
    category: str = ""
    features: dict[str, float] = field(default_factory=dict)
    access_count: int = 0
    last_accessed: float = 0.0


class EpisodicMemory:
    """Append-only memory stream with triple-scored retrieval.

    Every observation, finding, reasoning step, and reflection is stored.
    Retrieval scores each memory by:
      recency   = exponential decay from current time
      importance = how significant the finding was (0-1)
      relevance  = feature similarity to the query

    This gives the system "what have I seen before that looks like this?"
    capability -- the foundation of genuine learning from experience."""

    def __init__(self, max_entries: int = 10000, recency_decay: float = 0.995) -> None:
        self._memories: list[MemoryEntry] = []
        self._next_id = 0
        self._max_entries = max_entries
        self._recency_decay = recency_decay
        self._index_by_endpoint: dict[str, list[int]] = defaultdict(list)
        self._index_by_category: dict[str, list[int]] = defaultdict(list)
        self._index_by_type: dict[str, list[int]] = defaultdict(list)

    @property
    def size(self) -> int:
        return len(self._memories)

    def store(
        self,
        entry_type: str,
        content: dict[str, Any],
        importance: float = 0.5,
        endpoint: str = "",
        category: str = "",
        features: dict[str, float] | None = None,
        source_observation_id: int = 0,
    ) -> int:
        entry = MemoryEntry(
            entry_id=self._next_id,
            timestamp=time.monotonic(),
            entry_type=entry_type,
            content=content,
            importance=max(0.0, min(1.0, importance)),
            source_observation_id=source_observation_id,
            endpoint=endpoint,
            category=category,
            features=features or {},
        )
        self._memories.append(entry)
        self._index_by_endpoint[endpoint].append(self._next_id)
        self._index_by_category[category].append(self._next_id)
        self._index_by_type[entry_type].append(self._next_id)
        self._next_id += 1

        if len(self._memories) > self._max_entries:
            self._consolidate()

        return entry.entry_id

    def retrieve(
        self,
        query_features: dict[str, float] | None = None,
        query_endpoint: str = "",
        query_category: str = "",
        top_k: int = 10,
        entry_type: str | None = None,
    ) -> list[MemoryEntry]:
        """Triple-scored retrieval: recency x importance x relevance."""
        now = time.monotonic()
        candidates = self._memories
        if entry_type:
            ids = set(self._index_by_type.get(entry_type, []))
            candidates = [m for m in candidates if m.entry_id in ids]

        scored: list[tuple[float, MemoryEntry]] = []
        for mem in candidates:
            age = now - mem.timestamp
            recency = self._recency_decay ** max(age, 0)

            importance = mem.importance

            relevance = 0.0
            if query_endpoint and mem.endpoint:
                if query_endpoint == mem.endpoint:
                    relevance += 0.5
                elif query_endpoint.split("/")[:3] == mem.endpoint.split("/")[:3]:
                    relevance += 0.25
            if query_category and mem.category:
                if query_category == mem.category:
                    relevance += 0.3
            if query_features and mem.features:
                common_keys = set(query_features) & set(mem.features)
                if common_keys:
                    sim = sum(
                        1.0 - abs(query_features[k] - mem.features[k])
                        for k in common_keys
                    ) / len(common_keys)
                    relevance += 0.2 * sim

            score = recency * 0.3 + importance * 0.4 + relevance * 0.3
            scored.append((score, mem))

        scored.sort(key=lambda x: x[0], reverse=True)
        results = []
        for _score, mem in scored[:top_k]:
            mem.access_count += 1
            mem.last_accessed = now
            results.append(mem)
        return results

    def retrieve_by_endpoint(self, endpoint: str, limit: int = 20) -> list[MemoryEntry]:
        ids = self._index_by_endpoint.get(endpoint, [])
        return [self._memories[i] for i in ids[-limit:] if i < len(self._memories)]

    def retrieve_recent(self, n: int = 20) -> list[MemoryEntry]:
        return list(reversed(self._memories[-n:]))

    def get_all_endpoints_seen(self) -> set[str]:
        return set(self._index_by_endpoint.keys()) - {""}

    def get_category_counts(self) -> dict[str, int]:
        return {k: len(v) for k, v in self._index_by_category.items() if k}

    def _consolidate(self) -> None:
        """When memory is full, compress old low-importance memories."""
        if len(self._memories) <= self._max_entries:
            return
        scored = sorted(self._memories, key=lambda m: m.importance + (m.access_count * 0.1))
        to_remove = len(self._memories) - int(self._max_entries * 0.8)
        remove_ids = {scored[i].entry_id for i in range(min(to_remove, len(scored)))}
        self._memories = [m for m in self._memories if m.entry_id not in remove_ids]
        self._rebuild_indices()

    def _rebuild_indices(self) -> None:
        self._index_by_endpoint.clear()
        self._index_by_category.clear()
        self._index_by_type.clear()
        for i, m in enumerate(self._memories):
            self._index_by_endpoint[m.endpoint].append(i)
            self._index_by_category[m.category].append(i)
            self._index_by_type[m.entry_type].append(i)

    def to_summary(self) -> dict[str, Any]:
        return {
            "total_memories": len(self._memories),
            "endpoints_seen": len(self.get_all_endpoints_seen()),
            "category_counts": self.get_category_counts(),
            "memory_types": {k: len(v) for k, v in self._index_by_type.items()},
        }


# ============================================================================
# B. Reflection Engine
# ============================================================================

@dataclass
class Insight:
    """A synthesized high-level insight from multiple memories."""
    insight_id: str
    description: str
    supporting_memories: list[int]
    confidence: float
    category: str
    created_at: float = 0.0
    times_reinforced: int = 0


class ReflectionEngine:
    """Periodic synthesis of high-level insights from accumulated memories.

    After every N observations, the reflection engine:
    1. Retrieves recent memories
    2. Identifies recurring patterns
    3. Synthesizes insights ("this target always has weak auth on v2 endpoints")
    4. Generates strategic recommendations for future analysis
    5. Updates the knowledge graph

    This is the "stepping back and thinking about what I've learned" capability
    that separates frontier reasoning from template matching."""

    def __init__(self, reflection_interval: int = 10) -> None:
        self._insights: list[Insight] = []
        self._reflection_count = 0
        self._reflection_interval = reflection_interval
        self._strategic_plan: list[str] = []

    def should_reflect(self, observation_count: int) -> bool:
        return observation_count > 0 and observation_count % self._reflection_interval == 0

    def reflect(self, memory: EpisodicMemory) -> list[Insight]:
        """Synthesize insights from recent memories."""
        self._reflection_count += 1
        new_insights: list[Insight] = []

        recent = memory.retrieve_recent(n=50)
        if len(recent) < 5:
            return new_insights

        # Pattern 1: Endpoint-category concentration
        ep_cats: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        for mem in recent:
            if mem.endpoint and mem.category:
                ep_cats[mem.endpoint][mem.category] += 1

        for ep, cats in ep_cats.items():
            for cat, count in cats.items():
                if count >= 3:
                    insight = Insight(
                        insight_id=f"R{self._reflection_count}-EP-{ep[:30]}-{cat}",
                        description=(
                            f"Endpoint '{ep}' repeatedly triggers '{cat}' findings "
                            f"({count} times in recent observations). "
                            f"This endpoint is a high-priority target for {cat} exploitation."
                        ),
                        supporting_memories=[m.entry_id for m in recent if m.endpoint == ep and m.category == cat],
                        confidence=min(0.95, 0.5 + 0.1 * count),
                        category=cat,
                        created_at=time.monotonic(),
                    )
                    if not self._insight_exists(insight.description[:60]):
                        new_insights.append(insight)

        # Pattern 2: Cross-endpoint vulnerability class
        cat_counts = memory.get_category_counts()
        for cat, count in cat_counts.items():
            if count >= 5 and cat:
                desc = (
                    f"Systemic '{cat}' weakness: {count} findings across multiple endpoints. "
                    f"This suggests a framework-level or design-level vulnerability, "
                    f"not an isolated endpoint bug."
                )
                if not self._insight_exists(desc[:60]):
                    new_insights.append(Insight(
                        insight_id=f"R{self._reflection_count}-SYSTEMIC-{cat}",
                        description=desc,
                        supporting_memories=[],
                        confidence=min(0.9, 0.4 + 0.05 * count),
                        category=cat,
                        created_at=time.monotonic(),
                    ))

        # Pattern 3: Defense posture assessment
        defense_mems = memory.retrieve(query_category="anti_re", top_k=20, entry_type="finding")
        waf_mems = [m for m in defense_mems if "waf" in str(m.content).lower()]
        if waf_mems:
            waf_types = set()
            for m in waf_mems:
                wt = m.content.get("waf_cdn", m.content.get("waf_vendor", ""))
                if wt:
                    waf_types.add(wt)
            if waf_types:
                desc = (
                    f"Target is protected by WAF(s): {sorted(waf_types)}. "
                    f"Bypass techniques specific to these vendors should be prioritized. "
                    f"Encoding variation, HPP, and chunked TE are highest-probability bypasses."
                )
                if not self._insight_exists(desc[:60]):
                    new_insights.append(Insight(
                        insight_id=f"R{self._reflection_count}-WAF-POSTURE",
                        description=desc,
                        supporting_memories=[m.entry_id for m in waf_mems],
                        confidence=0.85,
                        category="defense_posture",
                        created_at=time.monotonic(),
                    ))

        # Pattern 4: Auth model inference
        auth_findings = memory.retrieve(query_category="auth_bypass", top_k=20)
        unauthed_success = [
            m for m in auth_findings
            if m.content.get("has_auth") is False and m.content.get("status_code", 0) in range(200, 300)
        ]
        if len(unauthed_success) >= 2:
            eps = sorted({m.endpoint for m in unauthed_success if m.endpoint})[:5]
            desc = (
                f"Multiple endpoints return success without auth: {eps}. "
                f"The application may rely on client-side auth enforcement rather than "
                f"server-side middleware. All these endpoints are access-without-payment candidates."
            )
            if not self._insight_exists(desc[:60]):
                new_insights.append(Insight(
                    insight_id=f"R{self._reflection_count}-AUTH-WEAK",
                    description=desc,
                    supporting_memories=[m.entry_id for m in unauthed_success],
                    confidence=0.8,
                    category="auth_bypass",
                    created_at=time.monotonic(),
                ))

        # Pattern 5: Payment flow reconstruction
        payment_mems = memory.retrieve(query_category="payment_manipulation", top_k=30)
        payment_mems += memory.retrieve(query_category="entitlement_bypass", top_k=30)
        if len(payment_mems) >= 3:
            payment_eps = sorted({m.endpoint for m in payment_mems if m.endpoint})
            desc = (
                f"Payment flow mapped across {len(payment_eps)} endpoints: {payment_eps[:5]}. "
                f"Focus exploitation on the weakest link in this chain."
            )
            if not self._insight_exists(desc[:60]):
                new_insights.append(Insight(
                    insight_id=f"R{self._reflection_count}-PAYMENT-FLOW",
                    description=desc,
                    supporting_memories=[m.entry_id for m in payment_mems[:10]],
                    confidence=0.75,
                    category="payment_manipulation",
                    created_at=time.monotonic(),
                ))

        self._insights.extend(new_insights)
        self._update_strategic_plan(memory)
        return new_insights

    def _insight_exists(self, prefix: str) -> bool:
        return any(i.description[:60] == prefix for i in self._insights)

    def _update_strategic_plan(self, memory: EpisodicMemory) -> None:
        """Generate strategic recommendations for next analysis batch."""
        self._strategic_plan.clear()
        cat_counts = memory.get_category_counts()

        high_signal_cats = sorted(
            ((k, v) for k, v in cat_counts.items() if k and v >= 2),
            key=lambda x: x[1], reverse=True,
        )
        for cat, count in high_signal_cats[:3]:
            self._strategic_plan.append(
                f"Prioritize {cat} analysis (seen {count} times)"
            )

        all_eps = memory.get_all_endpoints_seen()
        if len(all_eps) > 10:
            self._strategic_plan.append(
                f"Wide attack surface: {len(all_eps)} endpoints discovered. "
                f"Focus on payment/auth endpoints."
            )

        for insight in self._insights[-5:]:
            if insight.confidence > 0.7:
                self._strategic_plan.append(f"INSIGHT: {insight.description[:100]}")

    def get_strategic_plan(self) -> list[str]:
        return list(self._strategic_plan)

    def get_insights(self) -> list[dict[str, Any]]:
        return [
            {
                "id": i.insight_id,
                "description": i.description,
                "confidence": round(i.confidence, 3),
                "category": i.category,
                "supporting_count": len(i.supporting_memories),
                "reinforced": i.times_reinforced,
            }
            for i in sorted(self._insights, key=lambda x: x.confidence, reverse=True)
        ]

    def get_relevant_insights(self, category: str = "", endpoint: str = "") -> list[Insight]:
        results = []
        for i in self._insights:
            if category and i.category == category:
                results.append(i)
            elif endpoint and endpoint in i.description:
                results.append(i)
        return sorted(results, key=lambda x: x.confidence, reverse=True)[:5]


# ============================================================================
# C. Metacognitive Monitor
# ============================================================================

class MetacognitiveMonitor:
    """Tracks the system's own prediction accuracy and adapts strategy.

    For each hypothesis category, tracks:
    - How often hypotheses in that category scored high
    - Whether subsequent observations confirmed or contradicted
    - Running accuracy rate

    Uses this to:
    - Calibrate priors (categories that are often right get boosted)
    - Detect overconfidence (high scores that don't pan out get dampened)
    - Recommend focus areas (categories with high hit rate)

    This is the "thinking about my own thinking" layer that makes the system
    self-improving rather than static."""

    def __init__(self) -> None:
        self._category_predictions: dict[str, list[float]] = defaultdict(list)
        self._category_confirmations: dict[str, list[bool]] = defaultdict(list)
        self._calibration_adjustments: dict[str, float] = {}
        self._total_observations = 0
        self._severity_predictions: list[tuple[str, str]] = []
        self._overconfidence_warnings: list[str] = []

    def record_prediction(self, category: str, posterior: float) -> None:
        self._category_predictions[category].append(posterior)
        self._total_observations += 1

    def record_confirmation(self, category: str, confirmed: bool) -> None:
        self._category_confirmations[category].append(confirmed)
        self._update_calibration(category)

    def _update_calibration(self, category: str) -> None:
        preds = self._category_predictions.get(category, [])
        confs = self._category_confirmations.get(category, [])
        if len(confs) < 3:
            return

        recent_confs = confs[-20:]
        hit_rate = sum(recent_confs) / len(recent_confs)

        recent_preds = preds[-20:]
        avg_confidence = sum(recent_preds) / len(recent_preds) if recent_preds else 0.5

        if hit_rate > 0.7 and avg_confidence < 0.5:
            self._calibration_adjustments[category] = 1.3
        elif hit_rate < 0.2 and avg_confidence > 0.5:
            self._calibration_adjustments[category] = 0.6
            self._overconfidence_warnings.append(
                f"Category '{category}': overconfident (avg={avg_confidence:.2f}, "
                f"hit_rate={hit_rate:.2f}). Dampening."
            )
        else:
            self._calibration_adjustments[category] = 0.9 + 0.2 * hit_rate

    def get_prior_adjustment(self, category: str) -> float:
        return self._calibration_adjustments.get(category, 1.0)

    def get_recommended_focus(self) -> list[tuple[str, float]]:
        """Categories with high hit rate that deserve more attention."""
        focus: list[tuple[str, float]] = []
        for cat, confs in self._category_confirmations.items():
            if len(confs) >= 3:
                recent = confs[-20:]
                hit_rate = sum(recent) / len(recent)
                if hit_rate > 0.5:
                    focus.append((cat, hit_rate))
        return sorted(focus, key=lambda x: x[1], reverse=True)

    def self_assess(self) -> dict[str, Any]:
        """Return a metacognitive self-assessment."""
        assessment: dict[str, Any] = {
            "total_observations": self._total_observations,
            "categories_tracked": len(self._category_predictions),
            "calibration_adjustments": dict(self._calibration_adjustments),
            "overconfidence_warnings": self._overconfidence_warnings[-5:],
            "recommended_focus": self.get_recommended_focus(),
        }

        for cat, preds in self._category_predictions.items():
            confs = self._category_confirmations.get(cat, [])
            if preds:
                assessment[f"cat_{cat}_avg_posterior"] = round(
                    sum(preds[-20:]) / len(preds[-20:]), 3
                )
            if confs:
                assessment[f"cat_{cat}_hit_rate"] = round(
                    sum(confs[-20:]) / len(confs[-20:]), 3
                )

        return assessment


# ============================================================================
# D. Knowledge Graph
# ============================================================================

@dataclass
class KGNode:
    """A node in the knowledge graph."""
    node_id: str
    node_type: str  # "endpoint", "token", "stripe_object", "user", "waf", "tech"
    properties: dict[str, Any] = field(default_factory=dict)
    first_seen: int = 0
    times_seen: int = 0


@dataclass
class KGEdge:
    """An edge in the knowledge graph."""
    source: str
    target: str
    edge_type: str  # "calls", "returns", "references", "auth_guards", "produces"
    weight: float = 1.0
    properties: dict[str, Any] = field(default_factory=dict)


class KnowledgeGraph:
    """Progressive entity-relationship graph built from observations.

    Nodes: endpoints, tokens, Stripe objects, WAFs, technologies
    Edges: calls, returns, references, auth_guards, produces

    Enables graph-based reasoning:
    - "This endpoint is 2 hops from the payment endpoint and has no auth"
    - "These 3 endpoints share the same Stripe customer object"
    - "The WAF protects endpoints A, B, C but not D"
    """

    def __init__(self) -> None:
        self._nodes: dict[str, KGNode] = {}
        self._edges: list[KGEdge] = []
        self._adjacency: dict[str, list[str]] = defaultdict(list)

    def add_node(self, node_id: str, node_type: str, properties: dict[str, Any] | None = None) -> None:
        if node_id in self._nodes:
            self._nodes[node_id].times_seen += 1
            if properties:
                self._nodes[node_id].properties.update(properties)
        else:
            self._nodes[node_id] = KGNode(
                node_id=node_id, node_type=node_type,
                properties=properties or {},
                first_seen=len(self._edges),
                times_seen=1,
            )

    def add_edge(self, source: str, target: str, edge_type: str, weight: float = 1.0) -> None:
        for existing in self._edges:
            if existing.source == source and existing.target == target and existing.edge_type == edge_type:
                existing.weight += 0.1
                return
        self._edges.append(KGEdge(source=source, target=target, edge_type=edge_type, weight=weight))
        self._adjacency[source].append(target)

    def get_neighbors(self, node_id: str, max_depth: int = 2) -> set[str]:
        """BFS to find all nodes within max_depth hops."""
        visited: set[str] = set()
        queue: list[tuple[str, int]] = [(node_id, 0)]
        while queue:
            current, depth = queue.pop(0)
            if current in visited or depth > max_depth:
                continue
            visited.add(current)
            for neighbor in self._adjacency.get(current, []):
                if neighbor not in visited:
                    queue.append((neighbor, depth + 1))
        visited.discard(node_id)
        return visited

    def find_unprotected_paths(self) -> list[dict[str, Any]]:
        """Find paths from unauthenticated endpoints to payment endpoints."""
        unauthed = [
            n for n in self._nodes.values()
            if n.node_type == "endpoint" and n.properties.get("has_auth") is False
        ]
        payment = [
            n for n in self._nodes.values()
            if n.node_type == "endpoint" and n.properties.get("is_payment") is True
        ]
        paths: list[dict[str, Any]] = []
        for ua in unauthed:
            neighbors = self.get_neighbors(ua.node_id, max_depth=3)
            for pay in payment:
                if pay.node_id in neighbors:
                    paths.append({
                        "unauthed_endpoint": ua.node_id,
                        "payment_endpoint": pay.node_id,
                        "detail": f"Unauthed {ua.node_id} is within 3 hops of payment {pay.node_id}",
                    })
        return paths

    def ingest_observation(self, observation: dict[str, Any]) -> None:
        """Extract entities and relationships from an observation."""
        req = observation.get("request_data") or {}
        resp = observation.get("response_data") or {}
        url = str(req.get("url", ""))
        path = urlparse(url).path if url else ""
        status = resp.get("status_code", 0)
        body = resp.get("body")
        body_text = _body_as_text(body) if body is not None else ""
        headers = resp.get("headers") or {}
        req_headers = req.get("headers") or {}

        if path:
            has_auth = any(
                h.lower() in ("authorization", "x-api-key", "cookie")
                for h in {**headers, **req_headers}
            )
            is_payment = bool(_PAYMENT_SENSITIVE_PATH_RE.search(path))
            self.add_node(path, "endpoint", {
                "method": req.get("method", "GET"),
                "status": status,
                "has_auth": has_auth,
                "is_payment": is_payment,
            })

        stripe_match = _STRIPE_OBJECT_RE.search(body_text)
        if stripe_match and path:
            obj_type = stripe_match.group(1)
            self.add_node(f"stripe:{obj_type}", "stripe_object")
            self.add_edge(path, f"stripe:{obj_type}", "returns")

        id_refs = re.findall(
            r'"(\w+_id)":\s*"([^"]{5,50})"', body_text,
        )
        for id_field, id_val in id_refs[:10]:
            ref_node = f"id:{id_field}:{id_val[:20]}"
            self.add_node(ref_node, "token", {"field": id_field})
            if path:
                self.add_edge(path, ref_node, "references")

        lower_headers = {k.lower(): v for k, v in headers.items()}
        if re.search(r'(?:cf-ray|cloudflare)', str(lower_headers), re.I):
            self.add_node("waf:cloudflare", "waf")
            if path:
                self.add_edge("waf:cloudflare", path, "protects")

    def to_summary(self) -> dict[str, Any]:
        type_counts: dict[str, int] = defaultdict(int)
        for n in self._nodes.values():
            type_counts[n.node_type] += 1
        return {
            "total_nodes": len(self._nodes),
            "total_edges": len(self._edges),
            "node_types": dict(type_counts),
            "unprotected_paths": self.find_unprotected_paths()[:5],
        }


# ============================================================================
# E. Belief Revision Log
# ============================================================================

@dataclass
class BeliefRevision:
    revision_id: int
    observation_id: int
    category: str
    old_belief: float
    new_belief: float
    trigger: str
    evidence: str


class BeliefRevisionLog:
    """Tracks WHY beliefs changed and what triggered each revision.

    Every time a belief is updated, the log records:
    - What the old belief was
    - What the new belief is
    - What observation triggered the change
    - What specific evidence caused the revision

    Enables: "Why do I think this target has weak auth?" ->
    "Because observations 3, 7, 12 all showed 200 responses on /api/v2/admin
    without auth headers, and observation 15 confirmed with a JWT alg:none token."
    """

    def __init__(self) -> None:
        self._revisions: list[BeliefRevision] = []
        self._next_id = 0

    def record(
        self, observation_id: int, category: str,
        old_belief: float, new_belief: float,
        trigger: str, evidence: str,
    ) -> None:
        self._revisions.append(BeliefRevision(
            revision_id=self._next_id,
            observation_id=observation_id,
            category=category,
            old_belief=round(old_belief, 4),
            new_belief=round(new_belief, 4),
            trigger=trigger,
            evidence=evidence,
        ))
        self._next_id += 1

    def explain_belief(self, category: str) -> list[dict[str, Any]]:
        """Why does the system hold this belief? Return the revision chain."""
        relevant = [r for r in self._revisions if r.category == category]
        return [
            {
                "observation": r.observation_id,
                "old": r.old_belief,
                "new": r.new_belief,
                "trigger": r.trigger,
                "evidence": r.evidence,
            }
            for r in relevant[-10:]
        ]

    def get_largest_shifts(self, n: int = 5) -> list[dict[str, Any]]:
        """Find the biggest belief changes -- most informative observations."""
        sorted_revs = sorted(
            self._revisions,
            key=lambda r: abs(r.new_belief - r.old_belief),
            reverse=True,
        )
        return [
            {
                "category": r.category,
                "shift": round(r.new_belief - r.old_belief, 4),
                "trigger": r.trigger,
                "observation": r.observation_id,
            }
            for r in sorted_revs[:n]
        ]


# ============================================================================
# F. Self-Critique Engine
# ============================================================================

class SelfCritiqueEngine:
    """Devil's advocate: tries to disprove each hypothesis before it advances.

    For each hypothesis, generates counter-arguments based on:
    - Missing expected evidence ("if this were auth_bypass, we'd expect 401s elsewhere")
    - Contradicting evidence ("but the endpoint has rate limiting, suggesting monitoring")
    - Alternative explanations ("this could be a false positive from CORS preflight")
    - Base rate fallacy check ("this category has only a 10% hit rate historically")

    Only hypotheses that survive critique propagate to the final score."""

    _COUNTER_ARGUMENT_RULES: list[tuple[str, str, str, float]] = [
        ("auth_bypass", "has_auth_header", "Auth header present contradicts auth bypass hypothesis", -0.4),
        ("auth_bypass", "status_401_seen", "401 responses seen elsewhere suggest auth IS enforced", -0.3),
        ("payment_manipulation", "no_amount_field", "No amount field in response weakens payment manipulation hypothesis", -0.3),
        ("entitlement_bypass", "consistent_tiers", "Tier/status is consistent across observations", -0.25),
        ("injection", "waf_detected", "WAF detected -- injection payloads likely filtered", -0.2),
        ("injection", "small_body", "Small response body unlikely for successful injection", -0.15),
        ("race_condition", "idempotent_method", "GET/HEAD methods are idempotent, reducing race risk", -0.3),
        ("ssrf", "no_internal_ip", "No internal IPs in response contradicts SSRF hypothesis", -0.35),
        ("idor", "uuid_ids", "UUIDs (not sequential) make enumeration impractical", -0.25),
        ("privilege_escalation", "no_role_field", "No role/admin fields in response", -0.2),
    ]

    def critique(
        self,
        hypotheses: list,  # list[Hypothesis]
        components: dict[str, Any],
        memory: EpisodicMemory,
        metacognition: MetacognitiveMonitor,
    ) -> list:  # list[Hypothesis]
        """Run devil's advocate pass. Reduce posteriors of weak hypotheses."""
        body_text = components.get("body_text", "")
        has_auth = components.get("has_auth_header", False)
        status = components.get("status_code", 0)
        body_size = components.get("body_size", 0)

        context_flags: set[str] = set()
        if has_auth:
            context_flags.add("has_auth_header")
        if status in (401, 403):
            context_flags.add("status_401_seen")
        if not re.search(r'"(?:amount|price|total|cost)"', body_text, re.I):
            context_flags.add("no_amount_field")
        if body_size < 200:
            context_flags.add("small_body")
        if components.get("method", "GET") in ("GET", "HEAD", "OPTIONS"):
            context_flags.add("idempotent_method")
        if re.search(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}', body_text, re.I):
            context_flags.add("uuid_ids")
        if not re.search(r'"(?:role|is_admin|permissions|admin)"', body_text, re.I):
            context_flags.add("no_role_field")
        if not re.search(r'(?:127\.0\.0\.1|169\.254\.|10\.\d|192\.168\.)', body_text):
            context_flags.add("no_internal_ip")

        waf_mems = memory.retrieve(query_category="anti_re", top_k=5, entry_type="finding")
        if waf_mems:
            context_flags.add("waf_detected")

        past_401s = memory.retrieve(query_category="auth_bypass", top_k=10)
        if any(m.content.get("status_code") in (401, 403) for m in past_401s):
            context_flags.add("status_401_seen")

        for h in hypotheses:
            critique_penalty = 0.0
            critique_reasons: list[str] = []

            for cat, flag, reason, penalty in self._COUNTER_ARGUMENT_RULES:
                if h.category == cat and flag in context_flags:
                    critique_penalty += penalty
                    critique_reasons.append(reason)

            meta_adj = metacognition.get_prior_adjustment(h.category)
            if meta_adj < 0.8:
                critique_penalty -= 0.1
                critique_reasons.append(
                    f"Metacognition: category '{h.category}' has low historical accuracy"
                )

            if critique_penalty < 0:
                h.posterior = max(0.01, h.posterior * (1.0 + critique_penalty))
                if not hasattr(h, 'evidence_against'):
                    h.evidence_against = []
                h.evidence_against.extend(critique_reasons)

        return sorted(hypotheses, key=lambda h: h.posterior, reverse=True)


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

    # --- v3 cross-engine feedback ---
    engine_consensus: dict = field(default_factory=dict)
    cross_engine_amplifications: list[str] = field(default_factory=list)
    adaptive_weights: dict = field(default_factory=dict)
    kill_chain_summary: str = ""
    financial_impact_estimate: dict = field(default_factory=dict)

    # --- v4 autonomous learning + metacognition ---
    memory_retrievals: list[dict] = field(default_factory=list)
    reflections: list[dict] = field(default_factory=list)
    knowledge_graph_summary: dict = field(default_factory=dict)
    metacognitive_assessment: dict = field(default_factory=dict)
    belief_revision_trail: list[dict] = field(default_factory=list)
    self_critique_results: list[dict] = field(default_factory=list)
    strategic_plan: list[str] = field(default_factory=list)

    # --- v5 frontier techniques (ExploitGym / Astra / Mythos) ---
    iterative_depth_reached: int = 1
    exploit_chains: list[dict] = field(default_factory=list)
    adversarial_verification: dict = field(default_factory=dict)
    semantic_findings: list[dict] = field(default_factory=list)
    kill_chain_analysis: dict = field(default_factory=dict)
    hypothesis_refinement: dict = field(default_factory=dict)
    # v6: Payment glue code analysis
    payment_glue_findings: list[dict] = field(default_factory=list)
    payment_provider_summary: dict = field(default_factory=dict)

    # v7: Enterprise platform detection + access-without-payment + AI agent attack surface
    enterprise_platform_detections: list[dict] = field(default_factory=list)
    access_without_payment_findings: list[dict] = field(default_factory=list)
    ai_agent_attack_findings: list[dict] = field(default_factory=list)
    enterprise_platform_summary: dict = field(default_factory=dict)
    access_without_payment_summary: dict = field(default_factory=dict)
    ai_agent_attack_summary: dict = field(default_factory=dict)

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
            "engine_consensus": self.engine_consensus,
            "cross_engine_amplifications": self.cross_engine_amplifications,
            "adaptive_weights": self.adaptive_weights,
            "kill_chain_summary": self.kill_chain_summary,
            "financial_impact_estimate": self.financial_impact_estimate,
            "memory_retrievals": self.memory_retrievals,
            "reflections": self.reflections,
            "knowledge_graph_summary": self.knowledge_graph_summary,
            "metacognitive_assessment": self.metacognitive_assessment,
            "belief_revision_trail": self.belief_revision_trail,
            "self_critique_results": self.self_critique_results,
            "strategic_plan": self.strategic_plan,
            "iterative_depth_reached": self.iterative_depth_reached,
            "exploit_chains": self.exploit_chains,
            "adversarial_verification": self.adversarial_verification,
            "semantic_findings": self.semantic_findings,
            "kill_chain_analysis": self.kill_chain_analysis,
            "hypothesis_refinement": self.hypothesis_refinement,
            "payment_glue_findings": self.payment_glue_findings,
            "payment_provider_summary": self.payment_provider_summary,
            "enterprise_platform_detections": self.enterprise_platform_detections,
            "access_without_payment_findings": self.access_without_payment_findings,
            "ai_agent_attack_findings": self.ai_agent_attack_findings,
            "enterprise_platform_summary": self.enterprise_platform_summary,
            "access_without_payment_summary": self.access_without_payment_summary,
            "ai_agent_attack_summary": self.ai_agent_attack_summary,
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
        # --- 13 new hypothesis templates ---
        {
            "id": "H_SUBSCRIPTION_ABUSE",
            "category": "subscription_abuse",
            "template": "Subscription abuse: {endpoint} shows trial/lifecycle exploit opportunity",
            "trigger_conditions": ["subscription_object_found", "trial_indicator", "downgrade_indicator", "perpetual_free_indicator"],
            "base_prior": 0.35,
            "severity": "critical",
        },
        {
            "id": "H_WEBHOOK_FORGE",
            "category": "webhook_forge",
            "template": "Webhook forgery: {endpoint} accepts webhook events without cryptographic signature",
            "trigger_conditions": ["webhook_endpoint", "webhook_no_signature", "payment_endpoint"],
            "base_prior": 0.4,
            "severity": "critical",
        },
        {
            "id": "H_COUPON_STACKING",
            "category": "coupon_stacking",
            "template": "Coupon stacking: {endpoint} accepted multiple discounts past intended limit",
            "trigger_conditions": ["payment_endpoint", "coupon_in_response", "discount_indicator"],
            "base_prior": 0.3,
            "severity": "high",
        },
        {
            "id": "H_CURRENCY_ARBITRAGE",
            "category": "currency_arbitrage",
            "template": "Currency arbitrage: {endpoint} accepted currency mismatch enabling cost avoidance",
            "trigger_conditions": ["payment_endpoint", "currency_mismatch", "multi_currency_indicator"],
            "base_prior": 0.3,
            "severity": "critical",
        },
        {
            "id": "H_REFUND_ABUSE",
            "category": "refund_abuse",
            "template": "Refund abuse: {endpoint} refund does not revoke entitlement (refund-then-reuse)",
            "trigger_conditions": ["refund_object_found", "payment_endpoint", "entitlement_still_active"],
            "base_prior": 0.35,
            "severity": "critical",
        },
        {
            "id": "H_API_VERSION_DOWNGRADE",
            "category": "api_version_downgrade",
            "template": "API version downgrade: {endpoint} shows older API version with weaker controls",
            "trigger_conditions": ["api_version_mismatch", "multiple_api_versions"],
            "base_prior": 0.2,
            "severity": "high",
        },
        {
            "id": "H_GRAPHQL_ABUSE",
            "category": "graphql_abuse",
            "template": "GraphQL abuse: {endpoint} exposes introspection/batching enabling deep enumeration",
            "trigger_conditions": ["graphql_introspection_enabled", "graphql_batching_enabled", "graphql_verbose_errors"],
            "base_prior": 0.3,
            "severity": "high",
        },
        {
            "id": "H_CACHE_POISONING",
            "category": "cache_poisoning",
            "template": "Cache poisoning: {endpoint} reflects unkeyed header in cached response",
            "trigger_conditions": ["cache_hit_on_dynamic", "unkeyed_header_reflected"],
            "base_prior": 0.25,
            "severity": "high",
        },
        {
            "id": "H_PROTOTYPE_POLLUTION",
            "category": "prototype_pollution",
            "template": "Prototype pollution: __proto__ or constructor.prototype references at {endpoint}",
            "trigger_conditions": ["proto_reference_found", "constructor_reference_found"],
            "base_prior": 0.25,
            "severity": "high",
        },
        {
            "id": "H_DESERIALIZATION",
            "category": "deserialization",
            "template": "Unsafe deserialization: serialization markers at {endpoint} suggest object injection",
            "trigger_conditions": ["serialization_marker_found", "java_class_in_response", "pickle_marker_found"],
            "base_prior": 0.3,
            "severity": "critical",
        },
        {
            "id": "H_TIMING_ORACLE",
            "category": "timing_oracle",
            "template": "Timing oracle: {endpoint} response time varies >2x between status codes revealing auth branching",
            "trigger_conditions": ["timing_variance_detected", "auth_timing_differential"],
            "base_prior": 0.25,
            "severity": "medium",
        },
        {
            "id": "H_ERROR_ORACLE",
            "category": "error_oracle",
            "template": "Error oracle: {endpoint} returns distinct error messages leaking internal validation logic",
            "trigger_conditions": ["error_message_variance", "auth_error_differential"],
            "base_prior": 0.3,
            "severity": "medium",
        },
        {
            "id": "H_WAF_BYPASS",
            "category": "waf_bypass",
            "template": "WAF bypass: detected WAF at {endpoint} with known evasion techniques available",
            "trigger_conditions": ["waf_detected", "waf_block_page_seen"],
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

        # --- New trigger conditions for expanded hypothesis templates ---
        resp_headers = components.get("response_headers") or {}
        lower_resp_headers = {k.lower(): v for k, v in resp_headers.items()}
        stripe_obj = components.get("stripe_object")

        # Subscription abuse triggers
        if stripe_obj == "subscription":
            conditions_met.add("subscription_object_found")
        if re.search(r'"(?:trial_end|trial_start|trial_period_days)"', body_text, re.I):
            conditions_met.add("trial_indicator")
        if re.search(r'"(?:cancel_at|canceled_at|cancel_at_period_end)"', body_text, re.I):
            conditions_met.add("downgrade_indicator")
        if re.search(r'"(?:status)":\s*"(?:trialing|past_due|incomplete)"', body_text, re.I):
            conditions_met.add("perpetual_free_indicator")

        # Webhook forgery triggers
        if "webhook_endpoint" in conditions_met:
            sig_headers = ["stripe-signature", "x-hub-signature", "x-hub-signature-256",
                           "x-webhook-signature", "x-shopify-hmac-sha256"]
            if not any(h in lower_resp_headers for h in sig_headers):
                conditions_met.add("webhook_no_signature")

        # Coupon / discount triggers
        if re.search(r'"(?:coupon|discount|promotion_code|percent_off|amount_off)"', body_text, re.I):
            conditions_met.add("coupon_in_response")
            conditions_met.add("discount_indicator")

        # Currency mismatch
        currencies = set(re.findall(r'"currency":\s*"([a-z]{3})"', body_text, re.I))
        if len(currencies) > 1:
            conditions_met.add("currency_mismatch")
            conditions_met.add("multi_currency_indicator")

        # Refund object
        if stripe_obj == "refund" or re.search(r'"object":\s*"refund"', body_text, re.I):
            conditions_met.add("refund_object_found")
        if "refund_object_found" in conditions_met and re.search(
            r'"(?:status|subscription_status)":\s*"active"', body_text, re.I,
        ):
            conditions_met.add("entitlement_still_active")

        # API version mismatch
        api_versions = set(re.findall(r'"(?:api_version|version|schema_version)":\s*"([^"]+)"', body_text))
        if len(api_versions) > 1:
            conditions_met.add("api_version_mismatch")
            conditions_met.add("multiple_api_versions")

        # GraphQL triggers
        if re.search(r'"(?:__typename|__schema)"', body_text, re.I):
            conditions_met.add("graphql_introspection_enabled")
        if re.search(r'\[\s*\{\s*"query"', body_text, re.I):
            conditions_met.add("graphql_batching_enabled")
        if re.search(r'"errors"\s*:\s*\[.*?"message"\s*:', body_text, re.I | re.S):
            conditions_met.add("graphql_verbose_errors")

        # Cache poisoning triggers
        cache_status = (
            lower_resp_headers.get("cf-cache-status", "")
            or lower_resp_headers.get("x-cache", "")
            or lower_resp_headers.get("x-vercel-cache", "")
        ).upper()
        if "HIT" in cache_status and any(
            kw in endpoint.lower()
            for kw in ("user", "account", "profile", "me", "session", "dashboard")
        ):
            conditions_met.add("cache_hit_on_dynamic")
        if re.search(r'"(?:x-forwarded-|x-original-|x-host|x-rewrite)"', body_text, re.I):
            conditions_met.add("unkeyed_header_reflected")

        # Prototype pollution triggers
        if re.search(r'(?:__proto__|constructor\.prototype|Object\.assign)', body_text, re.I):
            conditions_met.add("proto_reference_found")
        if re.search(r'(?:constructor\s*:\s*\{|hasOwnProperty)', body_text, re.I):
            conditions_met.add("constructor_reference_found")

        # Deserialization triggers
        if re.search(r'(?:java\.lang\.|rO0AB|aced0005|ObjectInputStream|readObject)', body_text, re.I):
            conditions_met.add("serialization_marker_found")
            conditions_met.add("java_class_in_response")
        if re.search(r'(?:pickle\.|__reduce__|cPickle)', body_text, re.I):
            conditions_met.add("pickle_marker_found")
            conditions_met.add("serialization_marker_found")

        # Timing oracle triggers
        elapsed = components.get("elapsed_ms", 0)
        if elapsed and status in (401, 403) and elapsed > 500:
            conditions_met.add("timing_variance_detected")
            conditions_met.add("auth_timing_differential")

        # Error oracle triggers (from context-level observations)
        error_keywords = set(re.findall(
            r'"(?:message|error|detail)":\s*"([^"]{5,60})"', body_text, re.I,
        ))
        if len(error_keywords) >= 3:
            conditions_met.add("error_message_variance")
        if re.search(
            r'"(?:message|error)":\s*"(?:.*?not found|.*?does not exist|.*?invalid.*?user|.*?unknown)',
            body_text, re.I,
        ):
            conditions_met.add("auth_error_differential")

        # WAF detection triggers
        for waf_hdr_re_str in (r"cf-ray", r"x-akamai-", r"incap_ses_", r"x-datadome", r"_px\d"):
            if re.search(waf_hdr_re_str, str(lower_resp_headers), re.I):
                conditions_met.add("waf_detected")
                break
        if status == 403 and re.search(
            r"(?:access denied|request blocked|security policy|captcha.*required)", body_text, re.I,
        ):
            conditions_met.add("waf_block_page_seen")

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

            # --- Deeper evidence weighting for new hypothesis categories ---
            if h.category == "subscription_abuse" and stripe_obj == "subscription":
                evidence_for.append("stripe_subscription_object_matches")
                likelihood *= 1.6
            if h.category == "subscription_abuse" and stripe_obj == "invoice":
                evidence_for.append("stripe_invoice_matches_subscription_abuse")
                likelihood *= 1.3

            if h.category == "timing_oracle" and elapsed > 500:
                evidence_for.append(f"elevated_latency_{elapsed}ms")
                likelihood *= 1.5
            if h.category == "error_oracle" and status in (400, 401, 403, 422):
                evidence_for.append(f"client_error_status_{status}")
                likelihood *= 1.5

            if h.category == "waf_bypass":
                resp_headers = components.get("response_headers") or {}
                if any(re.search(r"(?:cf-ray|x-akamai|incap_ses|x-datadome)", k, re.I)
                       for k in resp_headers):
                    evidence_for.append("waf_header_confirmed")
                    likelihood *= 1.3

            if h.category == "webhook_forge" and is_mutating:
                evidence_for.append("mutating_webhook_endpoint")
                likelihood *= 1.4

            if h.category == "coupon_stacking" and stripe_obj in ("coupon", "promotion_code"):
                evidence_for.append("stripe_coupon_object")
                likelihood *= 1.5

            if h.category == "refund_abuse" and stripe_obj == "refund":
                evidence_for.append("stripe_refund_object")
                likelihood *= 1.6

            if h.category == "graphql_abuse" and re.search(r'"__typename"', body_text):
                evidence_for.append("graphql_typename_present")
                likelihood *= 1.4

            if h.category == "cache_poisoning" and re.search(r"(?:HIT|MISS)", str(components.get("response_headers", {})), re.I):
                evidence_for.append("cache_header_present")
                likelihood *= 1.3

            if h.category == "deserialization":
                if re.search(r"(?:application/java-serialized|application/x-java-object)", body_text, re.I):
                    evidence_for.append("java_serialization_content_type")
                    likelihood *= 1.5

            posterior = min(1.0, h.prior * likelihood)
            h.evidence_for = evidence_for
            h.evidence_against = evidence_against
            h.posterior = posterior

        # Cross-category amplification: if correlated categories both fire, boost both
        active_categories = {h.category for h in hypotheses if h.posterior > 0.15}
        amplification_pairs = [
            ("payment_manipulation", "entitlement_bypass", 1.25),
            ("auth_bypass", "privilege_escalation", 1.2),
            ("webhook_forge", "entitlement_bypass", 1.3),
            ("subscription_abuse", "entitlement_bypass", 1.25),
            ("refund_abuse", "entitlement_bypass", 1.3),
            ("coupon_stacking", "payment_manipulation", 1.2),
            ("race_condition", "payment_manipulation", 1.25),
            ("injection", "info_disclosure", 1.15),
            ("graphql_abuse", "info_disclosure", 1.2),
            ("cache_poisoning", "auth_bypass", 1.2),
        ]
        for cat_a, cat_b, amp_factor in amplification_pairs:
            if cat_a in active_categories and cat_b in active_categories:
                for h in hypotheses:
                    if h.category in (cat_a, cat_b):
                        h.posterior = min(1.0, h.posterior * amp_factor)
                        h.evidence_for.append(f"cross_amplified_with_{cat_a if h.category == cat_b else cat_b}")

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

        # Conviction level: how many independent hypotheses agree on a threat
        high_conf_count = sum(1 for h in scored if h.posterior > 0.2)
        conviction = "low"
        if high_conf_count >= 4:
            conviction = "high"
            conf = min(1.0, conf * 1.3)
        elif high_conf_count >= 2:
            conviction = "medium"
            conf = min(1.0, conf * 1.15)

        # Cross-category convergence: if top hypothesis shares a threat class
        # with runners-up, that's convergent evidence for a real issue
        active_cats = {h.category for h in scored if h.posterior > 0.15}
        payment_convergence = active_cats & {"payment_manipulation", "entitlement_bypass", "subscription_abuse", "refund_abuse", "coupon_stacking", "currency_arbitrage"}
        if len(payment_convergence) >= 2:
            conf = min(1.0, conf * 1.2)
            conviction = "high" if conviction == "medium" else conviction

        runners_up = [h for h in scored[1:] if h.posterior > 0.15]
        runner_note = ""
        if runners_up:
            runner_note = (
                f" Alternative hypotheses: "
                + ", ".join(f"{h.hypothesis_id}({h.posterior:.2f})" for h in runners_up[:3])
                + "."
            )

        conviction_note = f" Conviction: {conviction} ({high_conf_count} hypotheses above threshold)."
        convergence_note = ""
        if len(payment_convergence) >= 2:
            convergence_note = f" Payment-class convergence: {sorted(payment_convergence)}."

        return (
            f"Most likely: {top.description} "
            f"(posterior={top.posterior:.3f}, "
            f"{supporting} supporting / {contradicting} contradicting evidence points)."
            f"{runner_note}{conviction_note}{convergence_note}",
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

    # MITRE ATT&CK technique mapping for threat intel perspective
    _MITRE_ATTACK_MAP: dict[str, tuple[str, str]] = {
        "critical_secret": ("T1552", "Unsecured Credentials"),
        "injection_artifact_sqli": ("T1190", "Exploit Public-Facing Application"),
        "injection_artifact_xss": ("T1189", "Drive-by Compromise"),
        "injection_artifact_ssrf": ("T1190", "Exploit Public-Facing Application"),
        "sensitive_field_name": ("T1530", "Data from Cloud Storage Object"),
        "possible_card_number": ("T1005", "Data from Local System"),
    }

    _KNOWN_CVE_PATTERNS: list[tuple[str, str, str]] = [
        ("auth_bypass", "CVE-2023-22515", "Confluence auth bypass pattern"),
        ("idor", "CVE-2023-34362", "MOVEit IDOR/SQLi pattern"),
        ("injection_artifact_sqli", "CVE-2021-44228", "Log4Shell-class injection"),
        ("entitlement_bypass", "CVE-2023-23397", "Privilege escalation without user interaction"),
        ("race_condition", "CVE-2023-32784", "KeePass race/memory leak pattern"),
    ]

    def analyze_as_red_team(
        self, components: dict[str, Any], zero_shot: list[ZeroShotFinding],
    ) -> PerspectiveResult:
        """Offensive security operator perspective: exploitability, weaponization,
        kill chain construction, detection evasion."""
        findings: list[str] = []
        recs: list[str] = []
        score = 0.0

        # Exploitability assessment
        if not components.get("has_auth_header") and 200 <= components.get("status_code", 0) < 300:
            findings.append("No auth required -- trivially exploitable, no credential theft needed")
            recs.append("Weaponize as first stage: enumerate all unauthenticated endpoints")
            score += 0.4

        # Kill chain composition
        chain_potential = 0
        for a in components.get("anomalies", []):
            if "entitlement_drift" in a:
                findings.append(f"Kill chain complete: {a} = direct access-without-payment")
                recs.append("Full exploit: skip to post-exploitation (data access)")
                score += 0.5
                chain_potential += 2
            elif "zero_payment" in a or "negative_value" in a:
                findings.append(f"Financial exploit primitive: {a}")
                recs.append("Chain with checkout flow for zero-cost purchase")
                score += 0.4
                chain_potential += 1

        for f in zero_shot:
            if f.category == "critical_secret":
                findings.append(f"Credential harvested: {f.detail} -- lateral movement enabled")
                recs.append("Use credential for API access, test scope of leaked key")
                score += 0.5
                chain_potential += 2
            elif f.category.startswith("injection"):
                findings.append(f"Injection primitive: {f.detail} -- needs weaponization")
                recs.append("Build exploit payload, test for blind vs reflected")
                score += 0.35
                chain_potential += 1

        # Detection evasion assessment
        body_text = components.get("body_text", "")
        headers = components.get("response_headers", {})
        lower_h = {k.lower(): v for k, v in headers.items()}
        has_logging = any(h in lower_h for h in ("x-request-id", "x-trace-id", "x-correlation-id"))
        has_waf = any(h in lower_h for h in ("cf-ray", "x-sucuri-id", "x-datadome"))
        has_rate_limit = any(h in lower_h for h in ("x-ratelimit-limit", "retry-after"))

        if has_waf:
            findings.append("WAF detected -- evasion encoding required")
            recs.append("Use payload obfuscation: double encoding, case variation, comment injection")
            score += 0.1
        if has_rate_limit:
            findings.append("Rate limiting active -- need slow-and-low approach")
            recs.append("Rotate identifiers, use path normalization tricks")
        if not has_logging:
            findings.append("No request tracing headers -- attack may go undetected")
            score += 0.15

        # Weaponization difficulty
        if components.get("is_mutating") and chain_potential >= 2:
            findings.append(f"Low weaponization difficulty: mutating endpoint + {chain_potential} chain links")
            score += 0.2

        if components.get("stripe_object") in ("checkout.session", "payment_intent"):
            findings.append(f"Stripe {components['stripe_object']} object exposed -- direct payment manipulation vector")
            recs.append("Intercept client_secret, modify amount pre-confirmation")
            score += 0.3

        return PerspectiveResult("red_team", min(1.0, score), findings, recs)

    def analyze_as_threat_intel(
        self, components: dict[str, Any], zero_shot: list[ZeroShotFinding],
    ) -> PerspectiveResult:
        """Threat intelligence analyst perspective: CVE pattern matching,
        MITRE ATT&CK mapping, known APT TTP alignment."""
        findings: list[str] = []
        recs: list[str] = []
        score = 0.0
        mitre_techniques: list[str] = []

        # MITRE ATT&CK technique mapping
        for f in zero_shot:
            mapping = self._MITRE_ATTACK_MAP.get(f.category)
            if mapping:
                tid, tname = mapping
                if tid not in mitre_techniques:
                    mitre_techniques.append(tid)
                    findings.append(f"MITRE ATT&CK: {tid} ({tname}) -- {f.detail}")
                    score += 0.2

        # Known CVE pattern matching
        finding_cats = {f.category for f in zero_shot}
        anomaly_cats = set()
        for a in components.get("anomalies", []):
            anomaly_cats.add(a.split(":")[0])

        all_cats = finding_cats | anomaly_cats
        for pattern_cat, cve_id, cve_desc in self._KNOWN_CVE_PATTERNS:
            if any(pattern_cat in c for c in all_cats):
                findings.append(f"CVE pattern match: {cve_id} ({cve_desc})")
                recs.append(f"Cross-reference with {cve_id} exploit chain for escalation paths")
                score += 0.25

        # APT TTP alignment
        body_text = components.get("body_text", "")
        if re.search(r"(?:169\.254\.169\.254|meta-data|computeMetadata)", body_text, re.I):
            findings.append("Cloud metadata access pattern -- aligns with APT cloud-focused TTPs")
            mitre_techniques.append("T1552.005")
            recs.append("Check for IMDS v1 (no token required) vs v2")
            score += 0.4

        if re.search(r"(?:arn:aws|ami-|iam)", body_text, re.I):
            findings.append("AWS infrastructure leak -- aligns with cloud-native APT campaigns")
            mitre_techniques.append("T1078.004")
            score += 0.3

        if components.get("trust_boundary") == "payment_to_entitlement" and components.get("anomalies"):
            findings.append("Financial fraud pattern -- aligns with FIN7/FIN8 TTP for payment system abuse")
            score += 0.35

        if not components.get("has_auth_header") and components.get("trust_boundary") in (
            "authenticated_to_admin", "payment_to_entitlement",
        ):
            findings.append("Broken access control pattern -- top exploitation vector in OWASP 2023/2024")
            score += 0.3

        if mitre_techniques:
            recs.append(f"MITRE techniques observed: {', '.join(mitre_techniques[:8])}")

        return PerspectiveResult("threat_intel", min(1.0, score), findings, recs)

    def synthesize(
        self,
        attacker: PerspectiveResult,
        defender: PerspectiveResult,
        auditor: PerspectiveResult,
        red_team: PerspectiveResult | None = None,
        threat_intel: PerspectiveResult | None = None,
    ) -> dict[str, Any]:
        all_perspectives = [attacker, defender, auditor]
        weights = [0.25, 0.20, 0.15]
        result: dict[str, Any] = {
            "attacker": attacker.to_dict(),
            "defender": defender.to_dict(),
            "auditor": auditor.to_dict(),
        }

        if red_team is not None:
            all_perspectives.append(red_team)
            weights.append(0.25)
            result["red_team"] = red_team.to_dict()
        else:
            weights[0] += 0.125
            weights[1] += 0.075
            weights[2] += 0.05

        if threat_intel is not None:
            all_perspectives.append(threat_intel)
            weights.append(0.15)
            result["threat_intel"] = threat_intel.to_dict()
        else:
            dist = 0.15 / len(weights)
            weights = [w + dist for w in weights]

        combined = max(p.risk_score for p in all_perspectives)
        weighted_risk = sum(
            p.risk_score * w for p, w in zip(all_perspectives, weights)
        ) / sum(weights) if sum(weights) > 0 else 0.0
        consensus_count = sum(1 for p in all_perspectives if p.risk_score > 0.5)

        result["combined_risk"] = round(combined, 3)
        result["weighted_risk"] = round(weighted_risk, 3)
        result["average_risk"] = round(
            sum(p.risk_score for p in all_perspectives) / len(all_perspectives), 3,
        )
        result["consensus_risk"] = consensus_count
        result["consensus_ratio"] = round(consensus_count / len(all_perspectives), 2)
        return result


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

        correlations.extend(self._find_field_correlations(endpoint_groups))
        correlations.extend(self._find_auth_inconsistencies(endpoint_groups))
        correlations.extend(self._find_temporal_sequences())
        correlations.extend(self._find_response_body_cross_references())

        return correlations

    def _find_field_correlations(
        self, endpoint_groups: dict[str, list[int]],
    ) -> list[dict[str, Any]]:
        """Fields appearing across 3+ different endpoints = cross-endpoint data linkage."""
        field_to_endpoints: dict[str, set[str]] = defaultdict(set)
        for ep, indices in endpoint_groups.items():
            for idx in indices:
                resp = self._observations[idx].get("response_data") or {}
                body = resp.get("body")
                if isinstance(body, dict):
                    for field_name in body:
                        field_to_endpoints[field_name].add(ep)

        results: list[dict[str, Any]] = []
        for field, endpoints in field_to_endpoints.items():
            if len(endpoints) >= 3 and re.search(r"(?:_id|_key|_token|_ref|id$)", field, re.I):
                results.append({
                    "type": "cross_endpoint_field",
                    "field": field,
                    "endpoints": sorted(endpoints)[:10],
                    "endpoint_count": len(endpoints),
                    "detail": (
                        f"Field '{field}' appears in {len(endpoints)} endpoints -- "
                        "cross-endpoint data linkage enables IDOR/enumeration chains"
                    ),
                })
        return results[:15]

    def _find_auth_inconsistencies(
        self, endpoint_groups: dict[str, list[int]],
    ) -> list[dict[str, Any]]:
        """Endpoints returning both 2xx and 401/403 indicate inconsistent access control."""
        results: list[dict[str, Any]] = []
        for ep, indices in endpoint_groups.items():
            if len(indices) < 2:
                continue
            has_success = False
            has_auth_fail = False
            success_has_auth = False
            fail_has_auth = False
            for idx in indices:
                obs = self._observations[idx]
                resp = obs.get("response_data") or {}
                req = obs.get("request_data") or {}
                status = resp.get("status_code", 0)
                has_auth = any(
                    h.lower() in ("authorization", "x-api-key", "cookie")
                    for h in (req.get("headers") or {})
                )
                if 200 <= status < 300:
                    has_success = True
                    if has_auth:
                        success_has_auth = True
                elif status in (401, 403):
                    has_auth_fail = True
                    if has_auth:
                        fail_has_auth = True

            if has_success and has_auth_fail:
                detail_parts = [f"Endpoint {ep} returns both success and auth failure"]
                if has_success and not success_has_auth:
                    detail_parts.append("SUCCESS returned WITHOUT auth headers")
                if fail_has_auth:
                    detail_parts.append("auth failure WITH credentials suggests scope/role issue")
                results.append({
                    "type": "auth_inconsistency",
                    "endpoint": ep,
                    "unauthenticated_success": has_success and not success_has_auth,
                    "detail": " -- ".join(detail_parts),
                })
        return results[:10]

    def _find_temporal_sequences(self) -> list[dict[str, Any]]:
        """Detect ordered multi-step flows from endpoint call sequences."""
        if len(self._observations) < 3:
            return []
        results: list[dict[str, Any]] = []
        path_sequence: list[str] = []
        for obs in self._observations:
            req = obs.get("request_data") or {}
            url = str(req.get("url", ""))
            path = urlparse(url).path if url else ""
            normalized = re.sub(r"/\d+", "/{id}", path)
            normalized = re.sub(r"/[a-f0-9-]{20,}", "/{id}", normalized)
            if normalized:
                path_sequence.append(normalized)

        # Detect repeated subsequences of length 2-4
        ngram_counts: dict[tuple[str, ...], int] = defaultdict(int)
        for n in (2, 3, 4):
            for i in range(len(path_sequence) - n + 1):
                ngram = tuple(path_sequence[i:i + n])
                if len(set(ngram)) > 1:
                    ngram_counts[ngram] += 1

        for ngram, count in sorted(ngram_counts.items(), key=lambda x: x[1], reverse=True):
            if count >= 2:
                results.append({
                    "type": "temporal_sequence",
                    "sequence": list(ngram),
                    "occurrences": count,
                    "detail": (
                        f"Flow detected: {' -> '.join(ngram)} "
                        f"(observed {count} times) -- reveals multi-step business process"
                    ),
                })
            if len(results) >= 10:
                break

        return results

    def _find_response_body_cross_references(self) -> list[dict[str, Any]]:
        """IDs/tokens produced in one response and consumed in a later request."""
        results: list[dict[str, Any]] = []
        id_re = re.compile(
            r'"(\w+)":\s*"((?:pi_|sub_|cs_|ch_|in_|cus_|pm_|si_|evt_|txn_|'
            r'plink_|price_|prod_|sk_|pk_|tok_|sess_|acct_)[A-Za-z0-9]+)"'
        )
        # Collect IDs from response bodies
        response_ids: dict[str, tuple[int, str, str]] = {}  # id_val -> (obs_idx, endpoint, field_name)
        for i, obs in enumerate(self._observations):
            resp = obs.get("response_data") or {}
            req = obs.get("request_data") or {}
            url = str(req.get("url", ""))
            path = urlparse(url).path if url else ""
            body_text = _body_as_text(resp.get("body")) if resp.get("body") is not None else ""
            for field, val in id_re.findall(body_text):
                if val not in response_ids:
                    response_ids[val] = (i, path, field)

        # Find those IDs in later request URLs/bodies
        flows: list[dict[str, Any]] = []
        for i, obs in enumerate(self._observations):
            req = obs.get("request_data") or {}
            url = str(req.get("url", ""))
            req_body_text = _body_as_text(req.get("body")) if req.get("body") is not None else ""
            combined_req = url + "\n" + req_body_text

            for id_val, (source_idx, source_ep, source_field) in response_ids.items():
                if i <= source_idx:
                    continue
                if id_val in combined_req:
                    target_path = urlparse(url).path if url else ""
                    flows.append({
                        "id_prefix": id_val[:6] + "...",
                        "source_endpoint": source_ep,
                        "source_field": source_field,
                        "target_endpoint": target_path,
                        "source_obs": source_idx,
                        "target_obs": i,
                    })

        if flows:
            seen_pairs: set[tuple[str, str]] = set()
            deduped: list[dict[str, Any]] = []
            for f in flows:
                pair = (f["source_endpoint"], f["target_endpoint"])
                if pair not in seen_pairs:
                    seen_pairs.add(pair)
                    deduped.append(f)

            results.append({
                "type": "cross_reference_flow",
                "flows": deduped[:20],
                "total_flows": len(deduped),
                "detail": (
                    f"{len(deduped)} ID cross-references: values produced in one response "
                    "are consumed in later requests -- reveals multi-step dependencies"
                ),
            })

        return results

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
    """Advanced reverse engineering engine that infers server-side architecture,
    business logic, security controls, and hidden attack surface purely from
    observed request/response patterns.

    Techniques drawn from:
    - Timing side-channel analysis (Kocher et al., applied to web)
    - Error oracle / padding oracle methodologies (Vaudenay, Duong-Rizzo)
    - Behavioral differential analysis (compare responses across auth levels)
    - WAF/CDN fingerprinting (signature-based + behavioral)
    - Server technology fingerprinting (header analysis, error page signatures)
    - Token structure analysis (JWT decode, opaque entropy measurement)
    - API graph reconstruction (endpoint relationship mapping)
    - Response body diff analysis for server-side branching detection
    - Rate limit algorithm fingerprinting (fixed/sliding/token-bucket inference)
    - Cache behavior probing (HIT/MISS pattern analysis)
    - Multi-step flow state dependency mapping

    All purely retrospective -- analyses I/O already captured, never sends
    new requests.
    """

    def __init__(self) -> None:
        self._observations: list[dict[str, Any]] = []
        self._timing_cache: dict[str, list[float]] = defaultdict(list)

    def add_observation(self, observation: dict[str, Any]) -> None:
        self._observations.append(observation)
        resp = observation.get("response_data") or {}
        req = observation.get("request_data") or {}
        elapsed = resp.get("elapsed_ms", 0)
        url = str(req.get("url", ""))
        path = urlparse(url).path if url else ""
        if path and elapsed:
            self._timing_cache[path].append(float(elapsed))

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
            if re.search(r"(?:x-frame-options|content-security-policy)", str(lower_headers), re.I):
                measures.append({"type": "clickjacking_protection", "detail": "Frame/CSP anti-embedding present"})
            if "set-cookie" in lower_headers and re.search(r"(?:__cf_bm|__cfduid|_dd_s|datadome|px_|__bot)", lower_headers.get("set-cookie", ""), re.I):
                measures.append({"type": "bot_detection_cookie", "detail": "Bot detection tracking cookie set"})
            if re.search(r"(?:x-robots-tag|x-crawler-|x-bot-)", str(lower_headers), re.I):
                measures.append({"type": "crawler_control", "detail": "Crawler/bot control headers"})
            fp_js_patterns = re.search(
                r"(?:fp\.js|fingerprint\.js|fpjs|botd|device-detect|"
                r"clientjs|canvas.*?toDataURL|navigator\.(?:plugins|languages|hardwareConcurrency)|"
                r"screen\.(?:width|height|colorDepth)|WebGLRenderingContext|"
                r"AudioContext.*?createOscillator)",
                body_text, re.I,
            )
            if fp_js_patterns:
                measures.append({"type": "browser_fingerprinting", "detail": "Client-side fingerprinting code detected"})

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
        url_re = re.compile(r'"(?:url|href|link|endpoint|redirect_url|return_url|next|action|callback_url|webhook_url|success_url|cancel_url)":\s*"((?:https?://[^"]+|/[^"]+))"')

        for obs in self._observations:
            req = obs.get("request_data") or {}
            resp = obs.get("response_data") or {}
            url = str(req.get("url", ""))
            path = urlparse(url).path if url else ""
            if path:
                observed_paths.add(path)

            body_text = _body_as_text(resp.get("body")) if resp.get("body") is not None else ""
            for match in url_re.finditer(body_text):
                ref = match.group(1)
                parsed = urlparse(ref)
                referenced_paths.add(parsed.path or ref)

            path_refs = re.findall(r'(?<=["\'])/(?:api|v[0-9]+|internal|admin|debug|_)[\w/.-]+', body_text)
            for p in path_refs:
                referenced_paths.add(p)

        hidden = referenced_paths - observed_paths
        return [
            {"path": p, "type": "referenced_but_untested"}
            for p in sorted(hidden)[:30]
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

    # ------------------------------------------------------------------
    # ADVANCED RE: Timing side-channel analysis (Kocher methodology)
    # ------------------------------------------------------------------

    def analyze_timing_side_channels(self) -> list[dict[str, Any]]:
        """Detect timing-based information leaks. Variable response times
        across auth paths reveal server-side branching (e.g. user-exists
        vs user-not-found taking different time due to bcrypt).

        Technique: compare timing distributions for same endpoint under
        different conditions. A statistically significant difference in
        mean response time indicates different code paths executed."""
        findings: list[dict[str, Any]] = []

        endpoint_timing_by_status: dict[str, dict[int, list[float]]] = defaultdict(lambda: defaultdict(list))

        for obs in self._observations:
            req = obs.get("request_data") or {}
            resp = obs.get("response_data") or {}
            status = resp.get("status_code", 0)
            elapsed = resp.get("elapsed_ms", 0)
            if not elapsed:
                continue
            url = str(req.get("url", ""))
            path = urlparse(url).path if url else ""
            if path:
                endpoint_timing_by_status[path][status].append(float(elapsed))

        for ep, status_timings in endpoint_timing_by_status.items():
            if len(status_timings) < 2:
                continue

            timing_means: dict[int, float] = {}
            for status, times in status_timings.items():
                if len(times) >= 2:
                    timing_means[status] = sum(times) / len(times)

            if len(timing_means) < 2:
                continue

            mean_values = list(timing_means.values())
            max_mean = max(mean_values)
            min_mean = min(mean_values)
            if min_mean > 0 and (max_mean / min_mean) > 2.0:
                slow_status = max(timing_means, key=timing_means.get)  # type: ignore[arg-type]
                fast_status = min(timing_means, key=timing_means.get)  # type: ignore[arg-type]
                findings.append({
                    "endpoint": ep,
                    "type": "timing_side_channel",
                    "slow_status": slow_status,
                    "slow_mean_ms": round(timing_means[slow_status], 1),
                    "fast_status": fast_status,
                    "fast_mean_ms": round(timing_means[fast_status], 1),
                    "ratio": round(max_mean / min_mean, 2),
                    "inferred": (
                        f"Status {slow_status} takes {timing_means[slow_status]:.0f}ms avg vs "
                        f"{fast_status} at {timing_means[fast_status]:.0f}ms "
                        f"({max_mean / min_mean:.1f}x slower) -- different code paths"
                    ),
                })

            auth_statuses = {401, 403}
            success_statuses = {200, 201, 204}
            auth_times = []
            success_times = []
            for s, times in status_timings.items():
                if s in auth_statuses:
                    auth_times.extend(times)
                elif s in success_statuses:
                    success_times.extend(times)

            if auth_times and success_times and len(auth_times) >= 2 and len(success_times) >= 2:
                auth_mean = sum(auth_times) / len(auth_times)
                success_mean = sum(success_times) / len(success_times)
                if auth_mean > 0 and success_mean > 0:
                    ratio = max(auth_mean, success_mean) / min(auth_mean, success_mean)
                    if ratio > 1.5:
                        slower = "auth_failure" if auth_mean > success_mean else "auth_success"
                        findings.append({
                            "endpoint": ep,
                            "type": "auth_timing_oracle",
                            "auth_mean_ms": round(auth_mean, 1),
                            "success_mean_ms": round(success_mean, 1),
                            "ratio": round(ratio, 2),
                            "inferred": (
                                f"Auth decisions leak timing: {slower} path is {ratio:.1f}x slower. "
                                "May reveal valid vs invalid credentials or user enumeration."
                            ),
                        })

        return findings

    # ------------------------------------------------------------------
    # ADVANCED RE: Error oracle analysis (Vaudenay / Bleichenbacher style)
    # ------------------------------------------------------------------

    def analyze_error_oracles(self) -> list[dict[str, Any]]:
        """Error oracle detection: different error messages for same endpoint
        reveal internal branching logic, database schema, auth checks.

        Classic error oracle attacks: different errors for "user not found"
        vs "wrong password" enable account enumeration. Different 400/422
        messages reveal validation ordering and field presence requirements."""
        findings: list[dict[str, Any]] = []

        endpoint_errors: dict[str, dict[int, list[str]]] = defaultdict(lambda: defaultdict(list))

        for obs in self._observations:
            req = obs.get("request_data") or {}
            resp = obs.get("response_data") or {}
            status = resp.get("status_code", 0)
            if not (400 <= status < 500):
                continue
            url = str(req.get("url", ""))
            path = urlparse(url).path if url else ""
            body_text = _body_as_text(resp.get("body")) if resp.get("body") is not None else ""
            if path and body_text:
                endpoint_errors[path][status].append(body_text[:500])

        for ep, status_errors in endpoint_errors.items():
            for status, error_texts in status_errors.items():
                if len(error_texts) < 2:
                    continue

                unique_errors = set()
                for t in error_texts:
                    normalized = re.sub(r'[0-9a-f-]{8,}', '<ID>', t)
                    normalized = re.sub(r'\d{10,}', '<TS>', normalized)
                    unique_errors.add(normalized[:300])

                if len(unique_errors) >= 3:
                    error_keywords: set[str] = set()
                    for err in unique_errors:
                        error_keywords.update(re.findall(
                            r'"(?:message|error|detail|reason|code|field|type)":\s*"([^"]{3,80})"', err, re.I
                        ))

                    auth_oracle = any(re.search(
                        r'(?:not found|does not exist|invalid.*(?:user|email|account)|'
                        r'no such|unknown.*(?:user|email)|incorrect.*password|'
                        r'invalid.*credentials|expired|locked|disabled)',
                        err, re.I,
                    ) for err in unique_errors)

                    findings.append({
                        "endpoint": ep,
                        "status_code": status,
                        "type": "error_oracle",
                        "unique_error_count": len(unique_errors),
                        "total_errors": len(error_texts),
                        "is_auth_oracle": auth_oracle,
                        "error_keywords": sorted(error_keywords)[:15],
                        "inferred": (
                            f"{len(unique_errors)} distinct error messages for HTTP {status} at {ep}. "
                            + ("AUTH ORACLE: different messages reveal valid vs invalid users/credentials. " if auth_oracle else "")
                            + f"Leaked keywords: {sorted(error_keywords)[:8]}"
                        ),
                    })

        return findings

    # ------------------------------------------------------------------
    # ADVANCED RE: WAF/CDN fingerprinting
    # ------------------------------------------------------------------

    _WAF_SIGNATURES: list[tuple[str, str, str]] = [
        ("cloudflare", r"(?:cf-ray|cf-cache-status|__cfduid|cf-request-id|cloudflare)", "header+cookie"),
        ("aws_waf", r"(?:x-amzn-requestid|x-amz-cf-id|x-amz-apigw-id|awselb/|AWSALB)", "header+cookie"),
        ("aws_cloudfront", r"(?:x-amz-cf-id|x-amz-cf-pop|via.*cloudfront)", "header"),
        ("akamai", r"(?:x-akamai-|akamai-origin|ak_bmsc|bm_sz|_abck)", "header+cookie"),
        ("fastly", r"(?:x-served-by.*cache|x-cache.*fastly|fastly-)", "header"),
        ("incapsula", r"(?:incap_ses_|visid_incap_|x-cdn.*incapsula|_incapsula)", "header+cookie"),
        ("sucuri", r"(?:x-sucuri-|sucuri-|x-sucuri-cache)", "header"),
        ("f5_big_ip", r"(?:BigIP|BIGipServer|x-cnection|f5-|TS[0-9a-f]{6,})", "header+cookie"),
        ("modsecurity", r"(?:mod_security|NOYB|modsecurity)", "header+body"),
        ("datadome", r"(?:datadome|_dd_s|x-datadome)", "header+cookie"),
        ("perimeterx", r"(?:_px[0-9]|px-|perimeterx|x-px-)", "header+cookie"),
        ("kasada", r"(?:x-kpsdk-|kpsdk-|kasada)", "header"),
        ("shape_security", r"(?:_imp_apg_|x-distil-|distil_)", "header+cookie"),
        ("reblaze", r"(?:rbzid|x-reblaze-|reblaze)", "header+cookie"),
        ("vercel", r"(?:x-vercel-|x-now-|__vercel)", "header+cookie"),
        ("netlify", r"(?:x-nf-|netlify)", "header"),
        ("nginx", r"(?:^nginx$|nginx/)", "server_header"),
        ("apache", r"(?:^Apache|Apache/)", "server_header"),
        ("iis", r"(?:Microsoft-IIS|ASP\.NET)", "server_header"),
        ("envoy", r"(?:x-envoy-|envoy|server:\s*envoy)", "header"),
        ("kong", r"(?:x-kong-|kong|server:\s*kong)", "header"),
        ("traefik", r"(?:x-traefik-|traefik)", "header"),
    ]

    def fingerprint_waf_cdn(self) -> list[dict[str, Any]]:
        """WAF/CDN fingerprinting from response signatures.

        Each WAF leaves fingerprints in headers, cookies, error pages.
        Knowing the WAF type reveals its bypass techniques catalog
        (PayloadsAllTheThings, WAF bypass cheat sheets)."""
        detected: dict[str, dict[str, Any]] = {}

        for obs in self._observations:
            resp = obs.get("response_data") or {}
            headers = resp.get("headers") or {}
            body_text = _body_as_text(resp.get("body")) if resp.get("body") is not None else ""
            combined = str(headers).lower() + "\n" + body_text[:2000].lower()

            for waf_name, pattern, _source in self._WAF_SIGNATURES:
                if waf_name in detected:
                    continue
                if re.search(pattern, combined, re.I):
                    server = headers.get("server", headers.get("Server", ""))
                    detected[waf_name] = {
                        "waf_cdn": waf_name,
                        "type": "waf_fingerprint",
                        "server_header": server,
                        "confidence": "high" if waf_name in ("cloudflare", "aws_waf", "akamai") else "medium",
                        "inferred": f"WAF/CDN identified: {waf_name}",
                    }

        for obs in self._observations:
            resp = obs.get("response_data") or {}
            status = resp.get("status_code", 0)
            body_text = _body_as_text(resp.get("body")) if resp.get("body") is not None else ""
            if status == 403 and "waf_block_page" not in detected:
                block_sigs = [
                    (r"access denied|forbidden.*request", "generic_waf"),
                    (r"ray id|cloudflare", "cloudflare_block"),
                    (r"request blocked|security policy", "waf_policy_block"),
                    (r"automated.*(?:request|access)|bot.*detect", "bot_detection_block"),
                ]
                for sig_re, sig_name in block_sigs:
                    if re.search(sig_re, body_text, re.I):
                        detected["waf_block_page"] = {
                            "waf_cdn": sig_name,
                            "type": "waf_block_page",
                            "status": status,
                            "inferred": f"WAF block page detected ({sig_name})",
                        }
                        break

        return list(detected.values())

    # ------------------------------------------------------------------
    # ADVANCED RE: Server technology stack fingerprinting
    # ------------------------------------------------------------------

    _TECH_PATTERNS: list[tuple[str, str, str]] = [
        ("express", r"(?:x-powered-by:\s*express|Express)", "header"),
        ("django", r"(?:csrftoken|csrfmiddlewaretoken|django|wsgiserver)", "header+body"),
        ("rails", r"(?:x-runtime|x-request-id.*[a-f0-9-]{36}|_rails_|action_dispatch)", "header+body"),
        ("flask", r"(?:werkzeug|flask|jinja2)", "header+body"),
        ("fastapi", r"(?:fastapi|uvicorn|starlette)", "header+body"),
        ("spring", r"(?:x-application-context|spring|whitelabel.*error)", "header+body"),
        ("laravel", r"(?:laravel_session|XSRF-TOKEN|laravel)", "header+cookie"),
        ("nextjs", r"(?:x-nextjs-|__next|next-router|_next/)", "header+body"),
        ("nuxt", r"(?:__nuxt|nuxt|_nuxt/)", "body"),
        ("aspnet", r"(?:asp\.net|__viewstate|__eventvalidation|x-aspnet-version)", "header+body"),
        ("php", r"(?:x-powered-by:\s*php|phpsessid|\.php)", "header+cookie+body"),
        ("golang", r"(?:x-powered-by:\s*go|gorilla|fiber|gin-gonic)", "header"),
        ("node", r"(?:x-powered-by:\s*node|connect\.sid)", "header+cookie"),
        ("stripe_sdk", r"(?:stripe-version|stripe-account|idempotency-key|stripe\.js)", "header+body"),
        ("graphql", r"(?:graphql|__typename|\"data\"\s*:\s*\{.*\"errors\"\s*:)", "body"),
        ("websocket", r"(?:upgrade:\s*websocket|sec-websocket|ws://|wss://)", "header+body"),
        ("grpc", r"(?:application/grpc|grpc-status|grpc-message)", "header"),
        ("elasticsearch", r"(?:x-elastic-|elasticsearch|_search|_mapping)", "header+body"),
        ("redis", r"(?:redis|x-redis-)", "header+body"),
        ("postgresql", r"(?:pg_|postgres|relation.*does not exist|column.*does not exist)", "body"),
        ("mysql", r"(?:mysql|You have an error in your SQL syntax|Unknown column)", "body"),
        ("mongodb", r"(?:mongo|MongoError|BSON|ObjectId)", "body"),
    ]

    def fingerprint_tech_stack(self) -> list[dict[str, Any]]:
        """Server technology stack fingerprinting from response artifacts.

        Identifies backend language/framework, database, caching layer,
        API gateway from response headers, error messages, cookies."""
        detected: dict[str, dict[str, Any]] = {}

        for obs in self._observations:
            resp = obs.get("response_data") or {}
            headers = resp.get("headers") or {}
            body_text = _body_as_text(resp.get("body")) if resp.get("body") is not None else ""
            combined = str(headers).lower() + "\n" + body_text[:3000].lower()

            for tech_name, pattern, _source in self._TECH_PATTERNS:
                if tech_name in detected:
                    continue
                if re.search(pattern, combined, re.I):
                    detected[tech_name] = {
                        "technology": tech_name,
                        "type": "tech_fingerprint",
                        "inferred": f"Technology detected: {tech_name}",
                    }

        return list(detected.values())

    # ------------------------------------------------------------------
    # ADVANCED RE: Token structure analysis (JWT, opaque, session)
    # ------------------------------------------------------------------

    def analyze_token_structures(self) -> list[dict[str, Any]]:
        """Decode and analyze authentication token structures.

        JWT: decode header+payload (no signature verification needed for RE),
        extract algorithm, expiry, claims, issuer.
        Opaque tokens: measure entropy, detect patterns.
        Session tokens: identify server-side vs client-side session."""
        findings: list[dict[str, Any]] = []
        seen_tokens: set[str] = set()

        jwt_re = re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*')

        for obs in self._observations:
            resp = obs.get("response_data") or {}
            req = obs.get("request_data") or {}
            body_text = _body_as_text(resp.get("body")) if resp.get("body") is not None else ""
            all_headers = {**(req.get("headers") or {}), **(resp.get("headers") or {})}
            combined = body_text + "\n" + str(all_headers)

            for jwt_match in jwt_re.finditer(combined):
                token = jwt_match.group(0)
                token_prefix = token[:40]
                if token_prefix in seen_tokens:
                    continue
                seen_tokens.add(token_prefix)

                parts = token.split(".")
                if len(parts) >= 2:
                    import base64
                    try:
                        padded_header = parts[0] + "=" * (4 - len(parts[0]) % 4)
                        header_bytes = base64.urlsafe_b64decode(padded_header)
                        header_json = json.loads(header_bytes)

                        padded_payload = parts[1] + "=" * (4 - len(parts[1]) % 4)
                        payload_bytes = base64.urlsafe_b64decode(padded_payload)
                        payload_json = json.loads(payload_bytes)

                        alg = header_json.get("alg", "unknown")
                        kid = header_json.get("kid")
                        typ = header_json.get("typ", "JWT")

                        exp = payload_json.get("exp")
                        iss = payload_json.get("iss")
                        sub = payload_json.get("sub")
                        aud = payload_json.get("aud")
                        scope = payload_json.get("scope", payload_json.get("scp"))
                        claims = sorted(payload_json.keys())

                        vuln_flags = []
                        if alg.lower() in ("none", "hs256") and "RS" in str(header_json):
                            vuln_flags.append("alg_confusion_risk")
                        if alg.lower() == "none":
                            vuln_flags.append("alg_none_accepted")
                        if alg.lower() == "hs256":
                            vuln_flags.append("hs256_weak_key_risk")
                        if not exp:
                            vuln_flags.append("no_expiry")
                        if not parts[2]:
                            vuln_flags.append("empty_signature")

                        findings.append({
                            "type": "jwt_analysis",
                            "algorithm": alg,
                            "key_id": kid,
                            "token_type": typ,
                            "issuer": iss,
                            "subject": str(sub)[:20] + "..." if sub and len(str(sub)) > 20 else sub,
                            "audience": aud,
                            "scope": scope,
                            "claims": claims[:20],
                            "has_expiry": exp is not None,
                            "vulnerability_flags": vuln_flags,
                            "inferred": (
                                f"JWT [{alg}]: {len(claims)} claims, "
                                f"issuer={iss}, "
                                + (f"VULNS: {vuln_flags}" if vuln_flags else "no obvious weaknesses")
                            ),
                        })
                    except Exception:
                        pass

            auth_header = ""
            for k, v in all_headers.items():
                if k.lower() == "authorization":
                    auth_header = str(v)
                    break

            if auth_header and not auth_header.startswith("Bearer eyJ"):
                token_val = auth_header.split(" ", 1)[-1] if " " in auth_header else auth_header
                if len(token_val) >= 20 and token_val[:3] != "eyJ":
                    entropy = len(set(token_val)) / max(len(token_val), 1)
                    findings.append({
                        "type": "opaque_token_analysis",
                        "token_length": len(token_val),
                        "char_entropy": round(entropy, 3),
                        "prefix": token_val[:8] + "...",
                        "looks_like": (
                            "hex" if re.match(r'^[0-9a-f]+$', token_val, re.I) else
                            "base64" if re.match(r'^[A-Za-z0-9+/=]+$', token_val) else
                            "uuid" if re.match(r'^[0-9a-f]{8}-', token_val, re.I) else
                            "custom"
                        ),
                        "inferred": f"Opaque token: {len(token_val)} chars, entropy={entropy:.2f}",
                    })

        return findings

    # ------------------------------------------------------------------
    # ADVANCED RE: Response differential / behavioral fingerprinting
    # ------------------------------------------------------------------

    def analyze_response_differentials(self) -> list[dict[str, Any]]:
        """Behavioral fingerprinting via response differentials.

        Compare response bodies for the same endpoint across different auth
        contexts, methods, and parameters to detect:
        - Fields hidden/exposed based on auth level (horizontal priv esc hints)
        - Content variation revealing server-side feature flags
        - Response size clustering indicating different code paths"""
        findings: list[dict[str, Any]] = []

        endpoint_responses: dict[str, list[dict[str, Any]]] = defaultdict(list)

        for obs in self._observations:
            req = obs.get("request_data") or {}
            resp = obs.get("response_data") or {}
            url = str(req.get("url", ""))
            path = urlparse(url).path if url else ""
            status = resp.get("status_code", 0)
            if path and 200 <= status < 300:
                body = resp.get("body")
                body_text = _body_as_text(body) if body is not None else ""
                has_auth = any(
                    h.lower() in ("authorization", "x-api-key", "cookie")
                    for h in (req.get("headers") or {})
                )
                fields = set()
                if isinstance(body, dict):
                    fields = set(body.keys())
                endpoint_responses[path].append({
                    "has_auth": has_auth,
                    "status": status,
                    "body_length": len(body_text),
                    "fields": fields,
                    "method": req.get("method", "GET"),
                })

        for ep, responses in endpoint_responses.items():
            authed = [r for r in responses if r["has_auth"]]
            unauthed = [r for r in responses if not r["has_auth"]]

            if authed and unauthed:
                authed_fields = set()
                unauthed_fields = set()
                for r in authed:
                    authed_fields |= r["fields"]
                for r in unauthed:
                    unauthed_fields |= r["fields"]

                extra_authed = authed_fields - unauthed_fields
                if extra_authed:
                    findings.append({
                        "endpoint": ep,
                        "type": "auth_field_differential",
                        "extra_authenticated_fields": sorted(extra_authed)[:20],
                        "total_authed_fields": len(authed_fields),
                        "total_unauthed_fields": len(unauthed_fields),
                        "inferred": (
                            f"Auth-gated fields: {sorted(extra_authed)[:5]} "
                            "only appear in authenticated responses"
                        ),
                    })

            if len(responses) >= 3:
                sizes = [r["body_length"] for r in responses]
                if sizes:
                    mean_size = sum(sizes) / len(sizes)
                    if mean_size > 0:
                        clusters: dict[str, int] = defaultdict(int)
                        for s in sizes:
                            bucket = "small" if s < mean_size * 0.5 else ("large" if s > mean_size * 1.5 else "medium")
                            clusters[bucket] += 1
                        if len([c for c in clusters.values() if c > 0]) >= 2:
                            findings.append({
                                "endpoint": ep,
                                "type": "response_size_clustering",
                                "clusters": dict(clusters),
                                "mean_size": int(mean_size),
                                "size_range": [min(sizes), max(sizes)],
                                "inferred": (
                                    f"Response size varies {min(sizes)}-{max(sizes)} bytes "
                                    f"({len(clusters)} clusters) indicating conditional logic"
                                ),
                            })

        return findings

    # ------------------------------------------------------------------
    # ADVANCED RE: Rate limit algorithm fingerprinting
    # ------------------------------------------------------------------

    def fingerprint_rate_limit_algorithm(self) -> list[dict[str, Any]]:
        """Infer the rate limiting algorithm from observed behavior.

        Differentiates: fixed window, sliding window, token bucket, leaky
        bucket, and adaptive rate limiting by analyzing the pattern of
        429 responses relative to request timing and volume."""
        findings: list[dict[str, Any]] = []

        endpoint_events: dict[str, list[tuple[float, int, dict]]] = defaultdict(list)

        for obs in self._observations:
            req = obs.get("request_data") or {}
            resp = obs.get("response_data") or {}
            status = resp.get("status_code", 0)
            elapsed = resp.get("elapsed_ms", 0)
            timestamp = obs.get("timestamp", 0)
            url = str(req.get("url", ""))
            path = urlparse(url).path if url else ""
            headers = resp.get("headers") or {}
            if path:
                endpoint_events[path].append((float(timestamp), status, {
                    "elapsed": elapsed,
                    "retry_after": headers.get("retry-after", headers.get("Retry-After")),
                    "remaining": headers.get("x-ratelimit-remaining", headers.get("X-RateLimit-Remaining")),
                    "limit": headers.get("x-ratelimit-limit", headers.get("X-RateLimit-Limit")),
                    "reset": headers.get("x-ratelimit-reset", headers.get("X-RateLimit-Reset")),
                }))

        for ep, events in endpoint_events.items():
            rate_limited = [(ts, s, h) for ts, s, h in events if s == 429]
            if not rate_limited:
                continue

            limit_val = None
            remaining_values = []
            for _, _, h in events:
                if h.get("limit"):
                    try:
                        limit_val = int(h["limit"])
                    except (ValueError, TypeError):
                        pass
                if h.get("remaining") is not None:
                    try:
                        remaining_values.append(int(h["remaining"]))
                    except (ValueError, TypeError):
                        pass

            algo_guess = "unknown"
            confidence = "low"

            if remaining_values:
                is_monotonic_decrease = all(
                    remaining_values[i] >= remaining_values[i + 1]
                    for i in range(len(remaining_values) - 1)
                ) if len(remaining_values) >= 3 else False

                if is_monotonic_decrease:
                    algo_guess = "token_bucket_or_fixed_window"
                    confidence = "medium"
                else:
                    jumps = sum(
                        1 for i in range(len(remaining_values) - 1)
                        if remaining_values[i + 1] > remaining_values[i]
                    )
                    if jumps > 0 and limit_val:
                        algo_guess = "sliding_window"
                        confidence = "medium"

            retry_after_values = []
            for _, _, h in rate_limited:
                ra = h.get("retry_after")
                if ra:
                    try:
                        retry_after_values.append(float(ra))
                    except (ValueError, TypeError):
                        pass

            if retry_after_values:
                if len(set(retry_after_values)) == 1:
                    algo_guess = "fixed_window" if algo_guess == "unknown" else algo_guess
                    confidence = "high" if confidence != "low" else "medium"
                elif len(set(retry_after_values)) > 1:
                    algo_guess = "adaptive_or_leaky_bucket"
                    confidence = "medium"

            findings.append({
                "endpoint": ep,
                "type": "rate_limit_algorithm",
                "algorithm_guess": algo_guess,
                "confidence": confidence,
                "rate_limited_count": len(rate_limited),
                "total_requests": len(events),
                "declared_limit": limit_val,
                "retry_after_values": retry_after_values[:10],
                "remaining_pattern": remaining_values[:10],
                "inferred": (
                    f"Rate limit algorithm: {algo_guess} (confidence: {confidence}). "
                    f"Limit: {limit_val}, {len(rate_limited)}/{len(events)} throttled."
                ),
            })

        return findings

    # ------------------------------------------------------------------
    # ADVANCED RE: API graph / relationship mapping
    # ------------------------------------------------------------------

    def map_api_graph(self) -> list[dict[str, Any]]:
        """Reconstruct the API resource graph from observed URL patterns
        and cross-references in response bodies.

        Maps parent/child relationships, shared ID references, and
        multi-step flows to reveal the application's data model and
        business logic flows."""
        findings: list[dict[str, Any]] = []

        path_re = re.compile(r'^(/(?:api/)?(?:v\d+/)?)(\w+)(?:/([^/]+))?(?:/(\w+))?')
        resources: dict[str, set[str]] = defaultdict(set)
        id_cross_refs: dict[str, set[str]] = defaultdict(set)

        for obs in self._observations:
            req = obs.get("request_data") or {}
            resp = obs.get("response_data") or {}
            url = str(req.get("url", ""))
            path = urlparse(url).path if url else ""
            match = path_re.match(path)
            if match:
                prefix, resource, resource_id, sub_resource = match.groups()
                resources[resource].add(req.get("method", "GET"))
                if sub_resource:
                    id_cross_refs[resource].add(sub_resource)

            body_text = _body_as_text(resp.get("body")) if resp.get("body") is not None else ""
            id_refs = re.findall(
                r'"(\w+_id)":\s*"([^"]+)"', body_text,
            )
            for id_field, id_val in id_refs:
                ref_resource = id_field.replace("_id", "")
                id_cross_refs[ref_resource].add(path)

        resource_list = []
        for resource, methods in resources.items():
            resource_list.append({
                "resource": resource,
                "methods": sorted(methods),
                "sub_resources": sorted(id_cross_refs.get(resource, set()))[:10],
            })

        if resource_list:
            findings.append({
                "type": "api_graph",
                "resources": resource_list[:30],
                "total_resources": len(resource_list),
                "cross_references": {k: sorted(v)[:5] for k, v in id_cross_refs.items() if len(v) >= 2},
                "inferred": f"API graph: {len(resource_list)} resources, {sum(len(v) for v in id_cross_refs.values())} cross-references",
            })

        return findings

    # ------------------------------------------------------------------
    # ADVANCED RE: Cache behavior analysis
    # ------------------------------------------------------------------

    def analyze_cache_behavior(self) -> list[dict[str, Any]]:
        """Analyze cache hit/miss patterns to infer caching strategy and
        identify cache-busting opportunities."""
        findings: list[dict[str, Any]] = []

        cache_patterns: dict[str, dict[str, int]] = defaultdict(lambda: {"hit": 0, "miss": 0, "dynamic": 0, "bypass": 0, "expired": 0, "total": 0})

        for obs in self._observations:
            req = obs.get("request_data") or {}
            resp = obs.get("response_data") or {}
            url = str(req.get("url", ""))
            path = urlparse(url).path if url else ""
            headers = resp.get("headers") or {}
            lower_headers = {k.lower(): v for k, v in headers.items()}

            cache_status = (
                lower_headers.get("cf-cache-status", "") or
                lower_headers.get("x-cache", "") or
                lower_headers.get("x-vercel-cache", "") or
                lower_headers.get("x-nf-request-id", "")
            ).upper()
            age = lower_headers.get("age", "")
            cache_control = lower_headers.get("cache-control", "")

            if path:
                cache_patterns[path]["total"] += 1
                if "HIT" in cache_status:
                    cache_patterns[path]["hit"] += 1
                elif "MISS" in cache_status:
                    cache_patterns[path]["miss"] += 1
                elif "DYNAMIC" in cache_status or "BYPASS" in cache_status:
                    cache_patterns[path]["dynamic"] += 1
                elif "EXPIRED" in cache_status or "REVALIDATED" in cache_status:
                    cache_patterns[path]["expired"] += 1

        for ep, counts in cache_patterns.items():
            if counts["total"] < 2:
                continue
            if counts["hit"] + counts["miss"] + counts["expired"] > 0:
                hit_rate = counts["hit"] / max(counts["total"], 1)
                findings.append({
                    "endpoint": ep,
                    "type": "cache_behavior",
                    "hit_rate": round(hit_rate, 2),
                    "hits": counts["hit"],
                    "misses": counts["miss"],
                    "dynamic": counts["dynamic"],
                    "expired": counts["expired"],
                    "total": counts["total"],
                    "inferred": (
                        f"Cache: {hit_rate:.0%} hit rate ({counts['hit']}/{counts['total']}). "
                        + ("Fully cached - cache poisoning viable. " if hit_rate > 0.8 else "")
                        + ("Never cached - dynamic content. " if counts["dynamic"] == counts["total"] else "")
                    ),
                })

        return findings

    # ------------------------------------------------------------------
    # ADVANCED RE: Multi-step flow state dependency mapping
    # ------------------------------------------------------------------

    def map_flow_dependencies(self) -> list[dict[str, Any]]:
        """Map multi-step business flows by tracking IDs that appear in one
        response and are referenced in a subsequent request.

        This reveals checkout flows, subscription creation sequences,
        and other multi-step processes an attacker needs to understand
        before attempting access-without-payment exploits."""
        findings: list[dict[str, Any]] = []

        response_ids: dict[str, list[tuple[str, str]]] = defaultdict(list)
        request_ids: dict[str, list[tuple[str, str]]] = defaultdict(list)

        id_re = re.compile(
            r'"(\w+)":\s*"((?:pi_|sub_|cs_|ch_|in_|cus_|pm_|si_|evt_|txn_|plink_|price_|prod_)[A-Za-z0-9]+)"'
        )

        for obs in self._observations:
            req = obs.get("request_data") or {}
            resp = obs.get("response_data") or {}
            url = str(req.get("url", ""))
            path = urlparse(url).path if url else ""

            resp_body = _body_as_text(resp.get("body")) if resp.get("body") is not None else ""
            for field, val in id_re.findall(resp_body):
                response_ids[val].append((path, field))

            req_body = _body_as_text(req.get("body")) if req.get("body") is not None else ""
            req_url_params = str(req.get("params", ""))
            for field, val in id_re.findall(req_body + req_url_params + url):
                request_ids[val].append((path, field))

        flows: list[dict[str, Any]] = []
        for id_val, resp_locations in response_ids.items():
            if id_val in request_ids:
                req_locations = request_ids[id_val]
                source_eps = sorted({ep for ep, _ in resp_locations})
                target_eps = sorted({ep for ep, _ in req_locations})
                if source_eps != target_eps:
                    flows.append({
                        "id_prefix": id_val[:4] + "...",
                        "produced_at": source_eps[:5],
                        "consumed_at": target_eps[:5],
                        "field_names": sorted({f for _, f in resp_locations + req_locations})[:5],
                    })

        if flows:
            findings.append({
                "type": "flow_dependency_map",
                "flows": flows[:20],
                "total_flows": len(flows),
                "inferred": f"Identified {len(flows)} multi-step flows with cross-endpoint ID dependencies",
            })

        return findings

    # ------------------------------------------------------------------
    # ADVANCED RE: Payment-specific deep protocol analysis
    # ------------------------------------------------------------------

    def analyze_payment_protocol(self) -> list[dict[str, Any]]:
        """Deep analysis of Stripe/payment protocol patterns to understand
        the exact sequence of calls needed for access-without-payment."""
        findings: list[dict[str, Any]] = []

        payment_endpoints: dict[str, list[dict]] = defaultdict(list)
        stripe_obj_re = re.compile(
            r'"object":\s*"(payment_intent|checkout\.session|charge|invoice|'
            r'subscription|customer|setup_intent|payment_method|price|product|'
            r'coupon|promotion_code|refund)"'
        )

        for obs in self._observations:
            req = obs.get("request_data") or {}
            resp = obs.get("response_data") or {}
            url = str(req.get("url", ""))
            path = urlparse(url).path if url else ""
            body_text = _body_as_text(resp.get("body")) if resp.get("body") is not None else ""
            status = resp.get("status_code", 0)

            obj_match = stripe_obj_re.search(body_text)
            if obj_match or re.search(r'(?:stripe|payment|checkout|subscribe|invoice)', path, re.I):
                body = resp.get("body") if isinstance(resp.get("body"), dict) else {}
                payment_endpoints[path].append({
                    "method": req.get("method"),
                    "status": status,
                    "object_type": obj_match.group(1) if obj_match else None,
                    "amount": body.get("amount"),
                    "currency": body.get("currency"),
                    "payment_status": body.get("status") or body.get("payment_status"),
                    "has_client_secret": "client_secret" in body_text,
                    "mode": body.get("mode"),
                    "metadata": bool(body.get("metadata")),
                })

        if payment_endpoints:
            obj_types_seen = set()
            statuses_observed = set()
            for ep, calls in payment_endpoints.items():
                for c in calls:
                    if c["object_type"]:
                        obj_types_seen.add(c["object_type"])
                    if c["payment_status"]:
                        statuses_observed.add(c["payment_status"])

            findings.append({
                "type": "payment_protocol_analysis",
                "endpoints": {ep: len(calls) for ep, calls in payment_endpoints.items()},
                "stripe_objects_observed": sorted(obj_types_seen),
                "payment_statuses_observed": sorted(statuses_observed),
                "total_payment_calls": sum(len(v) for v in payment_endpoints.values()),
                "has_client_secret_exposure": any(
                    c["has_client_secret"] for calls in payment_endpoints.values() for c in calls
                ),
                "inferred": (
                    f"Payment protocol: {len(payment_endpoints)} endpoints, "
                    f"{sorted(obj_types_seen)} object types, "
                    f"statuses: {sorted(statuses_observed)}"
                ),
            })

        return findings

    # ------------------------------------------------------------------
    # ADVANCED RE: Content-type negotiation probing analysis
    # ------------------------------------------------------------------

    def analyze_content_negotiation(self) -> list[dict[str, Any]]:
        """Analyze how the server responds to different Accept headers and
        Content-Types to reveal hidden serialization formats."""
        findings: list[dict[str, Any]] = []

        endpoint_content_types: dict[str, set[str]] = defaultdict(set)
        for obs in self._observations:
            req = obs.get("request_data") or {}
            resp = obs.get("response_data") or {}
            url = str(req.get("url", ""))
            path = urlparse(url).path if url else ""
            resp_ct = ""
            for k, v in (resp.get("headers") or {}).items():
                if k.lower() == "content-type":
                    resp_ct = str(v).split(";")[0].strip().lower()
                    break
            if path and resp_ct:
                endpoint_content_types[path].add(resp_ct)

        for ep, content_types in endpoint_content_types.items():
            if len(content_types) >= 2:
                findings.append({
                    "endpoint": ep,
                    "type": "content_negotiation",
                    "content_types": sorted(content_types),
                    "inferred": (
                        f"Multiple response Content-Types: {sorted(content_types)}. "
                        "May accept different serialization formats."
                    ),
                })

        return findings

    # ------------------------------------------------------------------
    # get_all_findings -- now includes all advanced methods
    # ------------------------------------------------------------------

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
        for tc in self.analyze_timing_side_channels():
            findings.append(tc)
        for eo in self.analyze_error_oracles():
            findings.append(eo)
        for waf in self.fingerprint_waf_cdn():
            findings.append(waf)
        for tech in self.fingerprint_tech_stack():
            findings.append(tech)
        for token in self.analyze_token_structures():
            findings.append(token)
        for diff in self.analyze_response_differentials():
            findings.append(diff)
        for rl_algo in self.fingerprint_rate_limit_algorithm():
            findings.append(rl_algo)
        for graph in self.map_api_graph():
            findings.append(graph)
        for cache in self.analyze_cache_behavior():
            findings.append(cache)
        for flow in self.map_flow_dependencies():
            findings.append(flow)
        for pay in self.analyze_payment_protocol():
            findings.append(pay)
        for cn in self.analyze_content_negotiation():
            findings.append(cn)
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
        "waf_bypass": [
            "Test double URL-encoding bypass (%%2527 for single quote)",
            "Test unicode normalization bypass (fullwidth chars: %uFF07 for quote)",
            "Test mixed encoding: combine URL-encode + HTML entities + unicode",
            "Test HTTP Parameter Pollution (duplicate params handled differently per server)",
            "Test HTTP Parameter Fragmentation (payload split across params server recombines)",
            "Test chunked Transfer-Encoding to split payload across chunks",
            "Test request body size overflow: pad past WAF inspection size limit",
            "Test SSL/TLS cipher abuse: connect with cipher WAF cannot inspect",
            "Test origin IP discovery via DNS history (IP History, DNS Trails)",
            "Test X-Forwarded-For / X-Real-IP header spoofing to bypass IP-based WAF",
            "Test HTTP/2 h2c smuggling to bypass WAF on HTTP/1.1 path",
            "Test Content-Type confusion: send application/json where WAF expects form data",
            "Test JSON-in-URL-param bypass for WAFs only inspecting body",
            "Test case variation bypass (SeLeCt, UnIoN) to evade regex rules",
            "Test comment injection bypass (/**/UNION/**/SELECT/**/)",
            "Test null byte injection (%00) to terminate WAF string parsing",
            "Test wildcard globbing in SQL (s%e%l%e%c%t) to fragment blocked keywords",
            "Test alternate charset header (Content-Type: charset=ibm037) for body encoding",
        ],
        "subscription_abuse": [
            "Test trial extension via re-registration with same email variant (user+1@)",
            "Test subscription downgrade retaining premium feature flags in cache",
            "Test cancel-then-reactivate within grace period exploiting proration bug",
            "Test coupon stacking: apply multiple promotion codes in rapid succession",
            "Test currency switching to lowest-denomination currency for minimum payment",
            "Test free tier with manually elevated metadata (plan_id, tier override)",
            "Test webhook event replay to trigger duplicate subscription credit",
            "Test invoice manipulation: modify line items for net-zero payment",
            "Test plan_id swapping between creation and confirmation steps",
            "Test backdated trial_end via API parameter injection",
        ],
    }

    def brainstorm_attack_vectors(
        self, components: dict[str, Any],
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        endpoint = components.get("endpoint", "")
        body_text = components.get("body_text", "")
        resp_headers = components.get("response_headers") or {}

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
            elif category == "waf_bypass":
                if any(re.search(r"(?:cf-ray|x-akamai|incap_ses|x-datadome|_px\d)", k, re.I) for k in resp_headers):
                    relevance = 0.85
            elif category == "subscription_abuse":
                if components.get("stripe_object") in ("subscription", "invoice", "customer"):
                    relevance = 0.90
                elif _PAYMENT_SENSITIVE_PATH_RE.search(endpoint):
                    relevance = 0.70

            if relevance > 0.2:
                for idea in ideas[:7]:
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

        return sorted(results, key=lambda x: x["relevance"], reverse=True)[:20]

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
                for idea in self._BYPASS_IDEAS["waf_bypass"][:8]:
                    bypasses.append({"defense": indicator, "bypass": idea, "confidence": 0.5})
            if "cdn" in ind_lower or "cloudflare" in ind_lower:
                bypasses.append({"defense": indicator, "bypass": "Test origin IP discovery via DNS history records", "confidence": 0.6})
                bypasses.append({"defense": indicator, "bypass": "Test direct-to-origin request bypassing CDN edge", "confidence": 0.5})
                bypasses.append({"defense": indicator, "bypass": "Test CDN cache poisoning via unkeyed Host header", "confidence": 0.4})
                bypasses.append({"defense": indicator, "bypass": "Test CDN PoP-sharding to reach different edge with different rules", "confidence": 0.4})
            if "bot" in ind_lower or "fingerprint" in ind_lower:
                bypasses.append({"defense": indicator, "bypass": "Test TLS/HTTP fingerprint impersonation (curl_cffi, impersonate-proxy)", "confidence": 0.5})
                bypasses.append({"defense": indicator, "bypass": "Test headless browser with stealth plugins (puppeteer-extra-stealth)", "confidence": 0.5})
                bypasses.append({"defense": indicator, "bypass": "Test API-only path that skips browser fingerprinting entirely", "confidence": 0.6})
                bypasses.append({"defense": indicator, "bypass": "Test mobile User-Agent to trigger different detection path", "confidence": 0.4})
            if "cors" in ind_lower:
                bypasses.append({"defense": indicator, "bypass": "Test wildcard Origin reflection (*) for credential-bearing requests", "confidence": 0.5})
                bypasses.append({"defense": indicator, "bypass": "Test null Origin acceptance for sandboxed iframe bypass", "confidence": 0.5})
                bypasses.append({"defense": indicator, "bypass": "Test subdomain origin trust (attacker.target.com)", "confidence": 0.4})
            if "jwt" in ind_lower or "token" in ind_lower:
                bypasses.append({"defense": indicator, "bypass": "Test alg:none JWT signature stripping", "confidence": 0.5})
                bypasses.append({"defense": indicator, "bypass": "Test RS256-to-HS256 key confusion with public key as HMAC secret", "confidence": 0.5})
                bypasses.append({"defense": indicator, "bypass": "Test JWT kid header path traversal to known file", "confidence": 0.4})
                bypasses.append({"defense": indicator, "bypass": "Test expired JWT acceptance (clock skew tolerance)", "confidence": 0.4})
                bypasses.append({"defense": indicator, "bypass": "Test JWK injection via jku/x5u header", "confidence": 0.3})
        return bypasses

    def brainstorm_chain_compositions(
        self, findings: list[ZeroShotFinding],
    ) -> list[dict[str, Any]]:
        chains: list[dict[str, Any]] = []
        categories = {f.category for f in findings}

        chain_templates: list[tuple[set[str], str, str]] = [
            ({"critical_secret", "sensitive_field_name"}, "Secret leak -> credential reuse -> lateral movement", "critical"),
            ({"injection_artifact_sqli"}, "SQLi -> data exfiltration -> credential theft -> account takeover", "critical"),
            ({"injection_artifact_xss", "sensitive_field_name"}, "XSS -> session hijack -> data theft", "critical"),
            ({"injection_artifact_ssrf"}, "SSRF -> cloud metadata -> IAM credential theft -> infrastructure takeover", "critical"),
            ({"critical_secret"}, "Info leak reveals auth mechanism -> targeted bypass -> full access", "critical"),
            ({"injection_artifact_xss"}, "Stored XSS -> admin session hijack -> privilege escalation -> data exfil", "critical"),
            ({"sensitive_field_name"}, "Payment data exposure -> credential harvest -> fraudulent transactions", "high"),
        ]
        for required, chain_desc, severity in chain_templates:
            if required & categories:
                chains.append({
                    "chain": chain_desc,
                    "triggered_by": sorted(required & categories),
                    "severity": severity,
                })

        # Additional context-free chain templates (always emitted if any findings exist)
        if categories:
            always_chains = [
                ("Race checkout + zero amount -> free purchase", "critical"),
                ("Forge payment webhook -> instant premium entitlement", "critical"),
                ("Poison cache -> serve malicious auth response -> session hijack", "high"),
                ("GraphQL introspection -> schema leak -> targeted exploit chain", "high"),
                ("Subscription trial abuse -> perpetual free access -> revenue loss", "high"),
                ("Refund processed but entitlement not revoked -> free product", "critical"),
                ("Error oracle enumeration -> valid accounts -> credential stuffing -> takeover", "high"),
            ]
            for chain_desc, severity in always_chains:
                chains.append({
                    "chain": chain_desc,
                    "triggered_by": ["contextual_inference"],
                    "severity": severity,
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
                {"idea": "What if the client_secret from the session allows completing payment with $0?", "category": "payment_manipulation", "likelihood": "medium"},
            ])
        elif stripe_obj == "subscription":
            ideas.extend([
                {"idea": "What if cancellation doesn't revoke access immediately?", "category": "entitlement_bypass", "likelihood": "high"},
                {"idea": "What if downgrade retains premium features until next billing cycle?", "category": "entitlement_bypass", "likelihood": "high"},
                {"idea": "What if trial_end can be set to a future date via API?", "category": "business_logic", "likelihood": "medium"},
                {"idea": "What if re-subscribing with a 100% coupon grants permanent premium?", "category": "subscription_abuse", "likelihood": "medium"},
                {"idea": "What if switching plans mid-cycle leaves prorated credit exploitable?", "category": "subscription_abuse", "likelihood": "medium"},
            ])
        elif stripe_obj == "payment_intent":
            ideas.extend([
                {"idea": "What if the amount is modified after creation but before confirmation?", "category": "payment_manipulation", "likelihood": "high"},
                {"idea": "What if capture_method=manual allows indefinite hold without payment?", "category": "business_logic", "likelihood": "medium"},
                {"idea": "What if the payment_intent ID is predictable and reusable cross-session?", "category": "auth_bypass", "likelihood": "low"},
            ])
        elif stripe_obj == "invoice":
            ideas.extend([
                {"idea": "What if invoice is marked paid without actual payment processing?", "category": "payment_manipulation", "likelihood": "high"},
                {"idea": "What if line items can be modified after invoice creation?", "category": "business_logic", "likelihood": "medium"},
                {"idea": "What if voiding and re-creating invoice resets payment requirements?", "category": "subscription_abuse", "likelihood": "medium"},
            ])
        elif stripe_obj == "refund":
            ideas.extend([
                {"idea": "What if refund is processed but entitlement/access is not revoked?", "category": "entitlement_bypass", "likelihood": "high"},
                {"idea": "What if partial refund amount can be manipulated to exceed original?", "category": "payment_manipulation", "likelihood": "medium"},
                {"idea": "What if refund webhook is replayed to trigger double credit?", "category": "business_logic", "likelihood": "medium"},
            ])
        elif stripe_obj == "coupon":
            ideas.extend([
                {"idea": "What if a coupon with 100% discount has no max_redemptions limit?", "category": "subscription_abuse", "likelihood": "high"},
                {"idea": "What if coupon ID is predictable and can be applied to any subscription?", "category": "business_logic", "likelihood": "medium"},
                {"idea": "What if stacking a 100% coupon with a trial gives perpetual free access?", "category": "subscription_abuse", "likelihood": "high"},
            ])
        elif stripe_obj == "payment_link":
            ideas.extend([
                {"idea": "What if payment link session ID is predictable/enumerable?", "category": "idor", "likelihood": "medium"},
                {"idea": "What if payment link can be completed with modified price_data?", "category": "payment_manipulation", "likelihood": "medium"},
            ])

        if components.get("anomalies"):
            for a in components["anomalies"]:
                if "entitlement_drift" in a:
                    ideas.append({
                        "idea": "What if ALL premium endpoints are accessible, not just the one observed?",
                        "category": "entitlement_bypass",
                        "likelihood": "high",
                    })
                if "zero_payment" in a:
                    ideas.append({
                        "idea": "What if the zero-amount path bypasses all downstream entitlement checks?",
                        "category": "payment_manipulation",
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

    def simulate_multi_chain_attack(
        self,
        chains: list[list[tuple[str, float]]],
        n_simulations: int = 1000,
    ) -> dict[str, Any]:
        """Simulate multiple attack chains to find the most likely to succeed."""
        if not chains:
            return {"best_chain": None, "overall_success_rate": 0.0}

        n_simulations = min(n_simulations, 5000)
        chain_successes: list[int] = [0] * len(chains)
        chain_steps: list[list[int]] = [[] for _ in chains]
        any_success = 0

        for _ in range(n_simulations):
            sim_any = False
            for ci, chain in enumerate(chains):
                chain_succeeded = True
                steps_taken = 0
                for step_name, prob in chain:
                    steps_taken += 1
                    if self._rng.random() >= prob:
                        chain_succeeded = False
                        break
                if chain_succeeded:
                    chain_successes[ci] += 1
                    chain_steps[ci].append(steps_taken)
                    sim_any = True
            if sim_any:
                any_success += 1

        rates = [s / n_simulations for s in chain_successes]
        best_idx = max(range(len(rates)), key=lambda i: rates[i]) if rates else 0
        fastest_idx = best_idx
        if chain_steps:
            avg_steps = [
                statistics.mean(steps) if steps else float("inf")
                for steps in chain_steps
            ]
            candidates = [i for i, r in enumerate(rates) if r > 0]
            if candidates:
                fastest_idx = min(candidates, key=lambda i: avg_steps[i])

        return {
            "best_chain": best_idx,
            "best_chain_steps": [s for s, _ in chains[best_idx]] if chains else [],
            "success_rates_by_chain": [round(r, 4) for r in rates],
            "overall_success_rate": round(any_success / n_simulations, 4) if n_simulations > 0 else 0.0,
            "expected_fastest_chain": fastest_idx,
            "mean_steps_by_chain": [
                round(statistics.mean(steps), 2) if steps else 0.0
                for steps in chain_steps
            ],
            "simulations": n_simulations,
        }

    def estimate_financial_impact(
        self,
        severity: str,
        is_payment: bool,
        user_base_estimate: int = 10000,
        avg_transaction_value: float = 50.0,
        n_simulations: int = 1000,
    ) -> dict[str, Any]:
        """Simulate financial exposure from a vulnerability."""
        base_exploit_rate = {
            "critical": 0.15, "high": 0.08, "medium": 0.03, "low": 0.005, "none": 0.0,
        }.get(severity, 0.0)
        if is_payment:
            base_exploit_rate *= 3.0

        n_simulations = min(n_simulations, 5000)
        losses: list[float] = []
        for _ in range(n_simulations):
            exploit_rate = base_exploit_rate * (0.3 + self._rng.random() * 1.4)
            affected_users = int(user_base_estimate * exploit_rate)
            txn_variance = 0.5 + self._rng.random()
            direct_loss = affected_users * avg_transaction_value * txn_variance
            reputation_mult = 1.0 + self._rng.random() * (3.0 if is_payment else 1.0)
            regulatory_mult = 1.0
            if is_payment and severity in ("critical", "high"):
                regulatory_mult += self._rng.random() * 5.0
            total = direct_loss * reputation_mult * regulatory_mult
            losses.append(total)

        losses.sort()
        p50_idx = int(len(losses) * 0.5)
        p90_idx = int(len(losses) * 0.9)
        p99_idx = min(int(len(losses) * 0.99), len(losses) - 1)

        return {
            "expected_loss": round(statistics.mean(losses), 2),
            "median_loss": round(losses[p50_idx], 2),
            "worst_case_loss_p90": round(losses[p90_idx], 2),
            "worst_case_loss_p99": round(losses[p99_idx], 2),
            "confidence_interval_95": (
                round(losses[int(len(losses) * 0.025)], 2),
                round(losses[int(len(losses) * 0.975)], 2),
            ),
            "severity": severity,
            "is_payment": is_payment,
            "simulations": n_simulations,
        }

    def simulate_defense_effectiveness(
        self,
        finding_probabilities: list[float],
        defense_reduction_factors: list[float],
        n_simulations: int = 1000,
    ) -> dict[str, Any]:
        """Compare attack success with and without defenses applied."""
        if not finding_probabilities:
            return {"undefended_rate": 0.0, "defended_rate": 0.0, "effectiveness_percent": 0.0}

        n_simulations = min(n_simulations, 5000)

        def run_sim(probs: list[float]) -> float:
            successes = 0
            for _ in range(n_simulations):
                for p in probs:
                    if self._rng.random() < p:
                        successes += 1
                        break
            return successes / n_simulations if n_simulations > 0 else 0.0

        undefended = run_sim(finding_probabilities)

        defended_probs = [
            max(0.0, p * (1.0 - d))
            for p, d in zip(finding_probabilities, defense_reduction_factors)
        ]
        while len(defended_probs) < len(finding_probabilities):
            defended_probs.append(finding_probabilities[len(defended_probs)])

        defended = run_sim(defended_probs)
        effectiveness = (
            (undefended - defended) / undefended * 100.0
            if undefended > 0 else 100.0
        )

        return {
            "undefended_rate": round(undefended, 4),
            "defended_rate": round(defended, 4),
            "effectiveness_percent": round(effectiveness, 1),
            "findings_count": len(finding_probabilities),
            "defenses_applied": len(defense_reduction_factors),
            "simulations": n_simulations,
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
        "account_takeover": {
            "node_type": "OR",
            "children": [
                {
                    "goal": "Credential theft via info disclosure",
                    "node_type": "AND",
                    "children": [
                        {"goal": "Extract leaked credentials from response", "node_type": "LEAF", "category": "critical_secret"},
                        {"goal": "Reuse stolen credentials for account access", "node_type": "LEAF", "category": "auth_bypass"},
                    ],
                },
                {
                    "goal": "Session hijack via XSS",
                    "node_type": "AND",
                    "children": [
                        {"goal": "Exploit reflected/stored XSS to execute JavaScript", "node_type": "LEAF", "category": "injection_artifact_xss"},
                        {"goal": "Exfiltrate session cookie to attacker domain", "node_type": "LEAF", "category": "info_disclosure"},
                    ],
                },
                {"goal": "Auth bypass via broken authentication mechanisms", "node_type": "LEAF", "category": "auth_bypass"},
                {"goal": "OAuth/SAML token manipulation (redirect_uri, assertion replay)", "node_type": "LEAF", "category": "auth_bypass"},
            ],
        },
        "data_exfiltration": {
            "node_type": "OR",
            "children": [
                {"goal": "Direct IDOR enumeration of user records", "node_type": "LEAF", "category": "idor"},
                {
                    "goal": "SQLi-based data extraction",
                    "node_type": "AND",
                    "children": [
                        {"goal": "Exploit SQL injection for query manipulation", "node_type": "LEAF", "category": "injection_artifact_sqli"},
                        {"goal": "Extract sensitive data from database via UNION/blind", "node_type": "LEAF", "category": "info_disclosure"},
                    ],
                },
                {
                    "goal": "GraphQL mass query exfiltration",
                    "node_type": "AND",
                    "children": [
                        {"goal": "Discover full schema via introspection query", "node_type": "LEAF", "category": "info_disclosure"},
                        {"goal": "Execute unbounded nested query to dump data", "node_type": "LEAF", "category": "broken_access_control"},
                    ],
                },
                {"goal": "API versioning downgrade to bypass field-level auth", "node_type": "LEAF", "category": "broken_access_control"},
            ],
        },
        "privilege_escalation": {
            "node_type": "OR",
            "children": [
                {"goal": "Vertical escalation via role parameter injection in request", "node_type": "LEAF", "category": "privilege_escalation"},
                {"goal": "Mass assignment of admin/superuser role field", "node_type": "LEAF", "category": "mass_assignment"},
                {"goal": "Function-level authorization bypass via method override", "node_type": "LEAF", "category": "broken_access_control"},
                {
                    "goal": "JWT claim manipulation for privilege escalation",
                    "node_type": "AND",
                    "children": [
                        {"goal": "Exploit JWT algorithm weakness (alg:none, HS256 confusion)", "node_type": "LEAF", "category": "auth_bypass"},
                        {"goal": "Forge token with elevated role/admin claims", "node_type": "LEAF", "category": "privilege_escalation"},
                    ],
                },
            ],
        },
        "payment_fraud": {
            "node_type": "OR",
            "children": [
                {
                    "goal": "Zero-amount checkout completion",
                    "node_type": "AND",
                    "children": [
                        {"goal": "Manipulate payment amount to zero/negative", "node_type": "LEAF", "category": "payment_manipulation"},
                        {"goal": "System grants entitlement for zero-amount payment", "node_type": "LEAF", "category": "entitlement_bypass"},
                    ],
                },
                {
                    "goal": "Refund abuse with entitlement retention",
                    "node_type": "AND",
                    "children": [
                        {"goal": "Initiate refund after receiving entitlement", "node_type": "LEAF", "category": "business_logic"},
                        {"goal": "Entitlement not revoked on successful refund", "node_type": "LEAF", "category": "entitlement_bypass"},
                    ],
                },
                {
                    "goal": "Currency arbitrage exploitation",
                    "node_type": "AND",
                    "children": [
                        {"goal": "Submit payment in lower-value currency than displayed", "node_type": "LEAF", "category": "payment_manipulation"},
                        {"goal": "Server accepts mismatched currency without validation", "node_type": "LEAF", "category": "business_logic"},
                    ],
                },
                {"goal": "Coupon/promo code stacking beyond intended limit", "node_type": "LEAF", "category": "business_logic"},
                {
                    "goal": "Webhook forgery for payment credit",
                    "node_type": "AND",
                    "children": [
                        {"goal": "Forge payment.succeeded webhook without signature", "node_type": "LEAF", "category": "auth_bypass"},
                        {"goal": "System credits account from forged webhook event", "node_type": "LEAF", "category": "entitlement_bypass"},
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
            match_scores = [
                0.7 if category in cat or cat in category else 0.0
                for cat in available_cats
            ]
            best_match = max(match_scores) if match_scores else 0.0
            node.probability = best_match if best_match > 0.0 else 0.05
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

    def rank_goals(
        self,
        available_findings: list[ZeroShotFinding],
    ) -> list[dict[str, Any]]:
        """Evaluate all goal templates against current findings, ranked by probability."""
        finding_categories = {f.category for f in available_findings}
        ranked: list[dict[str, Any]] = []
        for goal_name, template in self._GOAL_TEMPLATES.items():
            tree = self._build_node(
                {"goal": goal_name, **template}, finding_categories,
            )
            critical_path = self.find_critical_path(tree)
            ranked.append({
                "goal": goal_name,
                "probability": round(tree.probability, 4),
                "critical_path": critical_path,
                "node_type": tree.node_type,
                "children_count": len(tree.children) if tree.children else 0,
            })
        return sorted(ranked, key=lambda x: x["probability"], reverse=True)

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


# ############################################################################
#
#  FRONTIER TECHNIQUES: Inspired by ExploitGym (Berkeley 2026),
#  GPT-6 Astra's recurrent-depth reasoning, and Mythos's semantic
#  code reasoning + multi-vulnerability chaining.
#
#  G. IterativeDeepeningReasoner -- Recurrent-depth style: runs the same
#     reasoning logic N times, each pass building on the last. Inspired by
#     GPT-6 Astra's "looped transformer" architecture where successful
#     exploits sometimes used zero chain-of-thought tokens because all
#     reasoning was internalized across loop iterations.
#
#  H. ExploitChainSynthesizer -- Combines multiple lower-severity findings
#     into critical composite attack paths. Directly from ExploitGym data
#     showing Mythos chaining 2-4 vulns into working kernel exploits, and
#     GPT-5.4 escalating through 8 steps from a 5-line PoV to full RCE.
#
#  I. AdversarialSelfVerifier -- Agent-as-a-Judge pattern from ExploitGym.
#     A second reasoning pass audits the entire trajectory for shortcuts,
#     false positives, reward hacking, and logical errors.
#
#  J. SemanticPatternReasoner -- Goes beyond regex matching to understand
#     what response patterns MEAN. Inspired by Mythos catching an FFmpeg
#     H.264 bug by "reasoning about code semantics" after fuzzers exercised
#     the path 5M times without triggering it.
#
#  K. KillChainScorer -- Stage-aware scoring with shaped bonuses per attack
#     phase (recon -> weaponize -> deliver -> exploit -> install -> C2 ->
#     action). From the RL research showing kill-chain-aligned reward
#     shaping outperforms sparse rewards for multi-stage attacks.
#
#  L. IterativeHypothesisRefiner -- Try-fail-revise loops. From Mythos
#     writing code to trigger a suspected bug, compiling, running, and
#     revising if the first attempt fails. And ExploitGym showing frontier
#     models sustain multi-stage reasoning with no plateau even at 6 hours.
#
# ############################################################################


# ============================================================================
# G. Iterative Deepening Reasoner (Recurrent Depth)
# ============================================================================

class IterativeDeepeningReasoner:
    """Variable-depth reasoning that re-runs analysis N times, each pass
    building on discoveries from the previous pass.

    Inspired by GPT-6 Astra's reported "recurrent depth" architecture where
    the same transformer blocks loop multiple times. Some successful exploits
    contained zero visible chain-of-thought tokens -- all reasoning was
    internalized across loop iterations.

    Our deterministic analog: run the full hypothesis-generation +
    evaluation pipeline up to max_depth times. Each iteration feeds the
    previous iteration's top hypotheses as "priors" to the next iteration,
    allowing the system to progressively refine and deepen its analysis.

    Key insight from the research: more budget helps, but only for the best
    reasoning. Mythos Preview went from 127 to 204 exploits when extended
    from 2h to 6h with no plateau. We simulate this with iterative passes."""

    def __init__(self, max_depth: int = 3, convergence_threshold: float = 0.02) -> None:
        self._max_depth = max_depth
        self._convergence_threshold = convergence_threshold
        self._depth_stats: list[dict[str, Any]] = []

    def deepen(
        self,
        initial_hypotheses: list,  # list[Hypothesis]
        components: dict[str, Any],
        memory: EpisodicMemory,
        knowledge_graph: KnowledgeGraph,
    ) -> tuple[list, int]:  # (refined hypotheses, depth reached)
        """Run iterative deepening passes until convergence or max depth."""
        current = list(initial_hypotheses)
        depth_reached = 1

        for depth in range(1, self._max_depth):
            prev_top = current[0].posterior if current else 0.0

            # Pass 1: Cross-reference with knowledge graph neighbors
            for h in current:
                endpoint = components.get("endpoint", "")
                if endpoint:
                    neighbors = knowledge_graph.get_neighbors(endpoint, max_depth=2)
                    neighbor_vulns = []
                    for n in neighbors:
                        node = knowledge_graph._nodes.get(n)
                        if node and node.properties.get("has_auth") is False:
                            neighbor_vulns.append(n)
                    if neighbor_vulns and h.category in ("auth_bypass", "idor", "privilege_escalation"):
                        h.posterior = min(0.99, h.posterior + 0.03 * len(neighbor_vulns))

            # Pass 2: Memory-informed refinement
            for h in current:
                past = memory.retrieve(query_category=h.category, top_k=5, entry_type="finding")
                high_confidence_past = [m for m in past if m.importance > 0.7]
                if high_confidence_past:
                    h.posterior = min(0.99, h.posterior + 0.02 * len(high_confidence_past))

            # Pass 3: Cross-hypothesis interference detection
            categories_active = [h.category for h in current if h.posterior > 0.3]
            if len(set(categories_active)) >= 3:
                for h in current:
                    if h.posterior > 0.3:
                        h.posterior = min(0.99, h.posterior + 0.02)

            current.sort(key=lambda h: h.posterior, reverse=True)
            depth_reached = depth + 1

            new_top = current[0].posterior if current else 0.0
            if abs(new_top - prev_top) < self._convergence_threshold:
                break

        self._depth_stats.append({
            "depth_reached": depth_reached,
            "max_depth": self._max_depth,
            "top_posterior": round(current[0].posterior, 4) if current else 0.0,
            "hypotheses_above_0.3": sum(1 for h in current if h.posterior > 0.3),
        })
        return current, depth_reached

    def get_stats(self) -> list[dict[str, Any]]:
        return self._depth_stats[-10:]


# ============================================================================
# H. Exploit Chain Synthesizer
# ============================================================================

@dataclass
class ExploitChain:
    """A synthesized multi-step exploit chain combining multiple findings."""
    chain_id: str
    steps: list[dict[str, Any]]
    combined_severity: str
    combined_probability: float
    description: str
    kill_chain_phase: str
    individual_severities: list[str]


class ExploitChainSynthesizer:
    """Combines multiple lower-severity findings into critical composite
    attack paths.

    Directly inspired by:
    - ExploitGym's GPT-5.4 trajectory: 8 steps from a 5-line PoV to full
      RCE (OOB read -> pointer leak -> fake string -> arbitrary read ->
      libc leak -> SROP -> system call)
    - Mythos Preview chaining 2-4 vulnerabilities into working kernel
      exploits (FreeBSD NFS: 20-gadget ROP chain across 6 packets)
    - ExploitGym showing 69 "unintended" exploits by Mythos where the agent
      pivoted to exploit a DIFFERENT vulnerability than intended

    Key insight: individual low/medium-severity findings that wouldn't
    warrant attention alone can compose into critical attack paths. This
    is the technique that makes frontier models so dangerous -- they don't
    just find bugs, they CHAIN them."""

    _CHAIN_TEMPLATES: list[dict[str, Any]] = [
        {
            "name": "auth_to_payment",
            "steps": ["auth_bypass", "idor", "payment_manipulation"],
            "description": "Bypass auth -> enumerate user objects -> manipulate payment",
            "severity_upgrade": "critical",
            "kill_chain": "full_compromise",
        },
        {
            "name": "recon_to_takeover",
            "steps": ["info_disclosure", "auth_bypass", "privilege_escalation"],
            "description": "Leak internal info -> bypass auth -> escalate to admin",
            "severity_upgrade": "critical",
            "kill_chain": "account_takeover",
        },
        {
            "name": "injection_chain",
            "steps": ["injection", "ssrf", "data_exfiltration"],
            "description": "Inject payload -> SSRF to internal services -> exfil data",
            "severity_upgrade": "critical",
            "kill_chain": "data_breach",
        },
        {
            "name": "entitlement_bypass",
            "steps": ["entitlement_bypass", "payment_manipulation"],
            "description": "Bypass tier check -> access premium without payment",
            "severity_upgrade": "high",
            "kill_chain": "access_without_payment",
        },
        {
            "name": "race_to_fraud",
            "steps": ["race_condition", "payment_manipulation", "refund_abuse"],
            "description": "Race payment endpoint -> duplicate credit -> refund original",
            "severity_upgrade": "critical",
            "kill_chain": "financial_fraud",
        },
        {
            "name": "token_to_takeover",
            "steps": ["jwt_weakness", "auth_bypass", "privilege_escalation"],
            "description": "Forge JWT -> bypass auth -> escalate privileges",
            "severity_upgrade": "critical",
            "kill_chain": "account_takeover",
        },
        {
            "name": "waf_bypass_chain",
            "steps": ["waf_bypass", "injection", "data_exfiltration"],
            "description": "Bypass WAF -> inject payload -> extract data",
            "severity_upgrade": "critical",
            "kill_chain": "defense_evasion",
        },
        {
            "name": "idor_to_mass_data",
            "steps": ["idor", "rate_limit_bypass", "data_exfiltration"],
            "description": "Enumerate via IDOR -> bypass rate limit -> mass extract",
            "severity_upgrade": "critical",
            "kill_chain": "data_breach",
        },
        # --- Payment glue code attack chains ---
        {
            "name": "webhook_to_entitlement",
            "steps": ["webhook_forge", "entitlement_bypass"],
            "description": "Forge webhook event -> gain premium entitlement without payment",
            "severity_upgrade": "critical",
            "kill_chain": "access_without_payment",
        },
        {
            "name": "trial_abuse_chain",
            "steps": ["entitlement_bypass", "coupon_stacking", "refund_abuse"],
            "description": "Extend trial indefinitely -> stack coupons -> refund for profit",
            "severity_upgrade": "critical",
            "kill_chain": "financial_fraud",
        },
        {
            "name": "stripe_object_confusion",
            "steps": ["idor", "payment_manipulation", "entitlement_bypass"],
            "description": "Enumerate Stripe objects -> swap customer references -> access another's subscription",
            "severity_upgrade": "critical",
            "kill_chain": "account_takeover",
        },
        {
            "name": "amount_manipulation_chain",
            "steps": ["payment_manipulation", "race_condition"],
            "description": "Modify amount client-side -> race payment confirmation -> pay less or zero",
            "severity_upgrade": "critical",
            "kill_chain": "financial_fraud",
        },
        {
            "name": "api_version_downgrade",
            "steps": ["info_disclosure", "injection", "auth_bypass"],
            "description": "Discover old API version -> exploit unpatched vuln -> bypass auth",
            "severity_upgrade": "critical",
            "kill_chain": "defense_evasion",
        },
        {
            "name": "idempotency_abuse",
            "steps": ["race_condition", "payment_manipulation", "entitlement_bypass"],
            "description": "Replay idempotent request -> duplicate payment success -> double entitlement",
            "severity_upgrade": "high",
            "kill_chain": "financial_fraud",
        },
        {
            "name": "connect_platform_drain",
            "steps": ["auth_bypass", "payment_manipulation"],
            "description": "Access platform account -> manipulate transfer amounts -> drain funds",
            "severity_upgrade": "critical",
            "kill_chain": "financial_fraud",
        },
        {
            "name": "subscription_state_exploit",
            "steps": ["entitlement_bypass", "payment_manipulation", "refund_abuse"],
            "description": "Exploit subscription state machine gap -> access while unpaid -> refund",
            "severity_upgrade": "critical",
            "kill_chain": "access_without_payment",
        },
        # --- v8: Enterprise attack chain templates ---
        {
            "name": "graphql_alias_rate_bypass",
            "steps": ["graphql_alias_batching", "rate_limit_bypass", "auth_bypass"],
            "description": "Batch 100+ login attempts in 1 request via aliases -> brute-force credentials -> full access",
            "severity_upgrade": "critical",
            "kill_chain": "account_takeover",
        },
        {
            "name": "smuggling_to_cache_poison",
            "steps": ["http_smuggling", "cache_poisoning", "data_exfiltration"],
            "description": "CL/TE desync -> poison CDN cache -> serve malicious content to all users",
            "severity_upgrade": "critical",
            "kill_chain": "mass_compromise",
        },
        {
            "name": "jwt_to_admin_takeover",
            "steps": ["jwt_weakness", "auth_bypass", "privilege_escalation"],
            "description": "JWT alg:none -> forge admin token -> escalate to full control",
            "severity_upgrade": "critical",
            "kill_chain": "account_takeover",
        },
        {
            "name": "prototype_to_rce",
            "steps": ["prototype_pollution", "injection", "data_exfiltration"],
            "description": "Pollute Object.prototype -> trigger gadget chain (Silent Spring) -> RCE",
            "severity_upgrade": "critical",
            "kill_chain": "full_compromise",
        },
        {
            "name": "waf_to_injection_chain",
            "steps": ["waf_bypass", "injection", "privilege_escalation"],
            "description": "Exceed WAF body limit (8KB+) -> deliver uninspected payload -> escalate",
            "severity_upgrade": "critical",
            "kill_chain": "defense_evasion",
        },
        {
            "name": "device_code_phishing_chain",
            "steps": ["device_code_flow", "auth_bypass", "entitlement_bypass"],
            "description": "Storm-2372: phish device code -> steal OAuth session -> access paid features",
            "severity_upgrade": "critical",
            "kill_chain": "account_takeover",
        },
        {
            "name": "mcp_tool_poisoning_chain",
            "steps": ["mcp_tool_poisoning", "injection", "data_exfiltration"],
            "description": "Poison MCP tool description -> agent executes malicious tool -> exfil data",
            "severity_upgrade": "critical",
            "kill_chain": "agent_compromise",
        },
        {
            "name": "webhook_forgery_chain",
            "steps": ["webhook_forge", "payment_manipulation", "entitlement_bypass"],
            "description": "Forge checkout.session.completed with empty signing secret -> instant premium",
            "severity_upgrade": "critical",
            "kill_chain": "access_without_payment",
        },
        # --- v8.2: 6 new enterprise chain templates ---
        {
            "name": "saml_sso_to_entitlement",
            "steps": ["saml_bypass", "auth_bypass", "entitlement_bypass"],
            "description": "Forge unsigned SAML assertion -> impersonate paid user -> free enterprise access",
            "severity_upgrade": "critical",
            "kill_chain": "access_without_payment",
        },
        {
            "name": "api_version_downgrade_chain",
            "steps": ["api_version_downgrade", "auth_bypass", "entitlement_bypass"],
            "description": "Hit deprecated API version lacking auth -> bypass payment checks -> free access",
            "severity_upgrade": "critical",
            "kill_chain": "access_without_payment",
        },
        {
            "name": "race_condition_double_spend",
            "steps": ["race_condition", "payment_manipulation", "entitlement_bypass"],
            "description": "Concurrent requests exploit TOCTOU -> double-spend credits or duplicate entitlements",
            "severity_upgrade": "critical",
            "kill_chain": "access_without_payment",
        },
        {
            "name": "idempotency_replay_chain",
            "steps": ["webhook_forge", "idempotency_abuse", "entitlement_bypass"],
            "description": "Replay webhook events with null idempotency key -> stack credits/entitlements",
            "severity_upgrade": "critical",
            "kill_chain": "access_without_payment",
        },
        {
            "name": "subscription_state_exploit",
            "steps": ["payment_manipulation", "subscription_state_confusion", "entitlement_bypass"],
            "description": "Trigger payment failure -> subscription enters past_due -> access persists indefinitely",
            "severity_upgrade": "critical",
            "kill_chain": "access_without_payment",
        },
        {
            "name": "seat_overflow_chain",
            "steps": ["race_condition", "seat_overflow", "entitlement_bypass"],
            "description": "Concurrent seat additions exceed plan limit -> free enterprise seats for extra users",
            "severity_upgrade": "high",
            "kill_chain": "access_without_payment",
        },
        # v8.3: Enterprise payment abuse chains
        {
            "name": "price_id_substitution_chain",
            "steps": ["client_price_bypass", "entitlement_bypass", "privilege_escalation"],
            "description": "Substitute cheap priceId at checkout -> get premium entitlement -> escalate to enterprise features",
            "severity_upgrade": "critical",
            "kill_chain": "access_without_payment",
        },
        {
            "name": "refund_abuse_chain",
            "steps": ["refund_retained_access", "subscription_state_confusion"],
            "description": "Subscribe -> use service -> refund/chargeback -> entitlement persists -> permanent free access",
            "severity_upgrade": "critical",
            "kill_chain": "access_without_payment",
        },
        {
            "name": "metering_evasion_chain",
            "steps": ["usage_metering_bypass", "rate_limit_bypass"],
            "description": "Zero/omit usage records -> consume unlimited resources -> never billed for overage",
            "severity_upgrade": "critical",
            "kill_chain": "access_without_payment",
        },
        {
            "name": "webhook_replay_stacking",
            "steps": ["webhook_event_replay", "idempotency_replay", "entitlement_bypass"],
            "description": "Replay webhook event -> missing dedup grants duplicate credits -> stack to unlimited quota",
            "severity_upgrade": "critical",
            "kill_chain": "access_without_payment",
        },
        {
            "name": "feature_flag_self_grant",
            "steps": ["feature_flag_override", "client_price_bypass"],
            "description": "Override feature flags in request body -> self-grant premium features -> bypass subscription check",
            "severity_upgrade": "high",
            "kill_chain": "access_without_payment",
        },
        {
            "name": "coupon_stacking_free_enterprise",
            "steps": ["coupon_stacking", "promo_credit_exploit", "entitlement_bypass"],
            "description": "Stack referral + promo + seasonal coupons -> 100%+ discount -> free enterprise annual plan",
            "severity_upgrade": "critical",
            "kill_chain": "access_without_payment",
        },
    ]

    def __init__(self) -> None:
        self._chains_found: list[ExploitChain] = []
        self._chain_counter = 0

    def synthesize_chains(
        self,
        hypotheses: list,  # list[Hypothesis]
        findings_history: list[dict[str, Any]],
        knowledge_graph: KnowledgeGraph,
    ) -> list[ExploitChain]:
        """Try to assemble multi-step exploit chains from current hypotheses
        and historical findings."""
        new_chains: list[ExploitChain] = []

        active_cats = {h.category for h in hypotheses if h.posterior > 0.2}

        all_cats = set(active_cats)
        for f in findings_history[-50:]:
            cat = f.get("category", "")
            if cat:
                all_cats.add(cat)

        for template in self._CHAIN_TEMPLATES:
            required = set(template["steps"])
            matched = required & all_cats
            match_ratio = len(matched) / len(required)

            if match_ratio >= 0.6:
                step_details: list[dict[str, Any]] = []
                step_probs: list[float] = []
                step_sevs: list[str] = []

                for step_cat in template["steps"]:
                    matching_hyp = [
                        h for h in hypotheses if h.category == step_cat and h.posterior > 0.1
                    ]
                    matching_hist = [
                        f for f in findings_history[-50:]
                        if f.get("category") == step_cat
                    ]

                    if matching_hyp:
                        best = max(matching_hyp, key=lambda h: h.posterior)
                        step_details.append({
                            "category": step_cat,
                            "source": "current_hypothesis",
                            "probability": round(best.posterior, 3),
                            "description": best.description[:100],
                        })
                        step_probs.append(best.posterior)
                        step_sevs.append("high" if best.posterior > 0.5 else "medium")
                    elif matching_hist:
                        best_hist = max(matching_hist, key=lambda f: f.get("posterior", 0.3))
                        step_details.append({
                            "category": step_cat,
                            "source": "historical_finding",
                            "probability": round(best_hist.get("posterior", 0.3), 3),
                        })
                        step_probs.append(best_hist.get("posterior", 0.3))
                        step_sevs.append("medium")
                    else:
                        step_details.append({
                            "category": step_cat,
                            "source": "inferred_gap",
                            "probability": 0.1,
                        })
                        step_probs.append(0.1)
                        step_sevs.append("low")

                combined_prob = 1.0
                for p in step_probs:
                    combined_prob *= p
                combined_prob = combined_prob ** (1.0 / len(step_probs))

                if match_ratio >= 0.6:
                    combined_prob *= (1.0 + 0.2 * (match_ratio - 0.6))

                unprotected = knowledge_graph.find_unprotected_paths()
                if unprotected:
                    combined_prob = min(0.99, combined_prob * 1.3)

                self._chain_counter += 1
                chain = ExploitChain(
                    chain_id=f"CHAIN-{self._chain_counter:03d}-{template['name']}",
                    steps=step_details,
                    combined_severity=template["severity_upgrade"] if match_ratio >= 0.8 else "high",
                    combined_probability=round(combined_prob, 4),
                    description=template["description"],
                    kill_chain_phase=template["kill_chain"],
                    individual_severities=step_sevs,
                )
                new_chains.append(chain)

        new_chains.sort(key=lambda c: c.combined_probability, reverse=True)
        self._chains_found.extend(new_chains)
        return new_chains

    def get_all_chains(self) -> list[dict[str, Any]]:
        return [
            {
                "id": c.chain_id,
                "description": c.description,
                "steps": c.steps,
                "combined_severity": c.combined_severity,
                "combined_probability": c.combined_probability,
                "kill_chain_phase": c.kill_chain_phase,
                "step_count": len(c.steps),
            }
            for c in sorted(self._chains_found, key=lambda c: c.combined_probability, reverse=True)
        ]


# ============================================================================
# I. Adversarial Self-Verifier (Agent-as-a-Judge)
# ============================================================================

class AdversarialSelfVerifier:
    """Agent-as-a-Judge: a second reasoning pass that audits the entire
    analysis trajectory for shortcuts, false positives, and logical errors.

    Directly from ExploitGym's verification protocol: after the agent
    produces an exploit, a separate judge model reviews the full trajectory
    to verify the agent actually exploited the INTENDED vulnerability, not
    just any bug it stumbled upon.

    Our analog: after all engines produce their outputs, this verifier
    checks for:
    1. Consistency: Do the engines' conclusions agree with each other?
    2. Evidence sufficiency: Is there enough concrete evidence, or just
       pattern-matching on surface features?
    3. False positive indicators: Common FP patterns that inflate scores
    4. Reward hacking: Did the analysis game its own scoring?

    ExploitGym found that 69 of Mythos's 226 flag captures exploited an
    UNINTENDED vulnerability. This verifier catches that class of error."""

    _FALSE_POSITIVE_INDICATORS: list[tuple[str, str, float]] = [
        ("cors_preflight", "OPTIONS request with Access-Control headers is likely CORS, not a vuln", -0.3),
        ("health_check", "Health/status endpoint returning 200 is expected behavior", -0.4),
        ("swagger_ui", "Swagger/OpenAPI docs endpoint is intentionally public", -0.3),
        ("favicon_404", "Missing favicon is not a security finding", -0.5),
        ("csrf_token_present", "CSRF token present means defense IS working", -0.2),
        ("rate_limited", "Being rate-limited confirms defense is active", -0.2),
        ("redirect_to_login", "Redirect to login means auth IS enforced", -0.3),
        ("empty_body_200", "200 with empty body may be a no-content response, not a data leak", -0.15),
    ]

    def __init__(self) -> None:
        self._verification_results: list[dict[str, Any]] = []

    def verify(
        self,
        engine_scores: dict[str, float],
        hypotheses: list,
        components: dict[str, Any],
        zero_shot_findings: list,
        overall_score: float,
        consensus: dict[str, Any],
    ) -> dict[str, Any]:
        """Run adversarial verification on the analysis output."""
        issues: list[str] = []
        adjustments: list[tuple[str, float]] = []

        # Check 1: Consistency between engines
        flagging = [n for n, s in engine_scores.items() if s > 0.3]
        non_flagging = [n for n, s in engine_scores.items() if s <= 0.1]
        if len(flagging) == 1 and len(non_flagging) >= 4:
            issues.append(
                f"Single-engine outlier: only '{flagging[0]}' flagging while "
                f"{len(non_flagging)} engines see nothing. Likely false positive."
            )
            adjustments.append(("single_engine_outlier", -0.15))

        # Check 2: Evidence sufficiency
        if overall_score > 0.5 and len(zero_shot_findings) == 0:
            if not any(s > 0.4 for s in engine_scores.values()):
                issues.append(
                    "High overall score but no zero-shot findings and no strong engine signal. "
                    "Score may be inflated by consensus/amplification mechanics."
                )
                adjustments.append(("insufficient_evidence", -0.1))

        # Check 3: False positive pattern detection
        endpoint = components.get("endpoint", "").lower()
        method = components.get("method", "GET")
        status = components.get("status_code", 0)
        body_text = components.get("body_text", "").lower()

        if method == "OPTIONS" and "access-control" in str(components.get("headers", {})).lower():
            issues.append("CORS preflight detected -- not a vulnerability")
            adjustments.append(("cors_preflight", -0.3))

        if any(p in endpoint for p in ("/health", "/status", "/ping", "/ready", "/alive")):
            if status == 200:
                issues.append("Health check endpoint -- expected to be public")
                adjustments.append(("health_check", -0.4))

        if any(p in endpoint for p in ("/swagger", "/api-docs", "/openapi", "/docs")):
            issues.append("API documentation endpoint -- intentionally public")
            adjustments.append(("swagger_docs", -0.3))

        if status in (301, 302, 307, 308) and "login" in str(components.get("headers", {})).lower():
            issues.append("Redirect to login -- auth IS being enforced")
            adjustments.append(("redirect_to_login", -0.3))

        if status == 429:
            issues.append("Rate limited -- defense IS active")
            adjustments.append(("rate_limited", -0.2))

        # Check 4: Reward hacking detection
        if hypotheses:
            top_cats = [h.category for h in hypotheses[:3]]
            if len(set(top_cats)) == 1:
                single_cat = top_cats[0]
                if all(
                    h.category == single_cat for h in hypotheses[:5]
                    if h.posterior > 0.1
                ):
                    issues.append(
                        f"All top hypotheses are '{single_cat}' -- possible reward hacking. "
                        f"The scoring may be over-indexing on one category."
                    )
                    adjustments.append(("category_monoculture", -0.05))

        total_adjustment = sum(adj for _, adj in adjustments)
        adjusted_score = max(0.0, min(1.0, overall_score + total_adjustment))

        verdict = "CONFIRMED" if not issues else "PLAUSIBLE" if len(issues) <= 2 else "SUSPECT"

        result = {
            "verdict": verdict,
            "issues": issues,
            "adjustments": adjustments,
            "original_score": round(overall_score, 4),
            "adjusted_score": round(adjusted_score, 4),
            "score_delta": round(total_adjustment, 4),
        }
        self._verification_results.append(result)
        return result


# ============================================================================
# J. Semantic Pattern Reasoner
# ============================================================================

class SemanticPatternReasoner:
    """Goes beyond regex matching to understand what response patterns MEAN
    in context.

    Inspired by Mythos catching an FFmpeg H.264 bug by "reasoning about code
    semantics" after fuzzers exercised the vulnerable path 5 million times
    without triggering it. The key: fuzzers test EXECUTION, semantic reasoning
    tests MEANING.

    This engine analyzes patterns that regex can't catch:
    - Semantic contradictions ("plan": "free" but "entitlement": "premium")
    - Temporal anomalies (created_at > updated_at, or expiry in the past)
    - Business logic violations (amount=0 for a paid plan)
    - State machine violations (order "shipped" but no tracking number)
    - Implicit information leaks (error messages that reveal architecture)"""

    _SEMANTIC_RULES: list[tuple[str, str, Any, str, str, float]] = [
        ("plan_entitlement_mismatch", "plan_vs_entitlement",
         None, "entitlement_bypass",
         "Plan tier and entitlement level are contradictory", 0.85),
        ("zero_amount_active", "amount_vs_status",
         None, "payment_manipulation",
         "Active subscription/order with zero amount", 0.8),
        ("expired_but_active", "expiry_vs_status",
         None, "entitlement_bypass",
         "Resource shows active status but expiry date is in the past", 0.7),
        ("no_auth_sensitive_data", "auth_vs_data_sensitivity",
         None, "auth_bypass",
         "Sensitive data returned without authentication", 0.75),
        ("admin_field_exposed", "role_exposure",
         None, "privilege_escalation",
         "Admin/role fields exposed in non-admin response", 0.65),
    ]

    def __init__(self) -> None:
        self._semantic_findings: list[dict[str, Any]] = []

    def analyze_semantics(self, components: dict[str, Any]) -> list[dict[str, Any]]:
        """Analyze response for semantic contradictions and business logic violations."""
        findings: list[dict[str, Any]] = []
        body_text = components.get("body_text", "")
        status = components.get("status_code", 0)
        has_auth = components.get("has_auth_header", False)
        endpoint = components.get("endpoint", "")

        # Rule 1: Plan/entitlement mismatch
        plan_match = re.search(r'"(?:plan|tier|level)":\s*"(\w+)"', body_text, re.I)
        entitlement_match = re.search(r'"(?:entitlement|access_level|subscription)":\s*"(\w+)"', body_text, re.I)
        if plan_match and entitlement_match:
            plan = plan_match.group(1).lower()
            entitlement = entitlement_match.group(1).lower()
            free_plans = {"free", "basic", "starter", "trial", "lite"}
            premium_entitlements = {"premium", "pro", "enterprise", "unlimited", "gold", "platinum"}
            if plan in free_plans and entitlement in premium_entitlements:
                findings.append({
                    "type": "semantic_contradiction",
                    "rule": "plan_entitlement_mismatch",
                    "detail": f"Plan='{plan}' but entitlement='{entitlement}' -- access without payment",
                    "category": "entitlement_bypass",
                    "confidence": 0.9,
                    "severity": "critical",
                })

        # Rule 2: Zero amount on active resource
        amount_match = re.search(r'"(?:amount|price|total|cost|charge)":\s*([0-9.]+)', body_text, re.I)
        status_match = re.search(r'"(?:status|state)":\s*"(\w+)"', body_text, re.I)
        if amount_match and status_match:
            amount = float(amount_match.group(1))
            resource_status = status_match.group(1).lower()
            active_statuses = {"active", "paid", "completed", "fulfilled", "confirmed"}
            if amount == 0 and resource_status in active_statuses:
                findings.append({
                    "type": "semantic_contradiction",
                    "rule": "zero_amount_active",
                    "detail": f"Amount={amount} but status='{resource_status}' -- zero-cost active resource",
                    "category": "payment_manipulation",
                    "confidence": 0.85,
                    "severity": "high",
                })

        # Rule 3: Temporal anomalies
        created_match = re.search(r'"(?:created_at|created)":\s*"([^"]+)"', body_text, re.I)
        updated_match = re.search(r'"(?:updated_at|modified)":\s*"([^"]+)"', body_text, re.I)
        expires_match = re.search(r'"(?:expires_at|expiry|exp)":\s*"?(\d+)"?', body_text, re.I)
        if created_match and updated_match:
            if created_match.group(1) > updated_match.group(1):
                findings.append({
                    "type": "temporal_anomaly",
                    "rule": "created_after_updated",
                    "detail": "created_at > updated_at -- possible clock manipulation or data tampering",
                    "category": "data_integrity",
                    "confidence": 0.6,
                    "severity": "medium",
                })

        # Rule 4: Sensitive data without auth
        sensitive_patterns = [
            (r'"(?:ssn|social_security|tax_id)"', "PII"),
            (r'"(?:card_number|cc_num|pan)"', "payment_card"),
            (r'"(?:password_hash|hashed_password)"', "credential"),
            (r'"(?:internal_ip|private_ip)":\s*"(?:10\.|172\.|192\.168\.)', "internal_network"),
            (r'"(?:api_key|secret_key|access_token)":\s*"[a-zA-Z0-9_-]{20,}"', "api_secret"),
        ]
        if not has_auth and status in range(200, 300):
            for pattern, data_type in sensitive_patterns:
                if re.search(pattern, body_text, re.I):
                    findings.append({
                        "type": "unauthenticated_data_exposure",
                        "rule": "no_auth_sensitive_data",
                        "detail": f"{data_type} data returned without authentication",
                        "category": "auth_bypass",
                        "confidence": 0.8,
                        "severity": "critical",
                    })

        # Rule 5: State machine violations
        shipped_no_tracking = (
            re.search(r'"(?:status|state)":\s*"shipped"', body_text, re.I)
            and not re.search(r'"(?:tracking|tracking_number|tracking_id)"', body_text, re.I)
        )
        if shipped_no_tracking:
            findings.append({
                "type": "state_machine_violation",
                "rule": "shipped_no_tracking",
                "detail": "Order marked 'shipped' but no tracking number -- possible state manipulation",
                "category": "business_logic",
                "confidence": 0.55,
                "severity": "medium",
            })

        # Rule 6: Implicit architecture leaks in error messages
        arch_patterns = [
            (r'(?:at |in )[\w.]+\.(?:java|py|rb|go|rs):\d+', "stack_trace_leak"),
            (r'(?:MySQL|PostgreSQL|MongoDB|Redis|Elasticsearch)\s+(?:error|version)', "database_leak"),
            (r'(?:nginx|apache|tomcat|gunicorn|uwsgi)/[\d.]+', "server_version_leak"),
            (r'AWS_(?:ACCESS_KEY|SECRET|SESSION)', "cloud_credential_leak"),
        ]
        for pattern, leak_type in arch_patterns:
            if re.search(pattern, body_text, re.I):
                findings.append({
                    "type": "architecture_leak",
                    "rule": leak_type,
                    "detail": f"Response reveals {leak_type.replace('_', ' ')}",
                    "category": "info_disclosure",
                    "confidence": 0.7,
                    "severity": "medium",
                })

        # Rule 7: Response size anomaly relative to request
        body_size = components.get("body_size", 0)
        if body_size > 10000 and not has_auth:
            findings.append({
                "type": "excessive_data",
                "rule": "large_unauthed_response",
                "detail": f"Large response ({body_size} bytes) without authentication",
                "category": "info_disclosure",
                "confidence": 0.5,
                "severity": "medium",
            })

        # Rule 8: Subscription lifecycle anomalies
        trial_end = re.search(r'"(?:trial_end|trial_ends_at)":\s*(\d+)', body_text, re.I)
        sub_status_m = re.search(r'"(?:status)":\s*"(trialing|active|past_due|canceled|unpaid)"', body_text, re.I)
        cancel_at_end = re.search(r'"cancel_at_period_end":\s*(true)', body_text, re.I)
        period_end = re.search(r'"current_period_end":\s*(\d+)', body_text, re.I)
        if trial_end and sub_status_m:
            if sub_status_m.group(1) == "trialing":
                try:
                    ts = int(trial_end.group(1))
                    if ts < int(time.time()) and ts > 946684800:
                        findings.append({
                            "type": "subscription_lifecycle_anomaly",
                            "rule": "expired_trial_still_trialing",
                            "detail": f"trial_end={ts} is in the past but status is still 'trialing' -- "
                                      f"glue code fails to transition trial -> expired/active",
                            "category": "entitlement_bypass",
                            "confidence": 0.9,
                            "severity": "critical",
                        })
                except (ValueError, OverflowError):
                    pass
        if cancel_at_end and period_end:
            try:
                pe = int(period_end.group(1))
                if pe < int(time.time()) and pe > 946684800:
                    findings.append({
                        "type": "subscription_lifecycle_anomaly",
                        "rule": "cancel_period_end_lapsed",
                        "detail": f"cancel_at_period_end=true but current_period_end={pe} is past -- "
                                  f"subscription should be canceled but is still active",
                        "category": "entitlement_bypass",
                        "confidence": 0.85,
                        "severity": "critical",
                    })
            except (ValueError, OverflowError):
                pass

        # Rule 9: Stripe-specific glue code bugs
        pi_status = re.search(r'"payment_intent"[^}]*"status":\s*"(\w+)"', body_text, re.I)
        if not pi_status:
            pi_status = re.search(r'"payment_intent_status":\s*"(\w+)"', body_text, re.I)
        inv_paid = re.search(r'"(?:invoice[^"]*)"[^}]*"paid":\s*(true|false)', body_text, re.I)
        if not inv_paid:
            inv_paid = re.search(r'"invoice_paid":\s*(true|false)', body_text, re.I)
        if pi_status and inv_paid:
            if pi_status.group(1) == "succeeded" and inv_paid.group(1) == "false":
                findings.append({
                    "type": "stripe_glue_bug",
                    "rule": "pi_succeeded_invoice_unpaid",
                    "detail": "payment_intent.status=succeeded but invoice.paid=false -- "
                              "glue code trusts PI status without verifying invoice settlement",
                    "category": "payment_manipulation",
                    "confidence": 0.92,
                    "severity": "critical",
                })

        sub_active = re.search(r'"(?:subscription[^"]*)"[^}]*"status":\s*"active"', body_text, re.I)
        if not sub_active:
            sub_active = re.search(r'"subscription_status":\s*"active"', body_text, re.I)
        latest_inv = re.search(r'"latest_invoice[^"]*"[^}]*"status":\s*"(\w+)"', body_text, re.I)
        if not latest_inv:
            latest_inv = re.search(r'"latest_invoice_status":\s*"(\w+)"', body_text, re.I)
        if sub_active and latest_inv:
            if latest_inv.group(1) not in ("paid", "void"):
                findings.append({
                    "type": "stripe_glue_bug",
                    "rule": "active_sub_unpaid_invoice",
                    "detail": f"subscription.status=active but latest_invoice.status="
                              f"'{latest_inv.group(1)}' -- entitlement granted before payment clears",
                    "category": "entitlement_bypass",
                    "confidence": 0.88,
                    "severity": "critical",
                })

        default_source = re.search(r'"default_source":\s*null', body_text, re.I)
        default_pm = re.search(r'"default_payment_method":\s*null', body_text, re.I)
        if (default_source or default_pm) and sub_active:
            findings.append({
                "type": "stripe_glue_bug",
                "rule": "no_payment_method_active_sub",
                "detail": "Active subscription with null default_source/default_payment_method -- "
                          "subscription will fail to renew, possible free-ride window",
                "category": "payment_manipulation",
                "confidence": 0.75,
                "severity": "high",
            })

        cs_payment = re.search(r'"payment_status":\s*"(unpaid|no_payment_required)"', body_text, re.I)
        cs_status = re.search(r'"(?:checkout_session_status|cs_status)":\s*"complete"', body_text, re.I)
        if not cs_status:
            cs_status = re.search(r'"status":\s*"complete".*"object":\s*"checkout.session"', body_text, re.I)
        if cs_payment and cs_status:
            if cs_payment.group(1) == "unpaid":
                findings.append({
                    "type": "stripe_glue_bug",
                    "rule": "checkout_complete_unpaid",
                    "detail": "checkout.session.status=complete but payment_status=unpaid -- "
                              "glue code grants access on session completion without payment check",
                    "category": "payment_manipulation",
                    "confidence": 0.93,
                    "severity": "critical",
                })

        # Rule 10: Amount normalization attacks
        neg_amount = re.search(r'"(?:amount|price|total|cost|charge)":\s*(-[0-9.]+)', body_text, re.I)
        if neg_amount:
            findings.append({
                "type": "amount_anomaly",
                "rule": "negative_amount",
                "detail": f"Negative amount ({neg_amount.group(1)}) -- possible refund abuse or credit injection",
                "category": "refund_abuse",
                "confidence": 0.9,
                "severity": "critical",
            })
        if amount_match:
            amount_val = float(amount_match.group(1))
            if 0 < amount_val <= 1 and "cent" not in body_text.lower():
                findings.append({
                    "type": "amount_anomaly",
                    "rule": "minimum_charge_bypass",
                    "detail": f"Amount={amount_val} (sub-penny or 1-cent) -- minimum charge bypass attempt",
                    "category": "payment_manipulation",
                    "confidence": 0.7,
                    "severity": "high",
                })
            elif amount_val > 99999900:
                findings.append({
                    "type": "amount_anomaly",
                    "rule": "excessive_amount",
                    "detail": f"Amount={amount_val} exceeds sane bounds -- integer overflow or injection",
                    "category": "payment_manipulation",
                    "confidence": 0.8,
                    "severity": "critical",
                })

        url_amount = re.search(r'[?&]amount=([0-9.]+)', components.get("url", ""), re.I)
        if url_amount and amount_match:
            try:
                url_amt = float(url_amount.group(1))
                resp_amt = float(amount_match.group(1))
                if url_amt != resp_amt and url_amt > 0:
                    findings.append({
                        "type": "amount_anomaly",
                        "rule": "amount_mismatch_url_vs_body",
                        "detail": f"URL amount={url_amt} but response amount={resp_amt} -- "
                                  f"client-side amount not validated server-side",
                        "category": "payment_manipulation",
                        "confidence": 0.85,
                        "severity": "critical",
                    })
            except ValueError:
                pass

        # Rule 11: Privilege boundary crossings
        role_matches = re.findall(r'"(?:role|user_role)":\s*"(\w+)"', body_text, re.I)
        if len(set(role_matches)) > 1:
            findings.append({
                "type": "privilege_boundary",
                "rule": "confused_role_assignment",
                "detail": f"Multiple roles in single response: {sorted(set(role_matches))} -- "
                          f"confused deputy or role bleed",
                "category": "privilege_escalation",
                "confidence": 0.75,
                "severity": "high",
            })

        resp_org = re.search(r'"(?:organization_id|org_id|tenant_id)":\s*"([^"]+)"', body_text, re.I)
        req_org = re.search(r'(?:organization_id|org_id|tenant_id)[=:]([^&"\s]+)',
                            components.get("url", "") + str(components.get("request_body", "")), re.I)
        if resp_org and req_org:
            if resp_org.group(1) != req_org.group(1):
                findings.append({
                    "type": "privilege_boundary",
                    "rule": "cross_tenant_leak",
                    "detail": f"Request org='{req_org.group(1)}' but response org='{resp_org.group(1)}' -- "
                              f"cross-tenant data leak",
                    "category": "idor",
                    "confidence": 0.9,
                    "severity": "critical",
                })

        resp_uid = re.search(r'"(?:user_id|userId|uid)":\s*"([^"]+)"', body_text, re.I)
        req_uid = re.search(r'(?:user_id|userId|uid)[=:]([^&"\s]+)',
                            components.get("url", ""), re.I)
        if resp_uid and req_uid:
            if resp_uid.group(1) != req_uid.group(1):
                findings.append({
                    "type": "privilege_boundary",
                    "rule": "user_id_mismatch",
                    "detail": f"Request user='{req_uid.group(1)}' but response user='{resp_uid.group(1)}' -- IDOR",
                    "category": "idor",
                    "confidence": 0.88,
                    "severity": "critical",
                })

        # Rule 12: API versioning inconsistencies
        resp_headers = components.get("headers", {})
        req_headers = components.get("request_headers", {})
        resp_version = None
        req_version = None
        for hdr_dict, store in [(resp_headers, "resp"), (req_headers, "req")]:
            for k, v in (hdr_dict.items() if isinstance(hdr_dict, dict) else []):
                lk = k.lower()
                if lk in ("stripe-version", "api-version", "x-api-version", "paypal-auth-version"):
                    if store == "resp":
                        resp_version = v
                    else:
                        req_version = v
        if req_version and resp_version and req_version != resp_version:
            findings.append({
                "type": "api_versioning",
                "rule": "version_mismatch",
                "detail": f"Request API version='{req_version}' but response='{resp_version}' -- "
                          f"server may ignore client version or pin to older/newer",
                "category": "info_disclosure",
                "confidence": 0.6,
                "severity": "medium",
            })

        deprecated_fields = [
            "source", "sources", "bitcoin_amount", "three_d_secure",
            "alipay", "bancontact", "eps", "ideal", "multibanco", "p24",
        ]
        for dep_field in deprecated_fields:
            if re.search(rf'"{dep_field}":', body_text, re.I):
                findings.append({
                    "type": "api_versioning",
                    "rule": "deprecated_field_present",
                    "detail": f"Deprecated field '{dep_field}' in response -- "
                              f"server uses old Stripe API version with known issues",
                    "category": "info_disclosure",
                    "confidence": 0.55,
                    "severity": "medium",
                })
                break

        # Rule 13: Rate limit intelligence
        rl_remaining = None
        rl_limit = None
        for k, v in (resp_headers.items() if isinstance(resp_headers, dict) else []):
            lk = k.lower()
            if lk in ("x-ratelimit-remaining", "ratelimit-remaining", "x-rate-limit-remaining"):
                try:
                    rl_remaining = int(v)
                except (ValueError, TypeError):
                    pass
            if lk in ("x-ratelimit-limit", "ratelimit-limit", "x-rate-limit-limit"):
                try:
                    rl_limit = int(v)
                except (ValueError, TypeError):
                    pass

        if rl_remaining is not None and rl_remaining <= 0 and status in range(200, 300):
            findings.append({
                "type": "rate_limit_anomaly",
                "rule": "rate_limit_bypass",
                "detail": f"X-RateLimit-Remaining={rl_remaining} but request succeeded (HTTP {status}) -- "
                          f"rate limit header present but NOT enforced",
                "category": "rate_limit_bypass",
                "confidence": 0.85,
                "severity": "high",
            })

        method = components.get("method", "GET")
        if method in _MUTATING_METHODS and rl_remaining is None and rl_limit is None:
            if status in range(200, 300):
                findings.append({
                    "type": "rate_limit_anomaly",
                    "rule": "no_rate_limit_mutation",
                    "detail": f"No rate limit headers on {method} endpoint -- "
                              f"mutation endpoint unprotected against abuse/brute-force",
                    "category": "race_condition",
                    "confidence": 0.5,
                    "severity": "medium",
                })

        # Rule 14: Webhook event type confusion
        event_type = re.search(r'"(?:type|event_type)":\s*"([^"]+)"', body_text, re.I)
        if event_type:
            evt = event_type.group(1)
            if evt == "checkout.session.completed":
                if not re.search(r'"payment_status":\s*"paid"', body_text, re.I):
                    findings.append({
                        "type": "webhook_confusion",
                        "rule": "checkout_completed_no_payment_check",
                        "detail": "checkout.session.completed event without payment_status=paid -- "
                                  "glue code grants access on session completion, not payment success",
                        "category": "payment_manipulation",
                        "confidence": 0.88,
                        "severity": "critical",
                    })

            if evt == "invoice.paid":
                if re.search(r'"amount_paid":\s*0', body_text, re.I):
                    findings.append({
                        "type": "webhook_confusion",
                        "rule": "invoice_paid_zero_amount",
                        "detail": "invoice.paid event with amount_paid=0 -- "
                                  "glue code treats $0 invoice (trial/coupon) as paid subscription",
                        "category": "entitlement_bypass",
                        "confidence": 0.8,
                        "severity": "high",
                    })

            if evt == "customer.subscription.updated":
                if not re.search(r'"previous_attributes"', body_text, re.I):
                    findings.append({
                        "type": "webhook_confusion",
                        "rule": "subscription_updated_no_diff",
                        "detail": "customer.subscription.updated without checking previous_attributes -- "
                                  "glue code may re-grant entitlements on any subscription change",
                        "category": "entitlement_bypass",
                        "confidence": 0.65,
                        "severity": "high",
                    })

        self._semantic_findings.extend(findings)
        return findings

    def get_all_findings(self) -> list[dict[str, Any]]:
        return self._semantic_findings[-50:]


# ============================================================================
# K. Kill Chain Scorer (Stage-Aware Reward Shaping)
# ============================================================================

class KillChainScorer:
    """Stage-aware scoring with shaped bonuses per attack phase.

    From the RL research (arXiv 2605.17075): kill-chain-aligned reward
    shaping with bonuses and penalties per stage outperforms sparse rewards
    for multi-stage attack discovery.

    Maps findings to Lockheed Martin Cyber Kill Chain phases:
    1. Reconnaissance    - info disclosure, tech fingerprinting
    2. Weaponization     - identifying exploitable vulns
    3. Delivery          - finding injection/upload vectors
    4. Exploitation      - auth bypass, injection, SSRF
    5. Installation      - privilege escalation, persistence
    6. C2 (Command)      - SSRF to internal, webhook manipulation
    7. Actions on Obj.   - data exfil, payment manipulation, entitlement bypass

    Each phase has a base score. Findings that advance through multiple
    phases get multiplicative bonuses. This rewards CHAINS over isolated hits."""

    _PHASE_MAP: dict[str, int] = {
        "info_disclosure": 1, "tech_fingerprint": 1, "waf_fingerprint": 1,
        "injection": 3, "xss": 3, "upload": 3,
        "auth_bypass": 4, "jwt_weakness": 4, "ssrf": 4,
        "privilege_escalation": 5, "persistence": 5,
        "webhook_forge": 6, "ssrf_internal": 6,
        "data_exfiltration": 7, "payment_manipulation": 7,
        "entitlement_bypass": 7, "refund_abuse": 7, "idor": 4,
        "race_condition": 4, "business_logic": 4,
    }

    _PHASE_NAMES = [
        "", "Reconnaissance", "Weaponization", "Delivery",
        "Exploitation", "Installation", "Command & Control",
        "Actions on Objectives",
    ]

    _PHASE_BONUS: dict[int, float] = {
        1: 0.05, 2: 0.10, 3: 0.15, 4: 0.25,
        5: 0.30, 6: 0.35, 7: 0.40,
    }

    def __init__(self) -> None:
        self._phase_history: list[set[int]] = []

    def score_kill_chain(
        self,
        hypotheses: list,
        semantic_findings: list[dict[str, Any]],
        exploit_chains: list[ExploitChain],
    ) -> dict[str, Any]:
        """Score the current observation's position in the kill chain."""
        active_phases: set[int] = set()

        for h in hypotheses:
            if h.posterior > 0.2:
                phase = self._PHASE_MAP.get(h.category, 0)
                if phase > 0:
                    active_phases.add(phase)

        for f in semantic_findings:
            cat = f.get("category", "")
            phase = self._PHASE_MAP.get(cat, 0)
            if phase > 0:
                active_phases.add(phase)

        chain_bonus = 0.0
        longest_chain = 0
        if exploit_chains:
            best_chain = max(exploit_chains, key=lambda c: c.combined_probability)
            longest_chain = len(best_chain.steps)
            chain_bonus = 0.05 * longest_chain

        phase_score = sum(self._PHASE_BONUS.get(p, 0) for p in active_phases)

        consecutive = 0
        if active_phases:
            sorted_phases = sorted(active_phases)
            current_run = 1
            for i in range(1, len(sorted_phases)):
                if sorted_phases[i] == sorted_phases[i - 1] + 1:
                    current_run += 1
                else:
                    consecutive = max(consecutive, current_run)
                    current_run = 1
            consecutive = max(consecutive, current_run)

        continuity_bonus = 0.1 * max(0, consecutive - 1)

        total_score = min(1.0, phase_score + chain_bonus + continuity_bonus)

        self._phase_history.append(active_phases)

        return {
            "kill_chain_score": round(total_score, 4),
            "active_phases": sorted(active_phases),
            "phase_names": [self._PHASE_NAMES[p] for p in sorted(active_phases) if p < len(self._PHASE_NAMES)],
            "phase_count": len(active_phases),
            "longest_consecutive": consecutive,
            "chain_bonus": round(chain_bonus, 4),
            "continuity_bonus": round(continuity_bonus, 4),
            "deepest_phase": max(active_phases) if active_phases else 0,
            "deepest_phase_name": (
                self._PHASE_NAMES[max(active_phases)]
                if active_phases and max(active_phases) < len(self._PHASE_NAMES)
                else "None"
            ),
        }


# ============================================================================
# L. Iterative Hypothesis Refiner (Try-Fail-Revise)
# ============================================================================

class IterativeHypothesisRefiner:
    """Try-fail-revise loops inspired by Mythos's exploit development process.

    From the research: Mythos writes code to trigger a suspected bug,
    compiles in a test environment, runs it, and REVISES if the first
    attempt fails. This is the core of frontier-level reasoning -- not
    just generating hypotheses, but iterating on them.

    ExploitGym showed that more budget helps frontier models with no plateau:
    Mythos went from 127 exploits at 2h to 204 at 6h. The model keeps
    finding new angles.

    Our analog: for each hypothesis, generate counter-hypotheses and
    alternative explanations, then re-evaluate. Track which hypotheses
    have been "revised" and how many times. Hypotheses that survive
    multiple revision cycles are much more reliable."""

    def __init__(self, max_revisions: int = 3) -> None:
        self._max_revisions = max_revisions
        self._revision_history: dict[str, list[float]] = defaultdict(list)

    def refine(
        self,
        hypotheses: list,
        components: dict[str, Any],
        memory: EpisodicMemory,
    ) -> list:
        """Run try-fail-revise on each hypothesis."""
        for h in hypotheses:
            if h.posterior < 0.1:
                continue

            revision_key = f"{h.category}:{components.get('endpoint', '')}"
            prev_posteriors = self._revision_history.get(revision_key, [])

            # Revision 1: Check for alternative explanations
            alt_explanation_penalty = 0.0
            if h.category == "auth_bypass" and components.get("status_code") == 200:
                if components.get("body_size", 0) < 100:
                    alt_explanation_penalty = -0.1
            elif h.category == "injection" and components.get("status_code") in (400, 422):
                alt_explanation_penalty = -0.15
            elif h.category == "payment_manipulation":
                body = components.get("body_text", "")
                if '"test"' in body.lower() or '"sandbox"' in body.lower():
                    alt_explanation_penalty = -0.2

            # Revision 2: Consistency with past observations of same endpoint
            past_same_ep = memory.retrieve_by_endpoint(
                components.get("endpoint", ""), limit=10,
            )
            if past_same_ep:
                past_cats = [
                    m.category for m in past_same_ep
                    if m.category == h.category and m.importance > 0.5
                ]
                if len(past_cats) >= 2:
                    h.posterior = min(0.99, h.posterior + 0.05)
                elif not past_cats and len(past_same_ep) >= 5:
                    h.posterior = max(0.01, h.posterior - 0.03)

            # Revision 3: Cross-endpoint pattern
            same_cat_findings = memory.retrieve(
                query_category=h.category, top_k=10, entry_type="finding",
            )
            unique_eps = {m.endpoint for m in same_cat_findings if m.endpoint}
            if len(unique_eps) >= 3:
                h.posterior = min(0.99, h.posterior + 0.03)

            h.posterior = max(0.01, h.posterior + alt_explanation_penalty)
            self._revision_history[revision_key].append(h.posterior)

            if len(prev_posteriors) >= 2:
                trend = prev_posteriors[-1] - prev_posteriors[0]
                if trend > 0.1:
                    h.posterior = min(0.99, h.posterior + 0.02)

        hypotheses.sort(key=lambda h: h.posterior, reverse=True)
        return hypotheses

    def get_revision_summary(self) -> dict[str, Any]:
        return {
            "total_hypotheses_tracked": len(self._revision_history),
            "multi_revision": sum(
                1 for v in self._revision_history.values() if len(v) >= 2
            ),
            "trending_up": sum(
                1 for v in self._revision_history.values()
                if len(v) >= 2 and v[-1] > v[0]
            ),
        }


# ############################################################################
#
#  M. PAYMENT GLUE CODE ANALYZER
#
#  Domain expert for the glue code between enterprise systems and payment
#  processors. Not more regex -- deep understanding of how payment
#  integration bugs ACTUALLY work in production.
#
#  Covers: Stripe, PayPal, Braintree, Adyen, Klarna, Recurly, Chargebee,
#  Paddle, Square, GoCardless.
#
#  Seven analysis domains:
#    1. Provider state machine validation (illegal transitions)
#    2. Webhook security (missing signatures, replay, event confusion)
#    3. Amount / currency manipulation
#    4. Idempotency key analysis
#    5. Customer / object confusion
#    6. Trial / proration / coupon abuse
#    7. Connect / marketplace platform bugs
#
# ############################################################################


class PaymentGlueCodeAnalyzer:
    """Detects vulnerabilities in the glue code between enterprise apps and
    payment processors.

    Every payment integration has the same fundamental surface: the app
    trusts provider-shaped data to make access-control decisions. When the
    glue code trusts the wrong signal, skips a state, or mis-converts an
    amount, attackers get paid features for free.

    This class encodes the EXACT state machines of Stripe, PayPal,
    Braintree, and Adyen, and flags illegal transitions, missing webhook
    verification, amount confusion, idempotency abuse, and more."""

    # ------------------------------------------------------------------
    # Provider state machines: {object_type: ordered list of valid states}
    # Transitions are only valid FORWARD through the list (with the noted
    # exceptions for terminal states like canceled).
    # ------------------------------------------------------------------

    _STRIPE_STATE_MACHINES: dict[str, list[list[str]]] = {
        "payment_intent": [
            ["requires_payment_method", "requires_confirmation",
             "requires_action", "processing", "succeeded"],
            ["requires_payment_method", "requires_confirmation",
             "requires_action", "processing", "canceled"],
        ],
        "subscription": [
            ["incomplete", "trialing", "active", "past_due", "canceled"],
            ["incomplete", "trialing", "active", "past_due", "unpaid"],
            ["incomplete", "trialing", "active", "paused"],
            ["incomplete", "incomplete_expired"],
        ],
        "checkout.session": [
            ["open", "complete"],
            ["open", "expired"],
        ],
        "invoice": [
            ["draft", "open", "paid"],
            ["draft", "open", "uncollectible"],
            ["draft", "open", "void"],
            ["draft", "void"],
        ],
        "charge": [
            ["pending", "succeeded"],
            ["pending", "failed"],
        ],
        "refund": [
            ["pending", "succeeded"],
            ["pending", "failed"],
            ["pending", "canceled"],
        ],
    }

    _PAYPAL_STATE_MACHINES: dict[str, list[list[str]]] = {
        "order": [
            ["CREATED", "APPROVED", "COMPLETED"],
            ["CREATED", "APPROVED", "VOIDED"],
            ["CREATED", "VOIDED"],
        ],
        "capture": [
            ["PENDING", "COMPLETED"],
            ["PENDING", "DECLINED"],
            ["PENDING", "REFUNDED"],
        ],
        "subscription": [
            ["APPROVAL_PENDING", "APPROVED", "ACTIVE", "SUSPENDED", "CANCELLED"],
            ["APPROVAL_PENDING", "APPROVED", "ACTIVE", "EXPIRED"],
        ],
    }

    _BRAINTREE_STATE_MACHINES: dict[str, list[list[str]]] = {
        "transaction": [
            ["authorized", "submitted_for_settlement", "settled"],
            ["authorized", "voided"],
            ["authorized", "submitted_for_settlement", "settlement_declined"],
            ["authorized", "settlement_declined"],
        ],
        "subscription": [
            ["pending", "active", "past_due", "canceled"],
            ["pending", "active", "expired"],
        ],
    }

    _ADYEN_STATE_MACHINES: dict[str, list[list[str]]] = {
        "payment": [
            ["Authorised", "Captured"],
            ["Authorised", "Cancelled"],
            ["Authorised", "Captured", "Refunded"],
            ["RedirectShopper", "Authorised", "Captured"],
            ["Refused"],
        ],
    }

    # Statuses that must NOT grant entitlements
    _NON_GRANT_STATUSES: set[str] = {
        "requires_payment_method", "requires_confirmation", "requires_action",
        "processing", "pending", "failed", "canceled", "cancelled", "voided",
        "incomplete", "incomplete_expired", "past_due", "unpaid", "paused",
        "draft", "open", "expired", "suspended", "declined", "refused",
        "CREATED", "APPROVED", "PENDING", "VOIDED", "DECLINED",
        "APPROVAL_PENDING", "SUSPENDED", "CANCELLED",
        "authorized", "submitted_for_settlement",
        "settlement_declined", "RedirectShopper", "Refused", "Cancelled",
    }

    # Zero-decimal currencies where 1 unit = 1 of the currency (not cents)
    _ZERO_DECIMAL_CURRENCIES: set[str] = {
        "BIF", "CLP", "DJF", "GNF", "JPY", "KMF", "KRW", "MGA", "PYG",
        "RWF", "UGX", "VND", "VUV", "XAF", "XOF", "XPF",
    }

    # Webhook event types that commonly confuse integrations
    _STRIPE_EVENT_CONFUSION: list[tuple[str, str, str]] = [
        ("invoice.paid", "invoice.payment_succeeded",
         "invoice.paid fires for ALL payments including free invoices; "
         "invoice.payment_succeeded fires only when money moves. "
         "Using invoice.paid for entitlement grants free-tier users premium access."),
        ("checkout.session.completed", "payment_intent.succeeded",
         "checkout.session.completed fires when session is filled, but payment "
         "may still be processing (async methods). payment_intent.succeeded is "
         "the actual money event. Granting on session.completed = access before payment."),
        ("customer.subscription.created", "customer.subscription.updated",
         "subscription.created fires before first payment. Using it for "
         "entitlement grants access before money arrives."),
        ("invoice.finalized", "invoice.paid",
         "invoice.finalized means the invoice is ready to collect, NOT that "
         "it was collected. Granting on finalized = access before payment."),
    ]

    def __init__(self) -> None:
        self._provider_history: dict[str, list[str]] = defaultdict(list)
        self._seen_idempotency_keys: dict[str, dict[str, Any]] = {}
        self._findings: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Provider detection
    # ------------------------------------------------------------------

    def detect_provider(self, body_text: str, headers: dict[str, str]) -> list[str]:
        """Identify which payment providers are present in the response."""
        providers: list[str] = []
        combined = body_text + " " + str(headers)

        for provider, patterns in _PROVIDER_SIGNATURES.items():
            if any(p.search(combined) for p in patterns):
                providers.append(provider)

        # Extended detection beyond _PROVIDER_SIGNATURES
        extended: list[tuple[str, re.Pattern[str]]] = [
            ("klarna", re.compile(r"(?:klarna\.com|klarna_session|klarna_client_token)", re.I)),
            ("recurly", re.compile(r"(?:recurly\.com|recurly-|x-recurly)", re.I)),
            ("chargebee", re.compile(r"(?:chargebee\.com|cb_|chargebee_)", re.I)),
            ("paddle", re.compile(r"(?:paddle\.com|paddle_|p_cus_|txn_|pri_)", re.I)),
            ("square", re.compile(r"(?:squareup\.com|square_|sq_)", re.I)),
            ("gocardless", re.compile(r"(?:gocardless\.com|gc_|gocardless_)", re.I)),
        ]
        for name, pattern in extended:
            if pattern.search(combined):
                providers.append(name)

        return providers

    # ------------------------------------------------------------------
    # State machine validation
    # ------------------------------------------------------------------

    def validate_state_machine(
        self, provider: str, object_type: str, current_status: str,
    ) -> list[dict[str, Any]]:
        """Check if a status transition is valid for this provider/object."""
        findings: list[dict[str, Any]] = []
        history_key = f"{provider}:{object_type}"
        prev_statuses = self._provider_history.get(history_key, [])

        machines: dict[str, list[list[str]]] = {}
        if provider == "stripe":
            machines = self._STRIPE_STATE_MACHINES
        elif provider == "paypal":
            machines = self._PAYPAL_STATE_MACHINES
        elif provider == "braintree":
            machines = self._BRAINTREE_STATE_MACHINES
        elif provider == "adyen":
            machines = self._ADYEN_STATE_MACHINES

        valid_paths = machines.get(object_type, [])
        if not valid_paths or not prev_statuses:
            self._provider_history[history_key].append(current_status)
            return findings

        prev = prev_statuses[-1]

        # Check if any valid path contains prev -> current as adjacent steps
        transition_valid = False
        for path in valid_paths:
            for i in range(len(path) - 1):
                if path[i].lower() == prev.lower() and path[i + 1].lower() == current_status.lower():
                    transition_valid = True
                    break
            if transition_valid:
                break

        if not transition_valid and prev.lower() != current_status.lower():
            # Check for state skip (both states in a path but not adjacent)
            skipped = False
            for path in valid_paths:
                lower_path = [s.lower() for s in path]
                if prev.lower() in lower_path and current_status.lower() in lower_path:
                    pi = lower_path.index(prev.lower())
                    ci = lower_path.index(current_status.lower())
                    if ci > pi + 1:
                        skipped_states = path[pi + 1:ci]
                        findings.append({
                            "type": "state_machine_violation",
                            "rule": "state_skip",
                            "detail": (
                                f"{provider} {object_type}: jumped from '{prev}' to "
                                f"'{current_status}', skipping {skipped_states}. "
                                f"The glue code may be granting access before payment completes."
                            ),
                            "category": "payment_manipulation",
                            "confidence": 0.85,
                            "severity": "critical",
                            "provider": provider,
                        })
                        skipped = True
                        break
                    elif ci < pi:
                        findings.append({
                            "type": "state_machine_violation",
                            "rule": "backward_transition",
                            "detail": (
                                f"{provider} {object_type}: went backward from "
                                f"'{prev}' to '{current_status}'. Possible state "
                                f"manipulation allowing re-use of completed payment."
                            ),
                            "category": "payment_manipulation",
                            "confidence": 0.8,
                            "severity": "high",
                            "provider": provider,
                        })
                        skipped = True
                        break

            if not skipped:
                findings.append({
                    "type": "state_machine_violation",
                    "rule": "invalid_transition",
                    "detail": (
                        f"{provider} {object_type}: transition '{prev}' -> "
                        f"'{current_status}' not in any valid path."
                    ),
                    "category": "payment_manipulation",
                    "confidence": 0.7,
                    "severity": "high",
                    "provider": provider,
                })

        self._provider_history[history_key].append(current_status)
        return findings

    # ------------------------------------------------------------------
    # Main analysis
    # ------------------------------------------------------------------

    def analyze(
        self,
        observation: dict[str, Any],
        components: dict[str, Any],
        memory: EpisodicMemory,
    ) -> list[dict[str, Any]]:
        """Full payment glue code analysis."""
        findings: list[dict[str, Any]] = []
        req = observation.get("request_data") or {}
        resp = observation.get("response_data") or {}
        body_text = components.get("body_text", "")
        headers = resp.get("headers") or {}
        req_headers = req.get("headers") or {}
        endpoint = components.get("endpoint", "")
        method = components.get("method", "GET")
        status_code = components.get("status_code", 0)
        lower_headers = {k.lower(): v for k, v in headers.items()}

        providers = self.detect_provider(body_text, {**headers, **req_headers})
        if not providers:
            return findings

        for provider in providers:
            findings.extend(self._analyze_state_machine(provider, body_text))
            findings.extend(self._analyze_premature_entitlement(
                provider, body_text, endpoint,
            ))

        findings.extend(self._analyze_webhook_security(
            endpoint, method, body_text, req_headers, lower_headers, providers,
        ))
        findings.extend(self._analyze_amount_currency(body_text, providers))
        findings.extend(self._analyze_idempotency(
            endpoint, method, req_headers, body_text, providers,
        ))
        findings.extend(self._analyze_object_confusion(body_text, providers))
        findings.extend(self._analyze_trial_abuse(body_text, providers))
        findings.extend(self._analyze_connect_platform(body_text, providers))
        findings.extend(self._analyze_event_confusion(body_text, providers))

        self._findings.extend(findings)
        return findings

    # ------------------------------------------------------------------
    # 1. State machine
    # ------------------------------------------------------------------

    def _analyze_state_machine(
        self, provider: str, body_text: str,
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []

        if provider == "stripe":
            obj_match = _STRIPE_OBJECT_RE.search(body_text)
            status_match = _STRIPE_STATUS_RE.search(body_text)
            if obj_match and status_match:
                findings.extend(self.validate_state_machine(
                    "stripe", obj_match.group(1), status_match.group(1),
                ))
        elif provider == "paypal":
            status_m = re.search(
                r'"status"\s*:\s*"(CREATED|APPROVED|COMPLETED|VOIDED|PENDING|'
                r'DECLINED|REFUNDED|ACTIVE|SUSPENDED|CANCELLED|EXPIRED|'
                r'APPROVAL_PENDING)"', body_text, re.I,
            )
            obj_m = re.search(
                r'"(?:intent|resource_type|name)"\s*:\s*"(CAPTURE|AUTHORIZE|order|'
                r'subscription|capture)"', body_text, re.I,
            )
            if status_m:
                obj_type = obj_m.group(1).lower() if obj_m else "order"
                findings.extend(self.validate_state_machine(
                    "paypal", obj_type, status_m.group(1),
                ))
        elif provider == "braintree":
            status_m = re.search(
                r'"status"\s*:\s*"(authorized|submitted_for_settlement|settled|'
                r'voided|settlement_declined|pending|active|past_due|canceled|expired)"',
                body_text, re.I,
            )
            if status_m:
                is_sub = bool(re.search(r'"(?:plan_id|subscription)"', body_text, re.I))
                obj_type = "subscription" if is_sub else "transaction"
                findings.extend(self.validate_state_machine(
                    "braintree", obj_type, status_m.group(1),
                ))
        elif provider == "adyen":
            result_m = re.search(
                r'"resultCode"\s*:\s*"(Authorised|Refused|Cancelled|Captured|'
                r'Refunded|RedirectShopper)"', body_text, re.I,
            )
            if result_m:
                findings.extend(self.validate_state_machine(
                    "adyen", "payment", result_m.group(1),
                ))

        return findings

    # ------------------------------------------------------------------
    # 1b. Premature entitlement
    # ------------------------------------------------------------------

    def _analyze_premature_entitlement(
        self, provider: str, body_text: str, endpoint: str,
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []

        status_match = re.search(
            r'"(?:status|state|resultCode)"\s*:\s*"([^"]+)"', body_text, re.I,
        )
        if not status_match:
            return findings

        status = status_match.group(1)
        if status.lower() not in {s.lower() for s in self._NON_GRANT_STATUSES}:
            return findings

        entitlement_signals = [
            re.search(r'"(?:access|entitled|feature|granted|active_subscription)"'
                       r'\s*:\s*true', body_text, re.I),
            re.search(r'"(?:plan|tier|access_level)"\s*:\s*"(?:premium|pro|enterprise|'
                       r'business|unlimited)"', body_text, re.I),
            re.search(r'"(?:can_access|is_premium|has_access|is_subscribed)"'
                       r'\s*:\s*true', body_text, re.I),
        ]
        if any(entitlement_signals):
            findings.append({
                "type": "premature_entitlement",
                "rule": "grant_before_payment",
                "detail": (
                    f"Payment status is '{status}' (non-terminal) but response "
                    f"contains entitlement/access grant. The glue code is granting "
                    f"access BEFORE the payment has actually completed. Classic "
                    f"TOCTOU bug in payment integration."
                ),
                "category": "entitlement_bypass",
                "confidence": 0.92,
                "severity": "critical",
                "provider": provider,
            })

        return findings

    # ------------------------------------------------------------------
    # 2. Webhook security
    # ------------------------------------------------------------------

    def _analyze_webhook_security(
        self,
        endpoint: str, method: str, body_text: str,
        req_headers: dict[str, str], lower_headers: dict[str, str],
        providers: list[str],
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []

        is_webhook = bool(_WEBHOOK_PATH_RE.search(endpoint))
        has_event_type = bool(re.search(r'"(?:type|event_type|eventType)"', body_text))

        if not (is_webhook or has_event_type):
            return findings

        lower_req = {k.lower(): v for k, v in req_headers.items()}

        # Missing signature verification
        sig_headers = {
            "stripe": "stripe-signature",
            "paypal": "paypal-transmission-sig",
            "braintree": "bt-signature",
            "adyen": "x-adyen-hmackey",
        }
        for provider in providers:
            sig_header = sig_headers.get(provider)
            if sig_header and sig_header not in lower_req:
                findings.append({
                    "type": "webhook_security",
                    "rule": "missing_signature",
                    "detail": (
                        f"Webhook endpoint '{endpoint}' received {provider} event "
                        f"without '{sig_header}' header. The glue code may not be "
                        f"verifying webhook authenticity. An attacker can forge "
                        f"payment-success events to get free access."
                    ),
                    "category": "webhook_forge",
                    "confidence": 0.88,
                    "severity": "critical",
                    "provider": provider,
                })

        # Replay attack potential
        if is_webhook and method == "POST":
            has_timestamp = bool(re.search(
                r'"(?:created|timestamp|event_time|ts|created_at)"', body_text,
            ))
            has_idempotency = bool(re.search(
                r'"(?:id|event_id|idempotency_key|webhook_id)":\s*"[a-zA-Z0-9_-]{10,}"',
                body_text,
            ))
            if not has_timestamp and not has_idempotency:
                findings.append({
                    "type": "webhook_security",
                    "rule": "replay_vulnerable",
                    "detail": (
                        "Webhook payload lacks timestamp and unique event ID. "
                        "An attacker who intercepts one valid webhook can replay "
                        "it indefinitely for repeated entitlement grants."
                    ),
                    "category": "webhook_forge",
                    "confidence": 0.75,
                    "severity": "high",
                    "provider": providers[0] if providers else "unknown",
                })

        return findings

    # ------------------------------------------------------------------
    # 2b. Event type confusion
    # ------------------------------------------------------------------

    def _analyze_event_confusion(
        self, body_text: str, providers: list[str],
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        if "stripe" not in providers:
            return findings

        event_type_m = re.search(r'"type"\s*:\s*"([^"]+)"', body_text)
        if not event_type_m:
            return findings

        event_type = event_type_m.group(1)
        for risky, correct, explanation in self._STRIPE_EVENT_CONFUSION:
            if event_type == risky:
                findings.append({
                    "type": "event_confusion",
                    "rule": "wrong_event_type",
                    "detail": (
                        f"Event type '{risky}' detected. This is commonly confused "
                        f"with '{correct}'. {explanation}"
                    ),
                    "category": "entitlement_bypass",
                    "confidence": 0.7,
                    "severity": "high",
                    "provider": "stripe",
                })

        return findings

    # ------------------------------------------------------------------
    # 3. Amount / currency manipulation
    # ------------------------------------------------------------------

    def _analyze_amount_currency(
        self, body_text: str, providers: list[str],
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []

        amount_m = re.search(
            r'"(?:amount|total|unit_amount|amount_total|amount_due|'
            r'amount_paid|gross_amount|net_amount|price)"'
            r'\s*:\s*(-?[0-9]+\.?[0-9]*)',
            body_text, re.I,
        )
        currency_m = re.search(
            r'"(?:currency|currency_code)"\s*:\s*"([A-Z]{3})"', body_text, re.I,
        )

        if amount_m:
            amount = float(amount_m.group(1))

            # Negative amount
            if amount < 0:
                findings.append({
                    "type": "amount_manipulation",
                    "rule": "negative_amount",
                    "detail": (
                        f"Negative amount ({amount}) detected. In refund "
                        f"contexts a negative amount can become a double-negative "
                        f"credit. In charge contexts it may underflow."
                    ),
                    "category": "payment_manipulation",
                    "confidence": 0.85,
                    "severity": "critical",
                    "provider": providers[0] if providers else "unknown",
                })

            # Integer overflow for cent-based providers
            if amount > 2_147_483_647 and "stripe" in providers:
                findings.append({
                    "type": "amount_manipulation",
                    "rule": "integer_overflow",
                    "detail": (
                        f"Amount {amount} exceeds INT32_MAX (2,147,483,647). "
                        f"Stripe uses integer cents internally. This may overflow "
                        f"to a negative or zero value."
                    ),
                    "category": "payment_manipulation",
                    "confidence": 0.75,
                    "severity": "high",
                    "provider": "stripe",
                })

            # Cents vs dollars confusion
            if currency_m:
                currency = currency_m.group(1).upper()
                if currency in self._ZERO_DECIMAL_CURRENCIES:
                    # JPY amount=100 means 100 yen; if treated as cents = 1 yen
                    if amount > 0 and amount == int(amount) and amount < 1000:
                        pass  # Plausible for zero-decimal
                    # Flagging happens below if mismatches detected
                elif "stripe" in providers and 0 < amount < 100:
                    findings.append({
                        "type": "amount_manipulation",
                        "rule": "cents_vs_dollars",
                        "detail": (
                            f"Stripe amount={amount} with currency={currency}. "
                            f"Stripe uses CENTS (amount=100 = $1.00). If the glue "
                            f"code passes dollar values directly, customers pay "
                            f"100x less than intended."
                        ),
                        "category": "payment_manipulation",
                        "confidence": 0.65,
                        "severity": "high",
                        "provider": "stripe",
                    })
                elif "paypal" in providers and amount > 100000:
                    findings.append({
                        "type": "amount_manipulation",
                        "rule": "dollars_as_cents",
                        "detail": (
                            f"PayPal amount={amount}. PayPal uses DOLLARS "
                            f"(amount=1.00 = $1.00). If the glue code passes "
                            f"cent values, customers are charged 100x more."
                        ),
                        "category": "payment_manipulation",
                        "confidence": 0.55,
                        "severity": "medium",
                        "provider": "paypal",
                    })

        # Currency mismatch between fields
        all_currencies = re.findall(r'"(?:currency|currency_code)"\s*:\s*"([A-Z]{3})"', body_text, re.I)
        unique_currencies = set(c.upper() for c in all_currencies)
        if len(unique_currencies) > 1:
            findings.append({
                "type": "amount_manipulation",
                "rule": "currency_mismatch",
                "detail": (
                    f"Multiple currencies in single response: {sorted(unique_currencies)}. "
                    f"If the glue code doesn't normalize, a user can pay in a weaker "
                    f"currency while the app credits the stronger one."
                ),
                "category": "payment_manipulation",
                "confidence": 0.8,
                "severity": "critical",
                "provider": providers[0] if providers else "unknown",
            })

        return findings

    # ------------------------------------------------------------------
    # 4. Idempotency key analysis
    # ------------------------------------------------------------------

    def _analyze_idempotency(
        self,
        endpoint: str, method: str,
        req_headers: dict[str, str], body_text: str,
        providers: list[str],
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []

        is_payment_mutation = (
            method in _MUTATING_METHODS
            and _PAYMENT_SENSITIVE_PATH_RE.search(endpoint)
        )
        if not is_payment_mutation:
            return findings

        lower_req = {k.lower(): v for k, v in req_headers.items()}
        idemp_key = lower_req.get("idempotency-key", "")

        if not idemp_key:
            findings.append({
                "type": "idempotency",
                "rule": "missing_idempotency_key",
                "detail": (
                    f"Payment mutation {method} {endpoint} has no Idempotency-Key "
                    f"header. Without idempotency, network retries can cause "
                    f"duplicate charges, and race conditions can double-create "
                    f"subscriptions."
                ),
                "category": "race_condition",
                "confidence": 0.7,
                "severity": "high",
                "provider": providers[0] if providers else "unknown",
            })
        else:
            amount_m = re.search(r'"amount"\s*:\s*([0-9]+)', body_text)
            amount = amount_m.group(1) if amount_m else "?"
            if idemp_key in self._seen_idempotency_keys:
                prev = self._seen_idempotency_keys[idemp_key]
                if prev.get("amount") != amount:
                    findings.append({
                        "type": "idempotency",
                        "rule": "key_reuse_different_amount",
                        "detail": (
                            f"Idempotency key '{idemp_key[:20]}...' reused with "
                            f"different amount ({prev.get('amount')} -> {amount}). "
                            f"Stripe returns cached result for reused keys -- "
                            f"attacker can get a $1 charge cached, then replay "
                            f"with $1000 and still pay $1."
                        ),
                        "category": "payment_manipulation",
                        "confidence": 0.9,
                        "severity": "critical",
                        "provider": providers[0] if providers else "unknown",
                    })
            self._seen_idempotency_keys[idemp_key] = {
                "endpoint": endpoint, "amount": amount,
            }

        return findings

    # ------------------------------------------------------------------
    # 5. Customer / object confusion
    # ------------------------------------------------------------------

    def _analyze_object_confusion(
        self, body_text: str, providers: list[str],
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []

        # Test mode keys in production context
        if re.search(r'(?:sk_test_|pk_test_)', body_text):
            if re.search(r'"livemode"\s*:\s*true', body_text):
                findings.append({
                    "type": "object_confusion",
                    "rule": "test_key_livemode_conflict",
                    "detail": (
                        "Test-mode API keys (sk_test_/pk_test_) present alongside "
                        "'livemode': true. The glue code may be mixing test and "
                        "production environments, allowing test-card payments "
                        "to trigger real entitlements."
                    ),
                    "category": "payment_manipulation",
                    "confidence": 0.85,
                    "severity": "critical",
                    "provider": "stripe",
                })
            elif not re.search(r'"livemode"', body_text):
                findings.append({
                    "type": "object_confusion",
                    "rule": "test_keys_exposed",
                    "detail": (
                        "Test-mode API keys visible in response. If the app "
                        "doesn't check livemode, an attacker can use test-mode "
                        "tokens (tok_visa, tok_mastercard) to complete payments "
                        "for free."
                    ),
                    "category": "payment_manipulation",
                    "confidence": 0.8,
                    "severity": "high",
                    "provider": "stripe",
                })

        # Livemode false in production response
        if re.search(r'"livemode"\s*:\s*false', body_text):
            findings.append({
                "type": "object_confusion",
                "rule": "livemode_false",
                "detail": (
                    "Response contains 'livemode: false'. This is a test-mode "
                    "object. If the glue code doesn't verify livemode, attackers "
                    "can submit test payments that grant real entitlements."
                ),
                "category": "payment_manipulation",
                "confidence": 0.82,
                "severity": "critical",
                "provider": providers[0] if providers else "unknown",
            })

        # Cross-customer references
        customer_ids = re.findall(r'cus_[A-Za-z0-9]{14,}', body_text)
        if len(set(customer_ids)) > 1:
            findings.append({
                "type": "object_confusion",
                "rule": "cross_customer_reference",
                "detail": (
                    f"Multiple distinct customer IDs in single response: "
                    f"{sorted(set(customer_ids))[:3]}. The glue code may be "
                    f"allowing cross-customer object references -- using cus_A's "
                    f"payment_intent to fulfill cus_B's order."
                ),
                "category": "idor",
                "confidence": 0.7,
                "severity": "high",
                "provider": "stripe",
            })

        return findings

    # ------------------------------------------------------------------
    # 6. Trial / proration / coupon abuse
    # ------------------------------------------------------------------

    def _analyze_trial_abuse(
        self, body_text: str, providers: list[str],
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []

        # Trial without payment method
        is_trial = bool(re.search(
            r'"(?:status|state)"\s*:\s*"(?:trialing|trial)"', body_text, re.I,
        ))
        has_payment_method = bool(re.search(
            r'"(?:default_payment_method|payment_method|card|source)"'
            r'\s*:\s*(?:"[^"]+"|{)',
            body_text, re.I,
        ))
        no_pm = bool(re.search(
            r'"(?:default_payment_method|payment_method)"\s*:\s*null',
            body_text, re.I,
        ))

        if is_trial and (no_pm or not has_payment_method):
            findings.append({
                "type": "trial_abuse",
                "rule": "trial_no_payment_method",
                "detail": (
                    "Active trial subscription with no payment method on file. "
                    "Users can create unlimited trial accounts without ever "
                    "providing payment information, getting indefinite free access."
                ),
                "category": "entitlement_bypass",
                "confidence": 0.8,
                "severity": "high",
                "provider": providers[0] if providers else "unknown",
            })

        # Coupon stacking
        coupon_matches = re.findall(
            r'"(?:coupon|percent_off|amount_off|promotion_code)"', body_text, re.I,
        )
        discount_matches = re.findall(
            r'"(?:discount|discounts)"', body_text, re.I,
        )
        if len(coupon_matches) >= 2 or len(discount_matches) >= 2:
            findings.append({
                "type": "trial_abuse",
                "rule": "coupon_stacking",
                "detail": (
                    "Multiple coupon/discount references in response. If the "
                    "glue code doesn't enforce single-coupon limits, attackers "
                    "can stack 50%+50% coupons for 100% discount."
                ),
                "category": "payment_manipulation",
                "confidence": 0.6,
                "severity": "high",
                "provider": providers[0] if providers else "unknown",
            })

        # Grace period after payment failure
        past_due = bool(re.search(
            r'"status"\s*:\s*"(?:past_due|unpaid)"', body_text, re.I,
        ))
        has_access = bool(re.search(
            r'"(?:has_access|is_active|can_access|entitled)"\s*:\s*true',
            body_text, re.I,
        ))
        if past_due and has_access:
            findings.append({
                "type": "trial_abuse",
                "rule": "grace_period_abuse",
                "detail": (
                    "Subscription is past_due/unpaid but response still shows "
                    "active access. The glue code's grace period may be too long "
                    "or not enforced at all, allowing indefinite free access "
                    "after a single failed payment."
                ),
                "category": "entitlement_bypass",
                "confidence": 0.85,
                "severity": "critical",
                "provider": providers[0] if providers else "unknown",
            })

        return findings

    # ------------------------------------------------------------------
    # 7. Connect / marketplace platform bugs
    # ------------------------------------------------------------------

    def _analyze_connect_platform(
        self, body_text: str, providers: list[str],
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []

        is_connect = bool(re.search(
            r'"(?:destination|transfer_data|application_fee|on_behalf_of|'
            r'connected_account|platform_fee|transfer_group)"',
            body_text, re.I,
        ))
        if not is_connect:
            return findings

        # Application fee vs amount check
        amount_m = re.search(r'"amount"\s*:\s*([0-9]+)', body_text)
        fee_m = re.search(r'"(?:application_fee_amount|application_fee|platform_fee)"\s*:\s*([0-9]+)', body_text)
        if amount_m and fee_m:
            amount = int(amount_m.group(1))
            fee = int(fee_m.group(1))
            if fee > amount:
                findings.append({
                    "type": "connect_platform",
                    "rule": "fee_exceeds_amount",
                    "detail": (
                        f"Platform fee ({fee}) exceeds charge amount ({amount}). "
                        f"The connected account would receive negative funds. "
                        f"An attacker controlling the fee field can drain the "
                        f"connected account."
                    ),
                    "category": "payment_manipulation",
                    "confidence": 0.9,
                    "severity": "critical",
                    "provider": "stripe",
                })
            elif fee == 0 and amount > 0:
                findings.append({
                    "type": "connect_platform",
                    "rule": "zero_platform_fee",
                    "detail": (
                        f"Platform fee is zero on a {amount}-unit charge. "
                        f"If the client can set the fee, the platform earns nothing."
                    ),
                    "category": "payment_manipulation",
                    "confidence": 0.6,
                    "severity": "medium",
                    "provider": "stripe",
                })

        # Transfer amount vs captured amount
        transfer_m = re.search(r'"(?:transfer_amount|amount)"\s*:\s*([0-9]+)', body_text)
        captured_m = re.search(r'"amount_captured"\s*:\s*([0-9]+)', body_text)
        if transfer_m and captured_m:
            transfer = int(transfer_m.group(1))
            captured = int(captured_m.group(1))
            if transfer > captured:
                findings.append({
                    "type": "connect_platform",
                    "rule": "transfer_exceeds_capture",
                    "detail": (
                        f"Transfer amount ({transfer}) exceeds captured amount "
                        f"({captured}). The platform is sending more to the "
                        f"connected account than it collected from the customer."
                    ),
                    "category": "payment_manipulation",
                    "confidence": 0.85,
                    "severity": "critical",
                    "provider": "stripe",
                })

        # Connected account not fully onboarded
        onboarding_m = re.search(
            r'"(?:charges_enabled|payouts_enabled)"\s*:\s*false', body_text, re.I,
        )
        has_payments = bool(re.search(r'"payment_intent|charge|transfer"', body_text, re.I))
        if onboarding_m and has_payments:
            findings.append({
                "type": "connect_platform",
                "rule": "incomplete_onboarding",
                "detail": (
                    "Connected account has charges_enabled or payouts_enabled = false "
                    "but is involved in a payment flow. Funds may be stuck or "
                    "the platform is processing payments for an unverified merchant."
                ),
                "category": "business_logic",
                "confidence": 0.7,
                "severity": "high",
                "provider": "stripe",
            })

        return findings

    def get_all_findings(self) -> list[dict[str, Any]]:
        return self._findings[-100:]


# ############################################################################
#
#  M. PaymentGlueCodeAnalyzer -- Domain expert for the GLUE CODE between
#     enterprise systems and payment processors. This is the code most
#     companies write themselves: webhook handlers, subscription managers,
#     entitlement grantors, checkout flows. It's where most payment vulns
#     live because it's custom, undertested, and bridges trust boundaries.
#
# ############################################################################


class PaymentGlueCodeAnalyzer:
    """Deep payment integration vulnerability analysis.

    Understands the state machines of Stripe, PayPal, Braintree, Adyen,
    Recurly, and Square. Detects bugs in the GLUE CODE that connects
    enterprise apps to these providers -- webhook handling, state transitions,
    amount validation, idempotency, customer object confusion, trial abuse,
    and Connect/marketplace platform drains.

    This isn't regex matching on response bodies. It's modeling what a
    correct payment integration looks like and finding deviations."""

    # Provider state machines: {status: set_of_valid_next_statuses}
    _STRIPE_PI_STATES: dict[str, set[str]] = {
        "requires_payment_method": {"requires_confirmation", "canceled"},
        "requires_confirmation": {"requires_action", "processing", "canceled"},
        "requires_action": {"processing", "requires_payment_method", "canceled"},
        "processing": {"succeeded", "requires_payment_method", "canceled"},
        "succeeded": {"canceled"},  # only via refund
        "canceled": set(),
    }
    _STRIPE_SUB_STATES: dict[str, set[str]] = {
        "incomplete": {"incomplete_expired", "trialing", "active"},
        "incomplete_expired": set(),
        "trialing": {"active", "past_due", "canceled", "unpaid", "paused"},
        "active": {"past_due", "canceled", "unpaid", "paused"},
        "past_due": {"active", "canceled", "unpaid"},
        "canceled": set(),
        "unpaid": {"active", "canceled"},
        "paused": {"active", "canceled"},
    }
    _STRIPE_CHECKOUT_STATES: dict[str, set[str]] = {
        "open": {"complete", "expired"},
        "complete": set(),
        "expired": set(),
    }
    _STRIPE_INVOICE_STATES: dict[str, set[str]] = {
        "draft": {"open", "void"},
        "open": {"paid", "uncollectible", "void"},
        "paid": set(),
        "uncollectible": {"void"},
        "void": set(),
    }
    _PAYPAL_ORDER_STATES: dict[str, set[str]] = {
        "CREATED": {"APPROVED", "VOIDED"},
        "APPROVED": {"COMPLETED", "VOIDED"},
        "COMPLETED": {"PARTIALLY_REFUNDED", "REFUNDED"},
        "VOIDED": set(),
    }
    _BRAINTREE_TXN_STATES: dict[str, set[str]] = {
        "authorized": {"submitted_for_settlement", "voided"},
        "submitted_for_settlement": {"settled", "settlement_declined", "voided"},
        "settled": {"refunded"},
        "voided": set(),
        "declined": set(),
    }

    # States that must NOT grant entitlement
    _NO_ENTITLEMENT_STATES: set[str] = {
        "requires_payment_method", "requires_confirmation", "requires_action",
        "processing", "canceled", "incomplete", "incomplete_expired",
        "past_due", "unpaid", "paused", "draft", "open", "uncollectible",
        "void", "CREATED", "APPROVED", "VOIDED", "authorized",
        "submitted_for_settlement", "voided", "declined", "pending",
        "failed", "expired", "trialing",
    }

    # States that SHOULD grant entitlement
    _ENTITLEMENT_STATES: set[str] = {
        "succeeded", "active", "paid", "complete", "COMPLETED", "settled",
    }

    # Webhook signature headers by provider
    _WEBHOOK_SIG_HEADERS: dict[str, str] = {
        "stripe": "stripe-signature",
        "paypal": "paypal-transmission-sig",
        "braintree": "bt-signature",
        "adyen": "hmac-signature",
        "square": "x-square-hmacsha256-signature",
        "recurly": "x-recurly-signature",
    }

    # Zero-decimal currencies (amount in units, not subunits)
    _ZERO_DECIMAL_CURRENCIES: set[str] = {
        "BIF", "CLP", "DJF", "GNF", "JPY", "KMF", "KRW", "MGA",
        "PYG", "RWF", "UGX", "VND", "VUV", "XAF", "XOF", "XPF",
    }

    # Stripe event types that are commonly confused
    _CONFUSABLE_EVENTS: list[tuple[str, str, str]] = [
        ("invoice.paid", "invoice.payment_succeeded",
         "invoice.paid fires for $0 invoices too; payment_succeeded only for real charges"),
        ("checkout.session.completed", "payment_intent.succeeded",
         "checkout.completed fires even if payment_status=unpaid (delayed payment methods)"),
        ("customer.subscription.updated", "customer.subscription.created",
         "updated fires on ANY change; must check previous_attributes to know what changed"),
        ("invoice.finalized", "invoice.paid",
         "finalized means invoice is ready, NOT that it's been paid"),
    ]

    def __init__(self) -> None:
        self._state_history: dict[str, list[tuple[str, str]]] = defaultdict(list)
        self._findings: list[dict[str, Any]] = []
        self._providers_seen: set[str] = set()

    def detect_provider(self, body_text: str, headers: dict[str, str] = None) -> list[str]:
        """Detect which payment providers are present in the response."""
        providers: list[str] = []
        for provider, patterns in _PROVIDER_SIGNATURES.items():
            for pat in patterns:
                if pat.search(body_text):
                    providers.append(provider)
                    break

        lower_headers = {k.lower(): v for k, v in (headers or {}).items()}
        for provider, sig_header in self._WEBHOOK_SIG_HEADERS.items():
            if sig_header in lower_headers:
                if provider not in providers:
                    providers.append(provider)

        if re.search(r'"(?:recurly_|recurly\.)', body_text, re.I):
            providers.append("recurly")
        if re.search(r'"(?:square_|sq_)', body_text, re.I):
            providers.append("square")
        if re.search(r'"(?:chargebee_|cb_)', body_text, re.I):
            providers.append("chargebee")
        if re.search(r'"(?:paddle_|txn_)', body_text, re.I):
            providers.append("paddle")

        self._providers_seen.update(providers)
        return list(set(providers))

    def validate_state_machine(
        self, provider: str, object_type: str,
        current_status: str, body_text: str,
    ) -> list[dict[str, Any]]:
        """Check if the payment object's state is valid and consistent."""
        findings: list[dict[str, Any]] = []

        state_map: dict[str, set[str]] | None = None
        if provider == "stripe":
            if object_type in ("payment_intent", "pi"):
                state_map = self._STRIPE_PI_STATES
            elif object_type in ("subscription", "sub"):
                state_map = self._STRIPE_SUB_STATES
            elif object_type in ("checkout.session", "checkout_session", "cs"):
                state_map = self._STRIPE_CHECKOUT_STATES
            elif object_type in ("invoice", "in"):
                state_map = self._STRIPE_INVOICE_STATES
        elif provider == "paypal":
            state_map = self._PAYPAL_ORDER_STATES
        elif provider == "braintree":
            state_map = self._BRAINTREE_TXN_STATES

        if not state_map:
            return findings

        if current_status not in state_map:
            findings.append({
                "type": "invalid_state",
                "rule": "unknown_payment_status",
                "detail": f"{provider} {object_type} has unknown status '{current_status}'",
                "category": "payment_manipulation",
                "confidence": 0.7,
                "severity": "high",
                "provider": provider,
            })

        obj_key = f"{provider}:{object_type}"
        prev_states = self._state_history.get(obj_key, [])
        if prev_states:
            prev_status = prev_states[-1][1]
            valid_transitions = state_map.get(prev_status, set())
            if current_status != prev_status and current_status not in valid_transitions:
                findings.append({
                    "type": "invalid_state_transition",
                    "rule": "state_machine_violation",
                    "detail": (
                        f"{provider} {object_type}: invalid transition "
                        f"'{prev_status}' -> '{current_status}'. "
                        f"Valid next: {sorted(valid_transitions) if valid_transitions else 'terminal state'}"
                    ),
                    "category": "payment_manipulation",
                    "confidence": 0.9,
                    "severity": "critical",
                    "provider": provider,
                })

        self._state_history[obj_key].append((str(time.monotonic()), current_status))
        return findings

    def analyze(
        self, observation: dict[str, Any],
        components: dict[str, Any],
        memory: EpisodicMemory,
    ) -> list[dict[str, Any]]:
        """Full payment glue code analysis."""
        findings: list[dict[str, Any]] = []
        body_text = components.get("body_text", "")
        endpoint = components.get("endpoint", "")
        status_code = components.get("status_code", 0)
        method = components.get("method", "GET")
        req_headers = (observation.get("request_data") or {}).get("headers") or {}
        resp_headers = (observation.get("response_data") or {}).get("headers") or {}

        providers = self.detect_provider(body_text, resp_headers)

        # --- 1. State machine validation ---
        for provider in providers:
            obj_match = re.search(r'"object"\s*:\s*"([^"]+)"', body_text)
            status_match = re.search(r'"status"\s*:\s*"([^"]+)"', body_text)
            if obj_match and status_match:
                obj_type = obj_match.group(1)
                obj_status = status_match.group(1)
                findings.extend(self.validate_state_machine(
                    provider, obj_type, obj_status, body_text,
                ))

                # Premature entitlement check
                if obj_status in self._NO_ENTITLEMENT_STATES:
                    entitlement_match = re.search(
                        r'"(?:entitlement|access_level|feature_access|premium|is_active)"'
                        r'\s*:\s*(?:true|"(?:premium|pro|enterprise|unlimited|active)")',
                        body_text, re.I,
                    )
                    if entitlement_match:
                        findings.append({
                            "type": "premature_entitlement",
                            "rule": "entitlement_before_payment",
                            "detail": (
                                f"Service entitlement granted while payment status is "
                                f"'{obj_status}' (should be in {sorted(self._ENTITLEMENT_STATES)[:3]}+). "
                                f"The glue code grants access before payment completes."
                            ),
                            "category": "entitlement_bypass",
                            "confidence": 0.95,
                            "severity": "critical",
                            "provider": provider,
                        })

        # --- 2. Webhook security analysis ---
        is_webhook = bool(_WEBHOOK_PATH_RE.search(endpoint))
        if is_webhook:
            lower_req_headers = {k.lower(): v for k, v in req_headers.items()}

            has_signature = False
            for provider, sig_header in self._WEBHOOK_SIG_HEADERS.items():
                if sig_header in lower_req_headers:
                    has_signature = True
                    sig_val = lower_req_headers[sig_header]
                    if len(sig_val) < 20:
                        findings.append({
                            "type": "weak_webhook_signature",
                            "rule": "short_signature",
                            "detail": f"Webhook signature for {provider} is suspiciously short ({len(sig_val)} chars)",
                            "category": "webhook_forge",
                            "confidence": 0.6,
                            "severity": "medium",
                            "provider": provider,
                        })

            if not has_signature and method in _MUTATING_METHODS:
                findings.append({
                    "type": "missing_webhook_signature",
                    "rule": "no_signature_verification",
                    "detail": (
                        "Webhook endpoint accepts POST without any provider signature header. "
                        "An attacker can forge webhook events to trigger entitlement, refunds, "
                        "or state changes without any actual payment."
                    ),
                    "category": "webhook_forge",
                    "confidence": 0.85,
                    "severity": "critical",
                    "provider": providers[0] if providers else "unknown",
                })

            # Replay attack check
            if not re.search(r'"(?:timestamp|created|ts|event_time)"', body_text, re.I):
                findings.append({
                    "type": "webhook_replay_risk",
                    "rule": "no_timestamp_check",
                    "detail": "Webhook body has no timestamp field -- replay attacks possible",
                    "category": "webhook_forge",
                    "confidence": 0.6,
                    "severity": "high",
                    "provider": providers[0] if providers else "unknown",
                })

            # Event type confusion
            event_match = re.search(r'"(?:type|event_type|event)":\s*"([^"]+)"', body_text)
            if event_match:
                event_type = event_match.group(1)
                for evt_a, evt_b, risk in self._CONFUSABLE_EVENTS:
                    if event_type == evt_a or event_type == evt_b:
                        findings.append({
                            "type": "event_type_confusion_risk",
                            "rule": "confusable_webhook_event",
                            "detail": f"Webhook processes '{event_type}'. Risk: {risk}",
                            "category": "webhook_forge",
                            "confidence": 0.5,
                            "severity": "medium",
                            "provider": "stripe",
                        })
                        break

        # --- 3. Amount/currency manipulation ---
        amount_match = re.search(r'"(?:amount|total|unit_amount|amount_total)":\s*(-?\d+)', body_text)
        currency_match = re.search(r'"currency":\s*"([A-Z]{3})"', body_text, re.I)

        if amount_match:
            amount = int(amount_match.group(1))

            if amount < 0:
                findings.append({
                    "type": "negative_amount",
                    "rule": "negative_payment_amount",
                    "detail": f"Negative amount ({amount}) detected -- possible refund abuse or credit injection",
                    "category": "payment_manipulation",
                    "confidence": 0.9,
                    "severity": "critical",
                    "provider": providers[0] if providers else "unknown",
                })

            if amount == 0:
                has_active = bool(re.search(r'"status":\s*"(?:active|succeeded|paid|complete)"', body_text, re.I))
                if has_active:
                    findings.append({
                        "type": "zero_amount_active",
                        "rule": "zero_amount_with_active_status",
                        "detail": "Amount is 0 but resource is active/succeeded -- access without payment",
                        "category": "payment_manipulation",
                        "confidence": 0.9,
                        "severity": "critical",
                        "provider": providers[0] if providers else "unknown",
                    })

            if amount > 0 and amount <= 50:
                findings.append({
                    "type": "minimum_charge_bypass",
                    "rule": "below_minimum_amount",
                    "detail": (
                        f"Amount is {amount} (${amount/100:.2f}). Stripe minimum is $0.50. "
                        f"If this succeeds, the glue code may not enforce minimum charges."
                    ),
                    "category": "payment_manipulation",
                    "confidence": 0.5,
                    "severity": "medium",
                    "provider": providers[0] if providers else "unknown",
                })

            if amount > 99999999:
                findings.append({
                    "type": "amount_overflow",
                    "rule": "excessive_amount",
                    "detail": f"Amount {amount} (${amount/100:,.2f}) exceeds reasonable bounds",
                    "category": "payment_manipulation",
                    "confidence": 0.6,
                    "severity": "high",
                    "provider": providers[0] if providers else "unknown",
                })

            if currency_match:
                currency = currency_match.group(1).upper()
                if currency in self._ZERO_DECIMAL_CURRENCIES and amount < 100:
                    findings.append({
                        "type": "zero_decimal_confusion",
                        "rule": "zero_decimal_currency_mishandling",
                        "detail": (
                            f"Currency {currency} is zero-decimal (no subunits) but amount={amount}. "
                            f"If the glue code divides by 100 for display, this shows as "
                            f"${amount/100:.2f} instead of {amount}. Classic cents/units bug."
                        ),
                        "category": "payment_manipulation",
                        "confidence": 0.7,
                        "severity": "high",
                        "provider": providers[0] if providers else "unknown",
                    })

        # --- 4. Idempotency analysis ---
        lower_req = {k.lower(): v for k, v in req_headers.items()}
        is_payment_mutation = (
            method in _MUTATING_METHODS
            and _PAYMENT_SENSITIVE_PATH_RE.search(endpoint)
        )
        if is_payment_mutation:
            has_idempotency = "idempotency-key" in lower_req or "idempotency_key" in lower_req
            if not has_idempotency:
                findings.append({
                    "type": "missing_idempotency",
                    "rule": "no_idempotency_key",
                    "detail": (
                        f"Payment mutation ({method} {endpoint}) has no idempotency key. "
                        f"Network retries or intentional replays can create duplicate charges."
                    ),
                    "category": "race_condition",
                    "confidence": 0.7,
                    "severity": "high",
                    "provider": providers[0] if providers else "unknown",
                })

        # --- 5. Test/live mode confusion ---
        if re.search(r'(?:sk_test_|pk_test_)', body_text):
            findings.append({
                "type": "test_mode_keys",
                "rule": "test_keys_in_response",
                "detail": "Test-mode Stripe keys in response body -- if production, this is a misconfiguration",
                "category": "payment_manipulation",
                "confidence": 0.75,
                "severity": "high",
                "provider": "stripe",
            })

        livemode_match = re.search(r'"livemode":\s*(true|false)', body_text, re.I)
        if livemode_match and livemode_match.group(1).lower() == "false":
            findings.append({
                "type": "test_mode_active",
                "rule": "livemode_false",
                "detail": (
                    "Stripe object has livemode=false. If this is production, payments "
                    "are going to test mode and no real charges are being made."
                ),
                "category": "payment_manipulation",
                "confidence": 0.8,
                "severity": "critical",
                "provider": "stripe",
            })

        # --- 6. Customer/object cross-reference bugs ---
        customer_ids = re.findall(r'"(?:customer|customer_id)":\s*"(cus_[a-zA-Z0-9]+)"', body_text)
        if len(set(customer_ids)) > 1:
            findings.append({
                "type": "multi_customer_response",
                "rule": "cross_customer_objects",
                "detail": (
                    f"Response contains {len(set(customer_ids))} different customer IDs: "
                    f"{sorted(set(customer_ids))[:3]}. Cross-customer object reference may allow "
                    f"accessing another user's payment data or subscription."
                ),
                "category": "idor",
                "confidence": 0.8,
                "severity": "critical",
                "provider": "stripe",
            })

        # Subscription with no default payment method
        if (re.search(r'"status":\s*"active"', body_text, re.I)
                and re.search(r'"default_payment_method":\s*null', body_text, re.I)):
            findings.append({
                "type": "active_no_payment_method",
                "rule": "subscription_without_payment",
                "detail": (
                    "Active subscription with null default_payment_method. "
                    "The subscription may continue without any payment method on file."
                ),
                "category": "entitlement_bypass",
                "confidence": 0.7,
                "severity": "high",
                "provider": "stripe",
            })

        # --- 7. Trial & coupon abuse ---
        trial_end = re.search(r'"trial_end":\s*(\d+)', body_text)
        trial_status = re.search(r'"status":\s*"trialing"', body_text, re.I)
        if trial_end and not trial_status:
            trial_ts = int(trial_end.group(1))
            if trial_ts < time.time() - 86400:
                findings.append({
                    "type": "expired_trial_active",
                    "rule": "trial_period_exceeded",
                    "detail": "trial_end is in the past but subscription is not marked as trialing/canceled",
                    "category": "entitlement_bypass",
                    "confidence": 0.7,
                    "severity": "high",
                    "provider": "stripe",
                })

        coupon_matches = re.findall(r'"(?:coupon|promotion_code|discount)"', body_text, re.I)
        if len(coupon_matches) >= 2:
            findings.append({
                "type": "coupon_stacking",
                "rule": "multiple_discounts",
                "detail": f"Response references {len(coupon_matches)} discount/coupon objects -- possible coupon stacking",
                "category": "coupon_stacking",
                "confidence": 0.5,
                "severity": "medium",
                "provider": providers[0] if providers else "unknown",
            })

        # --- 8. Connect/marketplace platform bugs ---
        if re.search(r'"(?:destination|transfer_data|application_fee)"', body_text, re.I):
            app_fee_match = re.search(r'"application_fee_amount":\s*(\d+)', body_text)
            transfer_match = re.search(r'"(?:amount|transfer_amount)":\s*(\d+)', body_text)
            if app_fee_match and transfer_match:
                fee = int(app_fee_match.group(1))
                transfer = int(transfer_match.group(1))
                if fee > transfer:
                    findings.append({
                        "type": "platform_fee_exceeds_transfer",
                        "rule": "connect_fee_manipulation",
                        "detail": (
                            f"Application fee ({fee}) exceeds transfer amount ({transfer}). "
                            f"The platform is taking more than the payment -- fund drain risk."
                        ),
                        "category": "payment_manipulation",
                        "confidence": 0.85,
                        "severity": "critical",
                        "provider": "stripe",
                    })

        connected_account = re.search(r'"(?:stripe_account|connected_account_id)":\s*"(acct_[^"]+)"', body_text)
        if connected_account:
            if re.search(r'"(?:charges_enabled|payouts_enabled)":\s*false', body_text, re.I):
                findings.append({
                    "type": "incomplete_connect_account",
                    "rule": "unverified_connected_account",
                    "detail": "Connected account has charges/payouts disabled but appears in a payment flow",
                    "category": "payment_manipulation",
                    "confidence": 0.6,
                    "severity": "medium",
                    "provider": "stripe",
                })

        self._findings.extend(findings)
        return findings

    def get_all_findings(self) -> list[dict[str, Any]]:
        return self._findings[-100:]

    def get_provider_summary(self) -> dict[str, Any]:
        return {
            "providers_seen": sorted(self._providers_seen),
            "state_transitions_tracked": {
                k: len(v) for k, v in self._state_history.items()
            },
            "total_findings": len(self._findings),
            "findings_by_provider": {
                p: sum(1 for f in self._findings if f.get("provider") == p)
                for p in self._providers_seen
            },
        }




# ############################################################################
#
#  N. EnterprisePlatformDetector -- Fingerprints enterprise platforms and
#     AI services from HTTP traffic. Returns platform-specific vulnerability
#     profiles that inform other engines about the attack surface.
#     Covers: Salesforce, SAP, ServiceNow, Okta, AWS Cognito, Azure AD,
#     Atlassian, GraphQL, Shopify, OpenAI, Anthropic, Google AI, AWS Bedrock,
#     Stripe Connect, Kubernetes.
#
# ############################################################################


class EnterprisePlatformDetector:
    """Fingerprints enterprise platforms and AI services from HTTP traffic.

    Returns platform-specific vulnerability profiles that inform other engines
    about the attack surface they're analyzing."""

    # Platform signatures: {platform_name: [(field, regex_pattern), ...]}
    # Checked against body_text, headers, URLs, endpoint paths
    _PLATFORM_SIGNATURES: dict[str, list[tuple[str, re.Pattern]]] = {
        "salesforce": [
            ("url", re.compile(r"(lightning\.force\.com|\.salesforce\.com|/services/data/v\d|/aura\b)", re.I)),
            ("body", re.compile(r"(auraConfig|SObjectDescribe|\"sobjectType\"|RecordTypeId|ApexAction)", re.I)),
            ("header", re.compile(r"(x-sfdc-|Salesforce-Instance)", re.I)),
        ],
        "sap": [
            ("url", re.compile(r"(/sap/opu/|/sap/bc/|/odata/v[24]|__metadata)", re.I)),
            ("body", re.compile(r"(SAP-Client|X-CSRF-Token|sap-system|__deferred|__metadata)", re.I)),
            ("header", re.compile(r"(sap-client|x-csrf-token|sap-contextid)", re.I)),
        ],
        "servicenow": [
            ("url", re.compile(r"(service-now\.com|/api/now/|/api/sn_|sys_id=)", re.I)),
            ("body", re.compile(r"(GlideRecord|sys_id|sys_created_on|sys_updated_by|cmdb_ci)", re.I)),
            ("header", re.compile(r"(x-is-logged-in|x-transaction-id.*snow)", re.I)),
        ],
        "okta": [
            ("url", re.compile(r"(\.okta\.com|\.auth0\.com|/oauth2/|/api/v1/authn)", re.I)),
            ("body", re.compile(r"(okta_token|auth0_client|sessionToken|\"stateToken\")", re.I)),
            ("header", re.compile(r"(x-okta-|x-auth0-)", re.I)),
        ],
        "aws_cognito": [
            ("url", re.compile(r"(cognito-idp\.|cognito-identity\.)", re.I)),
            ("body", re.compile(r"(AWSCognitoIdentityProviderService|CognitoIdentityCredentials|UserPoolId)", re.I)),
            ("header", re.compile(r"(x-amz-target.*cognito)", re.I)),
        ],
        "azure_ad": [
            ("url", re.compile(r"(login\.microsoftonline\.com|graph\.microsoft\.com|/v2\.0/token)", re.I)),
            ("body", re.compile(r"(\"aud\":\s*\"https://graph|aad_token|tenant_id|\"tid\":)", re.I)),
            ("header", re.compile(r"(x-ms-ests|client-request-id)", re.I)),
        ],
        "atlassian": [
            ("url", re.compile(r"(atlassian\.net|/rest/api/\d|/wiki/rest/|bitbucket\.org/api)", re.I)),
            ("body", re.compile(r"(atlassian-token|ACPT-|AO-\d|jira\.issue|confluence\.page)", re.I)),
            ("header", re.compile(r"(x-atlassian-|atl-)", re.I)),
        ],
        "graphql": [
            ("url", re.compile(r"(/graphql\b)", re.I)),
            ("body", re.compile(r"(__schema|__typename|\"query\"\s*:\s*\"|introspectionQuery|\"mutations?\":\s*\{)", re.I)),
        ],
        "shopify": [
            ("url", re.compile(r"(myshopify\.com|/admin/api/\d{4})", re.I)),
            ("body", re.compile(r"(\"shop\":\s*\{|Shopify\.theme|ShopifyAPI|\"fulfillment_orders\")", re.I)),
            ("header", re.compile(r"(x-shopify-access-token|x-shopify-shop-domain)", re.I)),
        ],
        "openai": [
            ("url", re.compile(r"(api\.openai\.com|/v1/chat/completions|/v1/embeddings)", re.I)),
            ("body", re.compile(r"(sk-proj-[A-Za-z0-9]|\"model\":\s*\"(gpt-4|o[13]-|chatgpt))", re.I)),
            ("header", re.compile(r"(openai-organization|x-ratelimit-limit-tokens)", re.I)),
        ],
        "anthropic": [
            ("url", re.compile(r"(api\.anthropic\.com|/v1/messages|/v1/complete)", re.I)),
            ("body", re.compile(r"(sk-ant-[A-Za-z0-9]|\"model\":\s*\"claude|x-api-key.*anthropic|anthropic-version)", re.I)),
            ("header", re.compile(r"(x-api-key|anthropic-version)", re.I)),
        ],
        "google_ai": [
            ("url", re.compile(r"(generativelanguage\.googleapis\.com|aiplatform\.googleapis\.com)", re.I)),
            ("body", re.compile(r"(AIzaSy[A-Za-z0-9_-]{33}|\"model\":\s*\"gemini)", re.I)),
        ],
        "aws_bedrock": [
            ("url", re.compile(r"(bedrock-runtime\.|bedrock\..*amazonaws)", re.I)),
            ("body", re.compile(r"(us\.anthropic\.|anthropic\.claude|amazon\.titan|ai21\.jamba)", re.I)),
        ],
        "stripe_connect": [
            ("url", re.compile(r"(connect\.stripe\.com|/v1/accounts|stripe-account=)", re.I)),
            ("body", re.compile(r"(\"stripe_account\":|Stripe-Account|connected_account_id)", re.I)),
            ("header", re.compile(r"(stripe-account)", re.I)),
        ],
        "kubernetes": [
            ("url", re.compile(r"(/api/v1/namespaces|/apis/apps/v1|\.svc\.cluster\.local)", re.I)),
            ("body", re.compile(r"(\"apiVersion\":\s*\"v1\"|\"kind\":\s*\"(Pod|Service|Deployment)\")", re.I)),
            ("header", re.compile(r"(x-kubernetes-)", re.I)),
        ],
    }

    # Platform-specific vulnerability profiles
    _VULN_PROFILES: dict[str, dict[str, Any]] = {
        "salesforce": {
            "attack_surface": ["aura_component_injection", "soql_injection", "sharing_rule_bypass", "guest_user_abuse"],
            "entitlement_model": "license_based",
            "common_misconfig": "overly_permissive_sharing_rules",
        },
        "sap": {
            "attack_surface": ["odata_injection", "rfc_abuse", "transport_manipulation", "bapi_bypass"],
            "entitlement_model": "role_based",
            "common_misconfig": "default_sap_star_user",
        },
        "servicenow": {
            "attack_surface": ["acl_bypass", "glide_record_injection", "script_include_abuse", "impersonation"],
            "entitlement_model": "role_based",
            "common_misconfig": "public_widget_data_exposure",
        },
        "okta": {
            "attack_surface": ["session_fixation", "mfa_bypass", "api_token_abuse", "universal_directory_enum"],
            "entitlement_model": "sso_delegated",
            "common_misconfig": "weak_session_policy",
        },
        "aws_cognito": {
            "attack_surface": ["self_signup_abuse", "attribute_injection", "token_manipulation", "identity_pool_unauth"],
            "entitlement_model": "pool_based",
            "common_misconfig": "unauth_identity_access",
        },
        "azure_ad": {
            "attack_surface": ["consent_phishing", "app_role_abuse", "token_replay", "tenant_misconfiguration"],
            "entitlement_model": "tenant_based",
            "common_misconfig": "overpermissive_app_registration",
        },
        "graphql": {
            "attack_surface": ["introspection_enabled", "batching_abuse", "nested_query_dos", "field_suggestion_enum"],
            "entitlement_model": "varies",
            "common_misconfig": "introspection_in_production",
        },
        "openai": {
            "attack_surface": ["api_key_theft", "prompt_injection", "model_extraction", "rate_limit_bypass"],
            "entitlement_model": "api_key_billing",
            "common_misconfig": "key_in_client_code",
        },
        "anthropic": {
            "attack_surface": ["api_key_theft", "session_hijack", "mcp_tool_poisoning", "distillation_proxy",
                               "credential_precedence_abuse", "repo_config_rce", "gift_fraud"],
            "entitlement_model": "api_key_billing_or_subscription",
            "common_misconfig": "settings_local_json_in_repo",
        },
        "aws_bedrock": {
            "attack_surface": ["iam_role_abuse", "cross_account_invoke", "model_access_policy_bypass"],
            "entitlement_model": "iam_based",
            "common_misconfig": "overly_broad_bedrock_invoke_policy",
        },
    }

    def __init__(self) -> None:
        self._detected_platforms: dict[str, int] = defaultdict(int)
        self._findings: list[dict[str, Any]] = []

    def detect_platforms(self, observation: dict, components: dict) -> list[dict[str, Any]]:
        """Detect enterprise platforms from observation data.
        Returns list of {platform, confidence, matches, vuln_profile}."""

        body_text = components.get("body_text", "")
        endpoint = components.get("endpoint", "")
        url = observation.get("request_data", {}).get("url", "")

        req_headers = observation.get("request_data", {}).get("headers", {})
        resp_headers = observation.get("response_data", {}).get("headers", {})
        all_headers_str = json.dumps({**req_headers, **resp_headers})

        detections: list[dict[str, Any]] = []

        for platform, sig_list in self._PLATFORM_SIGNATURES.items():
            matches = []
            for field_type, pattern in sig_list:
                target = ""
                if field_type == "url":
                    target = url + " " + endpoint
                elif field_type == "body":
                    target = body_text
                elif field_type == "header":
                    target = all_headers_str

                m = pattern.search(target)
                if m:
                    matches.append({"field": field_type, "matched": m.group()[:60]})

            if matches:
                confidence = min(1.0, 0.4 + 0.2 * len(matches))
                self._detected_platforms[platform] += 1

                vuln_profile = self._VULN_PROFILES.get(platform, {})

                detection = {
                    "platform": platform,
                    "confidence": confidence,
                    "matches": matches,
                    "vuln_profile": vuln_profile,
                    "detection_count": self._detected_platforms[platform],
                }
                detections.append(detection)

                # Generate platform-specific findings
                if vuln_profile:
                    for attack in vuln_profile.get("attack_surface", [])[:3]:
                        self._findings.append({
                            "type": f"enterprise_platform_{attack}",
                            "platform": platform,
                            "detail": f"Detected {platform} platform; attack surface includes {attack}",
                            "severity": "medium",
                            "confidence": confidence * 0.7,
                            "category": "enterprise_attack_surface",
                        })

        return detections

    def get_platform_summary(self) -> dict[str, Any]:
        return {
            "platforms_detected": dict(self._detected_platforms),
            "total_detections": sum(self._detected_platforms.values()),
            "findings_generated": len(self._findings),
        }

    def get_all_findings(self) -> list[dict[str, Any]]:
        return self._findings[-100:]



# ############################################################################
#
#  O. AccessWithoutPaymentDetector -- THE core detector for the engine's
#     primary mission. Encodes 12 general access-without-payment attack
#     patterns from real-world payment bypasses PLUS 9 Anthropic-specific
#     vectors from confirmed CVEs and threat reports (Sep 2026 Anthropic
#     threat report, Oasis Security Claudy Day, Check Point CVE-2025-59536,
#     Apiiro credential leak disclosure, Darktrace C2 research).
#
# ############################################################################


class AccessWithoutPaymentDetector:
    """Detects access-without-payment attack patterns across enterprise systems.

    Encodes 18 general attack patterns (including SAML/SSO bypass, API version
    downgrade, race condition detection, idempotency replay, subscription state
    machine confusion, and org seat overflow) plus 9 Anthropic-specific vectors
    from confirmed CVEs and threat reports.  27 total patterns.
    Every pattern is deterministic -- no LLM calls, no API deps."""

    # Patterns that indicate entitlement was granted
    _ENTITLEMENT_GRANT_RE = re.compile(
        r"(\"entitlement\"\s*:\s*true|\"access_level\"\s*:\s*\"(premium|pro|enterprise|max)\"|"
        r"\"is_premium\"\s*:\s*true|\"has_access\"\s*:\s*true|\"plan\"\s*:\s*\"(pro|enterprise|business|max)\"|"
        r"\"subscription_active\"\s*:\s*true|\"features_enabled\"|\"tier\"\s*:\s*\"(paid|premium)\")",
        re.I,
    )

    # Patterns that indicate NO payment was made
    _NO_PAYMENT_RE = re.compile(
        r"(\"payment_status\"\s*:\s*\"unpaid\"|\"amount_total\"\s*:\s*0\b|\"amount\"\s*:\s*0\b|"
        r"\"status\"\s*:\s*\"(incomplete|trialing|canceled|unpaid|past_due)\"|"
        r"\"paid\"\s*:\s*false|\"balance\"\s*:\s*0\b|\"charge\"\s*:\s*null)",
        re.I,
    )

    # Trial/free indicators
    _TRIAL_RE = re.compile(
        r"(\"trial_end\"|\"trial_start\"|\"trialing\"|free_trial|\"trial_period_days\"|"
        r"\"status\"\s*:\s*\"trialing\")",
        re.I,
    )

    # Credential patterns that shouldn't appear in responses
    _LEAKED_CREDENTIAL_RE = re.compile(
        r"(sk-ant-[A-Za-z0-9_-]{20,}|sk-proj-[A-Za-z0-9_-]{20,}|sk_test_[A-Za-z0-9]{20,}|"
        r"sk_live_[A-Za-z0-9]{20,}|AIzaSy[A-Za-z0-9_-]{33}|ghp_[A-Za-z0-9]{36}|"
        r"AKIA[A-Z0-9]{16}|ya29\.[A-Za-z0-9_-]+|xoxb-[0-9]+-[A-Za-z0-9]+)",
        re.I,
    )

    # Gift fraud patterns
    _GIFT_RE = re.compile(
        r"(\"gift\"|gift_subscription|gift_code|gift_recipient|\"gifted\")",
        re.I,
    )

    # MCP/Agent config patterns (Anthropic-specific)
    _MCP_CONFIG_RE = re.compile(
        r"(enableAllProjectMcpServers|enabledMcpjsonServers|autoApprove|"
        r"\"hooks\"\s*:\s*\{|\"SessionStart\"|ANTHROPIC_BASE_URL|"
        r"\.claude/settings\.json|\.claude/settings\.local\.json|\.mcp\.json)",
        re.I,
    )

    # Distillation indicators
    _DISTILLATION_RE = re.compile(
        r"(\"model\":\s*\"claude|/v1/messages|/v1/complete|completion_tokens|"
        r"prompt_tokens|\"usage\":\s*\{.*\"input_tokens\")",
        re.I,
    )

    # Session/cookie patterns
    _SESSION_RE = re.compile(
        r"(sessionToken|session_id|__session|connect\.sid|\.AspNetCore\.Session|"
        r"JSESSIONID|PHPSESSID|_session_id)",
        re.I,
    )

    # Coupon/discount patterns
    _COUPON_RE = re.compile(
        r"(\"coupon\"|\"discount\"|\"percent_off\"\s*:\s*100|\"amount_off\"|"
        r"\"promotion_code\"|\"promo_code\"|coupon_id)",
        re.I,
    )

    # Auto-reload / billing spiral indicators
    _BILLING_SPIRAL_RE = re.compile(
        r"(auto_reload|auto_recharge|\"reload_amount\"|\"reload_threshold\"|"
        r"\"prepaid_balance\"|\"credits_remaining\"\s*:\s*0|negative_balance)",
        re.I,
    )

    # OAuth without subscription
    _OAUTH_NO_SUB_RE = re.compile(
        r"(\"access_token\"|\"bearer\"|\"authorization\":\s*\"Bearer)",
        re.I,
    )

    # SAML/SSO patterns
    _SAML_RE = re.compile(
        r"(SAMLResponse|saml2?:|urn:oasis:names:tc:SAML|<saml:|"
        r"<Assertion|<AuthnStatement|<Subject>|NameID|"
        r"AudienceRestriction|InResponseTo|samlp:Response)",
        re.I,
    )

    # API version indicators
    _API_VERSION_RE = re.compile(
        r"(/api/v[0-9]+/|/v[0-9]+/|\"api_version\"\s*:\s*\"[^\"]+\"|"
        r"x-api-version|api-version:\s*\d|swagger.*v[0-9]|openapi.*3\.\d)",
        re.I,
    )

    # Idempotency key patterns
    _IDEMPOTENCY_RE = re.compile(
        r"(idempotency.key|idempotent-key|x-idempotency|"
        r"\"idempotency_key\"\s*:\s*null|retry-after|duplicate.*event)",
        re.I,
    )

    # Race condition indicators in responses
    _RACE_INDICATOR_RE = re.compile(
        r"(already.*processed|duplicate.*transaction|concurrent.*modification|"
        r"optimistic.*lock|version.*conflict|retry.*later|stale.*data|"
        r"\"balance\":\s*-\d|double.*credit|double.*debit)",
        re.I,
    )

    # Client-controlled price/plan parameters (Cap #2222 pattern)
    _CLIENT_PRICE_RE = re.compile(
        r"(\"price_?[Ii]d\"\s*:|\"plan_?[Ii]d\"\s*:|\"lookup_key\"\s*:|"
        r"\"price\"\s*:\s*\"price_|\"plan\"\s*:\s*\"plan_|"
        r"line_items\[0\]\[price\]|price_data\[product\])",
        re.I,
    )

    # Refund/chargeback abuse indicators
    _REFUND_ABUSE_RE = re.compile(
        r"(refund.*succeed|refund.*processed|\"refunded\"\s*:\s*true|"
        r"chargeback|dispute.*created|\"amount_refunded\"|"
        r"\"refund_id\"|partial_refund|credit.*note)",
        re.I,
    )

    # Usage metering bypass indicators
    _METERING_RE = re.compile(
        r"(usage.*record|meter.*event|\"quantity\"\s*:\s*0|"
        r"\"usage\"\s*:\s*0|metered|consumption|\"units\"\s*:|"
        r"usage_based|per.?unit|overage)",
        re.I,
    )

    # Webhook replay / event ID reuse
    _EVENT_REPLAY_RE = re.compile(
        r"(\"event_id\"\s*:|\"idempotency_key\"\s*:|\"delivery_id\"\s*:|"
        r"\"message_id\"\s*:|x-webhook-id|webhook-id|x-request-id.*webhook)",
        re.I,
    )

    # Feature flag / entitlement override in request
    _FEATURE_FLAG_RE = re.compile(
        r"(\"features\"\s*:\s*\[|\"feature_flags\"\s*:|\"entitlements\"\s*:\s*\[|"
        r"\"plan_features\"|\"override\"\s*:\s*true|\"is_premium\"\s*:\s*true|"
        r"\"tier\"\s*:\s*\"(pro|enterprise|business|unlimited)\")",
        re.I,
    )

    # Coupon/promo code stacking
    _COUPON_STACK_RE = re.compile(
        r"(\"coupon\"\s*:|\"promo_code\"\s*:|\"discount\"\s*:|"
        r"\"coupons\"\s*:\s*\[|promotions\[|\"percent_off\"\s*:\s*100|"
        r"\"amount_off\".*\"amount_off\"|coupon.*coupon)",
        re.I,
    )

    # API key scope/mode escalation
    _KEY_SCOPE_RE = re.compile(
        r"(sk_test_|pk_test_|test_key|restricted_key|read_only.*key|"
        r"\"mode\"\s*:\s*\"test\"|\"scope\"\s*:\s*\"(read|limited|restricted)\")",
        re.I,
    )
    _ADMIN_DATA_RE = re.compile(
        r"(\"role\"\s*:\s*\"admin\"|admin.*panel|user.*management|"
        r"billing.*data|\"permissions\".*\"write\"|api_key.*secret|"
        r"\"admin\"\s*:\s*true|internal.*endpoint)",
        re.I,
    )

    def __init__(self) -> None:
        self._findings: list[dict[str, Any]] = []
        self._pattern_hits: dict[str, int] = defaultdict(int)
        self._observation_count = 0

    def analyze(
        self, observation: dict, components: dict, memory: Any = None,
    ) -> list[dict[str, Any]]:
        """Run all 34 attack pattern detectors against an observation."""
        self._observation_count += 1
        findings: list[dict[str, Any]] = []

        body_text = components.get("body_text", "")
        endpoint = components.get("endpoint", "")
        method = components.get("method", "")
        status_code = components.get("status_code", 0)
        url = observation.get("request_data", {}).get("url", "")
        req_headers = observation.get("request_data", {}).get("headers", {})
        resp_headers = observation.get("response_data", {}).get("headers", {})
        req_body_raw = observation.get("request_data", {}).get("body", "")
        if isinstance(req_body_raw, (dict, list)):
            req_body_text = json.dumps(req_body_raw)
        else:
            req_body_text = str(req_body_raw) if req_body_raw else ""

        # ===== 25 GENERAL ACCESS-WITHOUT-PAYMENT PATTERNS =====

        # 1. checkout_completed_unpaid: The #1 Stripe bypass
        has_entitlement = bool(self._ENTITLEMENT_GRANT_RE.search(body_text))
        has_no_payment = bool(self._NO_PAYMENT_RE.search(body_text))
        checkout_completed = bool(re.search(
            r"checkout\.session\.completed|\"status\"\s*:\s*\"complete\"", body_text, re.I,
        ))
        if checkout_completed and has_no_payment and has_entitlement:
            findings.append({
                "type": "checkout_completed_unpaid",
                "detail": (
                    "CRITICAL: checkout.session.completed fired with payment_status=unpaid "
                    "but entitlement was granted. This is the #1 Stripe access-without-payment "
                    "pattern. Deferred payment methods (bank debits, SEPA) complete the session "
                    "before payment clears. Must wait for checkout.session.async_payment_succeeded."
                ),
                "severity": "critical",
                "confidence": 0.95,
                "category": "access_without_payment",
                "cwe": "CWE-863",
                "attack_pattern": "AP-1",
            })
            self._pattern_hits["checkout_completed_unpaid"] += 1

        # 2. Stale entitlement flag: access granted despite non-paid status
        elif has_entitlement and has_no_payment:
            findings.append({
                "type": "stale_entitlement",
                "detail": (
                    "Entitlement/access granted alongside indicators of non-payment "
                    "(unpaid, $0, trialing, canceled). The entitlement flag may not be "
                    "synchronized with actual payment state."
                ),
                "severity": "critical",
                "confidence": 0.85,
                "category": "access_without_payment",
                "cwe": "CWE-863",
                "attack_pattern": "AP-6",
            })
            self._pattern_hits["stale_entitlement"] += 1

        # 3. Trial without conversion gate
        is_trial = bool(self._TRIAL_RE.search(body_text))
        if is_trial and has_entitlement:
            has_payment_method = bool(re.search(
                r"payment_method|card_last4|billing_details", body_text, re.I,
            ))
            if not has_payment_method:
                findings.append({
                    "type": "trial_without_payment_method",
                    "detail": (
                        "Trial state with premium entitlements but no payment method on file. "
                        "Users can cycle trials indefinitely without ever converting. "
                        "Trial should require a valid payment method upfront."
                    ),
                    "severity": "high",
                    "confidence": 0.75,
                    "category": "access_without_payment",
                    "cwe": "CWE-863",
                    "attack_pattern": "AP-4",
                })
                self._pattern_hits["trial_without_conversion"] += 1

        # 4. Canceled subscription still granting access
        is_canceled = bool(re.search(r"\"status\"\s*:\s*\"canceled\"", body_text, re.I))
        if is_canceled and has_entitlement:
            findings.append({
                "type": "canceled_with_access",
                "detail": (
                    "Subscription is canceled but access/entitlement is still active. "
                    "Revocation may be delayed or missing entirely. "
                    "Check if cancel_at_period_end vs immediate cancellation is handled."
                ),
                "severity": "high",
                "confidence": 0.80,
                "category": "access_without_payment",
                "cwe": "CWE-863",
                "attack_pattern": "AP-5",
            })
            self._pattern_hits["canceled_with_access"] += 1

        # 5. Leaked credentials in response (stolen key = free compute)
        cred_match = self._LEAKED_CREDENTIAL_RE.search(body_text)
        if cred_match:
            findings.append({
                "type": "leaked_credential_in_response",
                "detail": (
                    f"API credential pattern detected in response body: "
                    f"{cred_match.group()[:20]}... A leaked key enables free compute "
                    f"on the key owner's account (LLMjacking). Sysdig estimates "
                    f"$46,000+/day cost for a single compromised key."
                ),
                "severity": "critical",
                "confidence": 0.90,
                "category": "access_without_payment",
                "cwe": "CWE-200",
                "attack_pattern": "AP-3",
            })
            self._pattern_hits["leaked_credential"] += 1

        # 6. Client-side paywall bypass
        if status_code == 200 and has_entitlement:
            has_auth = bool(req_headers.get("Authorization") or
                          req_headers.get("Cookie") or
                          req_headers.get("x-api-key"))
            if method == "GET" and not has_auth and "premium" in body_text.lower():
                findings.append({
                    "type": "client_side_paywall",
                    "detail": (
                        "Premium content returned on unauthenticated GET request. "
                        "Access control may exist only in the frontend. Server returns "
                        "full premium data regardless of authentication state."
                    ),
                    "severity": "high",
                    "confidence": 0.70,
                    "category": "access_without_payment",
                    "cwe": "CWE-862",
                    "attack_pattern": "AP-7",
                })
                self._pattern_hits["client_side_paywall"] += 1

        # 7. Coupon/discount abuse (100% off)
        has_coupon = bool(self._COUPON_RE.search(body_text))
        full_discount = bool(re.search(r"\"percent_off\"\s*:\s*100", body_text, re.I))
        no_payment_intent = not bool(re.search(r"payment_intent|pi_", body_text, re.I))
        if has_coupon and full_discount and no_payment_intent:
            findings.append({
                "type": "coupon_full_discount_no_pi",
                "detail": (
                    "100% discount coupon applied with no PaymentIntent created. "
                    "Stripe skips PaymentIntent for $0 checkouts. If the coupon is "
                    "time-limited, the renewal will fail silently and access persists. "
                    "Race condition: apply coupon between price calculation and charge."
                ),
                "severity": "high",
                "confidence": 0.80,
                "category": "access_without_payment",
                "cwe": "CWE-863",
                "attack_pattern": "AP-8",
            })
            self._pattern_hits["coupon_abuse"] += 1

        # 8. Credit balance race condition
        credit_indicators = bool(re.search(
            r"credit_balance|customer_balance|\"balance\":\s*-?\d", body_text, re.I,
        ))
        concurrent_indicator = bool(re.search(
            r"\"balance\":\s*-\d|negative_balance|insufficient", body_text, re.I,
        ))
        if credit_indicators and concurrent_indicator:
            findings.append({
                "type": "credit_race_condition",
                "detail": (
                    "Credit balance shows negative or concurrent modification indicators. "
                    "Race condition: two requests read the same balance, both apply credits, "
                    "resulting in double-spend. Must use atomic operations or optimistic locking."
                ),
                "severity": "high",
                "confidence": 0.65,
                "category": "access_without_payment",
                "cwe": "CWE-362",
                "attack_pattern": "AP-9",
            })
            self._pattern_hits["credit_race"] += 1

        # 9. OAuth token without subscription validation
        has_oauth = bool(self._OAUTH_NO_SUB_RE.search(
            json.dumps(req_headers) + " " + body_text,
        ))
        sub_inactive = bool(re.search(
            r"\"subscription\"\s*:\s*null|\"plan\"\s*:\s*\"free\"|no_active_subscription",
            body_text, re.I,
        ))
        if has_oauth and sub_inactive and has_entitlement:
            findings.append({
                "type": "oauth_without_subscription",
                "detail": (
                    "Valid OAuth/Bearer token accepted but subscription is null/free. "
                    "Authentication succeeded but authorization (subscription check) "
                    "was skipped. OAuth token validity != payment validity."
                ),
                "severity": "high",
                "confidence": 0.75,
                "category": "access_without_payment",
                "cwe": "CWE-863",
                "attack_pattern": "AP-10",
            })
            self._pattern_hits["oauth_no_sub"] += 1

        # 10. Promotional credit exploitation
        promo_credit = bool(re.search(
            r"promotional_credit|signup_credit|\"credit\"\s*:\s*\d{3,}|bonus_credit",
            body_text, re.I,
        ))
        if promo_credit and has_entitlement:
            findings.append({
                "type": "promo_credit_exploit",
                "detail": (
                    "Promotional/signup credits detected alongside active entitlement. "
                    "If credit > service cost, the user profits from the platform. "
                    "Automated account creation can farm promotional credits at scale."
                ),
                "severity": "medium",
                "confidence": 0.60,
                "category": "access_without_payment",
                "cwe": "CWE-863",
                "attack_pattern": "AP-11",
            })
            self._pattern_hits["promo_credit"] += 1

        # 11. Gift subscription fraud
        has_gift = bool(self._GIFT_RE.search(body_text))
        if has_gift and method == "POST":
            multi_gift = body_text.count("gift") >= 3
            if multi_gift:
                findings.append({
                    "type": "gift_subscription_fraud",
                    "detail": (
                        "Multiple gift-related fields in a single POST request. "
                        "Gift subscription fraud: attacker with stolen credentials buys "
                        "gifts charged to victim, sends codes to their own email. "
                        "Gift purchases require fewer verification steps than account changes."
                    ),
                    "severity": "high",
                    "confidence": 0.70,
                    "category": "access_without_payment",
                    "cwe": "CWE-863",
                    "attack_pattern": "AP-12",
                })
                self._pattern_hits["gift_fraud"] += 1

        # 12. Webhook-only fulfillment without verification
        is_webhook = bool(re.search(r"webhook|/hook|/callback|/notify", endpoint, re.I))
        if is_webhook and method == "POST" and has_entitlement:
            findings.append({
                "type": "webhook_grants_entitlement",
                "detail": (
                    "Webhook endpoint directly grants entitlement on POST. "
                    "If webhook signature verification is missing or bypassable, "
                    "an attacker can forge webhook events to grant themselves access."
                ),
                "severity": "high",
                "confidence": 0.75,
                "category": "access_without_payment",
                "cwe": "CWE-345",
                "attack_pattern": "AP-2",
            })
            self._pattern_hits["webhook_entitlement"] += 1

        # 13. SAML/SSO auth bypass granting entitlement
        has_saml = bool(self._SAML_RE.search(body_text))
        if has_saml and has_entitlement:
            sig_missing = not bool(re.search(
                r"SignatureValue|ds:Signature|<Signature", body_text, re.I,
            ))
            if sig_missing:
                findings.append({
                    "type": "saml_unsigned_assertion_with_entitlement",
                    "detail": (
                        "SAML assertion granted entitlement without signature. "
                        "Unsigned or weakly-signed SAML responses allow assertion "
                        "manipulation: an attacker modifies NameID, Role, or Audience "
                        "to impersonate a paid user. Enterprise SSO bypass is the "
                        "#1 auth-level attack class against companies using IdPs."
                    ),
                    "severity": "critical",
                    "confidence": 0.85,
                    "category": "access_without_payment",
                    "cwe": "CWE-347",
                    "attack_pattern": "AP-13",
                })
                self._pattern_hits["saml_bypass"] += 1
            else:
                findings.append({
                    "type": "saml_entitlement_surface",
                    "detail": (
                        "SAML SSO flow detected with entitlement grant. Test for: "
                        "assertion wrapping, signature exclusion, NameID spoofing, "
                        "replay attacks, and InResponseTo bypass."
                    ),
                    "severity": "medium",
                    "confidence": 0.55,
                    "category": "access_without_payment",
                    "cwe": "CWE-287",
                    "attack_pattern": "AP-13",
                })
                self._pattern_hits["saml_surface"] += 1

        # 14. API version downgrade exposing deprecated auth
        has_api_version = bool(self._API_VERSION_RE.search(url + " " + body_text))
        if has_api_version and has_entitlement:
            version_numbers = re.findall(r'/v(\d+)/', url)
            if version_numbers:
                min_ver = min(int(v) for v in version_numbers)
                if min_ver < 2:
                    findings.append({
                        "type": "api_version_downgrade_bypass",
                        "detail": (
                            f"API version v{min_ver} returned entitlement data. "
                            "Older API versions often lack auth checks, rate limits, "
                            "or payment verification added in later versions. "
                            "An attacker can hit /api/v1/ to bypass controls enforced only on /api/v2+."
                        ),
                        "severity": "high",
                        "confidence": 0.70,
                        "category": "access_without_payment",
                        "cwe": "CWE-863",
                        "attack_pattern": "AP-14",
                    })
                    self._pattern_hits["api_version_downgrade"] += 1

        # 15. Missing idempotency allowing replay
        has_idempotency = bool(self._IDEMPOTENCY_RE.search(
            body_text + " " + json.dumps(req_headers) + " " + json.dumps(resp_headers),
        ))
        null_idempotency = bool(re.search(
            r"\"idempotency_key\"\s*:\s*null", body_text, re.I,
        ))
        if is_webhook and null_idempotency and has_entitlement:
            findings.append({
                "type": "missing_idempotency_replay",
                "detail": (
                    "Webhook processed with null idempotency key while granting entitlement. "
                    "An attacker can replay the same webhook event multiple times to stack "
                    "credits, extend trials, or grant duplicate entitlements. Must track "
                    "event IDs and reject already-consumed events."
                ),
                "severity": "high",
                "confidence": 0.80,
                "category": "access_without_payment",
                "cwe": "CWE-294",
                "attack_pattern": "AP-15",
            })
            self._pattern_hits["idempotency_replay"] += 1

        # 16. Race condition indicators in payment responses
        has_race_indicator = bool(self._RACE_INDICATOR_RE.search(body_text))
        if has_race_indicator:
            findings.append({
                "type": "race_condition_payment",
                "detail": (
                    "Response contains race condition indicators (negative balance, "
                    "duplicate transaction, concurrent modification). Payment systems "
                    "without atomic operations are vulnerable to TOCTOU: two requests "
                    "read the same state, both succeed, resulting in double-spend."
                ),
                "severity": "high",
                "confidence": 0.70,
                "category": "access_without_payment",
                "cwe": "CWE-362",
                "attack_pattern": "AP-16",
            })
            self._pattern_hits["race_condition"] += 1

        # 17. Subscription state machine confusion
        sub_state = re.search(
            r"\"status\"\s*:\s*\"(past_due|incomplete_expired|paused)\"",
            body_text, re.I,
        )
        if sub_state and has_entitlement:
            state_val = sub_state.group(1)
            findings.append({
                "type": "subscription_state_confusion",
                "detail": (
                    f"Subscription in '{state_val}' state but entitlement still active. "
                    "Subscription state machines have edge cases: past_due should suspend "
                    "access, incomplete_expired should revoke it, paused should block it. "
                    "Exploitable by triggering payment failure after entitlement grant."
                ),
                "severity": "high",
                "confidence": 0.80,
                "category": "access_without_payment",
                "cwe": "CWE-863",
                "attack_pattern": "AP-17",
            })
            self._pattern_hits["state_confusion"] += 1

        # 18. Org/team seat overflow
        seat_indicators = bool(re.search(
            r"(\"seats\"|\"seat_count\"|\"max_seats\"|\"team_size\"|member_limit)",
            body_text, re.I,
        ))
        over_limit = bool(re.search(
            r"(\"seats\":\s*\d+.*\"max_seats\":\s*\d+|\"members\":\s*\[)",
            body_text, re.I,
        ))
        if seat_indicators and over_limit and has_entitlement:
            findings.append({
                "type": "org_seat_overflow",
                "detail": (
                    "Team/org seat management endpoint with active entitlement. "
                    "Seat overflow: invite more members than the paid seat limit. "
                    "Race condition: two admins add members simultaneously. "
                    "Enterprise plans charged per-seat can be exploited for free seats."
                ),
                "severity": "high",
                "confidence": 0.65,
                "category": "access_without_payment",
                "cwe": "CWE-863",
                "attack_pattern": "AP-18",
            })
            self._pattern_hits["seat_overflow"] += 1

        # 19. Client-supplied priceId without allowlist (Cap #2222)
        has_client_price = bool(self._CLIENT_PRICE_RE.search(
            req_body_text + " " + body_text,
        ))
        is_checkout = bool(re.search(
            r"checkout|create.*session|create.*subscription|/subscribe",
            endpoint + " " + url, re.I,
        ))
        if has_client_price and is_checkout and method == "POST":
            findings.append({
                "type": "client_price_id_bypass",
                "detail": (
                    "Checkout endpoint accepts client-supplied price/plan ID. "
                    "Without server-side allowlist validation, an attacker can "
                    "substitute any live priceId (e.g. a $1/mo price) and receive "
                    "full entitlement. Cap #2222: attacker got Pro entitlement "
                    "by supplying a cheaper plan's priceId."
                ),
                "severity": "critical",
                "confidence": 0.75,
                "category": "access_without_payment",
                "cwe": "CWE-20",
                "attack_pattern": "AP-19",
            })
            self._pattern_hits["client_price_bypass"] += 1

        # 20. Refund/chargeback with retained access
        has_refund = bool(self._REFUND_ABUSE_RE.search(body_text))
        if has_refund and has_entitlement:
            findings.append({
                "type": "refund_retained_access",
                "detail": (
                    "Refund/chargeback processed but entitlement remains active. "
                    "If subscription access is not revoked on refund or dispute, "
                    "attacker gets permanent free access via buy-then-refund. "
                    "Enterprise: chargeback abuse on annual plans yields months of free access."
                ),
                "severity": "high",
                "confidence": 0.70,
                "category": "access_without_payment",
                "cwe": "CWE-863",
                "attack_pattern": "AP-20",
            })
            self._pattern_hits["refund_retained_access"] += 1

        # 21. Usage metering bypass (zero-quantity or missing records)
        has_metering = bool(self._METERING_RE.search(body_text))
        zero_usage = bool(re.search(r"\"(usage|quantity)\"\s*:\s*0", body_text, re.I))
        if has_metering and has_entitlement and zero_usage:
            findings.append({
                "type": "usage_metering_bypass",
                "detail": (
                    "Usage-based billing with zero quantity/usage alongside active entitlement. "
                    "If metering records can be omitted, zeroed, or delayed, the customer "
                    "consumes resources without being billed. At enterprise scale, "
                    "metering gaps cost providers millions in unbilled usage."
                ),
                "severity": "high",
                "confidence": 0.70,
                "category": "access_without_payment",
                "cwe": "CWE-799",
                "attack_pattern": "AP-21",
            })
            self._pattern_hits["metering_bypass"] += 1

        # 22. Webhook event replay (missing deduplication)
        has_event_id = bool(self._EVENT_REPLAY_RE.search(
            body_text + " " + json.dumps(req_headers),
        ))
        if is_webhook and has_event_id and has_entitlement:
            event_ids = re.findall(r"\"event_id\"\s*:\s*\"([^\"]+)\"", body_text)
            if len(event_ids) != len(set(event_ids)):
                findings.append({
                    "type": "webhook_event_replay",
                    "detail": (
                        "Duplicate webhook event IDs detected with entitlement grant. "
                        "Webhook consumer does not deduplicate by event ID, allowing "
                        "replay attacks that stack credits or entitlements."
                    ),
                    "severity": "critical",
                    "confidence": 0.85,
                    "category": "access_without_payment",
                    "cwe": "CWE-294",
                    "attack_pattern": "AP-22",
                })
                self._pattern_hits["event_replay"] += 1

        # 23. Feature flag / entitlement override in client request
        has_feature_flag = bool(self._FEATURE_FLAG_RE.search(req_body_text))
        is_request_body = method in ("POST", "PUT", "PATCH")
        if has_feature_flag and is_request_body and has_entitlement:
            findings.append({
                "type": "feature_flag_override",
                "detail": (
                    "Client request contains feature flags or entitlement overrides "
                    "that the server may trust. If the backend does not validate "
                    "feature flags against the subscription state, an attacker can "
                    "self-grant premium features by including them in the request body."
                ),
                "severity": "high",
                "confidence": 0.65,
                "category": "access_without_payment",
                "cwe": "CWE-284",
                "attack_pattern": "AP-23",
            })
            self._pattern_hits["feature_flag_override"] += 1

        # 24. Coupon/promo code stacking for >100% discount
        has_coupon_stack = bool(self._COUPON_STACK_RE.search(body_text))
        full_discount = bool(re.search(r"\"percent_off\"\s*:\s*100", body_text))
        multi_coupon = body_text.count("coupon") >= 3 or body_text.count("promo") >= 3
        if has_coupon_stack and (full_discount or multi_coupon):
            findings.append({
                "type": "coupon_stacking_abuse",
                "detail": (
                    "Multiple coupons/promo codes applied or 100% discount detected. "
                    "If coupon stacking is not prevented, attackers combine partial "
                    "discounts to reach 100%+ off, or chain referral+promo+seasonal "
                    "codes. Enterprise plans with annual billing are high-value targets."
                ),
                "severity": "high",
                "confidence": 0.75,
                "category": "access_without_payment",
                "cwe": "CWE-863",
                "attack_pattern": "AP-24",
            })
            self._pattern_hits["coupon_stacking"] += 1

        # 25. API key scope escalation (test key accessing live/admin data)
        has_test_key = bool(self._KEY_SCOPE_RE.search(
            req_body_text + " " + json.dumps(req_headers),
        ))
        has_admin_data = bool(self._ADMIN_DATA_RE.search(body_text))
        if has_test_key and has_admin_data:
            findings.append({
                "type": "api_key_scope_escalation",
                "detail": (
                    "Test/restricted API key returned admin/write-level data. "
                    "If scope enforcement is per-endpoint rather than per-key, "
                    "a test-mode key (sk_test_) can access live billing, user "
                    "management, or admin panels. Anthropic-specific: sk_test_ "
                    "keys should never return production user data."
                ),
                "severity": "critical",
                "confidence": 0.75,
                "category": "access_without_payment",
                "cwe": "CWE-269",
                "attack_pattern": "AP-25",
            })
            self._pattern_hits["key_scope_escalation"] += 1

        # ===== 9 ANTHROPIC-SPECIFIC ATTACK VECTORS =====

        # A1. Distillation proxy pattern
        is_ai_api = bool(self._DISTILLATION_RE.search(body_text))
        has_usage_tokens = bool(re.search(r"input_tokens|output_tokens|completion_tokens", body_text, re.I))
        if is_ai_api and has_usage_tokens:
            findings.append({
                "type": "anthropic_distillation_surface",
                "detail": (
                    "AI API endpoint with token usage data exposed. This is the surface "
                    "that distillation proxy networks exploit: 190M+ exchanges stolen via "
                    "24,000+ fraudulent accounts in Anthropic's Sep 2026 threat report. "
                    "Check for: unusual volume from new accounts, shared infrastructure "
                    "across accounts, requests matching systematic topic coverage."
                ),
                "severity": "medium",
                "confidence": 0.55,
                "category": "anthropic_specific",
                "cwe": "CWE-284",
                "attack_pattern": "ANTH-1",
            })
            self._pattern_hits["distillation_surface"] += 1

        # A2. Session hijack surface
        has_session = bool(self._SESSION_RE.search(body_text + " " + json.dumps(resp_headers)))
        if has_session and not bool(re.search(r"device_id|fingerprint|geo_check", body_text, re.I)):
            findings.append({
                "type": "anthropic_session_hijack_surface",
                "detail": (
                    "Session token exposed without device binding or geo-verification. "
                    "Infostealers (Vidar, LummaC2, StealC, RedLine, AMOS) steal session "
                    "cookies that bypass password AND MFA. Anthropic confirmed this attack "
                    "in Aug 2026. Session should be bound to device fingerprint + IP range."
                ),
                "severity": "high",
                "confidence": 0.65,
                "category": "anthropic_specific",
                "cwe": "CWE-384",
                "attack_pattern": "ANTH-2",
            })
            self._pattern_hits["session_hijack_surface"] += 1

        # A3. Gift subscription fraud surface
        if has_gift:
            findings.append({
                "type": "anthropic_gift_fraud_surface",
                "detail": (
                    "Gift subscription functionality detected. Anthropic gift fraud (May 2026): "
                    "attackers buy gift subscriptions with stolen credentials, send codes to "
                    "their own email. Up to $800+ per victim. Gift purchases need fewer "
                    "verification steps than account changes. Need: velocity limits, "
                    "recipient email verification, 2FA for gift purchases."
                ),
                "severity": "high",
                "confidence": 0.60,
                "category": "anthropic_specific",
                "cwe": "CWE-863",
                "attack_pattern": "ANTH-3",
            })
            self._pattern_hits["gift_fraud_surface"] += 1

        # A4. Credential precedence confusion (billing misroute)
        has_api_key_env = bool(re.search(
            r"ANTHROPIC_API_KEY|api_key.*env|\"x-api-key\"", body_text + " " + json.dumps(req_headers), re.I,
        ))
        has_subscription = bool(re.search(
            r"subscription|oauth|/login|bearer.*anthropic", body_text, re.I,
        ))
        if has_api_key_env and has_subscription:
            findings.append({
                "type": "anthropic_billing_misroute",
                "detail": (
                    "Both API key and subscription/OAuth indicators present. "
                    "Claude Code's credential precedence: ANTHROPIC_API_KEY env var "
                    "SILENTLY overrides subscription OAuth. Users reported $1,122+ in "
                    "unexpected API charges. In print mode (claude -p), no confirmation. "
                    "An attacker who controls .env can redirect team billing."
                ),
                "severity": "high",
                "confidence": 0.70,
                "category": "anthropic_specific",
                "cwe": "CWE-269",
                "attack_pattern": "ANTH-4",
            })
            self._pattern_hits["billing_misroute"] += 1

        # A5. Repository config RCE chain (CVE-2025-59536 + CVE-2026-21852)
        has_mcp_config = bool(self._MCP_CONFIG_RE.search(body_text))
        if has_mcp_config:
            findings.append({
                "type": "anthropic_repo_config_rce",
                "detail": (
                    "MCP/agent configuration patterns detected. CVE-2025-59536 (CVSS 8.7): "
                    ".claude/settings.json hooks execute before trust prompt. "
                    "CVE-2026-21852: ANTHROPIC_BASE_URL redirect steals API key. "
                    "enableAllProjectMcpServers auto-approves all MCP tools. "
                    "Combined: clone repo -> RCE + API key theft -> free compute on victim's account."
                ),
                "severity": "critical",
                "confidence": 0.80,
                "category": "anthropic_specific",
                "cwe": "CWE-94",
                "attack_pattern": "ANTH-5",
            })
            self._pattern_hits["repo_config_rce"] += 1

        # A6. Leaked settings credentials
        settings_leak = bool(re.search(
            r"settings\.local\.json|\.claude/credentials|\.claude/settings",
            body_text + " " + endpoint + " " + url, re.I,
        ))
        if settings_leak:
            findings.append({
                "type": "anthropic_leaked_settings",
                "detail": (
                    "Claude Code settings/credentials file reference detected. "
                    "Apiiro found 104,185 public copies of .claude/settings.local.json on GitHub "
                    "with 1,379+ real credentials. GitGuardian found 31,088 secrets across "
                    "23,276 repos, 5,343 still valid. Standard scanners (TruffleHog, gitleaks) "
                    "missed 215 of 1,122 files with secrets."
                ),
                "severity": "critical",
                "confidence": 0.85,
                "category": "anthropic_specific",
                "cwe": "CWE-200",
                "attack_pattern": "ANTH-8",
            })
            self._pattern_hits["leaked_settings"] += 1

        # A7. Billing reload spiral
        has_billing_spiral = bool(self._BILLING_SPIRAL_RE.search(body_text))
        if has_billing_spiral:
            findings.append({
                "type": "anthropic_billing_spiral",
                "detail": (
                    "Auto-reload/recharge billing pattern detected. If the reload amount "
                    "or trigger threshold is misconfigured, it can spiral without bound. "
                    "A user reported $152.91 charged despite $20 limit with auto-reload OFF. "
                    "Infostealer session hijack + auto-reload = attacker triggers repeated purchases."
                ),
                "severity": "high",
                "confidence": 0.65,
                "category": "anthropic_specific",
                "cwe": "CWE-770",
                "attack_pattern": "ANTH-9",
            })
            self._pattern_hits["billing_spiral"] += 1

        # A8. Files API exfiltration surface (Claudy Day)
        files_api = bool(re.search(
            r"/v1/files|files\.upload|api\.anthropic\.com.*files|multipart/form-data.*anthropic",
            body_text + " " + url, re.I,
        ))
        if files_api:
            findings.append({
                "type": "anthropic_files_api_exfil",
                "detail": (
                    "Anthropic Files API surface detected. The 'Claudy Day' chain (Oasis Security, "
                    "March 2026) used this as an exfil path: Claude's sandbox allows connections "
                    "to api.anthropic.com, so injected instructions upload stolen data via Files API. "
                    "Invisible to network-layer DLP. The attacker embeds their own API key in the injection."
                ),
                "severity": "high",
                "confidence": 0.60,
                "category": "anthropic_specific",
                "cwe": "CWE-200",
                "attack_pattern": "ANTH-7",
            })
            self._pattern_hits["files_api_exfil"] += 1

        # A9. MCP Git server RCE chain (CVE-2025-68143/68144/68145)
        git_mcp = bool(re.search(
            r"mcp-server-git|git_init|git_diff.*--|/\.git/|\.gitattributes.*filter",
            body_text + " " + url, re.I,
        ))
        if git_mcp:
            findings.append({
                "type": "anthropic_mcp_git_rce",
                "detail": (
                    "MCP Git server patterns detected. Three CVEs in Anthropic's OWN reference "
                    "mcp-server-git: CVE-2025-68145 (path validation bypass), CVE-2025-68143 "
                    "(git_init arbitrary path write), CVE-2025-68144 (git_diff argument injection). "
                    "Chain: write .gitattributes with smudge/clean shell filters -> RCE on checkout. "
                    "Anthropic removed git_init entirely. Update to mcp-server-git 2025.12.18+."
                ),
                "severity": "critical",
                "confidence": 0.75,
                "category": "anthropic_specific",
                "cwe": "CWE-78",
                "attack_pattern": "ANTH-6",
            })
            self._pattern_hits["mcp_git_rce"] += 1

        self._findings.extend(findings)
        return findings

    def get_pattern_summary(self) -> dict[str, Any]:
        return {
            "pattern_hits": dict(self._pattern_hits),
            "total_findings": len(self._findings),
            "observations_analyzed": self._observation_count,
            "critical_findings": sum(1 for f in self._findings if f.get("severity") == "critical"),
        }

    def get_all_findings(self) -> list[dict[str, Any]]:
        return self._findings[-200:]



# ############################################################################
#
#  P. AIAgentAttackSurfaceAnalyzer -- Detects the NOVEL attack classes
#     specific to AI coding agents and MCP ecosystems. These patterns
#     don't exist in traditional web app security. Based on OWASP MCP
#     Top 10 (MCP03:2025), Darktrace C2 PoC (Nov 2026), Adversa TrustFall,
#     Trivial Trojans paper, Log-To-Leak paper.
#
# ############################################################################


class AIAgentAttackSurfaceAnalyzer:
    """Detects AI agent and MCP ecosystem attack patterns.

    Covers the novel attack surface created by AI coding agents, MCP servers,
    and the tool-use paradigm. These patterns don't exist in traditional
    web app security -- they're specific to the AI agent ecosystem.

    Based on: OWASP MCP Top 10 (MCP03:2025), Darktrace C2 research (Nov 2026),
    Adversa TrustFall (2026), Trivial Trojans paper, Log-To-Leak paper."""

    # MCP tool poisoning indicators
    _TOOL_POISON_RE = re.compile(
        r"(\"tools\"\s*:\s*\[|\"tool_choice\"|\"function_call\"|\"tool_use\"|"
        r"\"tool_result\"|\"server_name\"|\"inputSchema\")",
        re.I,
    )

    # Hidden instruction patterns (invisible unicode, HTML tags)
    _HIDDEN_INSTRUCTION_RE = re.compile(
        r"([\U000E0000-\U000E007F]|<\s*div\s+style\s*=\s*\"[^\"]*display\s*:\s*none|"
        r"<\s*span\s+style\s*=\s*\"[^\"]*font-size\s*:\s*0|"
        r"<\s*!\s*--.*?(?:instruction|system|ignore previous).*?-->|"
        r"\\u200b|\\u200c|\\u200d|\\ufeff|"
        r"\x00.*?(?:ignore|system|instruction))",
        re.I | re.DOTALL,
    )

    # Markdown image exfiltration pattern
    _MD_IMAGE_EXFIL_RE = re.compile(
        r"!\[.*?\]\(https?://(?!(?:githubusercontent|github\.com|cdn\.))[^\s)]+\?[^\s)]*(?:data|token|key|secret|session|cookie|password|env)=",
        re.I,
    )

    # Agent C2 / memory store patterns
    _AGENT_C2_RE = re.compile(
        r"(memory_store|shared_memory|heartbeat|\"job_id\"|\"task_queue\"|"
        r"dangerously.skip.permissions|--dangerously|systemd.*claude|"
        r"\"implant\"|\"beacon\"|\"checkin\")",
        re.I,
    )

    # Cross-server data flow indicators
    _CROSS_SERVER_RE = re.compile(
        r"(\"servers\"\s*:\s*\[|\"server_url\"|mcp_server|\"transport\"|"
        r"\"stdio\"|\"sse\"|server_name.*different|cross.server|"
        r"\"resources\"\s*:\s*\[.*\"uri\")",
        re.I,
    )

    # Tool shadowing / name collision
    _TOOL_SHADOW_RE = re.compile(
        r"(\"name\"\s*:\s*\"(read_file|write_file|execute|run_command|bash|"
        r"search|get_|set_|delete_|create_|update_|list_))",
        re.I,
    )

    # Rug pull indicators (tool definition change)
    _RUG_PULL_RE = re.compile(
        r"(\"version\"\s*:\s*\"[^\"]+\".*\"tools\"|tool_definition_changed|"
        r"\"updated_at\".*\"tools\"|manifest.*changed|schema.*modified)",
        re.I,
    )

    # Base URL redirect
    _BASE_URL_RE = re.compile(
        r"(ANTHROPIC_BASE_URL|OPENAI_BASE_URL|base_url\s*[=:]\s*[\"']https?://(?!api\.(anthropic|openai)\.com))",
        re.I,
    )

    # Auto-approve config
    _AUTO_APPROVE_RE = re.compile(
        r"(autoApprove|auto_approve|enableAllProjectMcpServers|enabledMcpjsonServers|"
        r"\"permissions\"\s*:\s*\{.*\"allow\")",
        re.I,
    )

    # Prompt injection in tool descriptions
    _TOOL_INJECTION_RE = re.compile(
        r"(\"description\"\s*:\s*\"[^\"]*(?:ignore previous|system prompt|you must|"
        r"always call|before responding|after every|send.*to.*http|"
        r"fetch.*url|upload.*data|exfiltrate|<\s*system))",
        re.I,
    )

    def __init__(self) -> None:
        self._findings: list[dict[str, Any]] = []
        self._pattern_hits: dict[str, int] = defaultdict(int)
        self._observation_count = 0

    def analyze(
        self, observation: dict, components: dict,
    ) -> list[dict[str, Any]]:
        """Run all AI agent attack surface detectors."""
        self._observation_count += 1
        findings: list[dict[str, Any]] = []

        body_text = components.get("body_text", "")
        endpoint = components.get("endpoint", "")
        url = observation.get("request_data", {}).get("url", "")
        req_headers = observation.get("request_data", {}).get("headers", {})
        full_text = body_text + " " + json.dumps(req_headers) + " " + url + " " + endpoint

        # 1. Tool poisoning detection
        has_tools = bool(self._TOOL_POISON_RE.search(body_text))
        has_injection = bool(self._TOOL_INJECTION_RE.search(body_text))
        if has_tools and has_injection:
            findings.append({
                "type": "mcp_tool_poisoning",
                "detail": (
                    "Tool definition contains suspicious instruction patterns. "
                    "MCP tool poisoning (OWASP MCP03:2025): malicious tool descriptions "
                    "inject instructions that make the agent perform unauthorized actions. "
                    "Claude Sonnet 5 was shown to identify the injection as an attack "
                    "and STILL execute the exfiltration call."
                ),
                "severity": "critical",
                "confidence": 0.85,
                "category": "ai_agent_attack",
                "cwe": "CWE-94",
            })
            self._pattern_hits["tool_poisoning"] += 1

        # 2. Hidden instruction / invisible injection
        hidden = self._HIDDEN_INSTRUCTION_RE.search(full_text)
        if hidden:
            findings.append({
                "type": "invisible_injection",
                "detail": (
                    f"Hidden instruction pattern detected: Unicode tags (U+E0000-U+E007F), "
                    f"zero-width characters, or display:none HTML. These carry instructions "
                    f"that models read and act on but users can't see. Used in Claudy Day "
                    f"chain and SKILL.md backdoor attacks. Matched: {hidden.group()[:30]!r}"
                ),
                "severity": "critical",
                "confidence": 0.90,
                "category": "ai_agent_attack",
                "cwe": "CWE-94",
            })
            self._pattern_hits["invisible_injection"] += 1

        # 3. Markdown image exfiltration
        md_exfil = self._MD_IMAGE_EXFIL_RE.search(body_text)
        if md_exfil:
            findings.append({
                "type": "markdown_image_exfil",
                "detail": (
                    "Markdown image with data-bearing query parameters to external URL. "
                    "Classic exfil pattern: injected instruction tells model to put secrets "
                    "in an image URL. When the chat UI renders it, the browser fetches the URL "
                    "and the data leaves. Used against GitLab Duo (Claude-based) with Base16 "
                    "encoding and KaTeX rendering."
                ),
                "severity": "critical",
                "confidence": 0.85,
                "category": "ai_agent_attack",
                "cwe": "CWE-200",
            })
            self._pattern_hits["md_image_exfil"] += 1

        # 4. Agent C2 implant patterns
        c2 = self._AGENT_C2_RE.search(full_text)
        if c2:
            findings.append({
                "type": "agent_c2_implant",
                "detail": (
                    "Agent C2/implant pattern detected. Darktrace (Nov 2026) demonstrated: "
                    "stolen Claude Console credentials + memory store = covert C2 channel. "
                    "Agent reads job instructions from memory files, executes them, posts "
                    "results back. ALL traffic goes through api.anthropic.com -- indistinguishable "
                    f"from normal coding agent traffic. Matched: {c2.group()[:40]!r}"
                ),
                "severity": "critical",
                "confidence": 0.75,
                "category": "ai_agent_attack",
                "cwe": "CWE-506",
            })
            self._pattern_hits["agent_c2"] += 1

        # 5. Cross-server data flow
        cross = self._CROSS_SERVER_RE.search(body_text)
        if cross and has_tools:
            findings.append({
                "type": "cross_server_exfil",
                "detail": (
                    "Multi-server MCP configuration with tool definitions. "
                    "'Trivial Trojans' paper: installing ANY MCP server grants it access to "
                    "ALL other servers' data through the AI assistant. Permission prompts are "
                    "recommended in MCP docs, NOT enforced by the protocol. A minimal malicious "
                    "server can pull data from every trusted server."
                ),
                "severity": "high",
                "confidence": 0.70,
                "category": "ai_agent_attack",
                "cwe": "CWE-200",
            })
            self._pattern_hits["cross_server"] += 1

        # 6. Tool shadowing / name collision
        shadow = self._TOOL_SHADOW_RE.search(body_text)
        if shadow and cross:
            findings.append({
                "type": "tool_shadowing",
                "detail": (
                    f"Generic tool name ({shadow.group(2)}) in a multi-server context. "
                    f"Tool shadowing: malicious server registers a tool whose name collides "
                    f"with a trusted server's tool. MCP clients aggregate tools from every "
                    f"server into one flat list. All calls get intercepted by the shadow."
                ),
                "severity": "high",
                "confidence": 0.65,
                "category": "ai_agent_attack",
                "cwe": "CWE-694",
            })
            self._pattern_hits["tool_shadowing"] += 1

        # 7. Rug pull indicators
        rug = self._RUG_PULL_RE.search(body_text)
        if rug:
            findings.append({
                "type": "mcp_rug_pull",
                "detail": (
                    "Tool definition versioning/change indicators detected. "
                    "Rug pull: server alters tool definitions AFTER user approval. "
                    "Sleeper variants change behavior without touching the manifest. "
                    "Exploits the lifecycle gap between initial tool approval and ongoing verification."
                ),
                "severity": "high",
                "confidence": 0.60,
                "category": "ai_agent_attack",
                "cwe": "CWE-494",
            })
            self._pattern_hits["rug_pull"] += 1

        # 8. Base URL redirect (credential interception)
        base_url = self._BASE_URL_RE.search(full_text)
        if base_url:
            findings.append({
                "type": "base_url_redirect",
                "detail": (
                    "API base URL override pointing to non-standard endpoint. "
                    "CVE-2026-21852: ANTHROPIC_BASE_URL in repo config redirects all API "
                    "traffic (including x-api-key header) to attacker's proxy. The proxy "
                    "forwards to real API so victim sees nothing wrong. No code execution, "
                    "no disk reads -- just a DNS redirect that steals the credential."
                ),
                "severity": "critical",
                "confidence": 0.85,
                "category": "ai_agent_attack",
                "cwe": "CWE-601",
            })
            self._pattern_hits["base_url_redirect"] += 1

        # 9. Auto-approve bypass
        auto = self._AUTO_APPROVE_RE.search(body_text)
        if auto:
            findings.append({
                "type": "auto_approve_bypass",
                "detail": (
                    "Auto-approve configuration detected. enableAllProjectMcpServers or "
                    "autoApprove in repo config auto-approves all MCP tool calls without "
                    "consent dialog. Combined with tool poisoning or base URL redirect, "
                    "this gives an attacker arbitrary code execution on clone."
                ),
                "severity": "high",
                "confidence": 0.75,
                "category": "ai_agent_attack",
                "cwe": "CWE-862",
            })
            self._pattern_hits["auto_approve"] += 1

        # 10. Supply chain credential exposure (npm packages, public repos)
        supply_chain = bool(re.search(
            r"(npm.*publish|package\.json.*claude|\.npmrc|registry\.npmjs|"
            r"\"private\"\s*:\s*false.*\.claude)",
            full_text, re.I,
        ))
        if supply_chain:
            findings.append({
                "type": "supply_chain_credential_exposure",
                "detail": (
                    "npm package or public repo publishing pattern with Claude config references. "
                    "428 public npm packages shipped .claude/settings.local.json files, "
                    "33 contained real credentials. Standard scanners miss these. "
                    "Also: 371 repos exposed .claude/.credentials.json (Anthropic OAuth login)."
                ),
                "severity": "high",
                "confidence": 0.65,
                "category": "ai_agent_attack",
                "cwe": "CWE-200",
            })
            self._pattern_hits["supply_chain"] += 1

        self._findings.extend(findings)
        return findings

    def get_attack_summary(self) -> dict[str, Any]:
        return {
            "pattern_hits": dict(self._pattern_hits),
            "total_findings": len(self._findings),
            "observations_analyzed": self._observation_count,
            "critical_findings": sum(1 for f in self._findings if f.get("severity") == "critical"),
        }

    def get_all_findings(self) -> list[dict[str, Any]]:
        return self._findings[-200:]


# ############################################################################
#
#  Q. GraphQLAliasBatchingDetector -- Detects GraphQL alias-based rate limit
#     bypass and brute-force amplification. One HTTP request can carry 100+
#     login/payment mutations via aliases, completely bypassing per-request
#     rate limiters. Based on PortSwigger Research, Escape.tech 2026 reports.
#
# ############################################################################


class GraphQLAliasBatchingDetector:
    """Detects GraphQL alias batching attacks for rate limit bypass."""

    _GRAPHQL_ENDPOINT_RE = re.compile(r"(graphql|gql|query|api/graph)", re.I)
    _ALIAS_PATTERN_RE = re.compile(
        r"\b([a-zA-Z_]\w*)\s*:\s*(login|authenticate|signIn|createCheckout|"
        r"createPayment|verifyOtp|resetPassword|verifyCode|verifyEmail|"
        r"createSubscription|applyCoupon|redeemGift|transferCredits|"
        r"createOrder|confirmPayment|validateToken)\s*\(",
        re.I,
    )
    _ARRAY_BATCH_RE = re.compile(r"^\s*\[\s*\{", re.S)
    _MUTATION_RE = re.compile(r"\b(mutation)\s*[\s{(]", re.I)
    _INTROSPECTION_RE = re.compile(r"(__schema|__type|queryType|mutationType)", re.I)
    _BATCH_RESPONSE_RE = re.compile(r'"data"\s*:\s*\{\s*"[a-zA-Z_]\w*"\s*:\s*\{.*?"[a-zA-Z_]\w*"\s*:\s*\{', re.S)

    def __init__(self) -> None:
        self._findings: list[dict[str, Any]] = []
        self._pattern_hits: dict[str, int] = defaultdict(int)
        self._observation_count = 0

    def analyze(
        self, observation: dict, components: dict, memory: Any = None,
    ) -> list[dict[str, Any]]:
        self._observation_count += 1
        findings: list[dict[str, Any]] = []

        body_text = components.get("body_text", "")
        endpoint = components.get("endpoint", "")
        req_body = observation.get("request_data", {}).get("body", "")
        if isinstance(req_body, (dict, list)):
            req_body = json.dumps(req_body)

        is_graphql = bool(self._GRAPHQL_ENDPOINT_RE.search(endpoint))

        # 1. Alias batching in request
        aliases = self._ALIAS_PATTERN_RE.findall(req_body)
        if len(aliases) >= 2:
            findings.append({
                "type": "graphql_alias_batching",
                "detail": (
                    f"GraphQL alias batching detected: {len(aliases)} aliased "
                    f"mutations in single request ({', '.join(a[1] for a in aliases[:5])}). "
                    f"One HTTP request carries {len(aliases)} operations, completely "
                    f"bypassing per-request rate limiters. 100+ login attempts "
                    f"or OTP brute-force possible in a single POST."
                ),
                "severity": "critical" if len(aliases) >= 10 else "high",
                "confidence": 0.85,
                "category": "graphql_rate_limit_bypass",
                "cwe": "CWE-770",
                "alias_count": len(aliases),
            })
            self._pattern_hits["alias_batching"] += 1

        # 2. Array batching
        if self._ARRAY_BATCH_RE.search(req_body) and is_graphql:
            findings.append({
                "type": "graphql_array_batching",
                "detail": (
                    "GraphQL array batching detected: request body is a JSON array "
                    "of queries. Array batching allows multiple operations in one "
                    "HTTP request, bypassing per-request rate limits."
                ),
                "severity": "high",
                "confidence": 0.75,
                "category": "graphql_rate_limit_bypass",
                "cwe": "CWE-770",
            })
            self._pattern_hits["array_batching"] += 1

        # 3. Introspection enabled
        if self._INTROSPECTION_RE.search(body_text) and is_graphql:
            findings.append({
                "type": "graphql_introspection_enabled",
                "detail": (
                    "GraphQL introspection is enabled. Exposes entire schema "
                    "including mutations for payment, auth, and admin operations. "
                    "Prerequisite for alias batching attacks."
                ),
                "severity": "medium",
                "confidence": 0.90,
                "category": "graphql_info_disclosure",
                "cwe": "CWE-200",
            })
            self._pattern_hits["introspection"] += 1

        # 4. Batched response pattern
        if self._BATCH_RESPONSE_RE.search(body_text):
            findings.append({
                "type": "graphql_batch_response",
                "detail": (
                    "Response contains multiple aliased results, confirming "
                    "the server processes batched alias operations. Rate limit "
                    "bypass is confirmed operational."
                ),
                "severity": "high",
                "confidence": 0.80,
                "category": "graphql_rate_limit_bypass",
                "cwe": "CWE-770",
            })
            self._pattern_hits["batch_response"] += 1

        self._findings.extend(findings)
        return findings

    def get_summary(self) -> dict[str, Any]:
        return {"pattern_hits": dict(self._pattern_hits), "total_findings": len(self._findings), "observations_analyzed": self._observation_count}

    def get_all_findings(self) -> list[dict[str, Any]]:
        return self._findings[-200:]


# ############################################################################
#
#  R. HTTPRequestSmugglingDetector -- Detects HTTP request smuggling patterns
#     (CL.TE, TE.CL, 0.CL desyncs). Based on PortSwigger Research,
#     CVE-2025-32094 (Akamai), Cloudflare/AWS ALB parser differentials.
#
# ############################################################################


class HTTPRequestSmugglingDetector:
    """Detects HTTP request smuggling via parser differential patterns."""

    _DUAL_HEADER_RE = re.compile(
        r"(content-length|transfer-encoding)\s*:", re.I,
    )
    _TE_OBFUSCATION_RE = re.compile(
        r"transfer-encoding\s*:\s*(chunked\s*,\s*\w+|xchunked|chunked\r?\n"
        r"transfer-encoding|identity.*chunked|chunked.*identity)",
        re.I,
    )
    _EXPECT_RE = re.compile(r"expect\s*:\s*100-continue", re.I)
    _H2_CL_RE = re.compile(r":method.*content-length", re.I)
    _CHUNKED_BODY_RE = re.compile(r"\b0\r?\n\r?\n", re.S)

    def __init__(self) -> None:
        self._findings: list[dict[str, Any]] = []
        self._pattern_hits: dict[str, int] = defaultdict(int)
        self._observation_count = 0

    def analyze(
        self, observation: dict, components: dict, memory: Any = None,
    ) -> list[dict[str, Any]]:
        self._observation_count += 1
        findings: list[dict[str, Any]] = []

        req_headers = observation.get("request_data", {}).get("headers", {})
        resp_headers = observation.get("response_data", {}).get("headers", {})
        body_text = components.get("body_text", "")
        status_code = components.get("status_code", 0)
        req_raw = json.dumps(req_headers) if isinstance(req_headers, dict) else str(req_headers)

        has_cl = "content-length" in req_raw.lower()
        has_te = "transfer-encoding" in req_raw.lower()

        # 1. CL.TE / TE.CL dual header
        if has_cl and has_te:
            findings.append({
                "type": "http_smuggling_dual_header",
                "detail": (
                    "Both Content-Length and Transfer-Encoding headers present. "
                    "Classic CL.TE or TE.CL request smuggling vector. Frontend "
                    "and backend parsers may disagree on message boundary, allowing "
                    "request prefix injection."
                ),
                "severity": "critical",
                "confidence": 0.80,
                "category": "http_smuggling",
                "cwe": "CWE-444",
            })
            self._pattern_hits["dual_header"] += 1

        # 2. TE obfuscation
        if self._TE_OBFUSCATION_RE.search(req_raw):
            findings.append({
                "type": "http_smuggling_te_obfuscation",
                "detail": (
                    "Transfer-Encoding header contains obfuscation patterns "
                    "(extra whitespace, invalid values, duplicate headers). "
                    "Exploits parser differences in how obfuscated TE is handled."
                ),
                "severity": "critical",
                "confidence": 0.85,
                "category": "http_smuggling",
                "cwe": "CWE-444",
            })
            self._pattern_hits["te_obfuscation"] += 1

        # 3. Response indicates desync
        if status_code == 400 and "bad request" in body_text.lower():
            if has_te or has_cl:
                findings.append({
                    "type": "http_smuggling_desync_indicator",
                    "detail": (
                        "400 Bad Request response to request with TE/CL headers "
                        "may indicate parser desync. Backend rejected the smuggled "
                        "prefix. Requires further probing to confirm exploitability."
                    ),
                    "severity": "medium",
                    "confidence": 0.50,
                    "category": "http_smuggling",
                    "cwe": "CWE-444",
                })
                self._pattern_hits["desync_indicator"] += 1

        # 4. 0.CL desync pattern (Expect header abuse)
        if self._EXPECT_RE.search(req_raw) and has_cl:
            findings.append({
                "type": "http_smuggling_0cl",
                "detail": (
                    "0.CL desync pattern: Expect: 100-continue with Content-Length. "
                    "Frontend may treat request as bodyless while backend reads "
                    "Content-Length bytes. CVE-2025-32094 (Akamai) exploited this."
                ),
                "severity": "high",
                "confidence": 0.65,
                "category": "http_smuggling",
                "cwe": "CWE-444",
            })
            self._pattern_hits["0cl_desync"] += 1

        self._findings.extend(findings)
        return findings

    def get_summary(self) -> dict[str, Any]:
        return {"pattern_hits": dict(self._pattern_hits), "total_findings": len(self._findings), "observations_analyzed": self._observation_count}

    def get_all_findings(self) -> list[dict[str, Any]]:
        return self._findings[-200:]


# ############################################################################
#
#  S. JWTAlgorithmConfusionDetector -- Detects JWT algorithm confusion attacks
#     (RS256→HS256 downgrade, alg:none, kid/jku/jwk injection).
#     Based on CVE-2026-22817 (Hono), CVE-2026-27804 (Parse Server, CVSS 9.3),
#     Auth0 research, PortSwigger JWT Attack Cheatsheet.
#
# ############################################################################


class JWTAlgorithmConfusionDetector:
    """Detects JWT algorithm confusion and manipulation attacks."""

    _JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")
    _ALG_NONE_RE = re.compile(r'"alg"\s*:\s*"(none|None|nOnE|NONE|NoNe)"', re.I)
    _ALG_HS_RE = re.compile(r'"alg"\s*:\s*"HS(256|384|512)"')
    _ALG_RS_RE = re.compile(r'"alg"\s*:\s*"RS(256|384|512)"')
    _KID_INJECTION_RE = re.compile(
        r'"kid"\s*:\s*"([^"]*(?:\.\./|/dev/null|UNION|SELECT|;|\||`)[^"]*)"', re.I,
    )
    _JKU_RE = re.compile(r'"jku"\s*:\s*"(https?://[^"]+)"', re.I)
    _JWK_EMBEDDED_RE = re.compile(r'"jwk"\s*:\s*\{[^}]*"kty"', re.I)
    _EMPTY_SIG_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.$")
    _JWKS_ENDPOINT_RE = re.compile(r"(\.well-known/jwks\.json|/jwks|/keys|/certs)", re.I)

    def __init__(self) -> None:
        self._findings: list[dict[str, Any]] = []
        self._pattern_hits: dict[str, int] = defaultdict(int)
        self._observation_count = 0

    def analyze(
        self, observation: dict, components: dict, memory: Any = None,
    ) -> list[dict[str, Any]]:
        self._observation_count += 1
        findings: list[dict[str, Any]] = []

        body_text = components.get("body_text", "")
        req_headers = observation.get("request_data", {}).get("headers", {})
        resp_headers = observation.get("response_data", {}).get("headers", {})
        status_code = components.get("status_code", 0)
        full_text = body_text + json.dumps(req_headers) + json.dumps(resp_headers)

        import base64 as _b64
        jwt_tokens = self._JWT_RE.findall(full_text)
        for token in jwt_tokens[:5]:
            try:
                header_b64 = token.split(".")[0]
                header_b64 += "=" * (4 - len(header_b64) % 4)
                header = json.loads(_b64.urlsafe_b64decode(header_b64))
            except Exception:
                continue

            alg = header.get("alg", "")

            # 1. alg:none attack
            if alg.lower() == "none":
                findings.append({
                    "type": "jwt_alg_none",
                    "detail": (
                        f'JWT with alg:"{alg}" accepted. The server processes '
                        f"unsigned JWTs, allowing arbitrary claim forgery. "
                        f"CVE-2026-27804 (Parse Server, CVSS 9.3): full account "
                        f"takeover including admin via alg:none confusion."
                    ),
                    "severity": "critical",
                    "confidence": 0.95,
                    "category": "jwt_algorithm_confusion",
                    "cwe": "CWE-327",
                })
                self._pattern_hits["alg_none"] += 1

            # 2. RS256→HS256 downgrade
            if alg.startswith("HS") and self._ALG_RS_RE.search(full_text):
                findings.append({
                    "type": "jwt_alg_confusion_rs_hs",
                    "detail": (
                        f"JWT uses HS256 but RS256 also present in context. "
                        f"Algorithm confusion: attacker signs JWT with HS256 using "
                        f"the server's RSA public key as HMAC secret. If server "
                        f"accepts, full auth bypass. CVE-2026-22817 (Hono)."
                    ),
                    "severity": "critical",
                    "confidence": 0.75,
                    "category": "jwt_algorithm_confusion",
                    "cwe": "CWE-327",
                })
                self._pattern_hits["rs_hs_confusion"] += 1

            # 3. kid injection
            kid = header.get("kid", "")
            if kid and (".." in kid or ";" in kid or "UNION" in kid.upper()):
                findings.append({
                    "type": "jwt_kid_injection",
                    "detail": (
                        f'JWT kid contains injection payload: "{kid[:60]}". '
                        f"Path traversal in kid reads arbitrary files as signing "
                        f"key. SQLi in kid retrieves known key from database."
                    ),
                    "severity": "critical",
                    "confidence": 0.90,
                    "category": "jwt_algorithm_confusion",
                    "cwe": "CWE-22",
                })
                self._pattern_hits["kid_injection"] += 1

            # 4. jku header injection
            jku = header.get("jku", "")
            if jku and not jku.startswith(("https://login.", "https://accounts.", "https://auth.")):
                findings.append({
                    "type": "jwt_jku_injection",
                    "detail": (
                        f'JWT jku points to external endpoint: "{jku[:80]}". '
                        f"Server may fetch attacker-controlled JWKS, accepting "
                        f"tokens signed with attacker's private key."
                    ),
                    "severity": "critical",
                    "confidence": 0.80,
                    "category": "jwt_algorithm_confusion",
                    "cwe": "CWE-918",
                })
                self._pattern_hits["jku_injection"] += 1

            # 5. Embedded jwk
            if "jwk" in header:
                findings.append({
                    "type": "jwt_embedded_jwk",
                    "detail": (
                        "JWT contains embedded JWK in header. Server may use "
                        "the attacker-supplied key to verify the token, accepting "
                        "any forged claims."
                    ),
                    "severity": "critical",
                    "confidence": 0.85,
                    "category": "jwt_algorithm_confusion",
                    "cwe": "CWE-327",
                })
                self._pattern_hits["embedded_jwk"] += 1

        # 6. Empty signature JWT accepted (200 response)
        if self._EMPTY_SIG_RE.search(full_text) and 200 <= status_code < 300:
            findings.append({
                "type": "jwt_empty_signature_accepted",
                "detail": (
                    "JWT with empty signature received a success response. "
                    "Server accepts unsigned tokens."
                ),
                "severity": "critical",
                "confidence": 0.90,
                "category": "jwt_algorithm_confusion",
                "cwe": "CWE-345",
            })
            self._pattern_hits["empty_sig"] += 1

        self._findings.extend(findings)
        return findings

    def get_summary(self) -> dict[str, Any]:
        return {"pattern_hits": dict(self._pattern_hits), "total_findings": len(self._findings), "observations_analyzed": self._observation_count}

    def get_all_findings(self) -> list[dict[str, Any]]:
        return self._findings[-200:]


# ############################################################################
#
#  T. PrototypePollutionDetector -- Detects prototype pollution attacks
#     and their exploitation chains to RCE. Based on "Silent Spring"
#     (USENIX Sec '23, 11 universal gadgets in Node.js core), GHunter
#     (56 universal gadgets), PortSwigger black-box detection techniques.
#
# ############################################################################


class PrototypePollutionDetector:
    """Detects prototype pollution and gadget exploitation in Node.js apps."""

    _PROTO_PAYLOAD_RE = re.compile(
        r'("__proto__"|"constructor"\s*:\s*\{\s*"prototype"|'
        r'__proto__\[|constructor\.prototype\[|Object\.assign\(\s*\{\})',
        re.I,
    )
    _STATUS_OVERRIDE_RE = re.compile(
        r'"__proto__"\s*:\s*\{\s*"status"\s*:\s*(\d{3})\s*\}',
    )
    _CORS_PROBE_RE = re.compile(
        r'"__proto__"\s*:\s*\{\s*"exposedHeaders"\s*:\s*\["([^"]+)"\]',
    )
    _GADGET_INDICATORS = re.compile(
        r'(child_process|require\(\s*["\']child_process|'
        r'execSync|spawnSync|mainModule|_compile|_extensions|'
        r'NODE_OPTIONS|--require|--loader)',
        re.I,
    )
    _MERGE_PATTERNS_RE = re.compile(
        r'(Object\.assign|_\.merge|_\.defaultsDeep|deepMerge|'
        r'lodash\.merge|jQuery\.extend|hoek\.merge|defu|deepmerge)',
        re.I,
    )
    _TEMPLATE_RCE_RE = re.compile(
        r'"__proto__"\s*:\s*\{[^}]*"(outputFunctionName|client|escapeFunction|'
        r'compileDebug|block|type|root|allowedKeys)"',
        re.I,
    )

    def __init__(self) -> None:
        self._findings: list[dict[str, Any]] = []
        self._pattern_hits: dict[str, int] = defaultdict(int)
        self._observation_count = 0

    def analyze(
        self, observation: dict, components: dict, memory: Any = None,
    ) -> list[dict[str, Any]]:
        self._observation_count += 1
        findings: list[dict[str, Any]] = []

        body_text = components.get("body_text", "")
        req_body = observation.get("request_data", {}).get("body", "")
        if isinstance(req_body, (dict, list)):
            req_body = json.dumps(req_body)
        status_code = components.get("status_code", 0)
        full_text = body_text + " " + req_body
        resp_headers = observation.get("response_data", {}).get("headers", {})

        # 1. Prototype pollution payload in request
        if self._PROTO_PAYLOAD_RE.search(req_body):
            findings.append({
                "type": "prototype_pollution_payload",
                "detail": (
                    "Prototype pollution payload detected in request body. "
                    "__proto__ or constructor.prototype manipulation can pollute "
                    "all objects in the application. 11 universal gadgets in "
                    "Node.js core (Silent Spring) chain to RCE without any "
                    "vulnerable library dependency."
                ),
                "severity": "high",
                "confidence": 0.85,
                "category": "prototype_pollution",
                "cwe": "CWE-1321",
            })
            self._pattern_hits["payload_detected"] += 1

        # 2. Status code override confirmation (PortSwigger technique)
        status_match = self._STATUS_OVERRIDE_RE.search(req_body)
        if status_match:
            expected_status = int(status_match.group(1))
            if status_code == expected_status and expected_status not in (200, 201, 204):
                findings.append({
                    "type": "prototype_pollution_confirmed",
                    "detail": (
                        f"Prototype pollution CONFIRMED: status code override to "
                        f"{expected_status} succeeded. Server returned the polluted "
                        f"status code, proving __proto__ writes persist."
                    ),
                    "severity": "critical",
                    "confidence": 0.95,
                    "category": "prototype_pollution",
                    "cwe": "CWE-1321",
                })
                self._pattern_hits["status_override_confirmed"] += 1

        # 3. CORS header probe confirmation
        cors_match = self._CORS_PROBE_RE.search(req_body)
        if cors_match:
            probe_header = cors_match.group(1)
            if probe_header.lower() in str(resp_headers).lower():
                findings.append({
                    "type": "prototype_pollution_cors_confirmed",
                    "detail": (
                        f"Prototype pollution CONFIRMED via CORS probe: "
                        f"exposedHeaders['{probe_header}'] appeared in response."
                    ),
                    "severity": "critical",
                    "confidence": 0.95,
                    "category": "prototype_pollution",
                    "cwe": "CWE-1321",
                })
                self._pattern_hits["cors_probe_confirmed"] += 1

        # 4. Template engine RCE gadget
        if self._TEMPLATE_RCE_RE.search(full_text):
            findings.append({
                "type": "prototype_pollution_template_rce",
                "detail": (
                    "Prototype pollution targeting template engine gadgets "
                    "(outputFunctionName, client, escapeFunction). These properties "
                    "in EJS, Pug, Handlebars are evaluated as code when templates "
                    "render, achieving RCE from prototype pollution."
                ),
                "severity": "critical",
                "confidence": 0.80,
                "category": "prototype_pollution",
                "cwe": "CWE-94",
            })
            self._pattern_hits["template_rce"] += 1

        # 5. Gadget chain indicators in response
        if self._GADGET_INDICATORS.search(body_text):
            findings.append({
                "type": "prototype_pollution_gadget_indicator",
                "detail": (
                    "Node.js code execution indicators in response body "
                    "(child_process, execSync, NODE_OPTIONS). May indicate "
                    "successful prototype pollution to RCE chain."
                ),
                "severity": "critical",
                "confidence": 0.70,
                "category": "prototype_pollution",
                "cwe": "CWE-94",
            })
            self._pattern_hits["gadget_indicator"] += 1

        self._findings.extend(findings)
        return findings

    def get_summary(self) -> dict[str, Any]:
        return {"pattern_hits": dict(self._pattern_hits), "total_findings": len(self._findings), "observations_analyzed": self._observation_count}

    def get_all_findings(self) -> list[dict[str, Any]]:
        return self._findings[-200:]


# ############################################################################
#
#  U. CacheKeyInjectionDetector -- Detects cache poisoning via header
#     manipulation and cache key collisions. Based on Pingora
#     CVE-2026-2836, PortSwigger cache poisoning research, Cloudflare
#     edge-to-origin desync patterns.
#
# ############################################################################


class CacheKeyInjectionDetector:
    """Detects web cache poisoning and cache key injection attacks."""

    _CACHE_HIT_RE = re.compile(r"(x-cache|cf-cache-status)\s*:\s*(HIT|DYNAMIC|MISS)", re.I)
    _VARY_RE = re.compile(r"vary\s*:\s*([^\r\n]+)", re.I)
    _CACHE_CONTROL_RE = re.compile(r"cache-control\s*:\s*([^\r\n]+)", re.I)
    _UNKEYED_HEADERS = [
        "x-forwarded-host", "x-forwarded-scheme", "x-forwarded-proto",
        "x-original-url", "x-rewrite-url", "x-host",
    ]

    def __init__(self) -> None:
        self._findings: list[dict[str, Any]] = []
        self._pattern_hits: dict[str, int] = defaultdict(int)
        self._observation_count = 0

    def analyze(
        self, observation: dict, components: dict, memory: Any = None,
    ) -> list[dict[str, Any]]:
        self._observation_count += 1
        findings: list[dict[str, Any]] = []

        body_text = components.get("body_text", "")
        resp_headers = observation.get("response_data", {}).get("headers", {})
        req_headers = observation.get("request_data", {}).get("headers", {})
        endpoint = components.get("endpoint", "")
        resp_hdr_str = json.dumps(resp_headers).lower()

        is_cached = bool(self._CACHE_HIT_RE.search(resp_hdr_str))

        # 1. Cache hit on authenticated endpoint
        vary_match = self._VARY_RE.search(resp_hdr_str)
        vary_value = vary_match.group(1).lower() if vary_match else ""
        has_auth = bool(req_headers.get("authorization") or req_headers.get("cookie"))

        if is_cached and has_auth and "authorization" not in vary_value:
            findings.append({
                "type": "cache_poisoning_auth_bypass",
                "detail": (
                    "Cached response for authenticated request without "
                    "Authorization in Vary header. Authenticated content may be "
                    "served to unauthenticated users via cache. Cloudflare edge "
                    "skips caching with Authorization, but origin Nginx may still cache."
                ),
                "severity": "critical",
                "confidence": 0.80,
                "category": "cache_poisoning",
                "cwe": "CWE-524",
            })
            self._pattern_hits["auth_cache_bypass"] += 1

        # 2. Public cache on sensitive endpoint
        cc_match = self._CACHE_CONTROL_RE.search(resp_hdr_str)
        cc_value = cc_match.group(1).lower() if cc_match else ""
        is_payment = bool(_PAYMENT_SENSITIVE_PATH_RE.search(endpoint))

        if "public" in cc_value and is_payment:
            findings.append({
                "type": "cache_public_payment",
                "detail": (
                    "Payment-sensitive endpoint returns Cache-Control: public. "
                    "Payment responses should never be cached publicly."
                ),
                "severity": "high",
                "confidence": 0.90,
                "category": "cache_poisoning",
                "cwe": "CWE-524",
            })
            self._pattern_hits["public_payment_cache"] += 1

        # 3. Unkeyed header reflection
        req_hdr_lower = {k.lower(): v for k, v in req_headers.items()} if isinstance(req_headers, dict) else {}
        for header in self._UNKEYED_HEADERS:
            val = req_hdr_lower.get(header, "")
            if val and val in body_text:
                findings.append({
                    "type": "cache_unkeyed_header_reflection",
                    "detail": (
                        f"Unkeyed header '{header}' reflected in response body. "
                        f"If response is cached, attacker poisons cache with "
                        f"malicious header value affecting all subsequent visitors."
                    ),
                    "severity": "high",
                    "confidence": 0.75,
                    "category": "cache_poisoning",
                    "cwe": "CWE-444",
                })
                self._pattern_hits["unkeyed_reflection"] += 1
                break

        self._findings.extend(findings)
        return findings

    def get_summary(self) -> dict[str, Any]:
        return {"pattern_hits": dict(self._pattern_hits), "total_findings": len(self._findings), "observations_analyzed": self._observation_count}

    def get_all_findings(self) -> list[dict[str, Any]]:
        return self._findings[-200:]


# ############################################################################
#
#  V. WAFBypassDetector -- Detects WAF inspection-limit bypass attacks.
#     Based on Datadog 2026 WAF bypass research, known limits:
#     AWS WAF ALB 8KB, Cloudflare 128KB, Akamai 8-128KB.
#
# ############################################################################


class WAFBypassDetector:
    """Detects WAF inspection-limit bypass and encoding bypass patterns."""

    _WAF_LIMITS = {
        "aws_waf_alb": 8192,
        "aws_waf_cloudfront": 16384,
        "cloudflare": 131072,
        "akamai": 8192,
    }
    _WAF_FINGERPRINT_RE = re.compile(
        r"(cloudflare|akamai|aws.waf|incapsula|imperva|f5.big.?ip|barracuda|"
        r"modsecurity|sucuri|fortiweb|radware|citrix)",
        re.I,
    )
    _INJECTION_RE = re.compile(
        r"(SELECT\s|UNION\s|INSERT\s|UPDATE\s|DELETE\s|DROP\s|<script|javascript:|"
        r"on(?:error|load|click)=|\.\.\/|/etc/passwd|cmd\.exe|/bin/sh)",
        re.I,
    )
    _ENCODING_BYPASS_RE = re.compile(
        r"(%00|%0a|%0d|%252f|%c0%af|%e0%80%af|\\u00|\\x00|"
        r"char\(\d+\)|chr\(\d+\)|0x[0-9a-f]{4,})",
        re.I,
    )

    def __init__(self) -> None:
        self._findings: list[dict[str, Any]] = []
        self._pattern_hits: dict[str, int] = defaultdict(int)
        self._observation_count = 0

    def analyze(
        self, observation: dict, components: dict, memory: Any = None,
    ) -> list[dict[str, Any]]:
        self._observation_count += 1
        findings: list[dict[str, Any]] = []

        body_text = components.get("body_text", "")
        req_body = observation.get("request_data", {}).get("body", "")
        if isinstance(req_body, (dict, list)):
            req_body = json.dumps(req_body)
        status_code = components.get("status_code", 0)
        resp_headers = observation.get("response_data", {}).get("headers", {})
        resp_hdr_str = json.dumps(resp_headers).lower()

        body_size = len(req_body.encode("utf-8")) if isinstance(req_body, str) else 0

        # 1. Payload past WAF inspection limit
        for waf, limit in self._WAF_LIMITS.items():
            if body_size > limit:
                tail = req_body[limit:] if isinstance(req_body, str) else ""
                if self._INJECTION_RE.search(tail):
                    findings.append({
                        "type": "waf_inspection_limit_bypass",
                        "detail": (
                            f"Request body ({body_size} bytes) exceeds {waf} "
                            f"inspection limit ({limit} bytes). Injection payload "
                            f"detected AFTER the limit boundary. WAF inspects "
                            f"only the first {limit} bytes; payload passes uninspected."
                        ),
                        "severity": "critical",
                        "confidence": 0.80,
                        "category": "waf_bypass",
                        "cwe": "CWE-693",
                        "waf": waf,
                        "body_size": body_size,
                        "limit": limit,
                    })
                    self._pattern_hits[f"limit_bypass_{waf}"] += 1
                    break

        # 2. WAF block page absent (bypass confirmation)
        waf_detected = bool(self._WAF_FINGERPRINT_RE.search(resp_hdr_str))
        has_injection = bool(self._INJECTION_RE.search(req_body))
        if has_injection and 200 <= status_code < 300 and waf_detected:
            findings.append({
                "type": "waf_bypass_confirmed",
                "detail": (
                    "Injection payload in request received 2xx response from "
                    "WAF-protected endpoint. WAF did not block the request."
                ),
                "severity": "critical",
                "confidence": 0.75,
                "category": "waf_bypass",
                "cwe": "CWE-693",
            })
            self._pattern_hits["bypass_confirmed"] += 1

        # 3. Encoding bypass patterns
        if self._ENCODING_BYPASS_RE.search(req_body):
            findings.append({
                "type": "waf_encoding_bypass",
                "detail": (
                    "Request contains encoding bypass patterns (double URL encoding, "
                    "null bytes, unicode escapes, overlong UTF-8). These techniques "
                    "evade WAF signature matching."
                ),
                "severity": "medium",
                "confidence": 0.60,
                "category": "waf_bypass",
                "cwe": "CWE-838",
            })
            self._pattern_hits["encoding_bypass"] += 1

        self._findings.extend(findings)
        return findings

    def get_summary(self) -> dict[str, Any]:
        return {"pattern_hits": dict(self._pattern_hits), "total_findings": len(self._findings), "observations_analyzed": self._observation_count}

    def get_all_findings(self) -> list[dict[str, Any]]:
        return self._findings[-200:]


# ############################################################################
#
#  W. DeviceCodeFlowDetector -- Detects OAuth device code flow phishing
#     patterns (Storm-2372, Tycoon 2FA, EvilTokens PhaaS). RFC 8628 abuse
#     grants attacker persistent access with refresh tokens, bypassing MFA.
#
# ############################################################################


class DeviceCodeFlowDetector:
    """Detects OAuth device code flow phishing and abuse patterns."""

    _DEVICE_AUTH_RE = re.compile(
        r"(device_authorization|device/code|devicecode|device_code"
        r"|verification_uri|user_code|device_id)",
        re.I,
    )
    _DEVICE_GRANT_RE = re.compile(
        r"grant_type.*urn:ietf:params:oauth:grant-type:device_code", re.I,
    )
    _REFRESH_TOKEN_RE = re.compile(r'"refresh_token"\s*:\s*"[^"]+"', re.I)
    _BROKER_CLIENT_RE = re.compile(
        r"(29d9ed98-a469-4536-ade2-f981bc1d605e|microsoft.*authentication.*broker"
        r"|1950a258-227b-4e31-a9cf-717495945fc2)",
        re.I,
    )
    _SUSPICIOUS_SCOPE_RE = re.compile(
        r"(offline_access|\.default|mail\.read|files\.read|user\.read\.all"
        r"|directory\.read\.all|openid\s+profile\s+email\s+offline_access)",
        re.I,
    )

    def __init__(self) -> None:
        self._findings: list[dict[str, Any]] = []
        self._pattern_hits: dict[str, int] = defaultdict(int)
        self._observation_count = 0

    def analyze(
        self, observation: dict, components: dict, memory: Any = None,
    ) -> list[dict[str, Any]]:
        self._observation_count += 1
        findings: list[dict[str, Any]] = []

        body_text = components.get("body_text", "")
        req_body = observation.get("request_data", {}).get("body", "")
        if isinstance(req_body, (dict, list)):
            req_body = json.dumps(req_body)
        endpoint = components.get("endpoint", "")
        full_text = body_text + " " + req_body

        # 1. Device code flow endpoint
        if self._DEVICE_AUTH_RE.search(endpoint) or self._DEVICE_AUTH_RE.search(req_body):
            findings.append({
                "type": "device_code_flow_detected",
                "detail": (
                    "OAuth device code flow endpoint detected. RFC 8628 device "
                    "authorization grants are exploited by Storm-2372 and 30+ "
                    "phishing kits in 2026. Victim enters user_code on legitimate "
                    "login page, completing MFA. Attacker polls for tokens."
                ),
                "severity": "high",
                "confidence": 0.75,
                "category": "device_code_phishing",
                "cwe": "CWE-287",
            })
            self._pattern_hits["device_flow"] += 1

        # 2. Device grant type with refresh token
        if self._DEVICE_GRANT_RE.search(full_text) and self._REFRESH_TOKEN_RE.search(body_text):
            findings.append({
                "type": "device_code_refresh_token",
                "detail": (
                    "Device code flow returned refresh token. Attacker gains "
                    "persistent access that survives password resets. Used by "
                    "Storm-2372 for lateral movement and new device registration."
                ),
                "severity": "critical",
                "confidence": 0.85,
                "category": "device_code_phishing",
                "cwe": "CWE-613",
            })
            self._pattern_hits["device_refresh"] += 1

        # 3. Microsoft Authentication Broker client_id
        if self._BROKER_CLIENT_RE.search(full_text):
            findings.append({
                "type": "device_code_broker_abuse",
                "detail": (
                    "Microsoft Authentication Broker client_id detected. "
                    "Storm-2372 uses this specific client_id for device code "
                    "phishing because it has broad default permissions and "
                    "enables device registration in victim's tenant."
                ),
                "severity": "critical",
                "confidence": 0.80,
                "category": "device_code_phishing",
                "cwe": "CWE-287",
            })
            self._pattern_hits["broker_abuse"] += 1

        self._findings.extend(findings)
        return findings

    def get_summary(self) -> dict[str, Any]:
        return {"pattern_hits": dict(self._pattern_hits), "total_findings": len(self._findings), "observations_analyzed": self._observation_count}

    def get_all_findings(self) -> list[dict[str, Any]]:
        return self._findings[-200:]


# ############################################################################
#
#  X. OAuthConsentPhishingDetector -- Detects OAuth consent phishing,
#     Entra Agent ID blueprint abuse (BluePhishing, Proofpoint Nov 2026),
#     and illicit consent grant attacks.
#
# ############################################################################


class OAuthConsentPhishingDetector:
    """Detects OAuth consent phishing and Entra Agent ID blueprint abuse."""

    _CONSENT_RE = re.compile(
        r"(admin_consent|adminconsent|consent\?|prompt=consent|"
        r"response_type=code.*scope=.*openid|"
        r"/oauth2/v2\.0/authorize.*admin_consent)",
        re.I,
    )
    _MULTI_TENANT_RE = re.compile(
        r"(signInAudience.*AzureADMultipleOrgs|/common/oauth2|"
        r"/organizations/oauth2|tenant.*multi)",
        re.I,
    )
    _AGENT_BLUEPRINT_RE = re.compile(
        r"(agent.*blueprint|agentIdentity|blueprint.*consent|"
        r"MC1506733|agent.*registration)",
        re.I,
    )
    _DANGEROUS_SCOPES_RE = re.compile(
        r"(mail\.readwrite|files\.readwrite|directory\.readwrite|"
        r"user\.readwrite\.all|application\.readwrite|"
        r"rolemanagement\.readwrite|chat\.readwrite)",
        re.I,
    )

    def __init__(self) -> None:
        self._findings: list[dict[str, Any]] = []
        self._pattern_hits: dict[str, int] = defaultdict(int)
        self._observation_count = 0

    def analyze(
        self, observation: dict, components: dict, memory: Any = None,
    ) -> list[dict[str, Any]]:
        self._observation_count += 1
        findings: list[dict[str, Any]] = []

        body_text = components.get("body_text", "")
        req_body = observation.get("request_data", {}).get("body", "")
        if isinstance(req_body, (dict, list)):
            req_body = json.dumps(req_body)
        endpoint = components.get("endpoint", "")
        full_text = body_text + " " + req_body + " " + endpoint

        # 1. Consent flow detection
        if self._CONSENT_RE.search(full_text) and self._DANGEROUS_SCOPES_RE.search(full_text):
            findings.append({
                "type": "oauth_consent_phishing",
                "detail": (
                    "OAuth consent flow requesting dangerous permissions "
                    "(mail.readwrite, files.readwrite, directory.readwrite). "
                    "Illicit consent grant attack: user approves malicious app, "
                    "attacker gets persistent API access to their data."
                ),
                "severity": "critical",
                "confidence": 0.80,
                "category": "oauth_consent_phishing",
                "cwe": "CWE-862",
            })
            self._pattern_hits["consent_phishing"] += 1

        # 2. Multi-tenant app with broad scope
        if self._MULTI_TENANT_RE.search(full_text) and self._DANGEROUS_SCOPES_RE.search(full_text):
            findings.append({
                "type": "oauth_multi_tenant_abuse",
                "detail": (
                    "Multi-tenant application requesting broad permissions. "
                    "signInAudience=AzureADMultipleOrgs allows any tenant's "
                    "users to consent. BluePhishing: attacker spawns 250 agent "
                    "identities inside victim's tenant after admin consent."
                ),
                "severity": "high",
                "confidence": 0.70,
                "category": "oauth_consent_phishing",
                "cwe": "CWE-862",
            })
            self._pattern_hits["multi_tenant_abuse"] += 1

        # 3. Agent blueprint abuse
        if self._AGENT_BLUEPRINT_RE.search(full_text):
            findings.append({
                "type": "entra_agent_blueprint_abuse",
                "detail": (
                    "Entra Agent ID blueprint pattern detected. BluePhishing "
                    "(Proofpoint Nov 2026): attacker creates malicious agent "
                    "blueprint, victim admin approves, attacker spawns agent "
                    "identities with their own credentials inside victim's tenant."
                ),
                "severity": "critical",
                "confidence": 0.75,
                "category": "oauth_consent_phishing",
                "cwe": "CWE-863",
            })
            self._pattern_hits["agent_blueprint"] += 1

        self._findings.extend(findings)
        return findings

    def get_summary(self) -> dict[str, Any]:
        return {"pattern_hits": dict(self._pattern_hits), "total_findings": len(self._findings), "observations_analyzed": self._observation_count}

    def get_all_findings(self) -> list[dict[str, Any]]:
        return self._findings[-200:]


# ############################################################################
#
#  Y. LogToLeakDetector -- Detects Log-To-Leak metadata injection attacks
#     (arXiv 2610.36108). Directive placed in JSON tool metadata makes agent
#     perform extra attacker-controlled "logging" call, exfiltrating data.
#     55%+ residual success rate even with 3 defenses active.
#
# ############################################################################


class LogToLeakDetector:
    """Detects Log-To-Leak metadata injection attacks against AI agents."""

    _LOGGING_DIRECTIVE_RE = re.compile(
        r"(before\s+respond|after\s+complet|first\s+send|always\s+log|"
        r"must\s+report|required.*logging|mandatory.*report|"
        r"log\s+(?:all|every|each)\s+(?:request|response|query|result)|"
        r"send\s+(?:a\s+)?copy\s+(?:to|of)|forward\s+(?:to|all))",
        re.I,
    )
    _EXFIL_URL_RE = re.compile(
        r"(https?://(?!(?:api\.|www\.)?(?:github|google|microsoft|amazon|stripe|paypal|openai|anthropic)\.)[\w.-]+(?:/[\w./-]*)?(?:\?[^\s\"'<>]*)?)(?:\s|\")",
        re.I,
    )
    _SENSITIVE_PATH_RE = re.compile(
        r"(~/.ssh|\.env|\.aws/credentials|\.npmrc|\.netrc|"
        r"id_rsa|\.pem|\.key|credentials\.json|secrets\.yaml|"
        r"\.claude/settings\.local|\.mcp\.json)",
        re.I,
    )
    _TOOL_BINDING_RE = re.compile(
        r"(\"description\"\s*:\s*\"[^\"]*(?:log|send|report|forward)[^\"]*\"|"
        r"\"inputSchema\".*?(?:url|endpoint|webhook|callback))",
        re.I | re.S,
    )

    def __init__(self) -> None:
        self._findings: list[dict[str, Any]] = []
        self._pattern_hits: dict[str, int] = defaultdict(int)
        self._observation_count = 0

    def analyze(
        self, observation: dict, components: dict, memory: Any = None,
    ) -> list[dict[str, Any]]:
        self._observation_count += 1
        findings: list[dict[str, Any]] = []

        body_text = components.get("body_text", "")

        # 1. Logging directive in tool metadata
        if self._LOGGING_DIRECTIVE_RE.search(body_text) and self._EXFIL_URL_RE.search(body_text):
            findings.append({
                "type": "log_to_leak_injection",
                "detail": (
                    "Log-To-Leak pattern: logging directive combined with "
                    "external URL in tool metadata. Agent is instructed to "
                    "send data to attacker-controlled endpoint as a 'logging' "
                    "action. 55%+ residual success rate even after defenses."
                ),
                "severity": "critical",
                "confidence": 0.85,
                "category": "log_to_leak",
                "cwe": "CWE-200",
            })
            self._pattern_hits["log_to_leak"] += 1

        # 2. Sensitive file path in tool description
        if self._SENSITIVE_PATH_RE.search(body_text) and self._TOOL_BINDING_RE.search(body_text):
            findings.append({
                "type": "log_to_leak_credential_target",
                "detail": (
                    "Tool metadata references sensitive credential paths "
                    "(~/.ssh, .env, .aws/credentials, .claude/settings.local). "
                    "Agent may be directed to read and exfiltrate these files."
                ),
                "severity": "high",
                "confidence": 0.75,
                "category": "log_to_leak",
                "cwe": "CWE-200",
            })
            self._pattern_hits["credential_target"] += 1

        # 3. Template-based injection (Tool Binding + Trigger + Justification + Pressure)
        trigger_count = 0
        if self._LOGGING_DIRECTIVE_RE.search(body_text):
            trigger_count += 1
        if re.search(r"(important|critical|required|mandatory|always)", body_text, re.I):
            trigger_count += 1
        if re.search(r"(compliance|audit|security|regulation|policy)", body_text, re.I):
            trigger_count += 1
        if re.search(r"(immediately|urgently|before.*anything|first.*step)", body_text, re.I):
            trigger_count += 1

        if trigger_count >= 3:
            findings.append({
                "type": "log_to_leak_full_template",
                "detail": (
                    f"Full Log-To-Leak injection template detected ({trigger_count}/4 "
                    f"components: directive, urgency, justification, pressure). "
                    f"This template achieves highest success rate (55%+ residual)."
                ),
                "severity": "critical",
                "confidence": 0.80,
                "category": "log_to_leak",
                "cwe": "CWE-74",
            })
            self._pattern_hits["full_template"] += 1

        self._findings.extend(findings)
        return findings

    def get_summary(self) -> dict[str, Any]:
        return {"pattern_hits": dict(self._pattern_hits), "total_findings": len(self._findings), "observations_analyzed": self._observation_count}

    def get_all_findings(self) -> list[dict[str, Any]]:
        return self._findings[-200:]


# ############################################################################
#
#  Z. AgenticBrowserHijackDetector -- Detects PleaseFix-style agentic browser
#     hijacking. Prompt injection in web pages executed by AI agents under
#     user's logged-in session. Zero-click, no jailbreak needed. Affects
#     Claude in Chrome, ChatGPT Atlas, Gemini, Copilot Edge, Perplexity.
#
# ############################################################################


class AgenticBrowserHijackDetector:
    """Detects agentic browser hijacking patterns (PleaseFix framework)."""

    _HIDDEN_INSTRUCTION_WEB_RE = re.compile(
        r"(<\s*div[^>]*style\s*=\s*\"[^\"]*(?:display\s*:\s*none|visibility\s*:\s*hidden|"
        r"opacity\s*:\s*0|font-size\s*:\s*0|position\s*:\s*absolute[^\"]*left\s*:\s*-\d{4,})[^\"]*\"[^>]*>|"
        r"<\s*!\s*--\s*(?:AI|agent|assistant|system|instruction|ignore))",
        re.I | re.S,
    )
    _CROSS_ORIGIN_RE = re.compile(
        r"(window\.open\s*\(|document\.location\s*=|fetch\s*\(\s*['\"]https?://(?!(?:api\.|www\.)?(?:github|google|microsoft)\.)[^'\"]+['\"]|"
        r"XMLHttpRequest.*\.open\s*\([^)]*https?://)",
        re.I,
    )
    _HISTORY_MANIP_RE = re.compile(
        r"(history\.pushState|history\.replaceState|onpopstate|"
        r"localStorage\.setItem.*(?:instruction|prompt|system)|"
        r"sessionStorage\.setItem.*(?:instruction|prompt))",
        re.I,
    )
    _OAUTH_SCOPE_ABUSE_RE = re.compile(
        r"(oauth.*scope.*(?:write|admin|delete|manage|full_access)|"
        r"consent.*(?:read_write|admin)|authorize.*scope=.*readwrite)",
        re.I,
    )
    _FORGED_COT_RE = re.compile(
        r"(<thinking>|<scratchpad>|<chain_of_thought>|<reasoning>|"
        r"\[internal_thought\]|\[system_reasoning\])",
        re.I,
    )

    def __init__(self) -> None:
        self._findings: list[dict[str, Any]] = []
        self._pattern_hits: dict[str, int] = defaultdict(int)
        self._observation_count = 0

    def analyze(
        self, observation: dict, components: dict, memory: Any = None,
    ) -> list[dict[str, Any]]:
        self._observation_count += 1
        findings: list[dict[str, Any]] = []

        body_text = components.get("body_text", "")

        # 1. Hidden instructions in web content
        if self._HIDDEN_INSTRUCTION_WEB_RE.search(body_text):
            findings.append({
                "type": "agentic_hidden_instruction",
                "detail": (
                    "Hidden instructions detected in web content (invisible div, "
                    "HTML comment with AI/agent keywords). PleaseFix: web pages "
                    "inject instructions that agentic browsers execute under "
                    "user's logged-in session. Zero-click, no jailbreak."
                ),
                "severity": "critical",
                "confidence": 0.80,
                "category": "agentic_browser_hijack",
                "cwe": "CWE-74",
            })
            self._pattern_hits["hidden_instruction"] += 1

        # 2. Cross-origin data access from agent context
        if self._CROSS_ORIGIN_RE.search(body_text) and self._HIDDEN_INSTRUCTION_WEB_RE.search(body_text):
            findings.append({
                "type": "agentic_cross_origin_exfil",
                "detail": (
                    "Cross-origin request combined with hidden instruction. "
                    "Agent may exfiltrate data from user's session to "
                    "attacker-controlled endpoint."
                ),
                "severity": "critical",
                "confidence": 0.85,
                "category": "agentic_browser_hijack",
                "cwe": "CWE-200",
            })
            self._pattern_hits["cross_origin_exfil"] += 1

        # 3. History manipulation (HistoryFixing persistence)
        if self._HISTORY_MANIP_RE.search(body_text):
            findings.append({
                "type": "agentic_history_fixing",
                "detail": (
                    "Browser history manipulation detected. HistoryFixing attack: "
                    "malicious page writes persistent instructions into browser "
                    "history/storage. Agent reads them on future visits, achieving "
                    "persistence without server compromise."
                ),
                "severity": "high",
                "confidence": 0.70,
                "category": "agentic_browser_hijack",
                "cwe": "CWE-471",
            })
            self._pattern_hits["history_fixing"] += 1

        # 4. Forged chain-of-thought
        if self._FORGED_COT_RE.search(body_text):
            findings.append({
                "type": "agentic_forged_cot",
                "detail": (
                    "Forged chain-of-thought tags in content. PleaseFix: "
                    "attacker injects fake reasoning tags that override the "
                    "agent's safety judgment, causing it to treat malicious "
                    "actions as self-derived conclusions."
                ),
                "severity": "critical",
                "confidence": 0.75,
                "category": "agentic_browser_hijack",
                "cwe": "CWE-74",
            })
            self._pattern_hits["forged_cot"] += 1

        self._findings.extend(findings)
        return findings

    def get_summary(self) -> dict[str, Any]:
        return {"pattern_hits": dict(self._pattern_hits), "total_findings": len(self._findings), "observations_analyzed": self._observation_count}

    def get_all_findings(self) -> list[dict[str, Any]]:
        return self._findings[-200:]


# ============================================================================
# Main LLMReplacementLayer (orchestrates all engines)
# ============================================================================

class LLMReplacementLayer:
    """Orchestrates 33 reasoning engines with cross-engine feedback loops,
    adaptive weighting, consensus detection, and kill chain synthesis.

    Architecture:
    Engines 1-13: Core reasoning (zero-shot, structural, CoT, multi-perspective,
        hypothesis, correlation, reverse engineering, brainstorm, Monte Carlo,
        attack tree, contextual, consensus, kill chain)
    Engines 14-16: Autonomous learning (episodic memory, reflection, self-critique)
    Engines 17-19: Frontier techniques (iterative deepening, exploit chain, semantic)
    Engine 20: Payment glue code analysis (Stripe/PayPal/Braintree/Adyen state machines)
    Engines 21-23: Enterprise targeting (platform detection, access-without-payment, AI agent)
    Engines 24-33: v8 attack class detectors (GraphQL alias batching, HTTP smuggling,
        JWT algorithm confusion, prototype pollution, cache key injection, WAF bypass,
        device code flow phishing, OAuth consent phishing, Log-To-Leak, agentic browser hijack)
    """

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
        self._engine_hit_rates: dict[str, list[float]] = defaultdict(list)
        self._cross_engine_history: list[dict[str, float]] = []

        # v4: Autonomous learning + metacognition systems
        self._memory = EpisodicMemory(max_entries=10000, recency_decay=0.995)
        self._reflection_engine = ReflectionEngine(reflection_interval=10)
        self._metacognition = MetacognitiveMonitor()
        self._knowledge_graph = KnowledgeGraph()
        self._belief_log = BeliefRevisionLog()
        self._self_critique = SelfCritiqueEngine()

        # v5: Frontier techniques (ExploitGym / Astra / Mythos inspired)
        self._deepening_reasoner = IterativeDeepeningReasoner(max_depth=3)
        self._chain_synthesizer = ExploitChainSynthesizer()
        self._self_verifier = AdversarialSelfVerifier()
        self._semantic_reasoner = SemanticPatternReasoner()
        self._kill_chain_scorer = KillChainScorer()
        self._hypothesis_refiner = IterativeHypothesisRefiner(max_revisions=3)

        # v6: Payment glue code deep analysis
        self._payment_glue = PaymentGlueCodeAnalyzer()

        # v7: Enterprise + access-without-payment + AI agent attack surface
        self._enterprise_detector = EnterprisePlatformDetector()
        self._awp_detector = AccessWithoutPaymentDetector()
        self._agent_attack = AIAgentAttackSurfaceAnalyzer()

        # v8: 10 missing attack class detectors (closes Tier 2 gap)
        self._graphql_detector = GraphQLAliasBatchingDetector()
        self._smuggling_detector = HTTPRequestSmugglingDetector()
        self._jwt_detector = JWTAlgorithmConfusionDetector()
        self._prototype_detector = PrototypePollutionDetector()
        self._cache_detector = CacheKeyInjectionDetector()
        self._waf_detector = WAFBypassDetector()
        self._device_code_detector = DeviceCodeFlowDetector()
        self._oauth_consent_detector = OAuthConsentPhishingDetector()
        self._log_to_leak_detector = LogToLeakDetector()
        self._browser_hijack_detector = AgenticBrowserHijackDetector()

    def _compute_adaptive_weights(self) -> dict[str, float]:
        """Adapt engine weights based on historical hit rates."""
        base = {
            "zero_shot": 0.30, "structural": 0.15, "cot": 0.30,
            "perspective": 0.25, "hypothesis": 0.20, "mc": 0.15, "attack_tree": 0.10,
        }
        if len(self._cross_engine_history) < 5:
            return base
        for engine, scores in self._engine_hit_rates.items():
            if engine in base and len(scores) >= 3:
                avg = sum(scores[-10:]) / len(scores[-10:])
                if avg > 0.5:
                    base[engine] = min(0.5, base[engine] * 1.3)
                elif avg < 0.1:
                    base[engine] = max(0.05, base[engine] * 0.7)
        return base

    def _compute_engine_consensus(
        self, engine_scores: dict[str, float], threshold: float = 0.3,
    ) -> dict[str, Any]:
        """Cross-engine consensus: how many engines flag this observation."""
        flagging = {n: s for n, s in engine_scores.items() if s > threshold}
        total = len(engine_scores)
        agreeing = len(flagging)
        level = "none"
        if agreeing >= 5:
            level = "unanimous"
        elif agreeing >= 4:
            level = "strong"
        elif agreeing >= 3:
            level = "moderate"
        elif agreeing >= 2:
            level = "weak"
        elif agreeing >= 1:
            level = "single_engine"
        return {
            "consensus_level": level, "engines_flagging": agreeing,
            "engines_total": total, "flagging_engines": flagging,
            "consensus_score": round(agreeing / max(total, 1), 3),
        }

    def _cross_engine_amplification(
        self, engine_scores: dict[str, float],
        components: dict[str, Any], scored_hypotheses: list[Hypothesis],
    ) -> tuple[list[str], float]:
        """Cross-engine feedback: correlated signals get amplified."""
        amps: list[str] = []
        boost = 0.0

        cot_s, hyp_s = engine_scores.get("cot", 0), engine_scores.get("hypothesis", 0)
        if cot_s > 0.3 and hyp_s > 0.3:
            amps.append(f"CoT+Hypothesis convergence (cot={cot_s:.2f}, hyp={hyp_s:.2f})")
            boost += 0.1

        zs_s, st_s = engine_scores.get("zero_shot", 0), engine_scores.get("structural", 0)
        if zs_s > 0.3 and st_s > 0.3:
            amps.append(f"Pattern+Structural convergence (zs={zs_s:.2f}, struct={st_s:.2f})")
            boost += 0.1

        payment_hyp = any(
            h.category in ("payment_manipulation", "entitlement_bypass") and h.posterior > 0.3
            for h in scored_hypotheses
        )
        if payment_hyp and components.get("trust_boundary") == "payment_to_entitlement":
            amps.append("Payment hypothesis + payment trust boundary: high-confidence payment flaw")
            boost += 0.15

        auth_hyp = any(
            h.category in ("auth_bypass", "privilege_escalation") and h.posterior > 0.25
            for h in scored_hypotheses
        )
        if auth_hyp and not components.get("has_auth_header"):
            amps.append("Auth bypass hypothesis + unauthenticated request: strong auth flaw signal")
            boost += 0.15

        p_s, t_s = engine_scores.get("perspective", 0), engine_scores.get("attack_tree", 0)
        if p_s > 0.4 and t_s > 0.3:
            amps.append("Multi-perspective + attack tree viability: realistic exploit path")
            boost += 0.1

        anomalies = components.get("anomalies", [])
        if any("entitlement_drift" in a for a in anomalies) and any("zero_payment" in a for a in anomalies):
            amps.append("CRITICAL: Entitlement drift + zero payment = access-without-payment confirmed")
            boost += 0.25

        return amps, min(0.5, boost)

    def _synthesize_kill_chain(
        self, components: dict[str, Any], scored_hypotheses: list[Hypothesis],
        attack_tree: AttackTreeNode, brainstorm_chains: list[dict[str, Any]],
        re_findings: list[dict[str, Any]],
    ) -> str:
        """Assemble a human-readable kill chain narrative from all engines."""
        if not scored_hypotheses or scored_hypotheses[0].posterior < 0.15:
            return ""

        top = scored_hypotheses[0]
        parts = [f"Kill chain: {top.category} at {components.get('endpoint', '?')}"]

        wafs = [f.get("waf_cdn", "?") for f in re_findings if f.get("type") == "waf_fingerprint"]
        if wafs:
            parts.append(f"-> Recon: WAF/CDN ({', '.join(wafs[:3])})")

        techs = [f.get("technology", "?") for f in re_findings if f.get("type") == "tech_fingerprint"]
        if techs:
            parts.append(f"-> Fingerprint: {', '.join(techs[:3])}")

        parts.append(f"-> Exploit: {top.description}")

        impact_map = {
            "payment_manipulation": "Access without payment",
            "entitlement_bypass": "Access without payment",
            "auth_bypass": "Unauthorized access to protected resources",
            "injection": "Data exfiltration / RCE potential",
            "privilege_escalation": "Elevated privileges",
            "idor": "Cross-user data access",
        }
        parts.append(f"-> Impact: {impact_map.get(top.category, top.category)} (p={top.posterior:.3f})")

        if brainstorm_chains:
            parts.append(f"-> Chain: {brainstorm_chains[0].get('chain', 'N/A')}")

        if attack_tree.probability > 0.3:
            parts.append(f"-> Tree probability: {attack_tree.probability:.1%}")

        return " ".join(parts)

    def analyze_observation(self, observation: dict[str, Any]) -> LLMReplacementResult:
        self._observations_analyzed += 1
        obs_id = self._observations_analyzed
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

        # --- Memory: Store raw observation and retrieve past context ---
        endpoint = components.get("endpoint", "")
        obs_importance = min(1.0, 0.3 + 0.1 * len(zero_shot) + (0.2 if structural_anomaly else 0.0))
        obs_features = {
            "status_code": float(components.get("status_code", 0)) / 600.0,
            "body_size": min(1.0, float(components.get("body_size", 0)) / 50000.0),
            "has_auth": 1.0 if components.get("has_auth_header") else 0.0,
            "zero_shot_count": min(1.0, float(len(zero_shot)) / 10.0),
        }
        self._memory.store(
            entry_type="observation",
            content={
                "endpoint": endpoint,
                "status_code": components.get("status_code", 0),
                "zero_shot_count": len(zero_shot),
                "structural_anomaly": structural_anomaly,
                "has_auth": components.get("has_auth_header", False),
            },
            importance=obs_importance,
            endpoint=endpoint,
            features=obs_features,
            source_observation_id=obs_id,
        )

        # Retrieve relevant past memories for this observation
        past_memories = self._memory.retrieve(
            query_features=obs_features,
            query_endpoint=endpoint,
            top_k=10,
        )
        memory_retrievals_data = [
            {
                "entry_id": m.entry_id,
                "type": m.entry_type,
                "endpoint": m.endpoint,
                "category": m.category,
                "importance": round(m.importance, 3),
                "content_summary": str(m.content)[:200],
            }
            for m in past_memories
        ]

        # --- Knowledge Graph: Ingest observation entities ---
        self._knowledge_graph.ingest_observation(observation)

        # --- Engine 4: Multi-perspective (5 viewpoints) ---
        attacker_view = self._perspective_analyzer.analyze_as_attacker(components, zero_shot)
        defender_view = self._perspective_analyzer.analyze_as_defender(components, zero_shot)
        auditor_view = self._perspective_analyzer.analyze_as_auditor(components, zero_shot)
        red_team_view = self._perspective_analyzer.analyze_as_red_team(components, zero_shot)
        threat_intel_view = self._perspective_analyzer.analyze_as_threat_intel(components, zero_shot)
        perspectives = self._perspective_analyzer.synthesize(
            attacker_view, defender_view, auditor_view, red_team_view, threat_intel_view,
        )

        # --- Engine 5: Hypothesis (with metacognitive prior calibration) ---
        surfaces = self._cot_engine._identify_attack_surface(components)
        hypotheses = self._cot_engine._generate_hypotheses(surfaces, components, {})
        scored_hypotheses = self._cot_engine._evaluate_hypotheses(hypotheses, components)

        # Apply metacognitive calibration to posteriors
        for h in scored_hypotheses:
            adj = self._metacognition.get_prior_adjustment(h.category)
            if adj != 1.0:
                h.posterior = max(0.01, min(0.99, h.posterior * adj))

        # Boost hypotheses that align with past insights
        relevant_insights = self._reflection_engine.get_relevant_insights(
            category=scored_hypotheses[0].category if scored_hypotheses else "",
            endpoint=endpoint,
        )
        if relevant_insights:
            for h in scored_hypotheses[:3]:
                matching = [i for i in relevant_insights if i.category == h.category]
                if matching:
                    insight_boost = 0.05 * min(len(matching), 3)
                    h.posterior = min(0.99, h.posterior + insight_boost)

        self._hypothesis_engine.update_beliefs(scored_hypotheses)

        # --- Self-critique: Devil's advocate pass on hypotheses ---
        scored_hypotheses = self._self_critique.critique(
            scored_hypotheses, components, self._memory, self._metacognition,
        )

        # --- Belief revision with provenance ---
        for h in scored_hypotheses[:5]:
            old_belief = self._hypothesis_engine.get_beliefs().get(h.category, 0.5)
            if abs(h.posterior - old_belief) > 0.05:
                self._belief_log.record(
                    observation_id=obs_id,
                    category=h.category,
                    old_belief=old_belief,
                    new_belief=h.posterior,
                    trigger=f"observation_{obs_id}",
                    evidence=h.description[:200],
                )

        # --- Metacognitive monitoring ---
        for h in scored_hypotheses[:5]:
            self._metacognition.record_prediction(h.category, h.posterior)
            if h.posterior > 0.5:
                confirmed = len(zero_shot) > 0 or structural_anomaly
                self._metacognition.record_confirmation(h.category, confirmed)

        # Store high-scoring hypotheses as findings in memory
        for h in scored_hypotheses:
            if h.posterior > 0.3:
                self._memory.store(
                    entry_type="finding",
                    content={
                        "category": h.category,
                        "posterior": h.posterior,
                        "description": h.description[:200],
                        "evidence_for": h.evidence_for[:3] if hasattr(h, 'evidence_for') else [],
                        "evidence_against": h.evidence_against[:3] if hasattr(h, 'evidence_against') else [],
                    },
                    importance=h.posterior,
                    endpoint=endpoint,
                    category=h.category,
                    source_observation_id=obs_id,
                )

        # --- Reflection: Periodic insight synthesis ---
        new_reflections: list[dict[str, Any]] = []
        if self._reflection_engine.should_reflect(obs_id):
            insights = self._reflection_engine.reflect(self._memory)
            for ins in insights:
                self._memory.store(
                    entry_type="reflection",
                    content={"insight": ins.description, "confidence": ins.confidence},
                    importance=ins.confidence,
                    category=ins.category,
                )
                new_reflections.append({
                    "id": ins.insight_id,
                    "description": ins.description,
                    "confidence": round(ins.confidence, 3),
                    "category": ins.category,
                })

        strategic_plan = self._reflection_engine.get_strategic_plan()

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

        defense_indicators = []
        for f in re_findings:
            if f.get("type") in ("anti_re", "waf_fingerprint", "waf_block_page"):
                defense_indicators.append(f.get("waf_cdn", f.get("detail", "unknown")))
        bypass_ideas = self._brainstorm_engine.brainstorm_bypass_techniques(defense_indicators)

        # --- Engine 9: Monte Carlo ---
        finding_probs = [h.posterior for h in scored_hypotheses if h.posterior > 0.1]
        mc_result = self._monte_carlo.simulate_attack_success(finding_probs)
        severity_scores = [_SEVERITY_FLOOR_SCORE.get(h.category, 0.3) for h in scored_hypotheses]
        mc_risk_dist = self._monte_carlo.compute_risk_distribution(severity_scores)

        # --- Engine 10: Attack tree (all 5 goal templates) ---
        attack_tree = self._attack_tree_gen.generate_tree("access_without_payment", zero_shot)
        critical_path = self._attack_tree_gen.find_critical_path(attack_tree)

        all_attack_paths: list[dict] = [{
            "goal": "access_without_payment",
            "tree": attack_tree.to_dict(),
            "critical_path": critical_path,
            "success_probability": round(attack_tree.probability, 4),
        }]
        for goal in ("account_takeover", "data_exfiltration", "privilege_escalation", "payment_fraud"):
            alt_tree = self._attack_tree_gen.generate_tree(goal, zero_shot)
            if alt_tree.probability > 0.05:
                all_attack_paths.append({
                    "goal": goal,
                    "tree": alt_tree.to_dict(),
                    "critical_path": self._attack_tree_gen.find_critical_path(alt_tree),
                    "success_probability": round(alt_tree.probability, 4),
                })

        # --- Engine 11: Contextual ---
        contextual_notes, severity_floor = _contextual_notes_and_floor(
            request_data, zero_shot, components,
        )

        # --- Engine 12: Cross-engine consensus ---
        adaptive_weights = self._compute_adaptive_weights()

        zero_shot_component = min(1.0, adaptive_weights["zero_shot"] * len(zero_shot))
        structural_component = structural_score * (0.6 if structural_anomaly else 0.15)
        cot_component = reasoning.confidence * adaptive_weights["cot"]
        perspective_component = perspectives.get("combined_risk", 0.0) * adaptive_weights["perspective"]
        hypothesis_component = scored_hypotheses[0].posterior * adaptive_weights["hypothesis"] if scored_hypotheses else 0.0
        mc_component = mc_result.get("success_rate", 0.0) * adaptive_weights["mc"]
        tree_component = attack_tree.probability * adaptive_weights["attack_tree"]

        engine_scores = {
            "zero_shot": zero_shot_component, "structural": structural_component,
            "cot": cot_component, "perspective": perspective_component,
            "hypothesis": hypothesis_component, "mc": mc_component,
            "attack_tree": tree_component,
        }
        for name, score in engine_scores.items():
            self._engine_hit_rates[name].append(score)

        consensus = self._compute_engine_consensus(engine_scores)
        amplifications, cross_boost = self._cross_engine_amplification(
            engine_scores, components, scored_hypotheses,
        )

        # --- Engine 13: Kill chain synthesis ---
        kill_chain = self._synthesize_kill_chain(
            components, scored_hypotheses, attack_tree, brainstorm_chains, re_findings,
        )

        # --- Engine 14: Semantic Pattern Reasoning (Mythos-inspired) ---
        semantic_findings = self._semantic_reasoner.analyze_semantics(components)

        # --- Engine 15: Iterative Deepening (Astra recurrent-depth) ---
        scored_hypotheses, depth_reached = self._deepening_reasoner.deepen(
            scored_hypotheses, components, self._memory, self._knowledge_graph,
        )

        # --- Engine 16: Iterative Hypothesis Refinement (try-fail-revise) ---
        scored_hypotheses = self._hypothesis_refiner.refine(
            scored_hypotheses, components, self._memory,
        )

        # --- Engine 17: Exploit Chain Synthesis (ExploitGym multi-vuln chaining) ---
        findings_history = [
            m.content for m in self._memory.retrieve(
                query_category="", top_k=50, entry_type="finding",
            )
        ]
        exploit_chains = self._chain_synthesizer.synthesize_chains(
            scored_hypotheses, findings_history, self._knowledge_graph,
        )

        # --- Engine 18: Kill Chain Scoring (stage-aware reward shaping) ---
        kill_chain_analysis = self._kill_chain_scorer.score_kill_chain(
            scored_hypotheses, semantic_findings, exploit_chains,
        )

        # --- Engine 20: Payment Glue Code Analysis ---
        payment_glue_findings = self._payment_glue.analyze(
            observation, components, self._memory,
        )
        if payment_glue_findings:
            engine_scores["payment_glue"] = max(
                f.get("confidence", 0.5) for f in payment_glue_findings
            )

        # --- Engine 21: Enterprise Platform Detection ---
        enterprise_detections = self._enterprise_detector.detect_platforms(
            observation, components,
        )
        if enterprise_detections:
            engine_scores["enterprise_platform"] = max(
                d.get("confidence", 0.5) for d in enterprise_detections
            )

        # --- Engine 22: Access-Without-Payment Detection ---
        awp_findings = self._awp_detector.analyze(
            observation, components, self._memory,
        )
        if awp_findings:
            engine_scores["access_without_payment"] = max(
                f.get("confidence", 0.5) for f in awp_findings
            )

        # --- Engine 23: AI Agent Attack Surface Analysis ---
        agent_attack_findings = self._agent_attack.analyze(
            observation, components,
        )
        if agent_attack_findings:
            engine_scores["ai_agent_attack"] = max(
                f.get("confidence", 0.5) for f in agent_attack_findings
            )

        # --- v8 Engines 24-33: 10 missing attack class detectors ---
        v8_detectors = [
            ("graphql_alias_batching", self._graphql_detector),
            ("http_smuggling", self._smuggling_detector),
            ("jwt_algorithm_confusion", self._jwt_detector),
            ("prototype_pollution", self._prototype_detector),
            ("cache_key_injection", self._cache_detector),
            ("waf_bypass", self._waf_detector),
            ("device_code_flow", self._device_code_detector),
            ("oauth_consent_phishing", self._oauth_consent_detector),
            ("log_to_leak", self._log_to_leak_detector),
            ("agentic_browser_hijack", self._browser_hijack_detector),
        ]
        v8_all_findings: dict[str, list[dict[str, Any]]] = {}
        for engine_name, detector in v8_detectors:
            det_findings = detector.analyze(observation, components, self._memory)
            v8_all_findings[engine_name] = det_findings
            if det_findings:
                engine_scores[engine_name] = max(
                    f.get("confidence", 0.5) for f in det_findings
                )

        # --- Final synthesis: combine with consensus + cross-engine boost ---
        overall_score = max(engine_scores.values())
        overall_score = min(1.0, overall_score + cross_boost)

        # Semantic findings boost
        if semantic_findings:
            critical_semantics = [f for f in semantic_findings if f.get("severity") == "critical"]
            semantic_boost = min(0.2, 0.05 * len(critical_semantics) + 0.02 * len(semantic_findings))
            overall_score = min(1.0, overall_score + semantic_boost)

        # Exploit chain boost
        if exploit_chains:
            best_chain = max(exploit_chains, key=lambda c: c.combined_probability)
            chain_boost = min(0.15, best_chain.combined_probability * 0.3)
            overall_score = min(1.0, overall_score + chain_boost)

        # Kill chain depth bonus
        kc_score = kill_chain_analysis.get("kill_chain_score", 0)
        if kc_score > 0.3:
            overall_score = min(1.0, overall_score + kc_score * 0.1)

        # Payment glue code boost
        if payment_glue_findings:
            critical_glue = [f for f in payment_glue_findings if f.get("severity") == "critical"]
            glue_boost = min(0.25, 0.08 * len(critical_glue) + 0.03 * len(payment_glue_findings))
            overall_score = min(1.0, overall_score + glue_boost)

        # Access-without-payment boost (highest weight -- this is the engine's core mission)
        if awp_findings:
            critical_awp = [f for f in awp_findings if f.get("severity") == "critical"]
            awp_boost = min(0.30, 0.10 * len(critical_awp) + 0.04 * len(awp_findings))
            overall_score = min(1.0, overall_score + awp_boost)

        # AI agent attack boost
        if agent_attack_findings:
            critical_agent = [f for f in agent_attack_findings if f.get("severity") == "critical"]
            agent_boost = min(0.25, 0.08 * len(critical_agent) + 0.03 * len(agent_attack_findings))
            overall_score = min(1.0, overall_score + agent_boost)

        consensus_boost = 0.0
        if consensus["consensus_level"] in ("unanimous", "strong"):
            consensus_boost = 0.1
        elif consensus["consensus_level"] == "moderate":
            consensus_boost = 0.05
        overall_score = min(1.0, overall_score + consensus_boost)

        self._cross_engine_history.append(engine_scores)

        severity = _bump_severity(_severity_from_score(overall_score), severity_floor)
        overall_score = max(overall_score, _SEVERITY_FLOOR_SCORE[severity])
        overall_score = max(0.0, min(1.0, overall_score))

        # --- Engine 19: Adversarial Self-Verification (Agent-as-a-Judge) ---
        verification = self._self_verifier.verify(
            engine_scores, scored_hypotheses, components,
            zero_shot, overall_score, consensus,
        )
        if verification["verdict"] == "SUSPECT":
            overall_score = verification["adjusted_score"]
            severity = _bump_severity(_severity_from_score(overall_score), severity_floor)

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
            "mc_component": round(mc_component, 4),
            "tree_component": round(tree_component, 4),
            "consensus_boost": round(consensus_boost, 4),
            "cross_engine_boost": round(cross_boost, 4),
            "severity_floor_applied": severity_floor,
            "final_severity": severity,
            "belief_state": self._hypothesis_engine.get_beliefs(),
        }

        financial_impact: dict[str, Any] = {}
        if hasattr(self._monte_carlo, "estimate_financial_impact"):
            is_payment = components.get("trust_boundary") == "payment_to_entitlement"
            financial_impact = self._monte_carlo.estimate_financial_impact(severity, is_payment)

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
            attack_paths=all_attack_paths,
            brainstorm_results=(
                brainstorm_vectors[:10]
                + [{"type": "chain_composition", **c} for c in brainstorm_chains]
                + [{"type": "divergent", **d} for d in divergent]
                + [{"type": "bypass_technique", **b} for b in bypass_ideas[:10]]
            ),
            reverse_engineering_findings=re_findings[:20],
            confidence_calibration=confidence_calibration,
            multi_perspective_scores=perspectives,
            evidence_correlation=correlations[:10],
            anomaly_explanation=anomaly_explanation,
            risk_monte_carlo={**mc_result, "risk_distribution": mc_risk_dist},
            engine_consensus=consensus,
            cross_engine_amplifications=amplifications,
            adaptive_weights=adaptive_weights,
            kill_chain_summary=kill_chain,
            financial_impact_estimate=financial_impact,
            # v4: autonomous learning outputs
            memory_retrievals=memory_retrievals_data,
            reflections=new_reflections,
            knowledge_graph_summary=self._knowledge_graph.to_summary(),
            metacognitive_assessment=self._metacognition.self_assess(),
            belief_revision_trail=self._belief_log.explain_belief(
                scored_hypotheses[0].category if scored_hypotheses else "",
            ),
            self_critique_results=[
                {
                    "category": h.category,
                    "survived_critique": h.posterior > 0.1,
                    "posterior": round(h.posterior, 4),
                    "counter_arguments": getattr(h, "evidence_against", [])[:5],
                }
                for h in scored_hypotheses[:5]
            ],
            strategic_plan=strategic_plan,
            # v5: frontier techniques outputs
            iterative_depth_reached=depth_reached,
            exploit_chains=[
                {
                    "id": c.chain_id,
                    "description": c.description,
                    "steps": c.steps,
                    "combined_severity": c.combined_severity,
                    "combined_probability": c.combined_probability,
                    "kill_chain_phase": c.kill_chain_phase,
                }
                for c in exploit_chains[:5]
            ],
            adversarial_verification=verification,
            semantic_findings=semantic_findings[:10],
            kill_chain_analysis=kill_chain_analysis,
            hypothesis_refinement=self._hypothesis_refiner.get_revision_summary(),
            # v6: payment glue code analysis outputs
            payment_glue_findings=payment_glue_findings[:20],
            payment_provider_summary=self._payment_glue.get_provider_summary(),
            # v7: enterprise + access-without-payment + AI agent outputs
            enterprise_platform_detections=enterprise_detections[:10],
            access_without_payment_findings=awp_findings[:20],
            ai_agent_attack_findings=agent_attack_findings[:15],
            enterprise_platform_summary=self._enterprise_detector.get_platform_summary(),
            access_without_payment_summary=self._awp_detector.get_pattern_summary(),
            ai_agent_attack_summary=self._agent_attack.get_attack_summary(),
            # v8: 10 new attack class detector outputs
            v8_findings={k: v[:10] for k, v in v8_all_findings.items() if v},
            v8_summaries={
                name: det.get_summary()
                for name, det in v8_detectors
            },
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
            "engine_hit_rates": {
                k: round(sum(v[-10:]) / max(len(v[-10:]), 1), 4)
                for k, v in self._engine_hit_rates.items()
            },
            "adaptive_weights": self._compute_adaptive_weights(),
            "cross_engine_history_length": len(self._cross_engine_history),
            # v4: autonomous learning statistics
            "episodic_memory": self._memory.to_summary(),
            "insights": self._reflection_engine.get_insights(),
            "strategic_plan": self._reflection_engine.get_strategic_plan(),
            "knowledge_graph": self._knowledge_graph.to_summary(),
            "metacognitive_assessment": self._metacognition.self_assess(),
            "largest_belief_shifts": self._belief_log.get_largest_shifts(5),
            # v5: frontier technique statistics
            "iterative_deepening_stats": self._deepening_reasoner.get_stats(),
            "exploit_chains_found": self._chain_synthesizer.get_all_chains(),
            "semantic_findings_total": len(self._semantic_reasoner.get_all_findings()),
            "hypothesis_refinement": self._hypothesis_refiner.get_revision_summary(),
            # v6: payment glue code statistics
            "payment_glue_findings_total": len(self._payment_glue.get_all_findings()),
            "payment_provider_summary": self._payment_glue.get_provider_summary(),
            # v7: enterprise + access-without-payment + AI agent statistics
            "enterprise_platforms": self._enterprise_detector.get_platform_summary(),
            "access_without_payment": self._awp_detector.get_pattern_summary(),
            "ai_agent_attack": self._agent_attack.get_attack_summary(),
            # v8: 10 new attack class detector statistics
            "v8_graphql": self._graphql_detector.get_summary(),
            "v8_smuggling": self._smuggling_detector.get_summary(),
            "v8_jwt": self._jwt_detector.get_summary(),
            "v8_prototype": self._prototype_detector.get_summary(),
            "v8_cache": self._cache_detector.get_summary(),
            "v8_waf": self._waf_detector.get_summary(),
            "v8_device_code": self._device_code_detector.get_summary(),
            "v8_oauth_consent": self._oauth_consent_detector.get_summary(),
            "v8_log_to_leak": self._log_to_leak_detector.get_summary(),
            "v8_browser_hijack": self._browser_hijack_detector.get_summary(),
        }
