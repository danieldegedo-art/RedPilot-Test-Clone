"""B40 (owns A37): Payment-Stack Fingerprinting -- the buildable half only.

B40 as specified has three halves; the owner's scope keeps ONE:

  * BUILT -- payment-stack fingerprinting: classify PUBLIC, structural signals already
    observed in the target's own pages/responses (a header name, a URL path, a script
    domain, a public field name) against a fixed signature table, to infer which
    payment provider/stack is in use. The result is a recon LEAD that feeds B36's
    knowledge graph and the planner -- never a finding.
  * SCOPED OUT -- threat-led "weaponization" (turning disclosed bypass patterns into
    pre-prioritised attacks) and credential/secret-structure inventory. These run
    against the platform's own "no credential attacks" contract. This module has NO
    surface for them: it only maps public signals to a provider label. It never reads,
    stores, or hunts secrets, and it emits no attack.

Only public, structural tokens are matched (no secret-key prefixes, no credentials).
Matching is deterministic; confidence is the fraction of a provider's signature that
was observed. Stdlib only; pure.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

MODULE_VERSION = "payment-fingerprint/1.0"

# What this module deliberately does NOT do (owner scope, turn 1).
SCOPE_EXCLUDED = ("bypass-pattern weaponization", "credential/secret-structure inventory")


@dataclass(frozen=True)
class ProviderSignature:
    provider: str
    signals: frozenset[str]   # PUBLIC structural tokens only


# Public, structural signatures only (header names, URL paths, script domains, public
# field names). No secret-key prefixes, no credential tokens.
SIGNATURES: tuple[ProviderSignature, ...] = (
    ProviderSignature("stripe", frozenset({"header:stripe-version", "path:/v1/payment_intents",
                                            "field:client_secret", "script:js.stripe.com"})),
    ProviderSignature("braintree", frozenset({"domain:braintreegateway.com", "field:client_token", "path:/merchants"})),
    ProviderSignature("adyen", frozenset({"domain:adyen.com", "path:/v1/payments", "field:pspReference"})),
    ProviderSignature("paypal", frozenset({"domain:paypalobjects.com", "path:/v2/checkout/orders", "field:orderID"})),
    ProviderSignature("square", frozenset({"domain:squareup.com", "script:web.squarecdn.com", "field:locationId"})),
)


class Confidence(str, Enum):
    HIGH = "high"       # >= 2/3 of the signature observed
    MEDIUM = "medium"   # >= 1/3
    LOW = "low"         # > 0


def _band(score: float) -> Confidence:
    if score >= 2 / 3:
        return Confidence.HIGH
    if score >= 1 / 3:
        return Confidence.MEDIUM
    return Confidence.LOW


@dataclass(frozen=True)
class ProviderMatch:
    provider: str
    confidence: Confidence
    score: float
    matched: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"provider": self.provider, "confidence": self.confidence.value,
                "score": round(self.score, 4), "matched": list(self.matched)}


@dataclass(frozen=True)
class FingerprintResult:
    best: str | None
    matches: tuple[ProviderMatch, ...]
    note: str

    def to_dict(self) -> dict[str, Any]:
        return {"best": self.best, "matches": [m.to_dict() for m in self.matches], "note": self.note,
                "scope_excluded": list(SCOPE_EXCLUDED)}


def fingerprint(observed_signals: set[str]) -> FingerprintResult:
    """Classify observed PUBLIC structural signals into a payment provider/stack.
    A provider is a candidate only if at least one of its signature tokens was
    observed; confidence is the fraction of its signature present."""
    observed = set(observed_signals)
    matches: list[ProviderMatch] = []
    for sig in SIGNATURES:
        hit = sig.signals & observed
        if not hit:
            continue
        score = len(hit) / len(sig.signals)
        matches.append(ProviderMatch(sig.provider, _band(score), score, tuple(sorted(hit))))

    matches.sort(key=lambda m: (-m.score, m.provider))
    if not matches:
        return FingerprintResult(None, (),
                                 "no known payment-stack signature matched the observed public signals "
                                 "(absence of a match is not proof; a lead, never a finding)")
    best = matches[0].provider
    return FingerprintResult(best, tuple(matches),
                             f"fingerprint LEAD: best match {best} (confidence {matches[0].confidence.value}); "
                             f"public-signal classification only, feeds B36 recon — never a finding, no secrets read")


def fingerprint_payload(observed_signals: set[str]) -> dict[str, Any]:
    res = fingerprint(observed_signals)
    return {"module_version": MODULE_VERSION, **res.to_dict(),
            "note": "Public-signal payment-stack fingerprinting only (owner scope). No bypass weaponization and no "
                    "credential/secret inventory — this module has no surface for either; it emits a recon lead, "
                    "never a finding or an attack."}
