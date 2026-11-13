"""Entitlement-Binding Invariant -- the identity/tenant BINDING dimension of
entitlement, as a pure, declarative check over a run's observations.

This is deliberately a SMALL, complementary addition, not a new capability:

  * `entitlement_invariants.py` (B2) checks the entitlement-STATE invariant ("a
    protected feature executes only while entitlement is valid at time of use");
  * `role_based_access.py` / `session_consistency.py` check the authorization
    controls at the HTTP layer (account isolation, payment-attribute protection,
    auth/CSRF/privilege consistency);
  * the engine's PBB-G / PBB-X experiments PROVE a live cross-subject bypass with
    the full oracle chain.

What was missing was a single, consolidated view of one specific, easily-missed
dimension: an ALLOWED outcome must be BOUND to the right subject's own qualifying
payment. This module computes exactly that, declaratively, over the
`(feature, identity, tenant, qualifying_payment, payer, outcome)` observations the
engine already records -- a lightweight cross-check for reporting and CI. It
proves nothing on its own (the experiments do that); it flags where the binding
does not hold and names which dimension broke.

A binding HOLDS iff a feature is ALLOWED only for a subject whose OWN qualifying
payment backs it. It is VIOLATED when a feature is ALLOWED without a qualifying
payment for that subject (unpaid access), or when the paying subject differs from
the subject granted access (cross-identity / cross-tenant). An indeterminate
oracle outcome is INCONCLUSIVE -- never a guessed violation.

Stdlib only; pure.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable

MODULE_VERSION = "entitlement-binding/1.0"


class BindingVerdict(str, Enum):
    HOLD = "hold"
    VIOLATED = "violated"
    INCONCLUSIVE = "inconclusive"


class BindingDimension(str, Enum):
    NONE = "none"
    UNPAID_ACCESS = "unpaid_access"       # ALLOWED with no qualifying payment for the subject
    CROSS_IDENTITY = "cross_identity"     # paid by a different identity
    CROSS_TENANT = "cross_tenant"         # paid under a different tenant


@dataclass(frozen=True)
class BindingObservation:
    feature_id: str
    identity_alias: str
    outcome: str                              # "allowed" | "denied" | "indeterminate" (oracle.py vocabulary)
    qualifying_payment: bool                  # does THIS subject hold its own qualifying payment?
    tenant_alias: str | None = None
    payer_identity: str | None = None         # who actually paid (if known)
    payer_tenant: str | None = None


@dataclass(frozen=True)
class BindingResult:
    feature_id: str
    identity_alias: str
    tenant_alias: str | None
    verdict: BindingVerdict
    dimension: BindingDimension
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {"feature_id": self.feature_id, "identity_alias": self.identity_alias, "tenant_alias": self.tenant_alias,
                "verdict": self.verdict.value, "dimension": self.dimension.value, "detail": self.detail}


def check_binding(obs: BindingObservation) -> BindingResult:
    """Decide the binding verdict for one observation. Deterministic; an
    indeterminate outcome is INCONCLUSIVE, never a guessed violation."""
    def result(verdict: BindingVerdict, dimension: BindingDimension, detail: str) -> BindingResult:
        return BindingResult(obs.feature_id, obs.identity_alias, obs.tenant_alias, verdict, dimension, detail)

    if obs.outcome == "indeterminate":
        return result(BindingVerdict.INCONCLUSIVE, BindingDimension.NONE,
                      "oracle outcome indeterminate -- binding can neither be confirmed nor denied")
    if obs.outcome == "denied":
        return result(BindingVerdict.HOLD, BindingDimension.NONE, "feature denied -- no entitlement to bind")
    if obs.outcome != "allowed":
        return result(BindingVerdict.INCONCLUSIVE, BindingDimension.NONE, f"unrecognized outcome {obs.outcome!r}")

    # outcome == "allowed": it must be backed by THIS subject's own qualifying payment.
    if not obs.qualifying_payment:
        return result(BindingVerdict.VIOLATED, BindingDimension.UNPAID_ACCESS,
                      "feature ALLOWED for a subject with no qualifying payment of its own (unpaid access)")
    if obs.payer_identity is not None and obs.payer_identity != obs.identity_alias:
        return result(BindingVerdict.VIOLATED, BindingDimension.CROSS_IDENTITY,
                      f"feature ALLOWED for {obs.identity_alias!r} but the qualifying payment was made by {obs.payer_identity!r}")
    if obs.payer_tenant is not None and obs.tenant_alias is not None and obs.payer_tenant != obs.tenant_alias:
        return result(BindingVerdict.VIOLATED, BindingDimension.CROSS_TENANT,
                      f"feature ALLOWED under tenant {obs.tenant_alias!r} but the qualifying payment was under tenant {obs.payer_tenant!r}")
    return result(BindingVerdict.HOLD, BindingDimension.NONE,
                  "feature ALLOWED and bound to the subject's own qualifying payment")


def analyze_bindings(observations: Iterable[BindingObservation]) -> dict[str, Any]:
    """Consolidated binding report over a set of observations: the per-observation
    results, a verdict tally, and the violations (with their broken dimension)
    surfaced first. Deterministic ordering."""
    results = [check_binding(o) for o in observations]
    tally: dict[str, int] = {}
    for r in results:
        tally[r.verdict.value] = tally.get(r.verdict.value, 0) + 1
    violations = sorted((r.to_dict() for r in results if r.verdict is BindingVerdict.VIOLATED),
                        key=lambda d: (d["feature_id"], d["identity_alias"], d["dimension"]))
    return {
        "module_version": MODULE_VERSION,
        "checked": len(results),
        "verdict_tally": dict(sorted(tally.items())),
        "all_bindings_hold": not violations,
        "violations": violations,
        "results": [r.to_dict() for r in results],
        "note": ("Declarative binding cross-check: an ALLOWED outcome must be bound to the subject's own qualifying "
                 "payment. Complements (does not replace) PBB-G/PBB-X, which prove a live bypass with the full "
                 "oracle chain, and entitlement_invariants.py, which checks the entitlement-state dimension."),
    }
