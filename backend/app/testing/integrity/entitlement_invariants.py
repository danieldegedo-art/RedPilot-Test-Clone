"""B2: Entitlement Invariant Library.

Codifies the entitlement invariants (spec Section 3 / §336) as a declarative,
versioned rule library: each invariant is a deterministic, checkable PREDICATE
over an entitlement observation, returning HOLD / VIOLATED / INCONCLUSIVE -- never
a heuristic judgement. The invariant STATEMENTS are reused verbatim from the
pre-registered oracle specs (`findings.SPECS[...].invariant`) so there is a single
source of truth and nothing is re-worded or invented.

This is distinct from `app/testing/invariants.py` (metamorphic request/response
invariants over HTTP attempt records). B2 is the ENTITLEMENT-STATE layer: "a
protected feature executes only if entitlement is in the valid set at time of
use", checked over paired before/after oracle observations.

Each invariant carries a FALSE-POSITIVE guard (spec §3.4/§3.5): an intended
business rule (a documented grace period, an intentionally shared resource, a
feature the owner declares free) must be excluded before a violation is believed.
A missing input yields INCONCLUSIVE, never a guessed violation. The library is
versioned and each invariant can be disabled without affecting the others.

Stdlib only; pure.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable

from app.testing.integrity.findings import EXPERIMENT_CLASSES, SPECS

LIBRARY_VERSION = "entitlement-invariants/1.0"


class InvariantStatus(str, Enum):
    HOLD = "HOLD"
    VIOLATED = "VIOLATED"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass(frozen=True)
class EntitlementObservation:
    """Typed facts from paired before/after protected-feature-oracle probes.
    Any field left None means 'not observed' -> the invariants that need it are
    INCONCLUSIVE, never guessed."""
    payment_qualifying: bool | None = None       # a valid, qualifying payment occurred
    feature_usable: bool | None = None           # the protected feature was actually usable (server-enforced)
    is_payer_identity: bool | None = None         # the using identity is the one that paid
    is_payer_tenant: bool | None = None           # the benefiting tenant is the one that paid
    paid_tier_rank: int | None = None             # tier actually paid for (higher = more)
    used_tier_rank: int | None = None             # tier actually usable
    billed_below_public_price: bool | None = None
    top_tier_usable: bool | None = None
    uses_observed: int | None = None              # quota uses obtained
    paid_quota: int | None = None
    refund_confirmed: bool | None = None
    beyond_revocation_tolerance: bool | None = None
    view_claims_paid: bool | None = None          # a customer-visible page claims paid/active
    server_allows: bool | None = None             # the server-enforced outcome
    never_paid: bool | None = None                # the identity never paid
    unrelated_identity: bool | None = None         # an identity unrelated to any payer


@dataclass(frozen=True)
class EntitlementInvariant:
    invariant_id: str
    statement: str
    p0_class: str
    required: tuple[str, ...]
    _violated: Callable[[EntitlementObservation], bool]
    false_positive_guard: str
    enabled: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {"invariant_id": self.invariant_id, "statement": self.statement, "p0_class": self.p0_class,
                "required": list(self.required), "false_positive_guard": self.false_positive_guard, "enabled": self.enabled}


@dataclass(frozen=True)
class InvariantResult:
    invariant_id: str
    status: InvariantStatus
    statement: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {"invariant_id": self.invariant_id, "status": self.status.value, "statement": self.statement, "reason": self.reason}


def _inv(hyp: str, required: tuple[str, ...], violated: Callable[[EntitlementObservation], bool], guard: str) -> EntitlementInvariant:
    return EntitlementInvariant(hyp, SPECS[hyp].invariant, EXPERIMENT_CLASSES[hyp], required, violated, guard)


# The library -- one invariant per pre-registered oracle class, statement reused from SPECS.
LIBRARY: tuple[EntitlementInvariant, ...] = (
    _inv("PBB-U", ("payment_qualifying", "feature_usable"), lambda o: o.payment_qualifying is False and o.feature_usable is True,
         "Confirm the payment really was non-qualifying (declined/cancelled/abandoned), not a sandbox-confirmed one."),
    _inv("PBB-F", ("paid_tier_rank", "used_tier_rank"), lambda o: (o.used_tier_rank or 0) > (o.paid_tier_rank or 0),
         "Confirm the higher tier was not granted by a documented promotion/trial."),
    _inv("PBB-H", ("billed_below_public_price", "top_tier_usable"), lambda o: o.billed_below_public_price is True and o.top_tier_usable is True,
         "Confirm the lower amount is not a documented regional/discounted public price for that currency."),
    _inv("PBB-C", ("uses_observed", "paid_quota"), lambda o: (o.uses_observed or 0) > (o.paid_quota or 0),
         "Confirm the extra uses are not a documented allowance/rollover."),
    _inv("PBB-G", ("feature_usable", "is_payer_tenant"), lambda o: o.feature_usable is True and o.is_payer_tenant is False,
         "Confirm the resource is not an intentionally shared platform-level asset (spec §3 cross-tenant guard)."),
    _inv("PBB-X", ("feature_usable", "is_payer_identity"), lambda o: o.feature_usable is True and o.is_payer_identity is False,
         "Confirm the payment was not legitimately transferable/giftable by design."),
    _inv("PBB-R", ("refund_confirmed", "feature_usable", "beyond_revocation_tolerance"),
         lambda o: o.refund_confirmed is True and o.feature_usable is True and o.beyond_revocation_tolerance is True,
         "Distinguish a documented grace period from true indefinite access (spec §3.4)."),
    _inv("PBB-E", ("view_claims_paid", "server_allows"), lambda o: o.view_claims_paid != o.server_allows,
         "NON-AUTHORITATIVE: a view/server divergence is a trust defect, never a P0 on its own (the server outcome governs)."),
    _inv("PBB-LEAK", ("unrelated_identity", "feature_usable"), lambda o: o.unrelated_identity is True and o.feature_usable is True,
         "Confirm the unrelated identity has no legitimate shared-plan/team entitlement."),
    _inv("PBB-OPEN", ("never_paid", "feature_usable"), lambda o: o.never_paid is True and o.feature_usable is True,
         "Confirm the feature is actually meant to be paid-only (plan-gating is customer-declared)."),
)
_BY_ID = {i.invariant_id: i for i in LIBRARY}


def get(invariant_id: str) -> EntitlementInvariant | None:
    return _BY_ID.get(invariant_id)


def enabled_invariants() -> tuple[EntitlementInvariant, ...]:
    return tuple(i for i in LIBRARY if i.enabled)


def check(invariant: EntitlementInvariant, obs: EntitlementObservation) -> InvariantResult:
    missing = [f for f in invariant.required if getattr(obs, f) is None]
    if missing:
        return InvariantResult(invariant.invariant_id, InvariantStatus.INCONCLUSIVE, invariant.statement,
                               f"inconclusive: missing observation(s) {missing} (never guessed)")
    if invariant._violated(obs):
        return InvariantResult(invariant.invariant_id, InvariantStatus.VIOLATED, invariant.statement,
                               f"VIOLATED (subject to the false-positive guard: {invariant.false_positive_guard})")
    return InvariantResult(invariant.invariant_id, InvariantStatus.HOLD, invariant.statement, "holds for this observation")


def check_all(obs: EntitlementObservation) -> list[InvariantResult]:
    return [check(i, obs) for i in enabled_invariants()]


def check_all_payload(obs: EntitlementObservation) -> dict[str, Any]:
    results = check_all(obs)
    return {"library_version": LIBRARY_VERSION, "results": [r.to_dict() for r in results],
            "violated": [r.invariant_id for r in results if r.status == InvariantStatus.VIOLATED],
            "note": "Deterministic predicate checks over entitlement observations; a VIOLATED result still requires its false-positive guard to be cleared before a finding is believed."}
