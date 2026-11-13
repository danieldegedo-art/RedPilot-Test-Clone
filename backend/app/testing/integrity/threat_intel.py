"""B40 (in-scope half): Threat-Led Test Ingestion -> prioritization.

B40's third facet, kept inside the owner's scope: ingest DISCLOSED advisory categories
(public threat intel about payment-abuse classes) and turn them into a PRIOR over the
pre-registered oracle classes -- i.e. which existing oracles to try first given what's
being seen in the wild. That is the whole capability: ingestion -> prioritization.

What stays OUT (owner scope, as everywhere in B40): WEAPONIZATION -- this module never
turns a disclosed bypass into an attack or a new probe; it only reweights the fixed
oracle set. And CREDENTIAL/SECRET inventory -- there is no surface for it here.

Bounds: a fixed, declared category->class map (ZR-036); unknown categories are listed
as `unmapped`, never invented into a class; the prior is Laplace-smoothed so no oracle
is dropped; deterministic. The prior feeds the planner like B31's, never a verdict.

Stdlib only; pure.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.testing.integrity.findings import EXPERIMENT_CLASSES

MODULE_VERSION = "threat-intel/1.0"
_CLASSES = tuple(sorted(EXPERIMENT_CLASSES.values()))
_N = len(_CLASSES)

# Fixed, declared mapping from a disclosed advisory category to the pre-registered
# oracle class(es) it suggests prioritising. Nothing is mapped to an off-catalog target.
ADVISORY_MAP: dict[str, tuple[str, ...]] = {
    "unconfirmed_payment": ("unconfirmed_payment_grants_access",),
    "coupon_abuse": ("plan_or_price_binding",),
    "currency_mismatch": ("currency_binding",),
    "price_tampering": ("plan_or_price_binding", "currency_binding"),
    "quota_replay": ("duplicate_value_via_return_flow_repetition",),
    "cross_tenant": ("cross_tenant_binding",),
    "cross_identity": ("cross_identity_binding",),
    "refund_retention": ("retention_after_refund",),
    "ui_divergence": ("ui_vs_server_divergence",),
    "open_access": ("paid_feature_open_to_unpaid",),
    "entitlement_leak": ("entitlement_leak_to_unrelated_identity",),
}


@dataclass(frozen=True)
class ThreatPrior:
    prior: dict[str, float]          # normalised weight per pre-registered class (sums to 1)
    unmapped: tuple[str, ...]        # advisory categories with no mapping (ignored, never invented)
    ingested: int                    # number of recognised advisory->class credits applied

    def to_dict(self) -> dict[str, Any]:
        return {"prior": {k: round(v, 6) for k, v in self.prior.items()},
                "unmapped": list(self.unmapped), "ingested": self.ingested}


def ingest(advisories: list[str]) -> ThreatPrior:
    """Turn disclosed advisory categories into a prior over the pre-registered classes.
    Unknown categories are collected in `unmapped`, never mapped to a class."""
    credits = {c: 0 for c in _CLASSES}
    unmapped: list[str] = []
    ingested = 0
    for adv in advisories:
        classes = ADVISORY_MAP.get(adv)
        if classes is None:
            unmapped.append(adv)
            continue
        for cls in classes:
            credits[cls] += 1
            ingested += 1
    denom = ingested + _N
    prior = {c: (credits[c] + 1) / denom for c in _CLASSES}   # Laplace -> no oracle dropped
    return ThreatPrior(prior, tuple(unmapped), ingested)


def ingest_payload(advisories: list[str]) -> dict[str, Any]:
    res = ingest(advisories)
    return {"module_version": MODULE_VERSION, **res.to_dict(),
            "note": "Threat-led INGESTION -> prioritisation only: reweights the fixed pre-registered oracle set "
                    "(ZR-036). No weaponization and no credential/secret inventory (no surface for either). The "
                    "prior feeds the planner, never a verdict."}
