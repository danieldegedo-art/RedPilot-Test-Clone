"""A13 (Severity & Impact-Assessment) + A28 (Impact Quantifier): one module.

Deterministic severity/impact assessment for a finding, from STRUCTURAL factors only
-- the finding's verdict and its pre-registered oracle class. It never invents a
financial figure; "impact" is a structural statement of what the verdict means for
entitlement, not a fabricated dollar amount.

Honesty rules:
  * A RULED_OUT finding is severity NONE -- never inflated. UNKNOWN/BLOCKED are
    INFORMATIONAL. Only a CONFIRMED_P0 carries its class's full severity; a
    PARTIALLY_VALIDATED finding is one step lower.
  * A view/server divergence (PBB-E, `ui_vs_server_divergence`) is capped at LOW even
    if a finding somehow claims it confirmed -- a non-authoritative surface is never a
    high-severity entitlement result (the PBB-E discipline).
  * The class must be a pre-registered oracle class; an off-catalog class is rejected
    (no severity invented for an unknown test).

Stdlib only; pure.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from app.testing.integrity.findings import EXPERIMENT_CLASSES

MODULE_VERSION = "impact-assessment/1.0"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"
    NONE = "none"


_ORDER = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFORMATIONAL, Severity.NONE)


def _downgrade(sev: Severity, *, floor: Severity = Severity.LOW) -> Severity:
    i = _ORDER.index(sev)
    lowered = _ORDER[min(i + 1, _ORDER.index(floor))]
    return lowered


# Base severity per pre-registered class for a CONFIRMED finding (structural, fixed).
CLASS_SEVERITY: dict[str, Severity] = {
    "paid_feature_open_to_unpaid": Severity.CRITICAL,
    "entitlement_leak_to_unrelated_identity": Severity.CRITICAL,
    "unconfirmed_payment_grants_access": Severity.HIGH,
    "cross_tenant_binding": Severity.HIGH,
    "cross_identity_binding": Severity.HIGH,
    "plan_or_price_binding": Severity.HIGH,
    "currency_binding": Severity.MEDIUM,
    "duplicate_value_via_return_flow_repetition": Severity.MEDIUM,
    "retention_after_refund": Severity.MEDIUM,
    "ui_vs_server_divergence": Severity.LOW,   # non-authoritative -> capped LOW
    "cross_subject_object_access": Severity.HIGH,  # BOLA: a non-owner reads another subject's private object
}
assert set(CLASS_SEVERITY) == set(EXPERIMENT_CLASSES.values()), "class-severity map must cover the pre-registered classes"

CLASS_IMPACT: dict[str, str] = {
    "paid_feature_open_to_unpaid": "a paid-gated feature is usable with no payment at all",
    "entitlement_leak_to_unrelated_identity": "one customer's payment makes a paid feature usable for an unrelated identity",
    "unconfirmed_payment_grants_access": "a declined/cancelled/abandoned payment yields a usable paid feature",
    "cross_tenant_binding": "a payment benefits a tenant that did not pay",
    "cross_identity_binding": "a payment is redeemable by an identity that did not make it",
    "plan_or_price_binding": "a higher tier is obtained without paying its public price",
    "currency_binding": "an under-billed currency payment unlocks the top tier",
    "duplicate_value_via_return_flow_repetition": "one payment yields more than the paid quota via return-flow repetition",
    "retention_after_refund": "a refunded payment keeps the paid feature usable beyond the declared tolerance",
    "ui_vs_server_divergence": "a customer-visible page contradicts the server-enforced outcome (trust defect, not a P0)",
}


@dataclass(frozen=True)
class Assessment:
    hypothesis_id: str
    p0_class: str
    severity: Severity
    impact: str
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        return {"hypothesis_id": self.hypothesis_id, "p0_class": self.p0_class, "severity": self.severity.value,
                "impact": self.impact, "rationale": self.rationale}


def assess(finding: dict[str, Any]) -> Assessment:
    """Structural severity/impact for one finding (needs `p0_class` + `verdict`)."""
    cls = finding.get("p0_class")
    verdict = finding.get("verdict", "")
    hid = finding.get("hypothesis_id", "?")
    if cls not in CLASS_SEVERITY:
        raise ValueError(f"unknown p0_class {cls!r} (not a pre-registered oracle class; severity is never invented)")

    base = CLASS_SEVERITY[cls]
    if verdict == "CONFIRMED_P0":
        sev, why = base, "confirmed P0 -> full class severity"
    elif verdict == "PARTIALLY_VALIDATED_PAYMENT_INTEGRITY_ISSUE":
        sev, why = _downgrade(base), "partially validated -> one step below the class severity"
    elif verdict == "RULED_OUT":
        sev, why = Severity.NONE, "ruled out -> no entitlement impact"
    else:
        sev, why = Severity.INFORMATIONAL, f"{verdict or 'no verdict'} -> informational (not a confirmed impact)"

    impact = CLASS_IMPACT[cls] if sev not in (Severity.NONE, Severity.INFORMATIONAL) else "no confirmed entitlement impact"
    return Assessment(hid, cls, sev, impact,
                      f"{why}; structural assessment only (no fabricated financial figure)")


def assess_all(findings: list[dict[str, Any]]) -> dict[str, Any]:
    results = [assess(f) for f in findings]
    counts: dict[str, int] = {}
    for a in results:
        counts[a.severity.value] = counts.get(a.severity.value, 0) + 1
    return {"module_version": MODULE_VERSION, "assessments": [a.to_dict() for a in results],
            "severity_counts": dict(sorted(counts.items())),
            "note": "Severity is structural (verdict + pre-registered class), on a fixed scale; RULED_OUT is NONE, "
                    "a view/server divergence is capped LOW, and no financial figure is fabricated."}
