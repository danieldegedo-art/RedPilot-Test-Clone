"""Black-Box capability-gap engine: which P0 classes can the CUSTOMER-LEVEL engine cover, which are PARTIALLY covered, UNKNOWN or BLOCKED.

Honest by construction: coverage is derived from (a) what the Execution Brief makes externally testable and (b) what the experiments actually
concluded in this run. 'No confirmed P0' never means 'no P0 exists' -- every class that is not COVERED is listed with the smallest safe next
capability and the exact input that would unlock it. Classes that are impossible for a pure black-box tester (forging provider events,
concurrent duplicate checkouts, lifecycle clocks) are reported BLOCKED, never silently dropped and never 'passed'. Stdlib only.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.testing.integrity.brief import ExecutionBrief
from app.testing.integrity.findings import EngineResult
from app.testing.purity.taxonomy import Coverage, Verdict
from app.testing.integrity.coverage import coverage_matrix  # ZR-006/ZR-022: multi-dimensional coverage


@dataclass(frozen=True)
class GapRow:
    p0_class: str
    coverage: Coverage
    experiment: str | None
    external_evidence_available: str
    external_evidence_missing: str
    reason: str
    false_negative_risk: str
    false_positive_risk: str
    smallest_safe_next_capability: str
    required_input: str

    def statement(self) -> str:
        return f"{self.p0_class}: {self.coverage.value} -- {self.reason}"

    def to_dict(self) -> dict[str, Any]:
        return {"p0_class": self.p0_class, "coverage": self.coverage.value, "experiment": self.experiment, "external_evidence_available": self.external_evidence_available,
                "external_evidence_missing": self.external_evidence_missing, "reason": self.reason, "false_negative_risk": self.false_negative_risk,
                "false_positive_risk": self.false_positive_risk, "smallest_safe_next_capability": self.smallest_safe_next_capability, "required_input": self.required_input}


# (experiment id, class name, what a conclusive result covers, residual limitation that keeps it PARTIAL even when conclusive, input that unlocks it)
_ENGINE_CLASSES = (
    ("PBB-U", "unconfirmed_payment_grants_access", "decline + cancel outcomes with a success-claiming return flow", None, "an approved sandbox decline/cancel outcome token and a return-flow operation"),
    ("PBB-F", "plan_or_price_binding", "plan-not-enforced, tampered checkout amount, return-flow plan claim", "other tamper channels (coupon, quantity, proration) are not modelled", "two plans with public prices and a feature gated by the top plan"),
    ("PBB-H", "currency_binding", "one alternative currency vs. the public price list", "a single alternative currency", "a second currency in the public price list and a top-tier feature"),
    ("PBB-C", "duplicate_value_via_return_flow_repetition", "two sequential return-flow repetitions, counted through a quota feature", "concurrent duplicates are not tested (see provider/concurrency rows)", "a bounded quota/credit feature (< probe cap)"),
    ("PBB-G", "cross_tenant_binding", "return-flow tenant claim with two synthetic tenants", "other tenant-selection channels (headers, switch endpoints) are not modelled", "two approved synthetic tenants whose ids are visible to their own users"),
    ("PBB-X", "cross_identity_binding", "foreign payment reference presented by a second identity", "ID guessing/enumeration is deliberately not attempted", "two approved synthetic identities"),
    ("PBB-R", "retention_after_refund_or_revocation_lag", "bounded polling after an externally confirmed own-payment refund vs. a declared tolerance", "poll window is bounded; revocation after it stays UNKNOWN", "an approved self-service refund flow and revocation_sla_seconds"),
    ("PBB-E", "ui_vs_server_divergence", "subscription view / return message vs. the oracle", None, "a customer-visible subscription/billing view"),
)

_NOT_SUPPORTED = (
    ("provider_event_authenticity_and_replay", "Forging, replaying or unsigned-posting PROVIDER webhooks needs the provider's signing secret, a provider-facing endpoint list or provider dashboards: all target-side information, i.e. grey-box.",
     "an approved provider-sandbox flow in which the REAL provider emits test-mode events during a normal customer checkout, observed only through the customer-visible effect (protected-feature oracle)", "customer-owned provider sandbox account + approval; no secret is ever handed to the QA system"),
    ("concurrent_duplicate_checkout_or_race", "Parallel checkouts/returns are unsafe without explicit, known rate and concurrency limits; the engine is sequential and low-volume by contract.",
     "a brief that approves a bounded 2-way concurrency window plus a reset/cleanup path", "explicit concurrency approval, documented provider/merchant rate limits, a reset mechanism"),
    ("lifecycle_trial_coupon_renewal_expiry_downgrade", "No approved external fixture models time (renewal, expiry, trial end) or discount state; these flows are not exercised.",
     "approved sandbox clock/fixtures or declared coupon/trial operations, each coupled to a protected-feature oracle", "approved lifecycle operations + a sandbox time-control mechanism"),
)


def _coverage_for(exp: str, brief: ExecutionBrief | None, result: EngineResult | None, residual: str | None) -> tuple[Coverage, str]:
    if brief is None:
        return Coverage.BLOCKED, "no Execution Brief: nothing is authorised, so no request was sent"
    if result is None:
        return Coverage.UNKNOWN, "no run result"
    f = result.by_id().get(exp)
    if f is None:
        return Coverage.UNKNOWN, "experiment was not part of this run"
    if f.verdict == Verdict.BLOCKED:
        return Coverage.BLOCKED, f.summary
    if f.verdict == Verdict.UNKNOWN:
        return Coverage.UNKNOWN, f.summary
    if f.verdict in (Verdict.PARTIALLY_VALIDATED_PAYMENT_INTEGRITY_ISSUE, Verdict.SUSPECTED_PAYMENT_INTEGRITY_ISSUE):
        return Coverage.PARTIALLY_COVERED, f.summary
    return (Coverage.PARTIALLY_COVERED, f"conclusive ({f.verdict.value}) within the tested channels; {residual}") if residual else (Coverage.COVERED, f"conclusive ({f.verdict.value}) within the tested channels")


def capability_gaps(brief: ExecutionBrief | None, result: EngineResult | None) -> list[GapRow]:
    rows: list[GapRow] = []
    for exp, name, covers, residual, unlock in _ENGINE_CLASSES:
        coverage, reason = _coverage_for(exp, brief, result, residual)
        conclusive = coverage in (Coverage.COVERED, Coverage.PARTIALLY_COVERED) and result is not None and (result.by_id().get(exp) is not None) and result.by_id()[exp].verdict in (Verdict.CONFIRMED_P0, Verdict.RULED_OUT)
        rows.append(GapRow(
            p0_class=name, coverage=coverage, experiment=exp, external_evidence_available=covers if conclusive else (covers if brief is not None else "none: no authorised target"),
            external_evidence_missing=residual or ("nothing known" if coverage == Coverage.COVERED else f"input needed: {unlock}"), reason=reason,
            false_negative_risk="low" if coverage == Coverage.COVERED else "medium" if coverage == Coverage.PARTIALLY_COVERED else "high",
            false_positive_risk="low (a confirmation needs control + feature use + clean reproduction)", smallest_safe_next_capability=f"declare/provide: {unlock}", required_input=unlock))
    for name, why, capability, needed in _NOT_SUPPORTED:
        rows.append(GapRow(p0_class=name, coverage=Coverage.BLOCKED, experiment=None, external_evidence_available="none", external_evidence_missing=why, reason="NOT SUPPORTED in pure black-box mode (never 'passed')",
                           false_negative_risk="high", false_positive_risk="n/a", smallest_safe_next_capability=capability, required_input=needed))
    if result is not None and "PBB-LEAK" in result.by_id():
        leak = result.by_id()["PBB-LEAK"]
        rows.append(GapRow(p0_class="entitlement_leak_to_unrelated_identity", coverage=Coverage.COVERED if leak.verdict == Verdict.CONFIRMED_P0 else Coverage.PARTIALLY_COVERED, experiment="PBB-LEAK",
                           external_evidence_available="a never-paying control identity was denied, then allowed after another identity's payment", external_evidence_missing="the internal cause stays UNKNOWN by design",
                           reason=leak.summary, false_negative_risk="low", false_positive_risk="low (control + clean-session reproduction)", smallest_safe_next_capability="fix the entitlement binding, then re-run the controls", required_input="none"))
    if result is not None and "PBB-OPEN" in result.by_id():
        rows.append(GapRow(p0_class="paid_feature_open_to_unpaid", coverage=Coverage.PARTIALLY_COVERED, experiment="PBB-OPEN", external_evidence_available="a fresh identity that never paid USED the feature",
                           external_evidence_missing="a denial control for a feature that is open to everyone (confirmation pattern not executable)", reason=result.by_id()["PBB-OPEN"].summary, false_negative_risk="low",
                           false_positive_risk="medium (plan-gating is customer-declared)", smallest_safe_next_capability="confirm with the product owner whether the feature is meant to be paid-only", required_input="product-owner confirmation"))
    return rows


def unknown_exposures(rows: list[GapRow]) -> list[GapRow]:
    return [r for r in rows if r.coverage != Coverage.COVERED]


def coverage_report(brief: ExecutionBrief | None, result: EngineResult | None) -> dict[str, Any]:
    """ZR-022: the per-p0-class capability-gap register PLUS the ZR-006
    multi-dimensional coverage matrix (flow + scope axes and a verdict tally),
    in one structure. Still never 'passed': a class/flow/scope is COVERED only
    when every contributing experiment was conclusive (CONFIRMED_P0 or RULED_OUT)."""
    rows = capability_gaps(brief, result)
    matrix = coverage_matrix(result) if result is not None else None
    return {
        "capability_gaps": [r.to_dict() for r in rows],
        "unknown_exposures": [r.to_dict() for r in unknown_exposures(rows)],
        "coverage_matrix": matrix.to_dict() if matrix is not None else None,
        "summary": {
            "p0_classes_total": len(rows),
            "p0_classes_covered": sum(1 for r in rows if r.coverage == Coverage.COVERED),
            "verdict_tally": dict(matrix.verdict_tally) if matrix is not None else {},
        },
    }
