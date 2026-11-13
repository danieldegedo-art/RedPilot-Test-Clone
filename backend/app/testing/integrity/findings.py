"""Finding model + pre-registered oracle specifications of the customer-level engine.

``Finding.__post_init__`` makes ``CONFIRMED_P0`` unconstructible without a ``ConfirmationToken`` that covers the hypothesis and that was
issued by ``ConfirmationGate.evaluate`` (i.e. without the full external Protected-Feature Oracle chain). Stdlib only.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.core.control_port import ConfirmationRefused
from app.core.control_port.contract import now_iso
from app.testing.purity.taxonomy import TruthLabel, Verdict

ENGINE_VERSION = "pbb-oracle-engine/1.0"


@dataclass(frozen=True)
class OracleSpec:
    """The ten elements every oracle is pre-registered with (fixed BEFORE any traffic, so no result can redefine its own test)."""

    invariant: str
    baseline_state: str
    identity_and_tenant: str
    controlled_variable: str
    action_sequence: str
    expected_outcome: str
    p0_condition: str
    rule_out_condition: str
    stop_condition: str
    evidence_requirements: str

    def completeness(self) -> float:
        values = list(self.__dict__.values())
        return sum(1 for v in values if isinstance(v, str) and v.strip()) / len(values)


_COMMON_EVIDENCE = ("every call is an admitted artifact with external provenance (identity alias, tenant alias, session isolation id, authorization ref, "
                    "hash, external classification); the allowed/denied outcome comes only from USING the server-enforced feature")
_COMMON_STOP = "scope/purity denial, kill switch, request budget exhausted, a pre-existing entitlement on a fresh identity (fixture contaminated), or any admitted-evidence rejection"

SPECS: dict[str, OracleSpec] = {
    "PBB-U": OracleSpec(
        invariant="A payment that is declined, cancelled or abandoned never makes a paid feature usable -- whatever the return URL, page or badge claims.",
        baseline_state="Fresh synthetic identity: paid feature DENIED (control identity K also denied, and a legitimate payer is ALLOWED, so the oracle can say both).",
        identity_and_tenant="subject S (own synthetic tenant, one per variant), control K, clean re-session of S.",
        controlled_variable="payment outcome (declined | cancelled) followed by a return-flow request claiming success.",
        action_sequence="pre-check S -> checkout (cheapest plan) -> sandbox pay with outcome -> return flow with success claim -> USE the feature as S -> clean re-session of S -> re-check K.",
        expected_outcome="Feature DENIED for S in every variant (a UI/redirect/badge claiming success is a divergence, not an entitlement).",
        p0_condition="S USES the feature successfully after a non-qualifying payment, K still denied, reproduced by a clean session of S, all artifacts admitted.",
        rule_out_condition="S denied in every tested variant while the oracle is proven discriminating (legitimate payer allowed, clean identity denied).",
        stop_condition=_COMMON_STOP, evidence_requirements=_COMMON_EVIDENCE),
    "PBB-F": OracleSpec(
        invariant="The plan a customer pays for -- at the price on the public price list -- is the plan they get. Neither a cheaper payment nor a client-side claim buys a higher tier.",
        baseline_state="Legitimate cheapest-plan payer: tier feature DENIED; legitimate top-plan payer: tier feature ALLOWED; clean identity: DENIED.",
        identity_and_tenant="V1 (cheapest payer from controls), S1 (checkout amount tamper), S2 (return plan claim), control K.",
        controlled_variable="plan enforcement / amount accepted at checkout / plan claimed at the return flow.",
        action_sequence="(0) V1 on tier feature; (A) checkout top plan with the cheapest public amount -> pay -> return -> tier; (B) pay cheapest -> return -> tier denied -> return with top-plan claim -> tier.",
        expected_outcome="Tier feature DENIED for every payer of the cheapest plan; a tampered checkout is rejected or billed at the public price.",
        p0_condition="A payer who did not pay the top-plan price USES the tier feature, K denied, clean re-session reproduces, artifacts admitted.",
        rule_out_condition="All applicable channels end DENIED (or the tampered checkout is rejected) with a discriminating tier oracle.",
        stop_condition=_COMMON_STOP, evidence_requirements=_COMMON_EVIDENCE),
    "PBB-H": OracleSpec(
        invariant="Paying in another listed currency is billed at the public price of that currency; an under-billed payment never unlocks the top tier.",
        baseline_state="Top-plan tier feature DENIED for a fresh identity; public price list gives the amount per currency.",
        identity_and_tenant="subject S (own tenant), control K.",
        controlled_variable="checkout currency.",
        action_sequence="checkout top plan in the alternative currency -> compare billed amount/currency with the public price list -> sandbox success -> return -> USE tier feature.",
        expected_outcome="Billed amount equals the public price for that currency, or the checkout is rejected; no tier access on an under-billed payment.",
        p0_condition="Billed amount < public price AND S USES the tier feature, K denied, clean re-session reproduces.",
        rule_out_condition="No billing mismatch, or a mismatch with tier access correctly DENIED (reported as a billing divergence, not P0).",
        stop_condition=_COMMON_STOP, evidence_requirements=_COMMON_EVIDENCE),
    "PBB-C": OracleSpec(
        invariant="One successful payment yields exactly the paid quota, however often the customer's browser repeats the return flow (refresh, back button, retry).",
        baseline_state="Legitimate single-payment baseline Q: counts n0 successful uses of the quota feature before the first denial; clean identity denied.",
        identity_and_tenant="baseline payer Q, subject R (and independent R2 for reproduction), control K.",
        controlled_variable="number of return-flow repetitions (0 for Q, 2 for R).",
        action_sequence="Q: pay -> return once -> use quota until denied (n0). R: pay -> return -> repeat return twice -> use until denied (n1). R2 repeats R. Re-check K.",
        expected_outcome="n1 == n0 (repetition grants nothing).",
        p0_condition="n1 > n0 for R and again for the independent R2, K denied, artifacts admitted.",
        rule_out_condition="n1 <= n0 for R, with 0 < n0 < probe cap (a bounded, observable quota).",
        stop_condition=_COMMON_STOP + "; quota not bounded within the probe cap (cap is low-volume by contract)", evidence_requirements=_COMMON_EVIDENCE),
    "PBB-G": OracleSpec(
        invariant="A payment benefits only the tenant that paid; another tenant cannot be named as beneficiary by a client claim.",
        baseline_state="Beneficiary identity B (own tenant) denied; control K denied.",
        identity_and_tenant="payer S/tenant_s, beneficiary B/tenant_b (its OWN tenant id, visible to B), control K.",
        controlled_variable="tenant claimed at the return flow.",
        action_sequence="S pays -> B pre-check denied -> S calls return flow naming B's tenant -> B USES the feature -> clean re-session of B -> re-check K.",
        expected_outcome="B denied.",
        p0_condition="B (never paid) USES the feature, K denied, clean re-session of B reproduces, artifacts admitted.",
        rule_out_condition="B denied while the oracle is discriminating.",
        stop_condition=_COMMON_STOP + "; B's tenant id not externally available", evidence_requirements=_COMMON_EVIDENCE),
    "PBB-X": OracleSpec(
        invariant="A payment can only be redeemed by the identity that made it.",
        baseline_state="Redeemer identity B denied; control K denied.",
        identity_and_tenant="payer S, redeemer B (different identity and tenant), control K.",
        controlled_variable="identity presenting the payment reference at the return flow.",
        action_sequence="S pays (no return by S) -> B pre-check denied -> B calls return flow with S's payment reference -> B USES the feature -> clean re-session of B -> re-check K.",
        expected_outcome="B denied (return flow rejects a payment that is not B's).",
        p0_condition="B USES the feature thanks to S's payment, K denied, clean re-session reproduces, artifacts admitted.",
        rule_out_condition="B denied while the oracle is discriminating.",
        stop_condition=_COMMON_STOP, evidence_requirements=_COMMON_EVIDENCE),
    "PBB-R": OracleSpec(
        invariant="After a customer-visible refund of their own sandbox payment the paid feature stops working within the declared revocation tolerance.",
        baseline_state="Payer V ALLOWED before the refund; control K denied.",
        identity_and_tenant="payer V (own tenant), clean re-session of V, control K.",
        controlled_variable="elapsed time since the externally confirmed refund (bounded poll schedule, <= 8 polls).",
        action_sequence="V pays + returns -> allowed -> refund own payment -> confirm refund response -> poll the feature on the schedule (and just beyond the declared tolerance) -> clean re-session at the first allowed-beyond-tolerance poll.",
        expected_outcome="Feature DENIED at or before the declared tolerance.",
        p0_condition="Feature still USABLE beyond the declared tolerance (CUSTOMER_DECLARED threshold), reproduced by a clean session, K denied, artifacts admitted.",
        rule_out_condition="First DENIED observation within the tolerance.",
        stop_condition=_COMMON_STOP + "; refund not externally confirmed", evidence_requirements=_COMMON_EVIDENCE + "; the measured lag is an upper bound given by the poll schedule"),
    "PBB-E": OracleSpec(
        invariant="What customer-visible pages say (return message, subscription view) never contradicts the server-enforced paid-feature outcome.",
        baseline_state="Observations collected during the controls and PBB-U (no extra traffic).",
        identity_and_tenant="V1 (legit payer), K (clean), S (declined payer).",
        controlled_variable="none (observation of the customer-visible views against the oracle).",
        action_sequence="compare subscription view / return message with the oracle outcome of the same identity at the same time.",
        expected_outcome="View says paid exactly where the oracle says ALLOWED.",
        p0_condition="never P0 by itself: a view/UI claim is non-authoritative evidence.",
        rule_out_condition="No contradiction observed (or none observable).",
        stop_condition=_COMMON_STOP, evidence_requirements=_COMMON_EVIDENCE),
    "PBB-LEAK": OracleSpec(
        invariant="One customer's payment never makes a paid feature usable for an unrelated identity that has not paid.",
        baseline_state="Clean control identity K DENIED before any payment of this run; a legitimate payer is then ALLOWED.",
        identity_and_tenant="control K (never pays, own tenant), legitimate payer V1 (own tenant), clean re-session of K.",
        controlled_variable="whether another identity has paid (time order: K denied -> V1 pays -> K checked again).",
        action_sequence="K uses the feature (denied) -> V1 pays and returns -> V1 uses the feature (allowed) -> K uses the feature again -> clean re-session of K.",
        expected_outcome="K stays DENIED.",
        p0_condition="K, which never paid, USES the feature after V1's payment, K was denied before, a clean re-session of K reproduces it, artifacts admitted.",
        rule_out_condition="K denied after V1's payment (checked as part of the controls; no separate finding is emitted then).",
        stop_condition=_COMMON_STOP, evidence_requirements=_COMMON_EVIDENCE),
    "PBB-OPEN": OracleSpec(
        invariant="A feature the brief declares plan-gated is DENIED to a fresh identity that never paid.",
        baseline_state="Two independent fresh identities, no payment attempt.",
        identity_and_tenant="K and K2 (independent fresh synthetic identities).",
        controlled_variable="none.",
        action_sequence="USE the feature as K and as K2.",
        expected_outcome="Both DENIED.",
        p0_condition="never CONFIRMED_P0: with no denial control the confirmation pattern cannot be executed -> PARTIALLY_VALIDATED.",
        rule_out_condition="Both denied.",
        stop_condition=_COMMON_STOP, evidence_requirements=_COMMON_EVIDENCE),
}

EXPERIMENT_CLASSES: dict[str, str] = {
    "PBB-U": "unconfirmed_payment_grants_access", "PBB-F": "plan_or_price_binding", "PBB-H": "currency_binding", "PBB-C": "duplicate_value_via_return_flow_repetition",
    "PBB-G": "cross_tenant_binding", "PBB-X": "cross_identity_binding", "PBB-R": "retention_after_refund", "PBB-E": "ui_vs_server_divergence", "PBB-OPEN": "paid_feature_open_to_unpaid", "PBB-LEAK": "entitlement_leak_to_unrelated_identity",
}

# ZR-006: the identity/tenant SCOPE each experiment probes. The smallest
# reasonable, documented categorization (parallel to EXPERIMENT_CLASSES); used
# only for coverage reporting (coverage.py), never for any verdict.
SCOPE_BY_HYPOTHESIS: dict[str, str] = {
    "PBB-U": "single_identity", "PBB-F": "single_identity", "PBB-H": "single_identity", "PBB-C": "single_identity", "PBB-R": "single_identity",
    "PBB-G": "cross_tenant", "PBB-X": "cross_identity", "PBB-LEAK": "unrelated_identity", "PBB-E": "view_consistency", "PBB-OPEN": "open_access",
}


@dataclass
class Finding:
    hypothesis_id: str
    p0_class: str
    title: str
    verdict: Verdict
    confidence: str
    summary: str
    spec: OracleSpec
    artifact_ids: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    divergences: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    token: Any = field(default=None, repr=False, compare=False)  # a ConfirmationToken issued by the confirmation gate (Control Adapter); answers covers()

    # ZR-019 (full schema, section 15.2) -- fields added beyond the original set.
    # Populated uniformly for every finding (see engine.py's _finding()):
    timestamp: str | None = None
    priority: str | None = None  # derived from verdict -- see engine.py's _PRIORITY_BY_VERDICT
    reproduction_status: str | None = None  # derived from verdict+token -- see engine.py's _finding()
    impact: str | None = None  # populated for CONFIRMED_P0 only, where it's a true structural statement of what the verdict means
    recommended_fix: str | None = None  # per-hypothesis-class remediation guidance, see engine.py's RECOMMENDED_FIX
    # Populated per-experiment where the local context exists (PBB-U demonstrates the pattern; not yet threaded through every experiment -- see engine.py):
    identity_tenant_dimension: str | None = None
    commercial_context: str | None = None
    expected_state: str | None = None
    actual_state: str | None = None
    payment_state: str | None = None
    entitlement_state: str | None = None
    server_side_oracle: str | None = None
    affected_flow: str | None = None  # flow FAMILY (fsm_compiler.FLOW_TYPES) the hypothesis exercises -- see engine.py's FLOW_BY_HYPOTHESIS; not yet a reference to a specific compiled FSM segment
    # Structurally present, deliberately None until the capability they depend on exists:
    reproduction_steps: str | None = None  # needs B20 (replay bundles)
    regression_test_reference: str | None = None  # ZR-023: set by regression.attach_regression_references in engine.run() (was benchmark-only)
    precondition: dict[str, Any] | None = None  # needs B32 (Phase 4)
    effect: dict[str, Any] | None = None  # needs B32 (Phase 4)

    def __post_init__(self) -> None:
        if self.verdict == Verdict.CONFIRMED_P0 and (self.token is None or not self.token.covers(self.hypothesis_id)):
            raise ConfirmationRefused("confirmed_p0_without_oracle_token", f"{self.hypothesis_id}: CONFIRMED_P0 requires a ConfirmationToken issued by ConfirmationGate (external Protected-Feature Oracle chain)")
        if self.confidence not in ("high", "medium", "low"):
            raise ValueError("confidence must be high|medium|low")
        if self.timestamp is None:
            self.timestamp = now_iso()

    def schema_completeness(self) -> float:
        """ZR-019's acceptance criterion / Section 19's hard gate: fraction of
        the full ZR-019 schema (section 15.2) that's actually populated, not
        merely present as a field. Mirrors OracleSpec.completeness() --
        counts non-empty strings and non-empty/non-None values generally,
        excluding fields that are structural bookkeeping rather than part of
        the schema itself (hypothesis_id/spec/token/artifact_ids -- the
        latter two are specifically covered by the 'server-side oracle' and
        'evidence references' schema items via server_side_oracle and
        artifact_ids respectively, so double-counting them here would be
        misleading, not more accurate)."""
        schema_fields = (
            "title", "priority", "verdict", "affected_flow", "identity_tenant_dimension", "commercial_context",
            "expected_state", "actual_state", "payment_state", "entitlement_state", "server_side_oracle",
            "artifact_ids", "reproduction_steps", "impact", "confidence", "limitations", "summary",
            "recommended_fix", "regression_test_reference", "reproduction_status", "timestamp",
            "precondition", "effect",
        )
        populated = 0
        for name in schema_fields:
            v = getattr(self, name)
            if v is None:
                continue
            if isinstance(v, str) and not v.strip():
                continue
            if isinstance(v, (list, dict)) and not v:
                continue
            populated += 1
        return populated / len(schema_fields)

    @property
    def truth_label(self) -> TruthLabel:
        return {Verdict.CONFIRMED_P0: TruthLabel.EXTERNALLY_REPRODUCED, Verdict.UNKNOWN: TruthLabel.UNKNOWN, Verdict.BLOCKED: TruthLabel.BLOCKED}.get(self.verdict, TruthLabel.EXTERNALLY_OBSERVED)

    def to_dict(self) -> dict[str, Any]:
        return {"hypothesis_id": self.hypothesis_id, "p0_class": self.p0_class, "title": self.title, "verdict": self.verdict.value, "confidence": self.confidence,
                "truth_label": self.truth_label.value, "summary": self.summary, "artifact_ids": list(self.artifact_ids), "reasons": list(self.reasons),
                "divergences": list(self.divergences), "limitations": list(self.limitations), "metrics": dict(self.metrics),
                "oracle_spec": dict(self.spec.__dict__), "confirmed_via_oracle_gate": self.token is not None,
                "internal_cause": "UNKNOWN (not externally observable; deliberately not inferred)"}


@dataclass
class EngineResult:
    findings: list[Finding]
    controls: dict[str, Any]
    ledger_summary: dict[str, Any]
    stats: dict[str, Any]
    brief_fingerprint: str
    engine_version: str = ENGINE_VERSION
    started_at: str = ""
    finished_at: str = ""
    replay_bundles: dict[str, Any] = field(default_factory=dict)  # ZR-015/B20: per-finding replay bundles (hypothesis_id -> ReplayBundle.to_dict())

    def by_id(self) -> dict[str, Finding]:
        return {f.hypothesis_id: f for f in self.findings}

    def verdicts(self) -> dict[str, str]:
        return {f.hypothesis_id: f.verdict.value for f in self.findings}

    def confirmed(self) -> list[Finding]:
        return [f for f in self.findings if f.verdict == Verdict.CONFIRMED_P0]

    def to_dict(self) -> dict[str, Any]:
        return {"engine_version": self.engine_version, "brief_fingerprint": self.brief_fingerprint, "started_at": self.started_at, "finished_at": self.finished_at,
                "controls": self.controls, "stats": self.stats, "evidence": self.ledger_summary, "replay_bundles": self.replay_bundles,
                "findings": [f.to_dict() for f in self.findings]}
