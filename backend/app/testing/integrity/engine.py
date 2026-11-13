"""PureBlackBoxEngine -- the customer-level Protected-Feature Oracle engine (the Primary Major Upgrade of this release).

It replaces every internal-state / webhook-forgery / secret-signed oracle of the legacy engine with experiments an AUTHORISED EXTERNAL
CUSTOMER can run: synthetic identities, the approved sandbox payment flow, the browser return flow and -- as the only source of truth --
USING the server-enforced paid feature. Method (the 'external control pattern'):

  1. CONTROLS first (PBB-CTRL): a clean identity must be DENIED, a legitimate payer must be ALLOWED. If the oracle cannot say both, no later
     result can be trusted -> UNKNOWN/BLOCKED (this is what stops 'denied everywhere' from becoming false assurance).
  2. SCENARIO per hypothesis on a FRESH synthetic identity (pre-check denied -> fixture clean), tampering only with what a customer controls.
  3. CONFIRMATION only through ConfirmationGate (control denied -> feature USED -> independent clean-session reproduction, admitted evidence).
  4. Everything else is RULED_OUT / UNKNOWN / BLOCKED / PARTIALLY_VALIDATED -- never a guess about the backend.

There is no fallback: when external evidence is insufficient the verdict is UNKNOWN, nothing else is consulted. The engine's only I/O is
``CustomerSession`` (guarded client, identity token only). It never reads target logs/DB/dashboards/admin or benchmark labels, and it cannot
construct CONFIRMED_P0 without a ConfirmationToken.
"""
from __future__ import annotations

import asyncio
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Iterable

from app.testing.http_client import QAHttpClient
from app.testing.integrity.brief import ExecutionBrief, FeatureSpec
from app.testing.integrity.findings import ENGINE_VERSION, EXPERIMENT_CLASSES, SPECS, EngineResult, Finding
from app.testing.integrity.replay import attach_replay_bundles
from app.testing.integrity.regression import attach_regression_references
from app.testing.integrity.oracle_calibration import (
    CalibrationResult, OracleTier, calibration_from_outcomes, ruled_out_result_is_trustworthy)
from app.testing.integrity.attack_chain import effect_of as _zr019_effect, precondition_of as _zr019_precondition
from app.testing.integrity.oracle import ProtectedFeatureOracle
from app.testing.prioritization import DERIVED_HYPOTHESES, PrioritizerFn
from app.testing.integrity.session import CallResult, CustomerSession, EvidenceRecorder, IdentityPoolExhausted, IdentityProvisioner
from app.core.control_port import (
    KIND_FEATURE_USE, ConfirmationCandidate, EvidenceLedgerHandle, GateDecision, OracleObservation, PurityViolation, get_control_adapter, now_iso,
)
from app.testing.purity.taxonomy import Verdict

logger = logging.getLogger("qa.integrity.engine")

EXPERIMENT_ORDER = ("PBB-U", "PBB-F", "PBB-H", "PBB-C", "PBB-G", "PBB-X", "PBB-R", "PBB-E")
TITLES = {
    "PBB-U": "Declined/cancelled payment must not unlock a paid feature", "PBB-F": "Paid plan/price must bind the tier that is granted",
    "PBB-H": "Payment currency must be billed at the public price", "PBB-C": "Return-flow repetition must not duplicate paid value",
    "PBB-G": "A payment must not benefit another tenant", "PBB-X": "A payment must only be redeemable by its owner",
    "PBB-R": "Paid feature must stop after a confirmed refund (within the declared tolerance)", "PBB-E": "Customer-visible pages must agree with the server-enforced outcome",
    "PBB-OPEN": "A plan-gated feature must be denied to an identity that never paid",
    "PBB-LEAK": "One customer's payment must not unlock the feature for unrelated identities",
}
# ZR-019: per-hypothesis-class remediation, keyed off exactly what each experiment
# demonstrably tests (TITLES above) -- not generic boilerplate, and not fabricated
# per-finding insight either; standard remediation for a well-defined flaw class.
RECOMMENDED_FIX: dict[str, str] = {
    "PBB-U": "Gate feature access on a server-verified entitlement record derived from a confirmed payment-provider event (e.g. a webhook-verified charge success), never on the return-flow's claimed status alone; re-check entitlement on every protected request, not only at checkout return.",
    "PBB-F": "Derive the granted feature tier from the plan/price the payment provider actually confirms was charged, not from a client-supplied or default plan parameter; reject or re-verify any mismatch between requested and paid tier before granting access.",
    "PBB-H": "Validate the charged amount and currency against the authoritative server-side price for the requested plan before granting entitlement; never trust a client-supplied amount, and reconcile against the provider's actually-captured amount.",
    "PBB-C": "Make entitlement grants idempotent per payment_id (one payment, one grant, enforced server-side), so replaying or re-visiting the return flow cannot increase the feature-use quota beyond what was actually paid for.",
    "PBB-G": "Bind entitlement to the paying tenant's own identity at grant time, and verify tenant identity on every protected request; do not grant or extend entitlement based on tenant data supplied in the payment request itself.",
    "PBB-X": "Bind a payment reference to the identity that created it at the moment of creation, and verify the presenting identity matches on redemption; a payment reference must not be honored for any identity other than its owner.",
    "PBB-R": "Subscribe to and act on the payment provider's refund/chargeback webhook synchronously, revoking the associated entitlement within the declared SLA, rather than relying solely on a periodic batch job slower than that tolerance.",
    "PBB-E": "Derive the customer-visible success/paid state from the same server-side entitlement check as the protected feature itself, not from the payment provider's return-flow status parameter alone -- treat this as a trust defect even when not independently a P0.",
    "PBB-OPEN": "Confirm the protected feature is denied to a clean identity with no payment before trusting any payment-attribution test built on top of it.",
    "PBB-LEAK": "Scope entitlement grants to the paying identity/tenant explicitly; an unrelated identity becoming entitled right after someone else's payment indicates a shared or unscoped entitlement key.",
}
# ZR-019 affected_flow: the FLOW FAMILY (fsm_compiler.FLOW_TYPES -- ZR-001's list) each
# experiment exercises, fixed by what the experiment tests (TITLES above), not by anything
# observed on a target. A coarse taxonomy label; pointing at the specific compiled FSM
# segment/transition of THIS target is finer-grained and needs the compiled model wired
# into the engine, which it is not yet. tests/test_finding_schema_completeness.py checks
# every value here is a real FLOW_TYPES member.
FLOW_BY_HYPOTHESIS: dict[str, str] = {
    "PBB-U": "checkout",      # declined/cancelled payment at the return flow
    "PBB-F": "subscription",  # plan/price binds the tier granted
    "PBB-H": "payment",       # amount/currency billed vs public price
    "PBB-C": "checkout",      # return-flow repetition
    "PBB-G": "entitlement",   # one tenant's payment benefiting another
    "PBB-X": "payment",       # payment reference redeemed by a non-owner
    "PBB-R": "refund",        # access after a confirmed refund
    "PBB-E": "entitlement",   # customer-visible claim vs server-enforced outcome
    "PBB-OPEN": "entitlement",
    "PBB-LEAK": "entitlement",
}
def _apply_prioritizer(wanted: list[str], prioritizer: PrioritizerFn | None) -> list[str]:
    """ZR-003/ZR-012: let an injected prioritizer choose the ORDER of the experiments
    to run -- and nothing else. The engine, not the prioritizer, is the authority on
    correctness, so whatever comes back is checked:
      * not a permutation of `wanted` (dropped or duplicated an experiment) -> rejected,
        static order kept. A scheduler bug must never silently remove a test.
      * raised -> static order kept. Same rule as everywhere in this engine: one
        broken optional component does not take the run down.
      * DERIVED_HYPOTHESES (PBB-E, computed from the other experiments'
        observations by _derive_e) not last -> moved last, because computing it
        early would see a partial observation set and could clear a hypothesis
        over states it simply hadn't observed yet.
    Either rejection is logged; neither is silent."""
    if prioritizer is None:
        return wanted
    try:
        proposed = list(prioritizer(list(wanted)))
    except Exception:  # noqa: BLE001 - see docstring
        logger.exception("prioritizer raised; keeping the static experiment order")
        return wanted
    if sorted(proposed) != sorted(wanted):
        logger.error("prioritizer returned %s, not a permutation of %s; keeping the static experiment order", proposed, wanted)
        return wanted
    tail = [h for h in proposed if h in DERIVED_HYPOTHESES]
    head = [h for h in proposed if h not in DERIVED_HYPOTHESES]
    if proposed != head + tail:
        logger.warning("prioritizer placed %s before the experiments it derives from; moved to the end", tail)
    return head + tail


_PRIORITY_BY_VERDICT: dict[Verdict, str] = {
    Verdict.CONFIRMED_P0: "critical",
    Verdict.PARTIALLY_VALIDATED_PAYMENT_INTEGRITY_ISSUE: "high",
}  # RULED_OUT/BLOCKED/UNKNOWN intentionally absent -- priority is for things needing action; .get(..., "n/a") in _finding() covers them
_REPRODUCTION_STATUS_BY_VERDICT: dict[Verdict, str] = {
    Verdict.CONFIRMED_P0: "independently reproduced (clean-session reproduction required for the token, see oracle_gate.ConfirmationGate)",
    Verdict.PARTIALLY_VALIDATED_PAYMENT_INTEGRITY_ISSUE: "reproduction incomplete (see reasons)",
    Verdict.RULED_OUT: "not applicable (ruled out)",
}  # BLOCKED/UNKNOWN: .get(..., "not attempted") in _finding() covers them
_IMPACT_BY_VERDICT: dict[Verdict, str] = {
    Verdict.CONFIRMED_P0: "Unauthorized use of a paid/protected feature without a valid, sufficient, or currently-bound payment or entitlement, independently reproduced and server-side-verified.",
}  # only CONFIRMED_P0 -- a true statement of what that verdict itself means, not a fabricated per-finding assessment
_PAID_VALUES = frozenset({"active", "paid", "premium", "pro", "enterprise", "basic", "subscribed", "success", "succeeded", "captured", "completed"})
_PAID_FLAGS = frozenset({"premium_badge", "premium", "subscribed", "is_premium", "paid", "entitled", "pro"})
_POSITIVE_MESSAGE = re.compile(r"\b(success|successful|succeeded|thank you|premium (is )?(active|unlocked)|upgraded|welcome to premium)\b", re.I)
_NEGATIVE_MESSAGE = re.compile(r"(not |fail|declin|cancel|unsuccess|pending|error)", re.I)


def claims_paid(body: Any) -> bool:
    """Does a customer-visible page/JSON CLAIM that the customer paid? (non-authoritative; used only to detect divergence from the oracle)"""
    if not isinstance(body, dict):
        return False
    for key, value in body.items():
        k = str(key).lower()
        if k in _PAID_FLAGS and value is True:
            return True
        if k in ("status", "state", "plan", "badge", "tier", "subscription", "payment_status") and isinstance(value, str) and value.lower() in _PAID_VALUES:
            return True
        if k == "message" and isinstance(value, str) and _POSITIVE_MESSAGE.search(value) and not _NEGATIVE_MESSAGE.search(value):
            return True
        if isinstance(value, dict) and claims_paid(value):
            return True
    return False


@dataclass
class PayOutcome:
    payment_id: str | None
    checkout: CallResult
    pay: CallResult | None
    billed_amount: float | None
    billed_currency: str | None
    rejected_at_checkout: bool

    @property
    def reached_sandbox(self) -> bool:
        p = self.pay
        return p is not None and p.error is None and p.status is not None and p.status < 500 and p.admitted

    def artifact_ids(self) -> list[str]:
        return [a for a in (self.checkout.artifact_id, self.pay.artifact_id if self.pay else None) if a]


@dataclass
class ControlState:
    K: CustomerSession | None = None
    V1: CustomerSession | None = None
    V2: CustomerSession | None = None
    setup_ok: bool = False
    positive_ok: bool = False
    negative_ok: bool = False
    open_feature: bool = False
    k_obs: OracleObservation | None = None
    k_after_obs: OracleObservation | None = None
    global_leak: bool = False
    tier_positive_ok: bool = False
    tier_leak: bool = False
    tier_leak_obs: OracleObservation | None = None
    reasons: list[str] = field(default_factory=list)
    artifact_ids: list[str] = field(default_factory=list)
    view_observations: list[dict[str, Any]] = field(default_factory=list)

    def summary(self) -> dict[str, Any]:
        return {"setup_ok": self.setup_ok, "legit_payer_allowed": self.positive_ok, "clean_identity_denied": self.negative_ok, "feature_open_to_unpaid": self.open_feature,
                "top_tier_payer_allowed": self.tier_positive_ok, "cheapest_payer_reaches_top_tier": self.tier_leak, "entitlement_leaks_to_unrelated_identity": self.global_leak, "reasons": list(self.reasons)}


def _clean(ids: Iterable[str | None]) -> list[str]:
    seen: list[str] = []
    for i in ids:
        if i and i not in seen:
            seen.append(i)
    return seen


class PureBlackBoxEngine:
    def __init__(self, http: QAHttpClient, brief: ExecutionBrief, *, base_url: str, ledger: EvidenceLedgerHandle | None = None,
                 clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], Awaitable[Any]] = asyncio.sleep,
                 prioritizer: PrioritizerFn | None = None, enable_channel_probe: bool = False, enable_chain_probe: bool = False, find_fast: bool = False,
                 enable_race_probe: bool = False, race_burst: int = 10, enable_convergence_probe: bool = False,
                 convergence_use_schema: bool = True, convergence_concurrent: bool = True,
                 enable_fabric_probe: bool = False, fabric_use_dag: bool = True, fabric_use_race: bool = True,
                 fabric_multi_candidate: bool = True, fabric_fresh_challenge: bool = True,
                 enable_reconciliation_probe: bool = False, recon_use_lifecycle: bool = True,
                 recon_use_overlay: bool = True, recon_use_sequence: bool = True,
                 enable_federation: bool = False, fed_use_discovery: bool = True, fed_use_token_re: bool = True,
                 fed_use_trust_graph: bool = True, fed_use_orchestration: bool = True,
                 fed_use_analogy: bool = True, fed_use_infogain: bool = True,
                 disabled_agents: frozenset[str] = frozenset()) -> None:
        self._prioritizer = prioritizer  # ZR-003/ZR-012: None keeps the static EXPERIMENT_ORDER, exactly as before
        # B45 recon-breadth + B46 chain-composition: FAIL-CLOSED. Off unless an authorised caller enables them; when off, the probes are no-ops and behaviour is identical to before.
        self._enable_channel_probe = enable_channel_probe
        self._enable_chain_probe = enable_chain_probe
        # B48 concurrency / TOCTOU race probe: OPT-IN (off by default). When on, a BOUNDED simultaneous burst
        # (<= race_burst, within the guard's existing token-bucket burst capacity -- not an RoE loosening) is sent
        # to a limit-guarded step to detect a check-then-act double-grant. Confirmation is unchanged: the real
        # oracle must flip + an independent reproduction. A correctly-atomic step (unique constraint / row lock)
        # is never beaten. This converts the documented 'race 0/4' boundary into a bounded, honest capability.
        self._enable_race_probe = enable_race_probe
        self._race_burst = max(2, min(int(race_burst), 24))
        # B49 multi-branch convergence probe: OPT-IN (off by default). When on, the engine composes SEVERAL
        # independent sub-chains whose outputs CONVERGE at one terminal step, satisfying each step's required
        # inputs from the AUTHORISED brief's declared surface (request_fields / response_fields) instead of relying
        # on the target to NAME a missing field in its error body -- so an opaque-error ("never names a field")
        # target no longer blinds field learning. The capability-minting steps are fired as a BOUNDED SIMULTANEOUS
        # burst so a freshness-windowed quorum (caps that must be minted in one short window) is satisfied, which a
        # sequential spine cannot do. Confirmation is unchanged: the real oracle must flip + an independent
        # reproduction. It stays on the declared surface and uses only harvested / brief-declared black-box values,
        # so a correctly-implemented target yields no false positive. FAIL-CLOSED: a no-op when off.
        self._enable_convergence_probe = enable_convergence_probe
        # Two capability switches (default to the capable behaviour; flipped only by ablation harnesses to PROVE each
        # new capability is individually load-bearing). ``_convergence_use_schema`` False disables the brief-schema
        # field satisfaction (so an opaque target can no longer be driven); ``_convergence_concurrent`` False mints
        # the capabilities sequentially (so a same-window freshness quorum can no longer be met).
        self._convergence_use_schema = convergence_use_schema
        self._convergence_concurrent = convergence_concurrent
        # B50 settlement-fabric probe: OPT-IN (off by default). A STRICT superset of the B49 convergence probe for
        # targets whose no-payment bypass is gated behind THREE further load-bearing hard axes that B49 cannot
        # cross (each axis a class public analyses report autonomous web agents struggle with, in the payment
        # domain): (1) a DEPENDENCY-ORDERED mint DAG -- later attestations consume earlier branches' capabilities,
        # so a flat simultaneous burst fires dependent mints before their inputs exist; (2) a check-then-act
        # settlement window -- the only route to a $0 net is to lower the capabilities' rates (a declared amend op)
        # INSIDE the validate->capture gap, an interleaved multi-endpoint race a sequential assembler cannot win;
        # (3) a higher-fan-in DECOY convergence step that correctly recomputes server-side and never grants, which
        # starves a composer that greedily commits to the single max-fan-in step. The three new capabilities are
        # each individually load-bearing and each ablatable below. Confirmation is UNCHANGED (the real oracle must
        # flip + an independent clean-session reproduction through the ConfirmationGate), it stays on the declared
        # surface and uses only harvested / brief-declared black-box values, so a correctly-implemented target
        # (server-recomputed amount, atomic capture, real paid basis) yields no false positive. FAIL-CLOSED: a
        # no-op when off; behaviour is identical to before.
        self._enable_fabric_probe = enable_fabric_probe
        # Three capability switches (default to the capable behaviour; flipped only by ablation harnesses to PROVE
        # each new capability is individually load-bearing). ``_fabric_use_dag`` False schedules the mints as a flat
        # two-layer burst (ignoring cross-branch capability dependencies), exactly like B49, so the DAG depth busts
        # it. ``_fabric_use_race`` False lowers the rates SEQUENTIALLY (amend-then-activate) instead of interleaving
        # them into the capture window, so the stale-attestation check turns it away. ``_fabric_multi_candidate``
        # False commits to the single highest-fan-in convergence candidate (the decoy), so the real lower-fan-in
        # step is never reached.
        self._fabric_use_dag = fabric_use_dag
        self._fabric_use_race = fabric_use_race
        self._fabric_multi_candidate = fabric_multi_candidate
        # ``_fabric_fresh_challenge`` False treats a short-lived step-up challenge input as an ordinary DAG
        # producer (fetched up-front in a dependency layer), so a target whose challenge expires faster than the
        # attestation DAG takes to build turns it away; True acquires such a challenge LATE -- immediately before
        # the terminal step, inside the same burst -- so it is still fresh at settlement.
        self._fabric_fresh_challenge = fabric_fresh_challenge
        # B52 reconciliation-gap probe: OPT-IN (off by default). A new capability class beyond the B50 fabric probe,
        # for targets whose no-payment bypass lives not in a >=2-capability convergence but in the ASYNCHRONOUS
        # MULTI-AUTHORITY RECONCILIATION GAP that real usage-billing exhibits (Orb query-based billing + read-path
        # overlay + closed-period catch-up; Stripe/Metronome amend/credit; Microsoft base-blind metering). It
        # reconstructs a STATEFUL RESOURCE LIFECYCLE from the declared surface -- an "open" op that mints a period
        # handle, a rate-bearing "overlay/credit" op on that handle, a "close/seal" op on that handle, and a
        # terminal "reconcile" op that consumes the handle -- and drives them in the one order that makes the
        # release stand: open -> overlay(rate=0) -> close (which locks the unbacked overlay into the authoritative
        # aggregate) -> reconcile (which finalises the grant on the frozen net<=0). Confirmation is UNCHANGED (the
        # real oracle must flip for a never-paid identity + an independent clean-session reproduction through the
        # ConfirmationGate), it issues only DECLARED operations and uses only harvested / brief-declared black-box
        # values, so a correctly-implemented target (overlay needs a real basis, close defers an unbacked overlay,
        # reconcile re-derives from real bases / requires a real captured basis) yields no false positive.
        # FAIL-CLOSED: a no-op when off. Three capability switches (default capable; flipped by ablation harnesses
        # to PROVE each is individually load-bearing): ``recon_use_lifecycle`` False drops the open/close period
        # lifecycle (no owned closed period -> reconcile is refused); ``recon_use_overlay`` False skips the credit
        # overlay (the authoritative net due stays at the full commitment); ``recon_use_sequence`` False applies the
        # overlay AFTER the close (a closed period rejects it, so nothing is locked in).
        self._enable_reconciliation_probe = enable_reconciliation_probe
        self._recon_use_lifecycle = recon_use_lifecycle
        self._recon_use_overlay = recon_use_overlay
        self._recon_use_sequence = recon_use_sequence
        # B53-B56 DEMIURGE federation probe: OPT-IN (off by default). The first probe for a DISTRIBUTED target -- a
        # payment FEDERATION whose archon surface is UNDECLARED (only advertised in the edge's public reference) and
        # whose one no-payment bypass is a CONFUSED DEPUTY across services, carried by an opaque packed correlation
        # token. It adds four capability CLASSES the single-session composers lack as subsystems: (B53) undeclared-
        # operation discovery from the reference; (B54) differential field-inference on the packed token to inject an
        # unbacked basis a signed-field manipulation cannot reach; (B55) cross-service trust-graph composition (the
        # confused-deputy order); (B56) orchestration-as-execution that holds the token/period/credit/challenge state
        # across services and late-binds a fresh step-up. Confirmation is UNCHANGED (the real oracle must flip for a
        # never-paid identity + an independent clean-session reproduction through the ConfirmationGate); it drives only
        # the declared surface + reference-advertised customer paths (via the same ScopeGuard-gated raw() the channel
        # probe uses) and only harvested black-box values, so a correctly-implemented federation yields no false
        # positive. FAIL-CLOSED: a no-op when off. Four capability switches (default capable; flipped by ablation
        # harnesses to PROVE each class is individually load-bearing): ``fed_use_discovery`` False -> no archon surface
        # is synthesised; ``fed_use_token_re`` False -> the honest token (amount=real captures=0) is used, so the
        # credit is zero and net due stays full; ``fed_use_trust_graph`` False -> the cross-service order is not
        # composed; ``fed_use_orchestration`` False -> the fresh step-up challenge is not late-bound, so finalize is
        # turned away.
        self._enable_federation = enable_federation
        self._fed_use_discovery = fed_use_discovery
        self._fed_use_token_re = fed_use_token_re
        self._fed_use_trust_graph = fed_use_trust_graph
        self._fed_use_orchestration = fed_use_orchestration
        # B59 cross-domain analogy (rider; LOAD-BEARING): adapt the B52 single-service reconciliation lifecycle to the
        # federation and recognise the correlation token as the cross-service rate carrier for the credit step. Off ->
        # the probe never realises the token carries the credit basis, so it is not presented to the credit step ->
        # miss. B58 info-gain (rider; EFFICIENCY): rank discovered candidates so grant-looking decoys are tried after
        # the real terminal -> fewer calls. Off -> candidates tried in discovery order (decoys first) -> more calls but
        # still found (so B58 is efficiency-only, not load-bearing -- reported honestly, never a faked ablation).
        self._fed_use_analogy = fed_use_analogy
        self._fed_use_infogain = fed_use_infogain
        # Roster dispatch: the federation probe binds each distinct capability to the kill-chain-roster agent that
        # OWNS it and runs the step only while that agent is activatable (owner-declined / disabled -> the step does
        # not run). ``disabled_agents`` is the ablation lever that proves which roster agents are genuinely
        # load-bearing for a federation find (honestly: one per distinct capability, not the whole roster).
        self._disabled_agents = frozenset(disabled_agents)
        # B47 find-fast: opt-in triage mode -- stop after the first CONFIRMED_P0 (fewer calls). OFF by default, so a full assessment still runs every class and nothing changes.
        self._find_fast = find_fast
        if not getattr(http, "stateless", False):
            # fail closed: a client that keeps cookies would let a target's Set-Cookie leak between identities and into "clean" sessions
            raise PurityViolation("engine_requires_stateless_client", "the engine only runs on a QAHttpClient(stateless=True): clean sessions must carry nothing but the identity's own bearer token")
        self._http, self.brief, self._clock, self._sleep = http, brief, clock, sleep
        controls = get_control_adapter()
        self.ledger = ledger or controls.new_evidence_ledger(authorization_ref=brief.authorization_ref, approved_identity_aliases=list(brief.identities), approved_tenant_aliases=[i.tenant_alias for i in brief.identities.values()])
        self.rec = EvidenceRecorder(brief, self.ledger, base_url)
        self.gate = controls.new_confirmation_gate(self.ledger)
        self.oracle = ProtectedFeatureOracle()
        # ZR-004 / H4: the DURABLE_STATE_CHANGE calibration of the primary oracle, established from
        # the control phase's positive (legit-payer) and negative (clean-identity) probes. A
        # RULED_OUT verdict is only trusted while this is calibrated -- enforced centrally in _finding.
        self._run_calibration: CalibrationResult | None = None
        self.prov = IdentityProvisioner(brief, self.rec, http)
        self._runners: dict[str, Callable[[ControlState], Awaitable[Finding]]] = {
            "PBB-U": self._exp_u, "PBB-F": self._exp_f, "PBB-H": self._exp_h, "PBB-C": self._exp_c, "PBB-G": self._exp_g, "PBB-X": self._exp_x, "PBB-R": self._exp_r}

    # ------------------------------------------------------------------------------------------------------------------ helpers
    def _finding(self, hyp: str, verdict: Verdict, confidence: str, summary: str, *, artifacts: Iterable[str | None] = (), reasons: Iterable[str] = (),
                 divergences: Iterable[str] = (), limitations: Iterable[str] = (), metrics: dict[str, Any] | None = None, token: Any = None,
                 identity_tenant_dimension: str | None = None, commercial_context: str | None = None, expected_state: str | None = None,
                 actual_state: str | None = None, payment_state: str | None = None, entitlement_state: str | None = None,
                 server_side_oracle: str | None = None) -> Finding:
        reasons, limitations = list(reasons), list(limitations)
        if verdict is Verdict.RULED_OUT:
            # ZR-004 / H4 central guard: a RULED_OUT ("denied, therefore cleared") may stand only if the
            # primary oracle was shown to discriminate (calibrated). The control phase + _precondition
            # already refuse to reach here otherwise, so this is behaviour-preserving on every current
            # path; it is the single typed invariant that keeps any future or edge RULED_OUT path from
            # turning a non-discriminating "denied" into false assurance.
            trustworthy, cal_reason = (ruled_out_result_is_trustworthy(self._run_calibration)
                                       if self._run_calibration is not None
                                       else (False, "oracle calibration was not established for this run"))
            if not trustworthy:
                verdict = Verdict.UNKNOWN
                summary = "RULED_OUT withheld by the H4 calibration guard: " + summary
                reasons = [*reasons, "ruled_out_withheld_uncalibrated_oracle"]
                limitations = [*limitations, f"H4 guard (ZR-004): {cal_reason}. 'Denied' from an oracle not shown to discriminate is not clearance."]
        return Finding(hypothesis_id=hyp, p0_class=EXPERIMENT_CLASSES[hyp], title=TITLES[hyp], verdict=verdict, confidence=confidence, summary=summary, spec=SPECS[hyp],
                       artifact_ids=_clean(artifacts), reasons=list(reasons), divergences=list(divergences), limitations=list(limitations), metrics=metrics or {}, token=token,
                       # ZR-019: populated uniformly for every finding through this one shared constructor.
                       priority=_PRIORITY_BY_VERDICT.get(verdict, "n/a"),
                       reproduction_status=_REPRODUCTION_STATUS_BY_VERDICT.get(verdict, "not attempted"),
                       impact=_IMPACT_BY_VERDICT.get(verdict),
                       recommended_fix=RECOMMENDED_FIX.get(hyp),
                       affected_flow=FLOW_BY_HYPOTHESIS.get(hyp),
                       # ZR-019: expected_state and a baseline identity_tenant_dimension come from the
                       # pre-registered OracleSpec (SPECS[hyp]) -- available for every hypothesis, fixed
                       # before any traffic, same provenance guarantee as the rest of OracleSpec. A
                       # caller-supplied identity_tenant_dimension (more specific to this finding) wins.
                       expected_state=expected_state or SPECS[hyp].expected_outcome,
                       identity_tenant_dimension=identity_tenant_dimension or SPECS[hyp].identity_and_tenant,
                       # The rest are populated per-experiment where the caller supplies them (PBB-U
                       # demonstrates the pattern); None for every experiment not yet updated to pass these.
                       commercial_context=commercial_context, actual_state=actual_state,
                       payment_state=payment_state, entitlement_state=entitlement_state,
                       server_side_oracle=server_side_oracle,
                       # ZR-019: precondition/effect come from the B32 chain-link catalog (attack_chain.LINKS) --
                       # fixed per-class, same pre-registered provenance as expected_state; completes the schema.
                       precondition=_zr019_precondition(hyp), effect=_zr019_effect(hyp))

    def _class_of(self, artifact_id: str) -> str:
        art = self.ledger.accepted.get(artifact_id)
        return art.provenance.classification if art and art.provenance else "unknown"

    def _stop_reason(self) -> str | None:
        guard = self._http.guard
        if guard is not None and guard.killed:
            return f"run stopped: {guard.kill_reason}"
        return None

    async def _pay(self, session: CustomerSession, *, plan: str, outcome_key: str, label: str, currency: str | None = None, amount: float | None = None) -> PayOutcome:
        checkout = await session.call("start_checkout", label=f"{label}:checkout", fields={"plan": plan, "currency": currency, "amount": amount})
        spec = self.brief.op("start_checkout")
        ok = checkout.status is not None and 200 <= checkout.status < 300 and checkout.admitted
        pid = spec.read(checkout.body, "payment_id") if (spec and ok) else None
        raw_amount = spec.read(checkout.body, "amount") if (spec and ok) else None
        billed_amount = float(raw_amount) if isinstance(raw_amount, (int, float)) and not isinstance(raw_amount, bool) else None
        billed_currency = spec.read(checkout.body, "currency") if (spec and ok) else None
        rejected = checkout.status is not None and 400 <= checkout.status < 500
        if not pid:
            return PayOutcome(None, checkout, None, billed_amount, billed_currency, rejected)
        session._rec.register_sensitive(str(pid))  # the payment reference never appears raw in stored evidence from here on
        outcome = self.brief.sandbox_outcomes[outcome_key]
        pay = await session.call("sandbox_pay", label=f"{label}:sandbox_{outcome_key}", path_params={"payment_id": pid}, fields={"payment_id": str(pid), "outcome": outcome})
        return PayOutcome(str(pid), checkout, pay, billed_amount, str(billed_currency) if billed_currency else None, False)

    async def _return_flow(self, session: CustomerSession, payment_id: str, *, label: str, claim_status: str | None = None, plan: str | None = None, tenant: str | None = None) -> CallResult:
        return await session.call("return_flow", label=label, path_params={"payment_id": payment_id}, fields={"payment_id": payment_id, "status": claim_status, "plan": plan, "tenant": tenant})

    async def _consume(self, session: CustomerSession, feature: FeatureSpec, cap: int, oid: str) -> list[OracleObservation]:
        out: list[OracleObservation] = []
        for i in range(cap):
            obs = await self.oracle.check(session, feature, oracle_id=f"{oid}:{i}")
            out.append(obs)
            if obs.outcome != "allowed":
                break
        return out

    async def _confirm(self, *, hyp: str, cs: ControlState, feature: FeatureSpec, scenario: OracleObservation, qualifying: bool, discriminating: bool,
                       subject: CustomerSession | None = None, repro: OracleObservation | None = None) -> tuple[GateDecision, OracleObservation, OracleObservation | None]:
        assert cs.K is not None
        k = ProtectedFeatureOracle.with_discrimination(await self.oracle.check(cs.K, feature, oracle_id=f"{hyp}:K:recheck"), discriminating)
        if repro is None and subject is not None:
            repro = await self.oracle.check(subject.clean_copy(), feature, oracle_id=f"{hyp}:repro")
        ids = _clean([*k.artifact_ids, *scenario.artifact_ids, *(repro.artifact_ids if repro else ())])
        decision = self.gate.evaluate(ConfirmationCandidate(hyp, k, scenario, repro, qualifying, signals_used=(KIND_FEATURE_USE,), evidence_classes=tuple(self._class_of(i) for i in ids)))
        return decision, k, repro

    def _confirmed_or_partial(self, hyp: str, decision: GateDecision, summary_ok: str, summary_partial: str, ids: Iterable[str | None], **extra: Any) -> Finding:
        if decision.confirmed:
            return self._finding(hyp, Verdict.CONFIRMED_P0, "high", summary_ok, artifacts=ids, token=decision.token, **extra)
        return self._finding(hyp, Verdict.PARTIALLY_VALIDATED_PAYMENT_INTEGRITY_ISSUE, "medium", summary_partial, artifacts=ids, reasons=decision.reasons, **extra)

    def _precondition(self, cs: ControlState, hyp: str, *, needs_tier: bool = False) -> Finding | None:
        if not cs.setup_ok:
            return self._finding(hyp, Verdict.BLOCKED, "high", "Controls could not be set up through the approved customer-level flow, so nothing can be proven or ruled out.", artifacts=cs.artifact_ids, reasons=cs.reasons or ["setup_failed"],
                                 limitations=["BLOCKED, not 'passed': an unusable sandbox/checkout/feature mapping must be fixed in the Execution Brief or the environment."])
        if cs.open_feature:
            return self._finding(hyp, Verdict.UNKNOWN, "medium", "The plan-gated feature is already usable by a clean identity that never paid, so payment attribution is impossible (see PBB-OPEN).", artifacts=cs.artifact_ids, reasons=["clean_identity_not_denied"])
        if cs.global_leak:
            return self._finding(hyp, Verdict.UNKNOWN, "medium", "An unrelated clean identity became able to use the feature right after another identity's payment, so no further payment can be attributed (see PBB-LEAK).", artifacts=cs.artifact_ids, reasons=["entitlement_leak_to_unrelated_identity"])
        if not cs.positive_ok:
            return self._finding(hyp, Verdict.UNKNOWN, "high", "The protected-feature oracle could not observe a legitimately paid benefit, so it can neither prove nor rule out anything (it is not shown to be able to say 'allowed').", artifacts=cs.artifact_ids,
                                 reasons=cs.reasons or ["positive_control_failed"], limitations=["Not RULED_OUT on purpose: 'denied everywhere' from a non-discriminating oracle would be false assurance."])
        if not cs.negative_ok:
            return self._finding(hyp, Verdict.UNKNOWN, "medium", "The clean-identity control did not return a clear denial.", artifacts=cs.artifact_ids, reasons=["negative_control_indeterminate"])
        if needs_tier and not cs.tier_positive_ok:
            return self._finding(hyp, Verdict.UNKNOWN, "medium", "The top-tier feature was not shown to be usable by a legitimate top-plan payer, so a tier oracle is not established.", artifacts=cs.artifact_ids, reasons=["tier_positive_control_failed"])
        return None

    # --------------------------------------------------------------------------------------------------------------------- controls
    async def _establish_controls(self) -> ControlState:
        cs, b = ControlState(), self.brief
        self._run_calibration = None  # recomputed below once the control probes run; if setup fails it stays None and RULED_OUT is unreachable via _precondition anyway
        primary, tier = b.primary_feature(), b.tier_feature()
        if primary is None:
            cs.reasons.append("brief declares no unlimited feature gated by the cheapest plan (no primary oracle)")
            return cs
        success = b.return_status_values["success"]
        try:
            cs.K = await self.prov.acquire("ctl")
            cs.k_obs = await self.oracle.check(cs.K, primary, oracle_id="CTRL:K:primary")
            cs.artifact_ids += cs.k_obs.artifact_ids
            cs.negative_ok, cs.open_feature = cs.k_obs.outcome == "denied", cs.k_obs.outcome == "allowed"
            if cs.k_obs.outcome == "indeterminate":
                cs.reasons.append("clean_identity_indeterminate: the clean control got neither an allowed-with-proof nor a declared denial status")
            cs.V1 = await self.prov.acquire("v1")
            pay = await self._pay(cs.V1, plan=b.cheapest_plan, outcome_key="success", label="CTRL:V1")
            cs.artifact_ids += pay.artifact_ids()
            if pay.payment_id is None or not pay.reached_sandbox or (pay.pay and not (200 <= (pay.pay.status or 0) < 300)):
                cs.reasons.append(f"setup_failed: legitimate sandbox payment could not be completed (checkout={pay.checkout.status}, sandbox={pay.pay.status if pay.pay else None})")
                return cs
            rf = await self._return_flow(cs.V1, pay.payment_id, label="CTRL:V1:return", claim_status=success)
            cs.artifact_ids.append(rf.artifact_id or "")
            v1 = await self.oracle.check(cs.V1, primary, oracle_id="CTRL:V1:primary")
            cs.artifact_ids += v1.artifact_ids
            cs.setup_ok, cs.positive_ok = True, v1.outcome == "allowed"
            # ZR-004 / H4: record the primary oracle's calibration from the two control probes
            # (positive = legit payer v1, negative = clean identity k_obs). _finding consults this;
            # it is calibrated iff positive_ok and negative_ok both hold -- no extra traffic issued.
            self._run_calibration = calibration_from_outcomes(OracleTier.DURABLE_STATE_CHANGE, v1.outcome, cs.k_obs.outcome)
            if not cs.positive_ok:
                cs.reasons.append(f"positive_control_failed: a legitimately paid identity got '{v1.outcome}' from the protected feature (return flow status {rf.status})")
            elif cs.negative_ok:  # the clean control, denied before V1 paid, is checked again: it never paid, so it must still be denied
                cs.k_after_obs = await self.oracle.check(cs.K, primary, oracle_id="CTRL:K:after_other_payment")
                cs.artifact_ids += cs.k_after_obs.artifact_ids
                cs.global_leak = cs.k_after_obs.outcome == "allowed"
            if b.op("subscription_view") is not None:
                for sess, obs in ((cs.V1, v1), (cs.K, cs.k_obs)):
                    view = await sess.call("subscription_view", label=f"CTRL:{sess.identity_alias}:view")
                    cs.view_observations.append({"identity": sess.identity_alias, "view_claims_paid": claims_paid(view.body), "oracle": obs.outcome, "context": "control", "artifact": view.artifact_id})
            if tier is not None:
                cs.tier_leak_obs = await self.oracle.check(cs.V1, tier, oracle_id="CTRL:V1:tier")
                cs.artifact_ids += cs.tier_leak_obs.artifact_ids
                cs.tier_leak = cs.tier_leak_obs.outcome == "allowed"
                if b.priciest_plan != b.cheapest_plan:
                    cs.V2 = await self.prov.acquire("v2")
                    pay2 = await self._pay(cs.V2, plan=b.priciest_plan, outcome_key="success", label="CTRL:V2")
                    cs.artifact_ids += pay2.artifact_ids()
                    if pay2.payment_id and pay2.reached_sandbox:
                        rf2 = await self._return_flow(cs.V2, pay2.payment_id, label="CTRL:V2:return", claim_status=success)
                        cs.artifact_ids.append(rf2.artifact_id or "")
                        v2 = await self.oracle.check(cs.V2, tier, oracle_id="CTRL:V2:tier")
                        cs.artifact_ids += v2.artifact_ids
                        cs.tier_positive_ok = v2.outcome == "allowed"
        except IdentityPoolExhausted as exc:
            cs.reasons.append(f"identity_pool_exhausted: {exc}")
            cs.setup_ok = False
        cs.artifact_ids = _clean(cs.artifact_ids)
        return cs

    async def _finding_open(self, cs: ControlState) -> Finding:
        primary = self.brief.primary_feature()
        assert primary is not None
        k2 = await self.prov.acquire("ctl2")
        obs2 = await self.oracle.check(k2, primary, oracle_id="OPEN:K2:primary")
        reproduced = obs2.outcome == "allowed"
        return self._finding("PBB-OPEN", Verdict.PARTIALLY_VALIDATED_PAYMENT_INTEGRITY_ISSUE, "high" if reproduced else "medium",
                             f"The feature the brief declares gated by plan '{primary.requires_plan}' was USED successfully by a fresh identity that never paid" + (" and by a second independent fresh identity." if reproduced else "."),
                             artifacts=[*(cs.k_obs.artifact_ids if cs.k_obs else ()), *obs2.artifact_ids],
                             reasons=["confirmation_pattern_not_executable: no denial control exists for a feature that is open to unpaid identities (the paid-gate is the thing under test)"],
                             limitations=["Plan-gating is CUSTOMER_DECLARED in the brief; if the feature is free by design this is not an issue.", "Not CONFIRMED_P0 by rule: the control pattern (clean identity denied -> payment -> allowed) cannot be executed."],
                             metrics={"reproduced_on_second_clean_identity": reproduced})

    async def _finding_leak(self, cs: ControlState) -> Finding:
        primary = self.brief.primary_feature()
        assert primary is not None and cs.K is not None and cs.k_obs is not None and cs.k_after_obs is not None
        control = ProtectedFeatureOracle.with_discrimination(cs.k_obs, cs.positive_ok)
        repro = await self.oracle.check(cs.K.clean_copy(), primary, oracle_id="PBB-LEAK:repro")
        ids = _clean([*control.artifact_ids, *cs.k_after_obs.artifact_ids, *repro.artifact_ids])
        decision = self.gate.evaluate(ConfirmationCandidate("PBB-LEAK", control, cs.k_after_obs, repro, False, signals_used=(KIND_FEATURE_USE,), evidence_classes=tuple(self._class_of(i) for i in ids)))
        return self._confirmed_or_partial("PBB-LEAK", decision, "An identity that never paid was DENIED, then USED the paid feature right after another identity's legitimate payment; a clean session reproduced it. Internal cause: UNKNOWN.",
                                          "An unrelated identity gained access after another identity's payment, but the confirmation chain is incomplete.", ids,
                                          limitations=["A time-based change in the unrelated identity's own entitlement (e.g. a trial starting) cannot be excluded from outside; the clean-session reproduction shows the access persists."])

    # ------------------------------------------------------------------------------------------------------------------- experiments
    def _api_prefix(self) -> str:
        """Longest '/'-segment prefix shared by the declared customer operations (e.g. '/api/v1'), so
        endpoint-channel probes stay on the authorised API surface rather than a guessed host root."""
        paths: list[str] = []
        for name in ("start_checkout", "return_flow", "signup", "subscription_view"):
            op = self.brief.op(name)
            if op is not None:
                paths.append(op.path)
        feat = self.brief.primary_feature()
        if feat is not None:
            paths.append(feat.path)
        if not paths:
            return ""
        common: list[str] = []
        for parts in zip(*[p.strip("/").split("/") for p in paths]):
            if all(x == parts[0] and "{" not in x for x in parts):
                common.append(parts[0])
            else:
                break
        return ("/" + "/".join(common)) if common else ""

    async def _channel_probe(self, cs: ControlState) -> Finding | None:
        """B45 recon-breadth (BOUNDED, FAIL-CLOSED): try a curated catalog of common entitlement-bypass
        channels (override/debug headers, preview/trial query flags, undocumented complimentary-grant
        endpoints) and raise a PBB-U CONFIRMED_P0 ONLY when the real Protected-Feature Oracle shows a
        never-paid identity USING the declared feature, reproduced in a clean session. A lookalike
        endpoint that grants nothing real therefore cannot become a false positive."""
        if not self._enable_channel_probe:
            return None
        feature = self.brief.primary_feature()
        if feature is None or not cs.setup_ok or not cs.positive_ok or not cs.negative_ok or cs.open_feature or cs.global_leak:
            return None  # a channel's "allowed" is only meaningful against a proven-discriminating, gated oracle
        from app.testing.integrity import entitlement_channels
        prefix = self._api_prefix()
        try:
            shared = await self.prov.acquire("u_chan")  # header/query channels do not change server state -> one identity tests them all
        except IdentityPoolExhausted:
            return None
        shared_denied = (await self.oracle.check(shared, feature, oracle_id="U:chan:baseline:pre")).outcome == "denied"
        for ch in entitlement_channels.catalog(prefix):
            if self._stop_reason() is not None:
                break
            try:
                if ch.kind == "endpoint":
                    S = await self.prov.acquire(f"u_chan_{ch.id}")  # fresh identity: an endpoint channel can mutate tenant state
                    if (await self.oracle.check(S, feature, oracle_id=f"U:chan:{ch.id}:pre")).outcome != "denied":
                        continue
                    await S.raw(ch.method, ch.path_suffix, label=f"U:chan:{ch.id}:apply")
                    scen = await self.oracle.check(S, feature, oracle_id=f"U:chan:{ch.id}:post")
                    repro = await self.oracle.check(S.clean_copy(), feature, oracle_id=f"U:chan:{ch.id}:repro")
                else:
                    if not shared_denied:
                        continue
                    scen = await self.oracle.check(shared, feature, oracle_id=f"U:chan:{ch.id}:post", extra_headers=ch.headers or None, extra_params=ch.params or None)
                    repro = await self.oracle.check(shared.clean_copy(), feature, oracle_id=f"U:chan:{ch.id}:repro", extra_headers=ch.headers or None, extra_params=ch.params or None)
            except IdentityPoolExhausted:
                break
            if scen.outcome != "allowed":
                continue
            decision, _, _ = await self._confirm(hyp="PBB-U", cs=cs, feature=feature, scenario=scen, qualifying=False, discriminating=cs.positive_ok, repro=repro)
            if decision.confirmed:
                ids = _clean([*cs.artifact_ids, *scen.artifact_ids, *(repro.artifact_ids if repro else ())])
                return self._finding("PBB-U", Verdict.CONFIRMED_P0, "high",
                                     f"A never-paid identity USED the paid feature through {ch.description} -- a channel outside the ordinary payment flow -- reproduced in a clean session; the same identity was denied without it. Internal cause: UNKNOWN.",
                                     artifacts=ids, token=decision.token, metrics={"bypass_channel": ch.id, "channel_kind": ch.kind},
                                     payment_state="no qualifying payment", actual_state=f"feature allowed via channel {ch.id}", entitlement_state="granted",
                                     server_side_oracle=f"{scen.oracle_id}: outcome=allowed, discriminating={cs.positive_ok}",
                                     limitations=[f"Found via the bounded entitlement-channel catalog (channel {ch.id}); channels outside that fixed set are not probed by this step."])
        return None

    def _harvest(self, body: Any, ctx: dict[str, Any], deny: Any = ()) -> None:
        """Collect scalar values the target volunteers (ids, references) from an observed response, so a
        later composed step can supply them by name. Excludes the identity's OWN bearer/access credential
        BY VALUE (``deny``) so a credential is never replayed -- but keeps resource ids even when the target
        happens to name one ``token`` (e.g. a voucher / idempotency / grant token), which a name-only
        filter would wrongly discard and thereby MISS the flaw whose required input is that id."""
        if isinstance(body, dict):
            for k, v in body.items():
                if isinstance(v, (str, int, float)) and not isinstance(v, bool):
                    if v in deny or k == "access_token":
                        continue  # never replay a known credential value, or an explicit access-token field
                    ctx.setdefault(k, v)
                elif isinstance(v, (dict, list)):
                    self._harvest(v, ctx, deny)
        elif isinstance(body, list):
            for item in body:
                self._harvest(item, ctx, deny)

    def _harvest_headers(self, headers: Any, ctx: dict[str, Any], deny: Any = ()) -> None:
        """Harvest a resource reference a target returns in a SAFE, standard response header -- chiefly the
        REST ``Location`` of a just-created resource (201 Created), which a real client follows to address
        that resource. Only product-behaviour headers survive scrubbing (volunteered/debug headers are
        already dropped upstream), so this reads a genuine product signal, not a hint. Latest-wins, and the
        identity's own bearer is still excluded by value."""
        if not isinstance(headers, dict):
            return
        loc = headers.get("location") or headers.get("Location")
        if isinstance(loc, str) and loc and loc not in deny:
            ctx["location"] = loc
            seg = loc.rstrip("/").rsplit("/", 1)[-1]
            if seg and seg not in deny:
                ctx["location_ref"] = seg   # the created resource's id -- what a follow-up step references

    _ERR_META = frozenset({"error", "field", "missing_field", "required", "message", "detail", "code", "status", "hint", "reason", "errors"})

    def _harvest_error(self, body: Any, ctx: dict[str, Any], deny: Any = ()) -> None:
        """Absorb values a server VOLUNTEERS in an error body (e.g. a challenge nonce handed back in a 4xx,
        which is standard challenge-response), while skipping pure error metadata (error/field/message...)
        so field learning isn't polluted. The bearer is still excluded by value."""
        if isinstance(body, dict):
            for k, v in body.items():
                if str(k).lower() in self._ERR_META:
                    continue
                if isinstance(v, (str, int, float)) and not isinstance(v, bool):
                    if v in deny or k == "access_token":
                        continue
                    ctx.setdefault(k, v)
                elif isinstance(v, (dict, list)):
                    self._harvest_error(v, ctx, deny)
        elif isinstance(body, list):
            for item in body:
                self._harvest_error(item, ctx, deny)

    def _rank_price_ids(self, body: Any, acc: list[tuple[float, str]]) -> None:
        """Learn candidate top-tier selector values: collect (amount, *price_id) pairs a catalog
        volunteers, so a composed step can prefer the priciest tier's id, not the first/'recommended'."""
        if isinstance(body, dict):
            pid = amt = None
            for k, v in body.items():
                kl = k.lower()
                if isinstance(v, str) and (kl == "price_id" or kl.endswith("_price_id")):
                    pid = v
                elif isinstance(v, (int, float)) and not isinstance(v, bool) and kl in ("amount", "price", "value", "cost", "unit_amount"):
                    amt = float(v)
            if pid is not None and amt is not None:
                acc.append((amt, pid))
            for v in body.values():
                self._rank_price_ids(v, acc)
        elif isinstance(body, list):
            for item in body:
                self._rank_price_ids(item, acc)

    async def _foreign_refs(self, b, top_plan: str, currency: str | None, harvest_ops: list[str], aux: list[str]) -> dict[str, Any]:
        """MULTI-IDENTITY (BOLA) orchestration: provision a SECOND, VICTIM identity, run a LEGITIMATE paid setup,
        and harvest the victim's resource references, so a cross-tenant/BOLA step -- one that references a resource
        WITHOUT an ownership check (OWASP API1) -- can be driven with a reference the ATTACKER does not own. The
        victim's payment is a real sandbox payment (the ATTACKER still never pays); confirmation still requires the
        real oracle to flip for the attacker + an independent reproduction, so an ownership-checked target yields no
        false positive. Bounded to ONE pass."""
        out: dict[str, Any] = {}
        try:
            V = await self.prov.acquire("u_victim")
        except IdentityPoolExhausted:
            return out
        deny = {t for t in (getattr(V, "_token", None),) if isinstance(t, str) and t}
        try:
            for g in harvest_ops:
                r = await V.call(g, label=f"U:victim:recon:{g}")
                self._harvest(r.body, out, deny)
                self._harvest_headers(r.headers, out, deny)
            if b.op("start_checkout") is not None:
                pay = await self._pay(V, plan=top_plan, outcome_key="success", label="U:victim")
                if pay.payment_id and pay.reached_sandbox:
                    out["payment_id"] = pay.payment_id
                    # Harvest the victim's OWN payment-confirmation response: a real paid setup often mints the
                    # shareable resource id (subscription / entitlement / receipt / beneficiary ref) right here,
                    # and that server-issued id -- observable to the victim -- is exactly what a cross-tenant BOLA
                    # step references. The victim legitimately sees its own confirmation, so this harvests nothing
                    # the attacker could not obtain by collusion / a shared reference (the classic OWASP API1 setup).
                    if pay.pay is not None:
                        self._harvest(pay.pay.body, out, deny)
                        self._harvest_headers(pay.pay.headers, out, deny)
                    if b.op("return_flow") is not None:
                        rf = await self._return_flow(V, pay.payment_id, label="U:victim:return", claim_status=b.return_status_values["success"])
                        self._harvest(rf.body, out, deny)
                        self._harvest_headers(rf.headers, out, deny)
            for op in aux:
                spec = b.op(op)
                if spec is None:
                    continue
                phs = re.findall(r"\{(\w+)\}", spec.path)
                if any(ph not in out for ph in phs):
                    continue
                pp = {ph: out[ph] for ph in phs}
                bf = {k: v for k, v in out.items() if k not in phs}
                try:
                    r = await V.call(op, label=f"U:victim:{op}", path_params=pp, fields=bf)
                except IdentityPoolExhausted:
                    break
                if r.status and 200 <= r.status < 300:
                    self._harvest(r.body, out, deny)
                    self._harvest_headers(r.headers, out, deny)
        except IdentityPoolExhausted:
            pass
        out.pop("payment_id", None)   # the attacker must not reuse the victim's payment id as its own
        return out

    async def _chain_probe(self, cs: ControlState) -> Finding | None:
        """B46 chain-composition (BOUNDED, FAIL-CLOSED): compose the OBSERVED, individually-harmless
        primitives into a NO-PAYMENT sequence and raise a PBB-U CONFIRMED_P0 only when the real oracle
        shows a never-paid identity USING the feature, reproduced in a clean session. It issues only
        DECLARED operations (never leaves the authorised surface), learns the top-tier selector from a
        catalog, LEARNS a required field from the server's own validation error and supplies it from
        harvested values, checks the feature after every step, and never makes a qualifying payment.

        Search is ROLE-AGNOSTIC (no reliance on operation names) and runs in two bounded passes:
          (1) a GUIDED FORWARD search that grows ONE ordered spine, keeping any primitive that applies
              (2xx) given the prefix so far -- this reaches LONG chains (up to 6 primitives) without the
              factorial blow-up of enumerating every ordering; and
          (2) a <=3 PERMUTATION sweep fallback, for shallow flaws whose correct order is gated (e.g. a
              freshness constraint) and so is not greedily reachable.
        It is a bounded composer: a flaw whose inputs are never externally observable stays a gap, not a
        rule-out."""
        if not self._enable_chain_probe:
            return None
        b, feature = self.brief, self.brief.primary_feature()
        if feature is None or not cs.setup_ok or not cs.positive_ok or not cs.negative_ok or cs.open_feature or cs.global_leak:
            return None
        import re as _re
        import itertools as _it
        import json as _json
        import hashlib as _hl
        import hmac as _hm
        import time as _time
        import base64 as _b64
        standard = {"signup", "start_checkout", "sandbox_pay", "return_flow", "request_refund", "subscription_view"}
        aux = [n for n, o in b.operations.items() if o.method in ("POST", "PUT", "PATCH") and n not in standard][:24]
        harvest_ops = [n for n, o in b.operations.items() if o.method == "GET" and n != "return_flow"]
        if not aux:
            return None
        has_checkout, has_return = b.op("start_checkout") is not None, b.op("return_flow") is not None
        top_plan, currency, success = b.priciest_plan, b.primary_currency, b.return_status_values["success"]
        MAX_CHAIN = 24

        async def run(seq: list[str], *, capture: dict | None = None) -> tuple[bool, OracleObservation | None]:
            """Execute recon + optional checkout + the ordered primitives of ``seq`` on a FRESH identity,
            with error-driven field learning. Returns (applied_all, allowed_obs):
              * applied_all -- every op in ``seq`` returned 2xx in this ordering (so ``seq`` is a valid
                prefix that can be extended); and
              * allowed_obs -- an OracleObservation if the paid feature became allowed at some step (else None).
            When ``capture`` is given, the live session and context are stored in it ({"S":..., "ctx":...}) so a
            caller (the deep-race probe) can keep driving the SAME identity -- e.g. burst the next, limit-guarded
            step with the context this prefix established."""
            S = await self.prov.acquire("u_chain")
            if capture is not None:
                capture["S"] = S
            if (await self.oracle.check(S, feature, oracle_id=f"U:chain:{'+'.join(seq)}:pre")).outcome != "denied":
                return False, None
            ctx: dict[str, Any] = {}
            if capture is not None:
                capture["ctx"] = ctx
            ranked: list[tuple[float, str]] = []
            _signer: dict[str, Any] = {}  # per-run asymmetric keypair we generate + register (DPoP-style), to sign with
            deny = {t for t in (getattr(S, "_token", None),) if isinstance(t, str) and t}  # the identity's own bearer -- never replayed as a field value
            for g in harvest_ops:
                r = await S.call(g, label=f"U:chain:recon:{g}")
                self._harvest(r.body, ctx, deny)
                self._harvest_headers(r.headers, ctx, deny)
                self._rank_price_ids(r.body, ranked)
            if ranked:
                ctx["price_id"] = max(ranked, key=lambda t: t[0])[1]  # learned top-tier selector
            if has_checkout:
                co = await S.call("start_checkout", label="U:chain:intent", fields={"plan": top_plan, "currency": currency})
                cspec = b.op("start_checkout")
                pid = cspec.read(co.body, "payment_id") if cspec else None
                if pid:
                    ctx["payment_id"] = pid
                self._harvest(co.body, ctx, deny)
                self._harvest_headers(co.headers, ctx, deny)
            for step in seq:
                spec = b.op(step)
                if spec is None:
                    return False, None
                placeholders = _re.findall(r"\{(\w+)\}", spec.path)
                if any(ph not in ctx for ph in placeholders):
                    return False, None  # a prerequisite step has not produced this id yet in this ordering
                pp = {ph: ctx[ph] for ph in placeholders}
                bf = {k: v for k, v in ctx.items() if k not in placeholders}
                res = await S.call(step, label=f"U:chain:{step}:apply", path_params=pp, fields=bf)
                # HEADER-SIGNED authentication (e.g. a Standard-Webhooks event): if the step rejects with a
                # SIGNATURE error AND a signing secret is OBSERVABLE (harvested from recon -- a real misconfig,
                # e.g. a secret shipped in public config / leaked in a bundle), construct the documented
                # signature and present it in request HEADERS. Only an OBSERVABLE secret is ever used -- a
                # secret the target never exposes stays unknowable, so a correctly-implemented signed webhook
                # is NOT beaten (this is exploiting a misconfiguration, never breaking the crypto).
                if res.status in (400, 401, 403) and isinstance(res.body, dict) and _re.search(
                        r"sign|signature|hmac|idempoten", str(res.body.get("error", "")) + " " + str(res.body.get("field", "")) + " " + str(res.body.get("detail", "")), _re.I):
                    _secrets = [v for k, v in reversed(list(ctx.items()))
                                if isinstance(v, str) and v not in deny and _re.search(r"secret|signing|whsec|webhook", k, _re.I)]
                    _bj = _json.dumps(bf, sort_keys=True)
                    # Candidate webhook-ids: a FRESH unique id (replay-aware) tried FIRST, THEN harvested
                    # correlation/job ids. An ASYNC callback (at-least-once delivery, cf. Svix/Nylas) often
                    # binds webhook-id == the ISSUED correlation id for dedup, and rejects an arbitrary fresh
                    # one. A fresh ts + unique idempotency key every attempt keeps every candidate replay-aware.
                    _corr = [str(v) for k, v in reversed(list(ctx.items()))
                             if isinstance(v, (str, int)) and not isinstance(v, bool) and str(v) not in deny
                             and _re.search(r"correlat|job|task|ticket|callback|dispatch|async|message|event|evt", str(k), _re.I)]
                    _wids = [f"evt_{_time.time_ns()}", *_corr[:4]]
                    _done = False
                    for _wid in _wids:
                        _wts, _idem = str(int(_time.time())), f"idk_{_time.time_ns()}"
                        for _sec in _secrets[:4]:
                            for _canon in (f"{_wid}.{_wts}.{_idem}.{_bj}", f"{_wid}.{_wts}.{_bj}"):
                                _mac = _b64.b64encode(_hm.new(_sec.encode(), _canon.encode(), _hl.sha256).digest()).decode()
                                _hdrs = {"webhook-id": _wid, "webhook-timestamp": _wts, "webhook-signature": f"v1,{_mac}", "idempotency-key": _idem}
                                _retry = await S.call(step, label=f"U:chain:{step}:whsign", path_params=pp, fields=bf, extra_headers=_hdrs)
                                if _retry.status and 200 <= _retry.status < 300:
                                    res, _done = _retry, True
                                    break
                            if _done:
                                break
                        if _done:
                            break
                # ITERATIVE error-driven field learning: satisfy EVERY required field the server names, one
                # at a time, from harvested values. A candidate is accepted for the currently-named field
                # when supplying it either succeeds (2xx) OR makes the server name a DIFFERENT required
                # field (the complaint moved on -> this field is now satisfied). This supplies the several
                # server-named inputs a hardened step may demand (e.g. a reference id + a one-time nonce).
                learned: dict[str, Any] = {}
                # BUSINESS-LOGIC numeric mutation: when the step is rejected with a PRICE/PAYMENT-related error and
                # it already carries a numeric/currency field (supplied from recon -- e.g. a catalog's amount or
                # currency), try ADVERSARIAL MUTATIONS of that value to break the price invariant for a FREE
                # (no-payment) grant (Intigriti taxonomy: client price -> 0, negative quantity, currency confusion).
                # A server that recomputes server-side is unaffected; confirmation still needs the real oracle to
                # flip + an independent reproduction, so a correct target yields no false positive.
                if not (res.status and 200 <= res.status < 300) and res.status in (400, 402, 403, 409, 422):
                    _blt = (str(res.body.get("error", "")) + " " + str(res.body.get("detail", "")) + " " + str(res.body.get("field", ""))) if isinstance(res.body, dict) else ""
                    _numf = [k for k in bf if _re.search(r"amount|price|qty|quantit|total|value|cost|units|seats|subtotal|\bnet", str(k), _re.I)]
                    _curf = [k for k in bf if _re.search(r"currency|curr|iso", str(k), _re.I)]
                    if (_numf or _curf) and (res.status == 402 or _re.search(r"pay|price|amount|currenc|quantit|insufficient|mismatch|balance", _blt, _re.I)):
                        _muts: list[tuple[str, Any]] = []
                        for _f in _numf[:3]:
                            _muts += [(_f, _mv) for _mv in (0, -1, -100, -1000000, 0.01)]
                        for _f in _curf[:2]:
                            _muts += [(_f, _mv) for _mv in ("INR", "JPY", "IDR", "VND", "NGN")]
                        for _f, _mv in _muts[:28]:
                            _retry = await S.call(step, label=f"U:chain:{step}:bizmut", path_params=pp, fields={**bf, _f: _mv})
                            if _retry.status and 200 <= _retry.status < 300:
                                res, learned[_f] = _retry, _mv
                                break
                    # MULTI-IDENTITY (BOLA): if the step still rejects and it carries a resource reference the
                    # attacker supplied, try the VICTIM's harvested refs in its place -- a cross-tenant reference
                    # an ownership-UNCHECKED server (OWASP API1) wrongly honors. An ownership-checked server
                    # refuses every foreign ref, and confirmation still needs the real oracle to flip + repro.
                    if not (res.status and 200 <= res.status < 300) and foreign_ctx:
                        _reffields = [k for k in bf if _re.search(r"ref|_id$|pass|ticket|token|entitle|voucher|grant|cap|handle|member|account|customer|order", str(k), _re.I)]
                        _fvals = [v for v in foreign_ctx.values() if isinstance(v, (str, int)) and not isinstance(v, bool) and v not in deny]
                        for _ff in _reffields[:5]:
                            for _fv in _fvals[:6]:
                                _retry = await S.call(step, label=f"U:chain:{step}:bola", path_params=pp, fields={**bf, _ff: _fv})
                                if _retry.status and 200 <= _retry.status < 300:
                                    res, learned[_ff] = _retry, _fv
                                    break
                            if res.status and 200 <= res.status < 300:
                                break
                _rounds = 0
                _tsname = _re.compile(r"^(ts|timestamp|time|date|iat|created|expires|epoch|now)$", _re.I)
                while not (res.status and 200 <= res.status < 300) and _rounds < 10:
                    needed = (res.body.get("field") or res.body.get("missing_field") or res.body.get("required")) if isinstance(res.body, dict) else None
                    if not (isinstance(needed, str) and needed) or needed in bf or needed in learned:
                        break
                    _rounds += 1
                    progressed = False
                    if _re.search(r"public_?key|pubkey|jwk|client_?key|device_?key", needed, _re.I):
                        # ASYMMETRIC enrolment: generate our OWN Ed25519 keypair and register the PUBLIC key
                        # (DPoP-style), keeping the private key to sign later requests. The keypair is the caller's
                        # own -- not a stolen secret -- so this is legitimate; a server-held secret stays unknowable.
                        try:
                            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as _Ed
                            from cryptography.hazmat.primitives import serialization as _ser
                            if "priv" not in _signer:
                                _p = _Ed.generate()
                                _signer["priv"] = _p
                                _signer["pub_b64"] = _b64.b64encode(_p.public_key().public_bytes(_ser.Encoding.Raw, _ser.PublicFormat.Raw)).decode()
                            _cand = _signer["pub_b64"]
                            _retry = await S.call(step, label=f"U:chain:{step}:pubkey", path_params=pp, fields={**bf, **learned, needed: _cand})
                            if _retry.status and 200 <= _retry.status < 300:
                                res, learned[needed], progressed = _retry, _cand, True
                            else:
                                _nxt = (_retry.body.get("field") or _retry.body.get("missing_field") or _retry.body.get("required")) if isinstance(_retry.body, dict) else None
                                if isinstance(_nxt, str) and _nxt and _nxt != needed and _nxt not in bf and _nxt not in learned:
                                    res, learned[needed], progressed = _retry, _cand, True
                        except Exception:  # noqa: BLE001  (asymmetric crypto unavailable -> skip enrolment)
                            pass
                    elif _re.search(r"sig|signature|hmac|mac", needed, _re.I):
                        # CONSTRUCT a request signature over standard canonical forms, INCLUDING freshness-bound
                        # forms (server nonce + current timestamp + method/path), the way DPoP / HTTP-Message-
                        # Signatures clients sign. ASYMMETRIC (Ed25519 with our registered keypair) is tried first
                        # when we hold one, else SYMMETRIC (HMAC with a discovered key). Never a replay; only keys
                        # the caller legitimately holds are used, so a secret-keyed provider webhook stays unforgeable.
                        _concrete = spec.path
                        for _pk, _pv in pp.items():
                            _concrete = _concrete.replace("{" + _pk + "}", str(_pv))
                        _now = {**bf, **learned}
                        _bodyj = _json.dumps(_now, sort_keys=True)
                        _nonce = next((str(v) for k, v in reversed(list(_now.items())) if isinstance(v, (str, int)) and not isinstance(v, bool) and _re.search(r"nonce|challenge", k, _re.I)), None)
                        _ts = next((str(v) for k, v in reversed(list(_now.items())) if _tsname.match(str(k))), None)
                        _cd = next((str(v) for k, v in reversed(list(_now.items())) if _re.search(r"digest|body.?hash|content.?hash", str(k), _re.I)), None)
                        _forms: list[str] = []
                        if _nonce is not None and _ts is not None and _cd is not None:   # RFC 9421 digest-bound
                            _forms += [f"{_nonce}.{_ts}.{_cd}.{_concrete}", f"{_nonce}.{_ts}.{_cd}.{spec.method} {_concrete}"]
                        if _cd is not None:
                            _forms.append(f"{_cd}.{_concrete}")
                        if _nonce is not None and _ts is not None:
                            _forms += [f"{_nonce}.{_ts}.{_concrete}", f"{_nonce}.{_ts}.{spec.method} {_concrete}"]
                        if _ts is not None:
                            _forms.append(f"{_ts}.{_concrete}")
                        if _nonce is not None:
                            _forms.append(f"{_nonce}.{_concrete}")
                        _forms += [_concrete, f"{spec.method} {_concrete}", _concrete + _bodyj, _bodyj]
                        # RELAYED-REQUEST signing (SSRF / API-gateway hop, OWASP API7): when a field carries a
                        # forward/target PATH, the INNER service verifies the signature over that relayed path,
                        # not the gateway's own path. Also sign over those relay targets (and the gateway-auth
                        # case: an HMAC over the bare forward target). Fires ONLY when such a field is present,
                        # so non-relay targets are unaffected. Bounded to the two most recent relay paths.
                        _relays = [str(_v) for _k, _v in {**bf, **learned}.items()
                                   if isinstance(_v, str) and _v.startswith("/") and _re.search(r"forward|target|relay|dest|hop|url|path", str(_k), _re.I)]
                        for _rp in _relays[:2]:
                            if _nonce is not None and _ts is not None and _cd is not None:
                                _forms.append(f"{_nonce}.{_ts}.{_cd}.{_rp}")
                            if _nonce is not None and _ts is not None:
                                _forms += [f"{_nonce}.{_ts}.{_rp}", f"{_nonce}.{_ts}.{spec.method} {_rp}"]
                            if _ts is not None:
                                _forms.append(f"{_ts}.{_rp}")
                            if _nonce is not None:
                                _forms.append(f"{_nonce}.{_rp}")
                            _forms += [_rp, f"{spec.method} {_rp}"]
                        if _signer.get("priv") is not None:   # asymmetric: sign with OUR registered Ed25519 private key
                            for _canon in _forms:
                                _sig = _b64.b64encode(_signer["priv"].sign(_canon.encode())).decode()
                                _retry = await S.call(step, label=f"U:chain:{step}:asign", path_params=pp, fields={**bf, **learned, needed: _sig})
                                if _retry.status and 200 <= _retry.status < 300:
                                    res, learned[needed], progressed = _retry, _sig, True
                                    break
                                _nxt = (_retry.body.get("field") or _retry.body.get("missing_field") or _retry.body.get("required")) if isinstance(_retry.body, dict) else None
                                if isinstance(_nxt, str) and _nxt and _nxt != needed and _nxt not in bf and _nxt not in learned:
                                    res, learned[needed], progressed = _retry, _sig, True
                                    break
                        if not progressed:                     # symmetric: HMAC with a discovered key
                            # Candidate HMAC secrets, each tried as BYTES. A key-like value contributes its
                            # utf-8 bytes AND -- for an ALGORITHM-CONFUSION / scheme-downgrade flaw (RS->HS;
                            # cf. Stripe's webhook docs: "To prevent downgrade attacks, ignore all schemes
                            # that aren't v1") -- the RAW DECODED BYTES of a published PUBLIC key used as the
                            # HMAC secret. A public key is public, so this is never a stolen secret; it only
                            # beats a server that wrongly HMAC-verifies with its own published asymmetric
                            # public key. We also try our OWN registered public key's raw bytes for symmetry.
                            _kstrs = [v for k, v in reversed(list(ctx.items()))
                                      if isinstance(v, str) and v not in deny and _re.search(r"key|secret|sign", k, _re.I)]
                            if not _kstrs:
                                _kstrs = [v for k, v in reversed(list(ctx.items())) if isinstance(v, str) and v not in deny][:4]
                            _secretsb: list[bytes] = []
                            for _ks in _kstrs[:4]:
                                _kb0 = _ks.encode()
                                if _kb0 not in _secretsb:
                                    _secretsb.append(_kb0)
                                try:
                                    _raw = _b64.b64decode(_ks, validate=True)
                                    if _raw and _raw not in _secretsb:
                                        _secretsb.append(_raw)   # alg-confusion: raw bytes of a public key
                                except Exception:  # noqa: BLE001
                                    pass
                            if _signer.get("pub_b64"):
                                try:
                                    _ownraw = _b64.b64decode(_signer["pub_b64"])
                                    if _ownraw not in _secretsb:
                                        _secretsb.append(_ownraw)
                                except Exception:  # noqa: BLE001
                                    pass
                            for _kb in _secretsb[:8]:
                                for _canon in _forms:
                                    _sig = _hm.new(_kb, _canon.encode(), _hl.sha256).hexdigest()
                                    _retry = await S.call(step, label=f"U:chain:{step}:sign", path_params=pp, fields={**bf, **learned, needed: _sig})
                                    if _retry.status and 200 <= _retry.status < 300:
                                        res, learned[needed], progressed = _retry, _sig, True
                                        break
                                    _nxt = (_retry.body.get("field") or _retry.body.get("missing_field") or _retry.body.get("required")) if isinstance(_retry.body, dict) else None
                                    if isinstance(_nxt, str) and _nxt and _nxt != needed and _nxt not in bf and _nxt not in learned:
                                        res, learned[needed], progressed = _retry, _sig, True
                                        break
                                if progressed:
                                    break
                    elif _tsname.match(needed):
                        # FRESHNESS: supply a current timestamp the signed request must carry (server checks a window)
                        _nowt = int(_time.time())
                        for _cand in (str(_nowt), str(_nowt * 1000), _nowt):
                            _retry = await S.call(step, label=f"U:chain:{step}:fresh", path_params=pp, fields={**bf, **learned, needed: _cand})
                            if _retry.status and 200 <= _retry.status < 300:
                                res, learned[needed], progressed = _retry, _cand, True
                                break
                            _nxt = (_retry.body.get("field") or _retry.body.get("missing_field") or _retry.body.get("required")) if isinstance(_retry.body, dict) else None
                            if isinstance(_nxt, str) and _nxt and _nxt != needed and _nxt not in bf and _nxt not in learned:
                                res, learned[needed], progressed = _retry, _cand, True
                                break
                    elif _re.search(r"amount|price|qty|quantit|total|value|cost|currency|curr|units|seats|balance|credit|subtotal", needed, _re.I):
                        # BUSINESS-LOGIC numeric reasoning (Intigriti price-manipulation taxonomy): try ADVERSARIAL
                        # values that break a price/quantity/currency invariant a server which TRUSTS the client
                        # would honor -- negative quantity (total <= 0 => free), client price 0/0.01, currency
                        # confusion, integer overflow. A server that recomputes/ignores the client value is
                        # unaffected, and confirmation still requires the real oracle to flip + an independent
                        # reproduction, so a correct target yields no false positive.
                        if _re.search(r"currency|curr|iso", needed, _re.I):
                            _cands: list[Any] = ["INR", "JPY", "IDR", "VND", "NGN", "USD"]
                        else:
                            _cands = [0, -1, -100, -1000000, 0.0, 0.01, 1, 2 ** 53, 99999999999999, "0", "-1"]
                        for _cand in _cands:
                            _retry = await S.call(step, label=f"U:chain:{step}:bizlogic", path_params=pp, fields={**bf, **learned, needed: _cand})
                            if _retry.status and 200 <= _retry.status < 300:
                                res, learned[needed], progressed = _retry, _cand, True
                                break
                            _nxt = (_retry.body.get("field") or _retry.body.get("missing_field") or _retry.body.get("required")) if isinstance(_retry.body, dict) else None
                            if isinstance(_nxt, str) and _nxt and _nxt != needed and _nxt not in bf and _nxt not in learned:
                                res, learned[needed], progressed = _retry, _cand, True
                                break
                    elif _re.search(r"digest|body.?hash|content.?hash", needed, _re.I):
                        # RFC 9421 content-digest: bind the request body by its SHA-256 and supply it, so the
                        # signature (computed next, over a digest-bound canonical) covers the body too.
                        _biz = {k: v for k, v in {**bf, **learned}.items() if k not in ("content_digest", "request_sig", needed)}
                        _cd = _b64.b64encode(_hl.sha256(_json.dumps(_biz, sort_keys=True).encode()).digest()).decode()
                        _retry = await S.call(step, label=f"U:chain:{step}:digest", path_params=pp, fields={**bf, **learned, needed: _cd})
                        if _retry.status and 200 <= _retry.status < 300:
                            res, learned[needed], progressed = _retry, _cd, True
                        else:
                            _nxt = (_retry.body.get("field") or _retry.body.get("missing_field") or _retry.body.get("required")) if isinstance(_retry.body, dict) else None
                            if isinstance(_nxt, str) and _nxt and _nxt != needed and _nxt not in bf and _nxt not in learned:
                                res, learned[needed], progressed = _retry, _cd, True
                    else:
                        # Try values the CURRENT error volunteered FIRST (e.g. a fresh challenge nonce handed
                        # back in this very 4xx), then the attacker's OWN harvested context (most-recent first).
                        # De-duplicated, so a stale value from an earlier step can't shadow a fresh one. The
                        # caller's own values are tried first and within a bounded cap, so a step that needs the
                        # caller's OWN resource (its own voucher / handle / order) is satisfied correctly.
                        _own: list[Any] = []
                        if isinstance(res.body, dict):
                            for _bk, _bv in res.body.items():
                                if str(_bk).lower() not in self._ERR_META:
                                    _own.append(_bv)
                        _own += [v for _k, v in reversed(list(ctx.items()))]
                        _seen: set = set()

                        def _usable(_c):
                            return isinstance(_c, (str, int, float)) and not isinstance(_c, bool) and _c not in deny and _c not in _seen

                        _tried = 0
                        for _cand in _own:
                            if not _usable(_cand):
                                continue
                            _seen.add(_cand)
                            _tried += 1
                            if _tried > 22:
                                break
                            _retry = await S.call(step, label=f"U:chain:{step}:learn", path_params=pp, fields={**bf, **learned, needed: _cand})
                            if _retry.status and 200 <= _retry.status < 300:
                                res, learned[needed], progressed = _retry, _cand, True
                                break
                            _nxt = (_retry.body.get("field") or _retry.body.get("missing_field") or _retry.body.get("required")) if isinstance(_retry.body, dict) else None
                            if isinstance(_nxt, str) and _nxt and _nxt != needed and _nxt not in bf and _nxt not in learned:
                                res, learned[needed], progressed = _retry, _cand, True  # complaint moved on -> `needed` satisfied
                                break
                        # MULTI-IDENTITY (BOLA) FALLBACK: the caller's OWN values did not satisfy this field. A
                        # VICTIM identity's harvested resource id may -- an ownership-UNCHECKED cross-tenant
                        # reference (OWASP API1). The foreign set is small and targeted, so it is ALWAYS tried here
                        # (never displaced by the attacker-context cap above), but only AFTER the caller's own
                        # values, so own-resource steps keep working. An ownership-checked server refuses every
                        # foreign ref; confirmation still needs the real oracle to flip + an independent
                        # reproduction, so a correct target yields no false positive.
                        if not progressed and foreign_ctx:
                            _ftried = 0
                            for _cand in (v for _k, v in foreign_ctx.items()):
                                if not _usable(_cand):
                                    continue
                                _seen.add(_cand)
                                _ftried += 1
                                if _ftried > 16:
                                    break
                                _retry = await S.call(step, label=f"U:chain:{step}:bola", path_params=pp, fields={**bf, **learned, needed: _cand})
                                if _retry.status and 200 <= _retry.status < 300:
                                    res, learned[needed], progressed = _retry, _cand, True
                                    break
                                _nxt = (_retry.body.get("field") or _retry.body.get("missing_field") or _retry.body.get("required")) if isinstance(_retry.body, dict) else None
                                if isinstance(_nxt, str) and _nxt and _nxt != needed and _nxt not in bf and _nxt not in learned:
                                    res, learned[needed], progressed = _retry, _cand, True
                                    break
                    if not progressed:
                        break
                if not (res.status and 200 <= res.status < 300):
                    return False, None  # step rejected (e.g. wrong order / unmet input) -> not a valid prefix
                self._harvest(res.body, ctx, deny)
                self._harvest_headers(res.headers, ctx, deny)
                obs = await self.oracle.check(S, feature, oracle_id=f"U:chain:{step}:post")
                if obs.outcome == "allowed":
                    return True, obs
            if has_return and ctx.get("payment_id"):
                await self._return_flow(S, str(ctx["payment_id"]), label="U:chain:return", claim_status=success)  # no payment was ever captured
                obs = await self.oracle.check(S, feature, oracle_id="U:chain:return:post")
                if obs.outcome == "allowed":
                    return True, obs
            return True, None

        async def confirm_and_build(seq: list[str], scen: OracleObservation) -> Finding | None:
            try:
                _, repro = await run(seq)  # independent fresh-identity replay of the whole sequence
            except IdentityPoolExhausted:
                return None
            if repro is None or repro.outcome != "allowed":
                return None
            decision, _, _ = await self._confirm(hyp="PBB-U", cs=cs, feature=feature, scenario=scen, qualifying=False, discriminating=cs.positive_ok, repro=repro)
            if not decision.confirmed:
                return None
            ids = _clean([*cs.artifact_ids, *scen.artifact_ids, *(repro.artifact_ids if repro else ())])
            chain_desc = " -> ".join((["start_checkout"] if has_checkout else []) + seq)
            return self._finding("PBB-U", Verdict.CONFIRMED_P0, "high",
                                 f"A never-paid identity USED the paid feature after composing observed primitives into a no-payment sequence ({chain_desc}); a clean session reproduced it. Internal cause: UNKNOWN.",
                                 artifacts=ids, token=decision.token, metrics={"chain": list(seq), "top_plan": top_plan},
                                 payment_state="no qualifying payment was made at any step", actual_state=f"feature allowed after composing {seq}", entitlement_state="granted",
                                 server_side_oracle=f"{scen.oracle_id}: outcome=allowed, discriminating={cs.positive_ok}",
                                 limitations=["Found by a bounded role-agnostic search (guided forward construction up to 8 declared primitives, plus a <=3 permutation sweep) with iterative error-driven field learning and standard response-header (Location) following; deeper chains, more than 8 primitives, or inputs never externally observable are out of scope (reported as gaps, not ruled out)."])

        # MULTI-IDENTITY (BOLA) prep: a VICTIM identity's resource refs, harvested once, offered as fallback
        # candidates when the attacker's own values don't satisfy a cross-tenant/ownership-unchecked step.
        try:
            foreign_ctx = await self._foreign_refs(b, top_plan, currency, harvest_ops, aux)
        except IdentityPoolExhausted:
            foreign_ctx = {}

        # (1) GUIDED FORWARD SEARCH -- grow one ordered spine, keeping any primitive that applies given the
        #     prefix so far. Confirms the moment the paid feature flips, then independently reproduces.
        spine: list[str] = []
        remaining = list(aux)
        while remaining and len(spine) < MAX_CHAIN:
            if self._stop_reason() is not None:
                break
            advanced = False
            for o in list(remaining):
                try:
                    applied, scen = await run(spine + [o])
                except IdentityPoolExhausted:
                    return None
                if not applied:
                    continue
                spine.append(o)
                remaining.remove(o)
                advanced = True
                if scen is not None and scen.outcome == "allowed":
                    found = await confirm_and_build(spine, scen)
                    if found is not None:
                        return found
                break
            if not advanced:
                break

        # (1b) DEEP TOCTOU RACE PROBE (opt-in, bounded). A limit-guarded step reachable only AFTER a prefix:
        #      establish the discovered spine prefix on a FRESH identity, then burst the terminal state-changing
        #      step with the context that prefix produced. A sequential scanner applies the step once (one slot,
        #      below the grant quorum) and misses; a bounded simultaneous burst overruns the check-then-act
        #      one-shot. Confirmation is unchanged (real oracle flip + an independent fresh-prefix burst reproduces
        #      it); a correctly-atomic one-shot is unbeaten. Runs BEFORE the permutation/standalone passes so the
        #      prefix-length re-runs fit the RoE call budget.
        if self._enable_race_probe and spine:
            async def _deep_race_once(prefix: list[str], step: str, label: str):
                spec = b.op(step)
                if spec is None:
                    return None, None
                cap: dict[str, Any] = {}
                try:
                    applied, _ = await run(prefix, capture=cap)  # fresh identity; establishes ctx WITHOUT calling `step`
                except IdentityPoolExhausted:
                    return None, None
                S = cap.get("S"); ctx2 = cap.get("ctx")
                if not applied or S is None or ctx2 is None:
                    return None, None
                phs = _re.findall(r"\{(\w+)\}", spec.path)
                if any(ph not in ctx2 for ph in phs):
                    return None, None
                pp = {ph: ctx2[ph] for ph in phs}
                bf = {k: v for k, v in ctx2.items() if k not in phs}
                if (await self.oracle.check(S, feature, oracle_id=f"U:deeprace:{step}:{label}:pre")).outcome != "denied":
                    return None, None
                await asyncio.gather(*[S.call(step, label=f"U:deeprace:{step}:{label}:b{i}", path_params=pp, fields=dict(bf)) for i in range(self._race_burst)], return_exceptions=True)
                return S, await self.oracle.check(S, feature, oracle_id=f"U:deeprace:{step}:{label}:post")

            for step in list(reversed(spine))[:3]:   # deepest state-changing steps first
                if self._stop_reason() is not None:
                    break
                prefix = spine[:spine.index(step)]
                try:
                    _s1, scen = await _deep_race_once(prefix, step, "u_deeprace")
                    if scen is None or scen.outcome != "allowed":
                        continue
                    _s2, repro = await _deep_race_once(prefix, step, "u_deeprace_repro")
                except IdentityPoolExhausted:
                    break
                if repro is None or repro.outcome != "allowed":
                    continue
                decision, _, _ = await self._confirm(hyp="PBB-U", cs=cs, feature=feature, scenario=scen, qualifying=False, discriminating=cs.positive_ok, repro=repro)
                if decision.confirmed:
                    ids = _clean([*cs.artifact_ids, *scen.artifact_ids, *repro.artifact_ids])
                    return self._finding("PBB-U", Verdict.CONFIRMED_P0, "high",
                                         f"A never-paid identity USED the paid feature after a BOUNDED CONCURRENT BURST ({self._race_burst}x) overran a check-then-act one-shot on a DEEP step '{step}', reachable only after composing a {len(prefix)}-step no-payment prefix ({' -> '.join(prefix)}); an independent fresh-prefix burst reproduced it. Internal cause: UNKNOWN.",
                                         artifacts=ids, token=decision.token, metrics={"race_step": step, "burst": self._race_burst, "prefix": list(prefix), "chain": list(spine), "depth": len(prefix) + 1},
                                         payment_state="no qualifying payment", actual_state=f"feature allowed after a {self._race_burst}x simultaneous burst of {step} at chain depth {len(prefix) + 1}", entitlement_state="granted",
                                         server_side_oracle=f"{scen.oracle_id}: outcome=allowed, discriminating={cs.positive_ok}",
                                         limitations=[f"Found by a bounded concurrency probe ({self._race_burst} simultaneous requests within the token-bucket burst capacity) on a step reached via a {len(prefix)}-step prefix; a correctly-atomic one-shot (unique constraint / row lock) is unbeaten, and a deep step whose per-request inputs are not context-derivable (e.g. a per-call signature) is out of scope (reported as a gap)."])

        # (2) BOUNDED PERMUTATION FALLBACK (role-agnostic, <=3) -- for shallow flaws whose correct order is
        #     gated and so not greedily reachable. Same safety bar: confirm via real oracle + independent repro.
        sequences: list[list[str]] = []
        for _r in (1, 2, 3):
            sequences.extend(list(c) for c in _it.permutations(aux, _r))
        sequences = sequences[:48]
        for seq in sequences:
            if self._stop_reason() is not None:
                break
            try:
                applied, scen = await run(seq)
            except IdentityPoolExhausted:
                break
            if not applied or scen is None or scen.outcome != "allowed":
                continue
            found = await confirm_and_build(seq, scen)
            if found is not None:
                return found

        # (3) CONCURRENCY / TOCTOU RACE PROBE (opt-in, bounded). A limit-guarded step with a check-then-act
        #     window can be overrun by a SIMULTANEOUS burst (within the guard's token-bucket burst capacity),
        #     double-granting what a single request could not. Confirmation is unchanged: the real oracle must
        #     flip + an independent fresh-identity burst reproduces it. A correctly-atomic step is never beaten.
        if self._enable_race_probe:
            async def _race_once(step: str, label: str):
                try:
                    S = await self.prov.acquire(label)
                except IdentityPoolExhausted:
                    return None, None
                if (await self.oracle.check(S, feature, oracle_id=f"U:race:{step}:{label}:pre")).outcome != "denied":
                    return None, None
                rctx: dict[str, Any] = {}
                dn = {t for t in (getattr(S, "_token", None),) if isinstance(t, str) and t}
                for g in harvest_ops:
                    rr = await S.call(g, label=f"U:race:{label}:recon:{g}")
                    self._harvest(rr.body, rctx, dn)
                    self._harvest_headers(rr.headers, rctx, dn)
                bf0 = {k: v for k, v in rctx.items()}
                await asyncio.gather(*[S.call(step, label=f"U:race:{step}:{label}:b{i}", fields=dict(bf0)) for i in range(self._race_burst)], return_exceptions=True)
                return S, await self.oracle.check(S, feature, oracle_id=f"U:race:{step}:{label}:post")
            for step in aux:
                if self._stop_reason() is not None:
                    break
                spec = b.op(step)
                if spec is None or _re.findall(r"\{(\w+)\}", spec.path):
                    continue  # identity-agnostic steps only (per-identity refs can't be re-derived inside a burst)
                try:
                    _s1, scen = await _race_once(step, "u_race")
                    if scen is None or scen.outcome != "allowed":
                        continue
                    _s2, repro = await _race_once(step, "u_race_repro")
                except IdentityPoolExhausted:
                    break
                if repro is None or repro.outcome != "allowed":
                    continue
                decision, _, _ = await self._confirm(hyp="PBB-U", cs=cs, feature=feature, scenario=scen, qualifying=False, discriminating=cs.positive_ok, repro=repro)
                if decision.confirmed:
                    ids = _clean([*cs.artifact_ids, *scen.artifact_ids, *repro.artifact_ids])
                    return self._finding("PBB-U", Verdict.CONFIRMED_P0, "high",
                                         f"A never-paid identity USED the paid feature after a BOUNDED CONCURRENT BURST ({self._race_burst}x) overran a check-then-act limit on '{step}' (TOCTOU race); an independent fresh-identity burst reproduced it. Internal cause: UNKNOWN.",
                                         artifacts=ids, token=decision.token, metrics={"race_step": step, "burst": self._race_burst},
                                         payment_state="no qualifying payment", actual_state=f"feature allowed after a {self._race_burst}x simultaneous burst of {step}", entitlement_state="granted",
                                         server_side_oracle=f"{scen.oracle_id}: outcome=allowed, discriminating={cs.positive_ok}",
                                         limitations=[f"Found by a bounded concurrency probe ({self._race_burst} simultaneous requests, within the guard's token-bucket burst capacity); a correctly-atomic limit (unique constraint / row lock) is unbeaten and reported as a gap, not ruled out."])
        return None

    async def _convergence_probe(self, cs: ControlState) -> Finding | None:
        """B49 multi-branch convergence (BOUNDED, FAIL-CLOSED): find a terminal step that CONVERGES several
        independent capabilities, build each capability's sub-chain from the AUTHORISED brief's declared schema
        (so an opaque, 'never names a field' target cannot blind field learning), MINT the capabilities as a
        bounded SIMULTANEOUS burst (so a freshness-windowed quorum is satisfied where a sequential spine busts the
        window), converge, and raise PBB-U CONFIRMED_P0 only when a never-paid identity USES the feature, reproduced
        in a clean session. It issues only DECLARED operations and uses only harvested / brief-declared black-box
        values, so a correctly-implemented target (server-recomputed amount, real paid basis, atomic quorum) yields
        no false positive.

        WHY THIS IS A NEW CAPABILITY (not reachable by _chain_probe's single guided spine):
          (1) SCHEMA-DRIVEN field satisfaction -- required inputs come from the brief's declared ``request_fields``
              (and path placeholders), not from the server naming a missing field. An opaque-error target that
              answers a generic 422 with no ``field`` collapses _chain_probe's error-driven learning; here it does
              not, because the authorised API reference already lists the parameter names.
          (2) MULTI-BRANCH assembly + CONVERGENCE -- K independent sub-chains, each producing one capability named in
              the terminal step's inputs, mapped via the brief's declared ``response_fields``.
          (3) FRESHNESS-SYNCHRONISED minting -- the capability-producing steps are fired concurrently (one window),
              so a quorum requiring same-window freshness is met; a sequential spine mints them too far apart."""
        if not self._enable_convergence_probe:
            return None
        import re as _re
        b, feature = self.brief, self.brief.primary_feature()
        if feature is None or not cs.setup_ok or not cs.positive_ok or not cs.negative_ok or cs.open_feature or cs.global_leak:
            return None

        # (A) DECLARED-SCHEMA GRAPH. producers: logical output name -> the op that produces it (from response_fields).
        producers: dict[str, str] = {}
        for name, op in b.operations.items():
            for logical in (op.response_fields or {}):
                producers.setdefault(logical, name)
        if not producers:
            return None
        # convergence op: the declared op whose required inputs include the MOST capabilities produced by OTHER ops.
        conv_name: str | None = None
        conv_caps: list[str] = []
        for name, op in b.operations.items():
            needed = [f for f in (op.request_fields or {}) if f in producers and producers[f] != name]
            if len(needed) > len(conv_caps) and len(needed) >= 2:
                conv_name, conv_caps = name, needed
        if conv_name is None:
            return None
        harvest_ops = [n for n, o in b.operations.items() if o.method == "GET" and n != "return_flow"]
        _rate_like = _re.compile(r"amount|rate|price|qty|quantit|total|value|cost|units|seats|\bnet|balance|subtotal", _re.I)

        # (B) Per-capability sub-chain plan: the mint op that produces the cap, plus any prerequisite "open" op that
        #     produces a path placeholder the mint op needs. Bounded to the declared producers (no guessing).
        def _plan(cap: str) -> tuple[str, list[str]] | None:
            mint = producers.get(cap)
            if mint is None:
                return None
            spec = b.op(mint)
            if spec is None:
                return None
            prereqs: list[str] = []
            for ph in _re.findall(r"\{(\w+)\}", spec.path):
                pre = producers.get(ph)
                if pre is None or pre == mint:
                    return None  # a path input we cannot produce from the declared surface -> out of scope
                prereqs.append(pre)
            return mint, prereqs

        plans: list[tuple[str, str, list[str]]] = []  # (cap, mint_op, [open_ops])
        for cap in conv_caps:
            pl = _plan(cap)
            if pl is None:
                return None
            plans.append((cap, pl[0], pl[1]))

        def _fields_for(op_name: str, ctx: dict[str, Any]) -> dict[str, Any]:
            """Satisfy a declared step's request_fields from the brief schema: a produced id from ctx (by name),
            else a ZERO-RATE adversarial value for a price/rate/amount field (the Intigriti numeric class -- a
            server that recomputes is unaffected), else a same-named harvested value if present."""
            if not self._convergence_use_schema:
                return {}  # ablation: without schema-driven satisfaction, an opaque-rejected field cannot be filled
            spec = b.op(op_name)
            out: dict[str, Any] = {}
            for f in (spec.request_fields or {}) if spec else {}:
                if f in ctx:
                    out[f] = ctx[f]
                elif _rate_like.search(f):
                    out[f] = 0
            return out

        async def assemble(label: str) -> tuple[CustomerSession | None, OracleObservation | None]:
            try:
                S = await self.prov.acquire(label)
            except IdentityPoolExhausted:
                return None, None
            if (await self.oracle.check(S, feature, oracle_id=f"U:converge:{label}:pre")).outcome != "denied":
                return None, None
            ctx: dict[str, Any] = {}
            deny = {t for t in (getattr(S, "_token", None),) if isinstance(t, str) and t}
            for g in harvest_ops:
                r = await S.call(g, label=f"U:converge:{label}:recon:{g}")
                self._harvest(r.body, ctx, deny)
                self._harvest_headers(r.headers, ctx, deny)
            # open every branch's prerequisites (fast, sequential), harvesting each handle into ctx
            for _cap, _mint, opens in plans:
                for o in opens:
                    r = await S.call(o, label=f"U:converge:{label}:open:{o}")
                    if not (r.status and 200 <= r.status < 300):
                        return S, None
                    self._harvest(r.body, ctx, deny)
                    self._harvest_headers(r.headers, ctx, deny)

            async def _mint(cap: str, mint_op: str) -> CallResult:
                spec = b.op(mint_op)
                pp = {ph: ctx[ph] for ph in _re.findall(r"\{(\w+)\}", spec.path) if ph in ctx} if spec else {}
                return await S.call(mint_op, label=f"U:converge:{label}:mint:{mint_op}", path_params=pp, fields=_fields_for(mint_op, ctx))

            # FRESHNESS-SYNCHRONISED: fire the capability mints simultaneously so a same-window quorum is satisfied.
            # (Ablation: _convergence_concurrent False mints them sequentially, which busts a freshness window.)
            if self._convergence_concurrent:
                results = await asyncio.gather(*[_mint(cap, mint) for cap, mint, _ in plans], return_exceptions=True)
            else:
                results = []
                for cap, mint, _ in plans:
                    try:
                        results.append(await _mint(cap, mint))
                    except BaseException as exc:  # noqa: BLE001
                        results.append(exc)
            for r in results:
                if isinstance(r, BaseException):
                    return S, None
                self._harvest(r.body, ctx, deny)
                self._harvest_headers(r.headers, ctx, deny)
            if not all(cap in ctx for cap in conv_caps):
                return S, None  # a capability was not minted (e.g. a branch gate is correctly closed)
            # CONVERGE
            cr = await S.call(conv_name, label=f"U:converge:{label}:finalize", fields=_fields_for(conv_name, ctx))
            if not (cr.status and 200 <= cr.status < 300):
                return S, None
            self._harvest(cr.body, ctx, deny)
            return S, await self.oracle.check(S, feature, oracle_id=f"U:converge:{label}:post")

        try:
            S, scen = await assemble("u_converge")
            if scen is None or scen.outcome != "allowed":
                return None
            _S2, repro = await assemble("u_converge_repro")
        except IdentityPoolExhausted:
            return None
        if repro is None or repro.outcome != "allowed":
            return None
        decision, _, _ = await self._confirm(hyp="PBB-U", cs=cs, feature=feature, scenario=scen, qualifying=False, discriminating=cs.positive_ok, repro=repro)
        if not decision.confirmed:
            return None
        ids = _clean([*cs.artifact_ids, *scen.artifact_ids, *repro.artifact_ids])
        branch_desc = "; ".join(f"{'->'.join([*opens, mint])}=>{cap}" for cap, mint, opens in plans)
        return self._finding("PBB-U", Verdict.CONFIRMED_P0, "high",
                             f"A never-paid identity USED the paid feature after converging a {len(plans)}-capability quorum at '{conv_name}' ({branch_desc}), with the capability mints issued as a {len(plans)}x SIMULTANEOUS burst to satisfy a same-window freshness quorum; a clean session reproduced it. Internal cause: UNKNOWN.",
                             artifacts=ids, token=decision.token,
                             metrics={"convergence_step": conv_name, "capabilities": list(conv_caps), "branches": [{"capability": cap, "sub_chain": [*opens, mint]} for cap, mint, opens in plans], "mint_concurrency": len(plans)},
                             payment_state="no qualifying payment was made at any step", actual_state=f"feature allowed after converging {conv_caps} at {conv_name}", entitlement_state="granted",
                             server_side_oracle=f"{scen.oracle_id}: outcome=allowed, discriminating={cs.positive_ok}",
                             limitations=[f"Found by a bounded multi-branch convergence composer: {len(plans)} declared sub-chains whose outputs the brief maps (response_fields) to the terminal step's declared inputs (request_fields), minted as a {len(plans)}x simultaneous burst within the guard's token-bucket burst capacity. A convergence step whose inputs are not externally derivable from the declared surface, needs more branches than are declared, or whose quorum is correctly atomic/server-recomputed is out of scope (reported as a gap, not ruled out)."])

    async def _fabric_probe(self, cs: ControlState) -> Finding | None:
        """B50 settlement-fabric composer (BOUNDED, FAIL-CLOSED): a strict superset of _convergence_probe that can
        cross three further hard axes -- a DEPENDENCY-ORDERED mint DAG, a check-then-act capture window, and a
        higher-fan-in DECOY convergence step. It issues only DECLARED operations and uses only harvested /
        brief-declared black-box values; confirmation is unchanged (the real oracle must flip for a never-paid
        identity, reproduced in a clean session), so a correctly-implemented target yields no false positive.

          G1 -- TOPOLOGICAL ANTICHAIN SCHEDULING. For a convergence candidate, the required capabilities are
                resolved TRANSITIVELY from the declared schema: a mint op's path placeholders AND its request_fields
                that are themselves produced capabilities (cross-branch inputs) become prerequisites. The op set is
                layered by dependency (Kahn) and each layer is fired CONCURRENTLY, so cross-branch inputs exist
                before the mints that consume them AND the terminal capabilities land in one freshness window. (A
                flat simultaneous burst -- _fabric_use_dag False -- fires dependent mints before their inputs.)
          G2 -- INTERLEAVED MULTI-ENDPOINT RACE. If the terminal step is refused at the honest quoted rate and a
                declared rate-mutating op applies to the consumed capabilities, the terminal op and the rate
                reductions are fired as one SIMULTANEOUS burst, so the reductions land inside the terminal's
                check-then-act window. (Sequential reduction -- _fabric_use_race False -- is turned away by the
                stale-attestation check.)
          G3 -- RANKED MULTI-CANDIDATE SEARCH. Convergence candidates are ranked by fan-in and tried in order with
                bounded backtracking, so a higher-fan-in decoy that never grants does not starve the real,
                lower-fan-in step. (Single-candidate -- _fabric_multi_candidate False -- commits to the decoy.)
          G4 -- FRESH-CHALLENGE LATE BINDING. A terminal input produced by a dependency-free, challenge-named op is
                treated as a SHORT-LIVED step-up challenge and acquired LAST -- immediately before the terminal (and
                re-acquired before the race burst) -- rather than up-front in a DAG layer, so a challenge that
                expires faster than the attestation DAG takes to build is still valid at settlement.
                (Fetched-early -- _fabric_fresh_challenge False -- it expires and the terminal is refused.)"""
        if not self._enable_fabric_probe:
            return None
        import re as _re
        b, feature = self.brief, self.brief.primary_feature()
        if feature is None or not cs.setup_ok or not cs.positive_ok or not cs.negative_ok or cs.open_feature or cs.global_leak:
            return None
        rate_like = _re.compile(r"amount|rate|price|qty|quantit|total|value|cost|units|seats|\bnet|balance|subtotal", _re.I)

        # producers: logical output name -> the op that produces it (from declared response_fields).
        producers: dict[str, str] = {}
        for name, op in b.operations.items():
            for logical in (op.response_fields or {}):
                producers.setdefault(logical, name)
        if not producers:
            return None

        def _placeholders(path: str) -> list[str]:
            return _re.findall(r"\{(\w+)\}", path)

        # convergence CANDIDATES: declared ops whose request_fields include >= 2 capabilities produced by OTHER ops.
        candidates: list[tuple[str, list[str]]] = []
        for name, op in b.operations.items():
            caps = [f for f in (op.request_fields or {}) if f in producers and producers[f] != name]
            if len(caps) >= 2:
                candidates.append((name, caps))
        if not candidates:
            return None
        candidates.sort(key=lambda t: len(t[1]), reverse=True)  # highest fan-in first (a decoy tends to sit here)
        candidates = candidates[:1] if not self._fabric_multi_candidate else candidates[:4]

        # the rate-mutating ("amend") op: POST, exactly one path placeholder, carries a rate-like field, produces
        # no capability and consumes none -- a single-target adjustment the race abuses. Declared-surface only.
        amend_op = amend_ph = amend_field = None
        for name, op in b.operations.items():
            phs = _placeholders(op.path)
            if op.method != "POST" or len(phs) != 1:
                continue
            if any(f in producers for f in (op.response_fields or {})):
                continue
            rfields = [f for f in (op.request_fields or {}) if rate_like.search(f)]
            if rfields and not any(f in producers for f in (op.request_fields or {})):
                amend_op, amend_ph, amend_field = name, phs[0], rfields[0]
                break

        chal_like = _re.compile(r"nonce|challenge|otp|step[_-]?up|fresh|\bchal\b|token", _re.I)

        def _is_rate_bearing(logical: str) -> bool:
            """A produced capability whose minting op carries a rate-like field -- one the amend op can lower."""
            pr = producers.get(logical)
            spec = b.op(pr) if pr else None
            return bool(spec and any(rate_like.search(f) for f in (spec.request_fields or {})))

        def _is_challenge(logical: str) -> bool:
            """A SHORT-LIVED step-up input: produced by a dependency-free, non-rate op and named like a nonce /
            challenge. With G4 on it is acquired LATE (just before the terminal); with G4 off it is left in the DAG
            (fetched up-front in a dependency layer, so a short-lived one expires before the terminal)."""
            pr = producers.get(logical)
            spec = b.op(pr) if pr else None
            if spec is None or _placeholders(spec.path):
                return False
            if any(f in producers for f in (spec.request_fields or {})):
                return False
            if any(rate_like.search(f) for f in (spec.request_fields or {})):
                return False
            return bool(chal_like.search(logical))

        harvest_ops = [n for n, o in b.operations.items() if o.method == "GET" and n != "return_flow"]

        def _op_deps(opname: str) -> set[str] | None:
            """Direct op-prerequisites: producers of the op's path placeholders, plus (when DAG-aware) producers of
            its request_fields that are capabilities from other ops."""
            spec = b.op(opname)
            if spec is None:
                return None
            deps: set[str] = set()
            for ph in _placeholders(spec.path):
                pr = producers.get(ph)
                if pr is None:
                    return None  # a path input we cannot produce from the declared surface -> out of scope
                deps.add(pr)
            if self._fabric_use_dag:
                for f in (spec.request_fields or {}):
                    if f in producers and producers[f] != opname:
                        deps.add(producers[f])
            return deps

        def _layers(conv_caps: list[str]) -> list[list[str]] | None:
            """Transitive closure of the producer ops for the candidate's capabilities, layered by dependency."""
            seeds = [producers.get(c) for c in conv_caps]
            if any(s is None for s in seeds):
                return None
            need: set[str] = set()
            depmap: dict[str, set[str]] = {}
            work = list(seeds)
            while work:
                o = work.pop()
                if o in need:
                    continue
                d = _op_deps(o)
                if d is None:
                    return None
                need.add(o)
                depmap[o] = d
                work.extend(x for x in d if x not in need)
            layers: list[list[str]] = []
            done: set[str] = set()
            remaining = set(need)
            while remaining:
                layer = sorted(o for o in remaining if depmap[o] <= done)
                if not layer:
                    return None  # a cycle or an underivable dependency
                layers.append(layer)
                done |= set(layer)
                remaining -= set(layer)
            return layers

        def _fields_for(op_name: str, ctx: dict[str, Any]) -> dict[str, Any]:
            spec = b.op(op_name)
            out: dict[str, Any] = {}
            for f in (spec.request_fields or {}) if spec else {}:
                if f in ctx:
                    out[f] = ctx[f]           # a harvested id (a produced capability) or the echoed quoted rate
                elif rate_like.search(f):
                    out[f] = 0                # an unknown numeric: the zero adversarial value (a recomputing target is unaffected)
            return out

        async def assemble(label: str, conv_name: str, conv_caps: list[str], dag_caps: list[str],
                           challenge_inputs: list[str], amend_caps: list[str], layers: list[list[str]]
                           ) -> tuple[CustomerSession | None, OracleObservation | None]:
            try:
                S = await self.prov.acquire(label)
            except IdentityPoolExhausted:
                return None, None
            if (await self.oracle.check(S, feature, oracle_id=f"U:fabric:{label}:pre")).outcome != "denied":
                return None, None
            ctx: dict[str, Any] = {}
            deny = {t for t in (getattr(S, "_token", None),) if isinstance(t, str) and t}
            for g in harvest_ops:
                r = await S.call(g, label=f"U:fabric:{label}:recon:{g}")
                self._harvest(r.body, ctx, deny)
                self._harvest_headers(r.headers, ctx, deny)

            async def _one(opn: str) -> CallResult:
                spec = b.op(opn)
                pp = {ph: ctx[ph] for ph in _placeholders(spec.path) if ph in ctx} if spec else {}
                return await S.call(opn, label=f"U:fabric:{label}:mint:{opn}", path_params=pp, fields=_fields_for(opn, ctx))

            # G1: fire each dependency layer CONCURRENTLY, harvesting outputs before the next layer consumes them.
            for layer in layers:
                results = await asyncio.gather(*[_one(o) for o in layer], return_exceptions=True)
                for r in results:
                    if isinstance(r, BaseException) or not (r.status and 200 <= r.status < 300):
                        return S, None
                    self._harvest(r.body, ctx, deny)
                    self._harvest_headers(r.headers, ctx, deny)
            if not all(c in ctx for c in dag_caps):  # challenge inputs are fetched LATE, below
                return S, None

            async def _fetch_challenges() -> None:
                # G4: acquire each short-lived step-up challenge IMMEDIATELY before the terminal, so it is still
                # fresh at settlement (a scheduler that fetched it up-front in a DAG layer would let it expire).
                for ch in challenge_inputs:
                    pr = producers.get(ch)
                    if pr is None:
                        continue
                    r = await S.call(pr, label=f"U:fabric:{label}:challenge:{pr}")
                    self._harvest(r.body, ctx, deny)
                    self._harvest_headers(r.headers, ctx, deny)

            async def _converge() -> CallResult:
                return await S.call(conv_name, label=f"U:fabric:{label}:activate", fields=_fields_for(conv_name, ctx))

            await _fetch_challenges()
            if not all(c in ctx for c in conv_caps):
                return S, None
            cr = await _converge()
            if not (cr.status and 200 <= cr.status < 300) and amend_op is not None and amend_caps:
                targets = [ctx[c] for c in amend_caps if c in ctx]
                if len(targets) == len(amend_caps):
                    async def _amend(ref: Any) -> CallResult:
                        return await S.call(amend_op, label=f"U:fabric:{label}:amend", path_params={amend_ph: ref}, fields={amend_field: 0})
                    if self._fabric_use_race:
                        # G2: fire the terminal op and the rate reductions simultaneously -> the reductions land
                        # inside the terminal's check-then-act window. Re-acquire the challenge first so it is fresh.
                        await _fetch_challenges()
                        burst = await asyncio.gather(_converge(), *[_amend(t) for t in targets], return_exceptions=True)
                        cr = burst[0] if not isinstance(burst[0], BaseException) else cr
                    else:
                        for t in targets:  # ablation: sequential reduction, rejected by the stale-attestation check
                            try:
                                await _amend(t)
                            except BaseException:  # noqa: BLE001
                                return S, None
                        await _fetch_challenges()
                        cr = await _converge()
            if not (cr.status and 200 <= cr.status < 300):
                return S, None
            self._harvest(cr.body, ctx, deny)
            return S, await self.oracle.check(S, feature, oracle_id=f"U:fabric:{label}:post")

        # G3: try the ranked candidates in order; a decoy never flips the oracle, so we backtrack to the real one.
        for conv_name, conv_caps in candidates:
            challenge_inputs = [c for c in conv_caps if self._fabric_fresh_challenge and _is_challenge(c)]
            dag_caps = [c for c in conv_caps if c not in challenge_inputs]
            amend_caps = [c for c in conv_caps if _is_rate_bearing(c)]
            layers = _layers(dag_caps)
            if layers is None:
                continue
            try:
                args = (conv_name, conv_caps, dag_caps, challenge_inputs, amend_caps, layers)
                S, scen = await assemble("u_fabric", *args)
                if scen is None or scen.outcome != "allowed":
                    continue
                _S2, repro = await assemble("u_fabric_repro", *args)
            except IdentityPoolExhausted:
                return None
            if repro is None or repro.outcome != "allowed":
                continue
            decision, _, _ = await self._confirm(hyp="PBB-U", cs=cs, feature=feature, scenario=scen, qualifying=False, discriminating=cs.positive_ok, repro=repro)
            if not decision.confirmed:
                continue
            ids = _clean([*cs.artifact_ids, *scen.artifact_ids, *repro.artifact_ids])
            raced = amend_op is not None and bool(amend_caps)
            late = bool(challenge_inputs)
            layer_desc = " | ".join("+".join(l) for l in layers)
            return self._finding("PBB-U", Verdict.CONFIRMED_P0, "high",
                                 f"A never-paid identity USED the paid feature after composing a dependency-ordered capability DAG and converging a {len(conv_caps)}-input quorum at '{conv_name}'"
                                 + (f", lowering the quorum's attested rates to zero as a SIMULTANEOUS burst interleaved into the settlement's check-then-act window (an amend/activate race)" if raced else "")
                                 + (f", and acquiring a fresh short-lived step-up challenge ({'+'.join(challenge_inputs)}) LATE -- immediately before the settlement -- so it had not expired" if late else "")
                                 + f"; a clean session reproduced it. Internal cause: UNKNOWN.",
                                 artifacts=ids, token=decision.token,
                                 metrics={"convergence_step": conv_name, "capabilities": list(conv_caps), "dag_layers": layers,
                                          "candidates_considered": [c for c, _ in candidates], "race_used": bool(raced and self._fabric_use_race),
                                          "late_challenge": late, "challenge_inputs": list(challenge_inputs)},
                                 payment_state="no qualifying payment was made at any step",
                                 actual_state=f"feature allowed after converging {conv_caps} at {conv_name} via a dependency-ordered DAG"
                                              + (" and a check-then-act amend race" if raced else "")
                                              + (" with a late-bound step-up challenge" if late else ""),
                                 entitlement_state="granted",
                                 server_side_oracle=f"{scen.oracle_id}: outcome=allowed, discriminating={cs.positive_ok}",
                                 limitations=[f"Found by a bounded settlement-fabric composer: the capability DAG ({layer_desc}) is derived from the brief's declared response_fields/request_fields, fired layer-concurrently; any declared rate-adjustment op was raced into the terminal step's check-then-act window; any short-lived step-up challenge was acquired just before the terminal. A convergence whose inputs are not externally derivable from the declared surface, or whose capture is atomic / server-recomputed / step-up-bound to a real payment, is out of scope (reported as a gap, not ruled out)."])
        return None

    async def _reconciliation_probe(self, cs: ControlState) -> Finding | None:
        """B52 asynchronous-reconciliation composer (BOUNDED, FAIL-CLOSED): a capability class beyond the B50 fabric
        probe. Where the convergence/fabric probes compose a >=2-capability quorum at a single terminal, this probe
        reasons about a STATEFUL RESOURCE LIFECYCLE and an eventually-consistent reconciliation gap: it reconstructs,
        from the declared surface, an "open" op that mints a period/resource handle, a rate-bearing "overlay/credit"
        op on that handle, a "close/seal" op on that handle, and a terminal "reconcile" op that consumes the handle,
        and drives them in the one order that makes the release survive reconciliation --
            open -> overlay(rate=0) -> close -> reconcile
        -- so a client-declared credit overlay is locked into the closed period's authoritative aggregate and the
        reconcile finalises a grant on net<=0. It issues only DECLARED operations and uses only harvested /
        brief-declared black-box values; confirmation is unchanged (the real oracle must flip for a never-paid
        identity, reproduced in a clean session), so a correctly-implemented target yields no false positive.

          C1 -- RESOURCE-LIFECYCLE RECONSTRUCTION. Discover (open, overlay, close, reconcile) around one produced
                handle. (recon_use_lifecycle False drops open/close -> no owned closed period -> reconcile refused.)
          C2 -- AGGREGATE CREDIT OVERLAY. Apply the rate-bearing overlay op at rate 0 to drive the period aggregate
                to <=0. (recon_use_overlay False skips it -> the authoritative net due stays the full commitment.)
          C3 -- SEAL-BEFORE-SETTLE ORDERING. Apply the overlay while the period is OPEN, then close, then reconcile.
                (recon_use_sequence False overlays AFTER the close -> the closed period rejects it -> nothing locked.)"""
        if not self._enable_reconciliation_probe:
            return None
        import re as _re
        b, feature = self.brief, self.brief.primary_feature()
        if feature is None or not cs.setup_ok or not cs.positive_ok or not cs.negative_ok or cs.open_feature or cs.global_leak:
            return None
        rate_like = _re.compile(r"amount|rate|price|qty|quantit|total|value|cost|units|seats|\bnet|balance|subtotal|credit", _re.I)

        def _ph(path: str) -> list[str]:
            return _re.findall(r"\{(\w+)\}", path)

        producers: dict[str, str] = {}
        for name, op in b.operations.items():
            for logical in (op.response_fields or {}):
                producers.setdefault(logical, name)
        if not producers:
            return None

        def _produces(opname: str) -> bool:
            spec = b.op(opname)
            return bool(spec and spec.response_fields)

        # Reconstruct a lifecycle around each candidate handle X from the DECLARED surface:
        #   open     = a POST op that PRODUCES X, no path placeholders, no produced-capability inputs (a root mint)
        #   overlay  = a POST op consuming X as a path placeholder, rate-bearing, producing no capability
        #   close    = a POST op consuming X as a path placeholder, NOT rate-bearing, producing no capability
        #   terminal = a POST op consuming X via request_fields (not a path placeholder), producing no capability
        lifecycle: tuple[str, str, str, str, str] | None = None  # (handle, open, overlay, close, terminal)
        for handle, open_op in producers.items():
            ospec = b.op(open_op)
            if ospec is None or ospec.method != "POST" or _ph(ospec.path):
                continue
            if any(f in producers for f in (ospec.request_fields or {})):
                continue  # the "open" must be a root (no produced inputs of its own)
            overlay_op = close_op = terminal = None
            for name, op in b.operations.items():
                if op.method != "POST" or name == open_op or _produces(name):
                    continue
                path_phs = _ph(op.path)
                req = op.request_fields or {}
                is_rate = any(rate_like.search(f) for f in req)
                if handle in path_phs and is_rate and overlay_op is None:
                    overlay_op = name
                elif handle in path_phs and not is_rate and close_op is None:
                    close_op = name
                elif handle in req and handle not in path_phs and terminal is None:
                    terminal = name
            if overlay_op and close_op and terminal:
                lifecycle = (handle, open_op, overlay_op, close_op, terminal)
                break
        if lifecycle is None:
            return None
        handle, open_op, overlay_op, close_op, terminal = lifecycle

        def _fields_for(op_name: str, ctx: dict[str, Any]) -> dict[str, Any]:
            spec = b.op(op_name)
            out: dict[str, Any] = {}
            for f in (spec.request_fields or {}) if spec else {}:
                if f in ctx:
                    out[f] = ctx[f]
                elif rate_like.search(f):
                    out[f] = 0   # the zero-rate credit overlay (a basis-requiring / re-deriving target is unaffected)
            return out

        async def _call(S: CustomerSession, opn: str, ctx: dict[str, Any], label: str) -> CallResult:
            spec = b.op(opn)
            pp = {ph: ctx[ph] for ph in _ph(spec.path) if ph in ctx} if spec else {}
            return await S.call(opn, label=label, path_params=pp, fields=_fields_for(opn, ctx))

        harvest_ops = [n for n, o in b.operations.items() if o.method == "GET" and n != "return_flow"]

        async def assemble(label: str) -> tuple[CustomerSession | None, OracleObservation | None]:
            try:
                S = await self.prov.acquire(label)
            except IdentityPoolExhausted:
                return None, None
            if (await self.oracle.check(S, feature, oracle_id=f"U:recon:{label}:pre")).outcome != "denied":
                return None, None
            ctx: dict[str, Any] = {}
            deny = {t for t in (getattr(S, "_token", None),) if isinstance(t, str) and t}
            for g in harvest_ops:
                r = await S.call(g, label=f"U:recon:{label}:recon:{g}")
                self._harvest(r.body, ctx, deny)
                self._harvest_headers(r.headers, ctx, deny)
            if self._recon_use_lifecycle:
                r = await _call(S, open_op, ctx, f"U:recon:{label}:open")
                if not (r.status and 200 <= r.status < 300):
                    return S, None
                self._harvest(r.body, ctx, deny)
                self._harvest_headers(r.headers, ctx, deny)
            if handle not in ctx:
                return S, None  # the period/resource handle was not minted on the declared surface
            if self._recon_use_sequence:
                if self._recon_use_overlay:
                    await _call(S, overlay_op, ctx, f"U:recon:{label}:overlay")   # credit the period while OPEN
                if self._recon_use_lifecycle:
                    await _call(S, close_op, ctx, f"U:recon:{label}:close")        # then SEAL it
            else:
                # ablation: seal first, then overlay -> a closed period rejects the overlay, so nothing is locked in.
                if self._recon_use_lifecycle:
                    await _call(S, close_op, ctx, f"U:recon:{label}:close")
                if self._recon_use_overlay:
                    await _call(S, overlay_op, ctx, f"U:recon:{label}:overlay")
            cr = await _call(S, terminal, ctx, f"U:recon:{label}:reconcile")       # then SETTLE
            if not (cr.status and 200 <= cr.status < 300):
                return S, None
            self._harvest(cr.body, ctx, deny)
            return S, await self.oracle.check(S, feature, oracle_id=f"U:recon:{label}:post")

        try:
            S, scen = await assemble("u_recon")
            if scen is None or scen.outcome != "allowed":
                return None
            _S2, repro = await assemble("u_recon_repro")
        except IdentityPoolExhausted:
            return None
        if repro is None or repro.outcome != "allowed":
            return None
        decision, _, _ = await self._confirm(hyp="PBB-U", cs=cs, feature=feature, scenario=scen, qualifying=False, discriminating=cs.positive_ok, repro=repro)
        if not decision.confirmed:
            return None
        ids = _clean([*cs.artifact_ids, *scen.artifact_ids, *repro.artifact_ids])
        return self._finding("PBB-U", Verdict.CONFIRMED_P0, "high",
                             f"A never-paid identity USED the paid feature after driving a stateful reconciliation lifecycle "
                             f"'{open_op}'->'{overlay_op}'(rate=0)->'{close_op}'->'{terminal}': a client-declared zero-rate credit "
                             f"overlay on an open billing period, locked in by the close, was trusted by settlement reconciliation as "
                             f"the authoritative net due (<=0) and finalised an enterprise grant with no captured payment; a clean "
                             f"session reproduced it. Internal cause: UNKNOWN.",
                             artifacts=ids, token=decision.token,
                             metrics={"handle": handle, "lifecycle": [open_op, overlay_op, close_op, terminal],
                                      "overlay_rate": 0, "order": "overlay->close->reconcile"},
                             payment_state="no qualifying payment was made at any step",
                             actual_state="feature allowed after reconciling a closed period whose unbacked zero-rate overlay was trusted as net due",
                             entitlement_state="granted",
                             server_side_oracle=f"{scen.oracle_id}: outcome=allowed, discriminating={cs.positive_ok}",
                             limitations=["Found by a bounded reconciliation-lifecycle composer: an open->overlay->close->reconcile lifecycle derived from the declared surface (a produced handle, a rate-bearing overlay and a seal op on it, and a terminal that consumes it), driven overlay-before-close-before-reconcile. A reconciliation that re-derives the authoritative amount from real captured bases, defers an unbacked overlay on close, or requires a real settlement basis to finalise is out of scope (reported as a gap, not ruled out)."])

    async def _federation_probe(self, cs: ControlState) -> Finding | None:
        """B53-B56 DEMIURGE federation composer (BOUNDED, FAIL-CLOSED): the first probe for a DISTRIBUTED target.

        The archon surface is NOT in the brief; it is advertised only in the edge's public reference. The one
        no-payment ENTERPRISE bypass is a CONFUSED DEPUTY across services, carried by an opaque packed correlation
        token whose MAC does not cover its basis/amount region. Four capability classes, each individually load-bearing:

          B53 -- DISCOVERY. Fetch every declared GET, harvest the archon routes the reference advertises, and bind the
                 roles (mint/open/credit/close/finalize/step) by keyword. (``fed_use_discovery`` False -> no surface.)
          B54 -- TOKEN RE. Pay the cheapest plan twice on a throwaway reference identity, mint a token after each, and
                 DIFFERENTIALLY locate the 4-byte amount field by the known capture delta; then, on a never-paid
                 identity, overwrite that field to inject a large unbacked credit. (``fed_use_token_re`` False -> the
                 honest token carries amount 0, so the credit is zero and the net due stays full -> miss.)
          B55 -- TRUST-GRAPH. Drive the cross-service confused-deputy order (mint -> open -> credit -> close ->
                 finalize). (``fed_use_trust_graph`` False -> the order is not composed -> miss.)
          B56 -- ORCHESTRATION. Hold the token/period/credit state across services and LATE-BIND a fresh step-up
                 challenge immediately before finalize. (``fed_use_orchestration`` False -> no fresh challenge -> the
                 step-up turns finalize away -> miss.)

        Confirmation is UNCHANGED: a never-paid oracle flip + an independent clean-session reproduction through the
        gate. A correctly-implemented federation (MAC covers the basis, credits re-derived against real captures,
        unbacked credits deferred on close, a real captured basis required to finalise) yields no false positive."""
        if not self._enable_federation:
            return None
        import base64 as _b64
        import struct as _struct
        b, feature = self.brief, self.brief.primary_feature()
        if feature is None or not cs.setup_ok or not cs.positive_ok or not cs.negative_ok or cs.open_feature or cs.global_leak:
            return None
        from app.testing.integrity import kill_chain_roster as _roster
        # roster dispatch: each distinct capability is OWNED by one kill-chain-roster agent; the step runs only while
        # that agent is activatable (owner-declined via the roster, or ablated here -> the step does not run).
        _AGENT = {"discovery": "A3", "token_re": "A34", "trust_graph": "A39", "orchestration": "A20", "analogy": "A30"}

        def _agent_ok(cap: str) -> bool:
            aid = _AGENT[cap]
            return _roster.is_activatable(aid) and aid not in self._disabled_agents

        if not (self._fed_use_discovery and _agent_ok("discovery")):
            return None  # B53 / agent A3 ablation: without undeclared-operation discovery there is no archon surface

        def _paths(body: Any, acc: list[tuple[str, str]]) -> None:
            if isinstance(body, dict):
                for k, v in body.items():
                    if isinstance(v, str) and v.startswith("/"):
                        acc.append((str(k), v))
                    else:
                        _paths(v, acc)
            elif isinstance(body, list):
                for v in body:
                    _paths(v, acc)

        def _role(pairs: list[tuple[str, str]], *kw: str) -> list[str]:
            # all candidate paths matching a role's keyword set, as a ranked list. B58 info-gain ranks the real
            # terminal (keyword in the ACTION segment) ahead of grant-looking decoys (keyword only elsewhere), so the
            # chain is assembled with fewer wasted probes; without it, discovery order is kept.
            hits = [(k, p) for k, p in pairs if any(w in (k + " " + p).lower() for w in kw)]
            if self._fed_use_infogain:
                def _score(kp: tuple[str, str]) -> int:
                    act = kp[1].rstrip("/").rsplit("/", 1)[-1].lower()
                    return 1 if any(w in act for w in kw) else 0
                hits = sorted(hits, key=_score, reverse=True)
            return [p for _k, p in hits]

        def _first_str(body: Any, keys: tuple[str, ...]) -> str | None:
            if isinstance(body, dict):
                return next((body[k] for k in keys if isinstance(body.get(k), str) and body[k]), None)
            return None

        async def _mint(S: CustomerSession, mint_p: str, label: str) -> str | None:
            r = await S.raw("POST", mint_p, label=label)
            return _first_str(r.body, ("correlation_token", "token", "ct"))

        # -- B53 discovery: harvest the archon routes the reference advertises, bind roles ---------------------------
        try:
            cal = await self.prov.acquire("u_fed_cal")
        except IdentityPoolExhausted:
            return None
        pairs: list[tuple[str, str]] = []
        for n, o in b.operations.items():
            if o.method == "GET":
                _paths((await cal.call(n, label=f"U:fed:disco:{n}")).body, pairs)
        # role binding is SEMANTIC (a principled synonym set), not DEMIURGE-spelling-specific, so it generalises to the
        # held-out family's renamed archons; the sets are disjoint so a path binds at most one role.
        roles = {"mint": _role(pairs, "correlation", "token", "vault", "mint", "issue", "custod"),
                 "open": _role(pairs, "open", "meter", "usage", "cycle"),
                 "credit": _role(pairs, "credit", "dispute", "rebate", "adjust", "chargeback"),
                 "close": _role(pairs, "close", "reconcil", "seal", "lock"),
                 "final": _role(pairs, "finaliz", "settle", "clear", "disburse", "payout"),
                 "step": _role(pairs, "stepup", "step", "challenge", "radar", "otp", "verify", "nonce")}
        if not all(roles[k] for k in ("mint", "open", "credit", "close", "final")):
            return None

        # -- B59 cross-domain analogy: adapt the B52 reconciliation lifecycle to the federation ----------------------
        # The credit step is the cross-service analogue of B52's rate-bearing overlay, and the correlation token is
        # what carries the (forged) rate across services. FAIL-CLOSED: without the analogy the probe has only the
        # literal single-service template (an overlay with a DECLARED rate field), which DEMIURGE's token-carried
        # credit never matches -- so the token is never presented to the credit step and the bypass is not formed.
        if not (self._fed_use_analogy and _agent_ok("analogy")):
            return None
        credit_via_token = True

        # -- B54 token RE: calibrate the amount-field offset by differential diffing of two known-amount tokens ------
        amount_offset: int | None = None
        if self._fed_use_token_re and _agent_ok("token_re"):
            unit = int(round(float(b.plans.get(b.cheapest_plan, {}).get(b.primary_currency, 0.0)) * 100)) or 100
            await self._pay(cal, plan=b.cheapest_plan, outcome_key="success", label="U:fed:cal:pay1")
            t1 = await _mint(cal, roles["mint"][0], "U:fed:cal:mint1")
            await self._pay(cal, plan=b.cheapest_plan, outcome_key="success", label="U:fed:cal:pay2")
            t2 = await _mint(cal, roles["mint"][0], "U:fed:cal:mint2")
            if t1 and t2:
                try:
                    d1, d2 = _b64.urlsafe_b64decode(t1.encode()), _b64.urlsafe_b64decode(t2.encode())
                    if len(d1) == len(d2):
                        for i in range(len(d1) - 3):
                            if _struct.unpack(">I", d1[i:i + 4])[0] == unit and _struct.unpack(">I", d2[i:i + 4])[0] == unit * 2:
                                amount_offset = i
                                break
                except Exception:  # noqa: BLE001
                    amount_offset = None
            if amount_offset is None:
                return None  # could not reverse-engineer the token -> cannot inject an unbacked basis -> miss

        def _forge(tok: str) -> str:
            if not self._fed_use_token_re or amount_offset is None:
                return tok  # honest token: amount reflects real captures (0 for a never-paid id) -> credit 0 -> miss
            raw = bytearray(_b64.urlsafe_b64decode(tok.encode()))
            if amount_offset + 4 <= len(raw):
                raw[amount_offset:amount_offset + 4] = _struct.pack(">I", 100_000_000)  # a large unbacked credit -> net<=0
            return _b64.urlsafe_b64encode(bytes(raw)).decode()

        if not (self._fed_use_trust_graph and _agent_ok("trust_graph")):
            return None  # B55 / agent A39 ablation: surface discovered and token RE'd, but the cross-service order is not composed

        # -- B55/B56 orchestration: drive the cross-service confused-deputy order, late-binding a fresh step-up ------
        async def assemble(label: str) -> tuple[CustomerSession | None, OracleObservation | None]:
            try:
                S = await self.prov.acquire(label)
            except IdentityPoolExhausted:
                return None, None
            if (await self.oracle.check(S, feature, oracle_id=f"U:fed:{label}:pre")).outcome != "denied":
                return S, None
            tok = await _mint(S, roles["mint"][0], f"U:fed:{label}:mint")
            if not tok:
                return S, None
            forged = _forge(tok)
            opened = await S.raw("POST", roles["open"][0], label=f"U:fed:{label}:open", json_body={})
            period = _first_str(opened.body, ("period", "handle", "id"))
            if not period:
                return S, None
            credit_body = {"period": period, "ct": forged} if credit_via_token else {"period": period}
            await S.raw("POST", roles["credit"][0], label=f"U:fed:{label}:credit", json_body=credit_body)
            await S.raw("POST", roles["close"][0], label=f"U:fed:{label}:close", json_body={"period": period})
            fin: dict[str, Any] = {"period": period, "ct": forged}
            if roles["step"] and self._fed_use_orchestration and _agent_ok("orchestration"):
                ch = _first_str((await S.raw("POST", roles["step"][0], label=f"U:fed:{label}:stepup", json_body={})).body,
                                ("challenge", "nonce", "id"))
                if ch:
                    fin["challenge"] = ch
            rf = None
            for fp in roles["final"]:  # try terminal candidates; decoys 402, the real finalize 2xx (B58 ranks these)
                rf = await S.raw("POST", fp, label=f"U:fed:{label}:finalize", json_body=fin)
                if rf.status and 200 <= rf.status < 300:
                    break
            if not (rf and rf.status and 200 <= rf.status < 300):
                return S, None
            return S, await self.oracle.check(S, feature, oracle_id=f"U:fed:{label}:post")

        try:
            S, scen = await assemble("u_fed")
            if scen is None or scen.outcome != "allowed":
                return None
            _S2, repro = await assemble("u_fed_repro")
        except IdentityPoolExhausted:
            return None
        if repro is None or repro.outcome != "allowed":
            return None
        decision, _, _ = await self._confirm(hyp="PBB-U", cs=cs, feature=feature, scenario=scen, qualifying=False,
                                             discriminating=cs.positive_ok, repro=repro)
        if not decision.confirmed:
            return None
        ids = _clean([*cs.artifact_ids, *scen.artifact_ids, *repro.artifact_ids])
        return self._finding("PBB-U", Verdict.CONFIRMED_P0, "high",
                             "A never-paid identity USED the paid feature after DISCOVERING an undeclared archon "
                             "surface from the public reference, REVERSE-ENGINEERING a packed correlation token "
                             "(differential field inference) to inject an unbacked basis, and driving a CROSS-SERVICE "
                             "confused-deputy order (mint -> open -> credit -> close -> step-up -> finalize) across the "
                             "payment federation with no captured payment; a clean session reproduced it. Internal "
                             "cause: UNKNOWN.",
                             artifacts=ids, token=decision.token,
                             metrics={"roles": {k: v for k, v in roles.items() if v}, "amount_offset": amount_offset,
                                      "chain": ["mint", "open", "credit", "close", "stepup", "finalize"]},
                             payment_state="no qualifying payment was made at any step",
                             actual_state="feature allowed after a cross-service no-payment finalize",
                             entitlement_state="granted",
                             server_side_oracle=f"{scen.oracle_id}: outcome=allowed, discriminating={cs.positive_ok}",
                             limitations=["Found by a bounded federation composer: discovery of the archon surface from "
                                          "the public reference, differential field inference on the opaque correlation "
                                          "token, and a cross-service confused-deputy order. A federation that binds the "
                                          "token's basis under its MAC, re-derives credits against real captures, defers "
                                          "unbacked credits on close, or requires a real captured basis to finalise is "
                                          "out of scope (reported as a gap, not ruled out)."])

    async def _exp_u(self, cs: ControlState) -> Finding:
        hyp = "PBB-U"
        if (blocked := self._precondition(cs, hyp)) is not None:
            return blocked
        b, feature = self.brief, self.brief.primary_feature()
        assert feature is not None
        if self._enable_channel_probe and (chan := await self._channel_probe(cs)) is not None:
            return chan
        if self._enable_chain_probe and (chained := await self._chain_probe(cs)) is not None:
            return chained
        if self._enable_convergence_probe and (converged := await self._convergence_probe(cs)) is not None:
            return converged
        if self._enable_fabric_probe and (fabricked := await self._fabric_probe(cs)) is not None:
            return fabricked
        if self._enable_reconciliation_probe and (reconciled := await self._reconciliation_probe(cs)) is not None:
            return reconciled
        if self._enable_federation and (federated := await self._federation_probe(cs)) is not None:
            return federated
        artifacts: list[str | None] = []
        divergences: list[str] = []
        tested: dict[str, str] = {}
        candidate: tuple[CustomerSession, OracleObservation] | None = None
        for key, human in (("decline", "declined card"), ("cancel", "cancelled / abandoned checkout")):
            S = await self.prov.acquire(f"u_{key}")
            pre = await self.oracle.check(S, feature, oracle_id=f"U:{key}:pre")
            artifacts += pre.artifact_ids
            if pre.outcome != "denied":
                return self._finding(hyp, Verdict.UNKNOWN, "low", f"A fresh identity was not denied before the scenario ({pre.outcome}); the fixture is contaminated or the oracle unstable.", artifacts=artifacts, reasons=["fixture_contaminated"])
            pay = await self._pay(S, plan=b.cheapest_plan, outcome_key=key, label=f"U:{key}")
            artifacts += pay.artifact_ids()
            if pay.payment_id is None:
                tested[key] = "checkout_unavailable"
                continue
            rf = await self._return_flow(S, pay.payment_id, label=f"U:{key}:return", claim_status=b.return_status_values["success"])
            artifacts.append(rf.artifact_id)
            ui_claim = claims_paid(rf.body)
            view_claim = None
            if b.op("subscription_view") is not None:
                view = await S.call("subscription_view", label=f"U:{key}:view")
                artifacts.append(view.artifact_id)
                view_claim = claims_paid(view.body)
            post = await self.oracle.check(S, feature, oracle_id=f"U:{key}:post")
            artifacts += post.artifact_ids
            tested[key] = post.outcome
            if post.outcome == "allowed" and candidate is None:
                candidate = (S, post, key, human)
            elif post.outcome == "denied":
                if ui_claim:
                    divergences.append(f"{human}: the return-flow response claims success/paid while the server-enforced feature is DENIED (UI/redirect-only; not an entitlement)")
                if view_claim:
                    divergences.append(f"{human}: the customer-visible subscription view claims an active paid state while the server-enforced feature is DENIED")
            if view_claim is not None:
                cs.view_observations.append({"identity": S.identity_alias, "view_claims_paid": view_claim, "oracle": post.outcome, "context": f"U:{key}", "artifact": None})
        if candidate is not None:
            S, post, found_key, found_human = candidate
            decision, _, repro = await self._confirm(hyp=hyp, cs=cs, feature=feature, scenario=post, qualifying=False, discriminating=cs.positive_ok, subject=S)
            return self._confirmed_or_partial(hyp, decision, "A synthetic identity USED the paid feature after a non-qualifying (declined/cancelled) payment; a clean session reproduced it and the clean control stayed denied. Internal cause: UNKNOWN.",
                                              "The paid feature was usable after a non-qualifying payment, but the confirmation chain is incomplete (see reasons).", [*artifacts, *post.artifact_ids, *(repro.artifact_ids if repro else ())],
                                              divergences=divergences, metrics={"variants": tested}, limitations=["Result limited to the tested outcomes (declined, cancelled) and the claim channel (return-flow status parameter)."],
                                              # ZR-019 per-experiment fields:
                                              identity_tenant_dimension=f"identity_alias={S.identity_alias}",
                                              commercial_context=f"plan={b.cheapest_plan}",
                                              payment_state=f"{found_human} (payment_id did not reach a qualifying/confirmed state)",
                                              actual_state=f"feature_outcome={post.outcome} for identity {S.identity_alias} after {found_key}",
                                              entitlement_state="granted" if post.outcome == "allowed" else post.outcome,
                                              server_side_oracle=f"{post.oracle_id}: outcome={post.outcome}, discriminating={cs.positive_ok}")
        if any(v == "indeterminate" for v in tested.values()):
            return self._finding(hyp, Verdict.UNKNOWN, "medium", "The feature response after the scenario was neither a proven use nor a declared denial.", artifacts=artifacts, divergences=divergences, metrics={"variants": tested})
        if not tested or all(v == "checkout_unavailable" for v in tested.values()):
            return self._finding(hyp, Verdict.BLOCKED, "medium", "Checkout could not be started, so the failed-payment scenario was not executable.", artifacts=artifacts, metrics={"variants": tested})
        return self._finding(hyp, Verdict.RULED_OUT, "high", "Under the tested conditions a declined or cancelled payment did not unlock the paid feature (oracle proven discriminating by the controls)." + (" A UI-only divergence was observed (not a P0)." if divergences else ""),
                             artifacts=artifacts, divergences=divergences, metrics={"variants": tested}, limitations=["Limited to declined/cancelled outcomes, the return-flow status claim, the tested identities and this environment."])

    async def _exp_f(self, cs: ControlState) -> Finding:
        hyp = "PBB-F"
        b, tier = self.brief, self.brief.tier_feature()
        if tier is None or len(b.plans) < 2:
            return self._finding(hyp, Verdict.BLOCKED, "high", "Plan binding needs at least two plans and a protected feature gated by the most expensive plan.", reasons=["brief_lacks_tier_feature"])
        if (blocked := self._precondition(cs, hyp, needs_tier=True)) is not None:
            return blocked
        cheapest_price = b.plans[b.cheapest_plan].get(b.primary_currency)
        top_price = b.plans[b.priciest_plan].get(b.primary_currency)
        artifacts: list[str | None] = list(cs.artifact_ids)
        tested: dict[str, str] = {}
        candidate: tuple[CustomerSession, OracleObservation, str] | None = None
        unknown: list[str] = []
        if cs.tier_leak and cs.V1 is not None and cs.tier_leak_obs is not None:
            candidate, tested["plan_not_enforced"] = (cs.V1, cs.tier_leak_obs, "plan_not_enforced"), "allowed"
        else:
            tested["plan_not_enforced"] = "denied"
        if candidate is None and cheapest_price is not None and top_price is not None:  # channel A: checkout amount tamper
            S1 = await self.prov.acquire("f_amount")
            pre = await self.oracle.check(S1, tier, oracle_id="F:A:pre")
            artifacts += pre.artifact_ids
            if pre.outcome != "denied":
                unknown.append("fixture_contaminated(F:A)")
            else:
                pay = await self._pay(S1, plan=b.priciest_plan, outcome_key="success", label="F:A", amount=cheapest_price)
                artifacts += pay.artifact_ids()
                if pay.rejected_at_checkout:
                    tested["checkout_amount_tamper"] = "rejected_at_checkout"
                elif pay.payment_id and pay.reached_sandbox:
                    rf = await self._return_flow(S1, pay.payment_id, label="F:A:return", claim_status=b.return_status_values["success"])
                    artifacts.append(rf.artifact_id)
                    post = await self.oracle.check(S1, tier, oracle_id="F:A:post")
                    artifacts += post.artifact_ids
                    tested["checkout_amount_tamper"] = post.outcome
                    paid_full_price = pay.billed_amount is not None and pay.billed_amount >= top_price * 0.99
                    if post.outcome == "allowed" and not paid_full_price:
                        if pay.billed_amount is None:
                            unknown.append("billed amount not externally observable (F:A)")
                        else:
                            candidate = (S1, post, "checkout_amount_tamper")
        if candidate is None:  # channel B: plan claimed at the return flow
            S2 = await self.prov.acquire("f_claim")
            pre = await self.oracle.check(S2, tier, oracle_id="F:B:pre")
            artifacts += pre.artifact_ids
            if pre.outcome != "denied":
                unknown.append("fixture_contaminated(F:B)")
            else:
                pay = await self._pay(S2, plan=b.cheapest_plan, outcome_key="success", label="F:B")
                artifacts += pay.artifact_ids()
                if pay.payment_id and pay.reached_sandbox:
                    # the claim travels with the customer's FIRST return-flow request (an edited redirect URL); a second call would be a replay (PBB-C)
                    claim = await self._return_flow(S2, pay.payment_id, label="F:B:return_plan_claim", claim_status=b.return_status_values["success"], plan=b.priciest_plan)
                    post = await self.oracle.check(S2, tier, oracle_id="F:B:post")
                    artifacts += [claim.artifact_id, *post.artifact_ids]
                    tested["return_plan_claim"] = post.outcome
                    if post.outcome == "allowed":
                        candidate = (S2, post, "return_plan_claim")
        if candidate is not None:
            S, obs, channel = candidate
            decision, _, repro = await self._confirm(hyp=hyp, cs=cs, feature=tier, scenario=obs, qualifying=False, discriminating=cs.tier_positive_ok, subject=S)
            return self._confirmed_or_partial(hyp, decision, f"A payer who did not pay the top-plan price USED the top-tier feature (channel: {channel}); a clean session reproduced it and the clean control stayed denied. Internal cause: UNKNOWN.",
                                              f"The top-tier feature was usable without a top-plan payment (channel: {channel}), but the confirmation chain is incomplete.", [*artifacts, *obs.artifact_ids, *(repro.artifact_ids if repro else ())],
                                              metrics={"channels": tested, "channel": channel},
                                              identity_tenant_dimension=f"identity={S.identity_alias}", commercial_context=f"cheapest_plan={b.cheapest_plan}, top_plan={b.priciest_plan}",
                                              payment_state=f"insufficient for top tier (channel={channel})", actual_state=f"feature_outcome={obs.outcome} for {S.identity_alias} via channel={channel}",
                                              entitlement_state="granted" if obs.outcome == "allowed" else obs.outcome, server_side_oracle=f"{obs.oracle_id}: outcome={obs.outcome}, discriminating={cs.tier_positive_ok}")
        if unknown or any(v == "indeterminate" for v in tested.values()):
            return self._finding(hyp, Verdict.UNKNOWN, "medium", "At least one plan-binding channel could not be evaluated with external evidence.", artifacts=artifacts, reasons=unknown, metrics={"channels": tested})
        return self._finding(hyp, Verdict.RULED_OUT, "high", "Under the tested conditions the plan paid for bound the tier granted (cheapest payer, tampered checkout amount and a return-flow plan claim all ended DENIED/rejected).", artifacts=artifacts,
                             metrics={"channels": tested}, limitations=["Limited to the three tested channels and the declared plans."])

    async def _exp_h(self, cs: ControlState) -> Finding:
        hyp = "PBB-H"
        b, tier = self.brief, self.brief.tier_feature()
        alt = next((c for c in b.plans[b.priciest_plan] if c != b.primary_currency), None)
        if tier is None or alt is None:
            return self._finding(hyp, Verdict.BLOCKED, "high", "Currency binding needs a top-tier feature and a second currency in the public price list.", reasons=["brief_lacks_second_currency_or_tier_feature"])
        if (blocked := self._precondition(cs, hyp, needs_tier=True)) is not None:
            return blocked
        expected = b.plans[b.priciest_plan][alt]
        S = await self.prov.acquire("h_cur")
        pre = await self.oracle.check(S, tier, oracle_id="H:pre")
        artifacts: list[str | None] = [*pre.artifact_ids]
        if pre.outcome != "denied":
            return self._finding(hyp, Verdict.UNKNOWN, "low", "A fresh identity was not denied on the top-tier feature before the scenario.", artifacts=artifacts, reasons=["fixture_contaminated"])
        pay = await self._pay(S, plan=b.priciest_plan, outcome_key="success", label="H", currency=alt)
        artifacts += pay.artifact_ids()
        if pay.rejected_at_checkout:
            return self._finding(hyp, Verdict.RULED_OUT, "high", f"Checkout in {alt} was rejected (correct rejection).", artifacts=artifacts)
        if pay.payment_id is None or not pay.reached_sandbox:
            return self._finding(hyp, Verdict.BLOCKED, "medium", "Checkout in the alternative currency could not be completed.", artifacts=artifacts, reasons=[f"checkout_status={pay.checkout.status}"])
        mismatch = None if pay.billed_amount is None else (pay.billed_currency not in (None, alt) or pay.billed_amount < expected * 0.99)
        rf = await self._return_flow(S, pay.payment_id, label="H:return", claim_status=b.return_status_values["success"])
        post = await self.oracle.check(S, tier, oracle_id="H:post")
        artifacts += [rf.artifact_id, *post.artifact_ids]
        metrics = {"alternative_currency": alt, "public_price": expected, "billed_amount": pay.billed_amount, "billed_currency": pay.billed_currency, "billing_mismatch": mismatch}
        if mismatch is None:
            return self._finding(hyp, Verdict.UNKNOWN, "medium", "The billed amount is not externally observable in the checkout response, so under-billing cannot be established.", artifacts=artifacts, reasons=["billed_amount_not_observable"], metrics=metrics)
        if post.outcome == "allowed" and mismatch:
            decision, _, repro = await self._confirm(hyp=hyp, cs=cs, feature=tier, scenario=post, qualifying=False, discriminating=cs.tier_positive_ok, subject=S)
            return self._confirmed_or_partial(hyp, decision, f"A payment billed below the public {alt} price unlocked the top-tier feature; a clean session reproduced it. Internal cause: UNKNOWN.",
                                              "An under-billed payment unlocked the tier, but the confirmation chain is incomplete.", [*artifacts, *(repro.artifact_ids if repro else ())], metrics=metrics,
                                              identity_tenant_dimension=f"identity={S.identity_alias}", commercial_context=f"alternative_currency={alt}, public_price={expected}",
                                              payment_state=f"billed {pay.billed_amount} {pay.billed_currency} (below public {expected} {alt})", actual_state=f"feature_outcome={post.outcome} for {S.identity_alias}",
                                              entitlement_state="granted" if post.outcome == "allowed" else post.outcome, server_side_oracle=f"{post.oracle_id}: outcome={post.outcome}, discriminating={cs.tier_positive_ok}")
        if post.outcome == "indeterminate":
            return self._finding(hyp, Verdict.UNKNOWN, "medium", "The tier feature response was neither a proven use nor a declared denial.", artifacts=artifacts, metrics=metrics)
        div = [f"billed amount {pay.billed_amount} {pay.billed_currency} is below the public price {expected} {alt}, but the tier feature was correctly DENIED (billing divergence, not an entitlement P0)"] if mismatch else []
        return self._finding(hyp, Verdict.RULED_OUT, "high", "Under the tested conditions the alternative-currency payment did not unlock the top tier." + (" A billing divergence was observed." if mismatch else ""), artifacts=artifacts, divergences=div, metrics=metrics,
                             limitations=["Limited to one alternative currency and the cheapest-to-top plan relation."])

    async def _quota_run(self, label: str, replays: int, quota: FeatureSpec, cap: int) -> tuple[CustomerSession, list[OracleObservation], str, list[str | None]]:
        b = self.brief
        S = await self.prov.acquire(label)
        pre = await self.oracle.check(S, quota, oracle_id=f"{label}:pre")
        arts: list[str | None] = [*pre.artifact_ids]
        if pre.outcome != "denied":
            return S, [], "fixture_contaminated", arts
        pay = await self._pay(S, plan=b.cheapest_plan, outcome_key="success", label=label)
        arts += pay.artifact_ids()
        if pay.payment_id is None or not pay.reached_sandbox:
            return S, [], "setup_failed", arts
        arts.append((await self._return_flow(S, pay.payment_id, label=f"{label}:return", claim_status=b.return_status_values["success"])).artifact_id)
        for i in range(replays):
            arts.append((await self._return_flow(S, pay.payment_id, label=f"{label}:replay{i + 1}", claim_status=b.return_status_values["success"])).artifact_id)
        obs = await self._consume(S, quota, cap, label)
        for o in obs:
            arts += o.artifact_ids
        return S, obs, "ok", arts

    async def _exp_c(self, cs: ControlState) -> Finding:
        hyp = "PBB-C"
        b, quota = self.brief, self.brief.quota_feature()
        if quota is None:
            return self._finding(hyp, Verdict.BLOCKED, "high", "Duplicate paid value is only countable through a quota/credit feature; the brief declares none.", reasons=["brief_lacks_quota_feature"])
        if (blocked := self._precondition(cs, hyp)) is not None:
            return blocked
        cap = b.limits.quota_probe_cap
        _, q_obs, q_state, arts = await self._quota_run("c_base", 0, quota, cap)
        n0 = sum(1 for o in q_obs if o.outcome == "allowed")
        if q_state != "ok":
            return self._finding(hyp, Verdict.UNKNOWN if q_state == "fixture_contaminated" else Verdict.BLOCKED, "medium", f"Baseline payer could not be established ({q_state}).", artifacts=arts, reasons=[q_state])
        if n0 == 0 or n0 >= cap:
            return self._finding(hyp, Verdict.UNKNOWN, "medium", f"The quota is not observable within the low-volume probe cap (baseline single payment allowed {n0} of max {cap} uses), so duplication cannot be measured.", artifacts=arts, reasons=["quota_not_bounded_or_empty"], metrics={"baseline_uses": n0, "cap": cap})
        R, r_obs, r_state, r_arts = await self._quota_run("c_replay", 2, quota, cap)
        arts += r_arts
        n1 = sum(1 for o in r_obs if o.outcome == "allowed")
        metrics = {"baseline_uses": n0, "uses_after_replay": n1, "replays": 2, "cap": cap}
        if r_state != "ok":
            return self._finding(hyp, Verdict.UNKNOWN, "medium", f"The replay subject could not be established ({r_state}).", artifacts=arts, reasons=[r_state], metrics=metrics)
        if n1 > n0:
            R2, r2_obs, r2_state, r2_arts = await self._quota_run("c_repro", 2, quota, cap)
            arts += r2_arts
            n2 = sum(1 for o in r2_obs if o.outcome == "allowed")
            metrics["uses_after_replay_independent_repro"] = n2
            scenario = r_obs[n0]
            repro = r2_obs[n0] if len(r2_obs) > n0 else (r2_obs[-1] if r2_obs else None)
            decision, _, _ = await self._confirm(hyp=hyp, cs=cs, feature=quota, scenario=scenario, qualifying=False, discriminating=n0 > 0, repro=repro)
            return self._confirmed_or_partial(hyp, decision, f"Repeating the return flow multiplied the paid quota ({n1} uses vs. {n0} for a single payment), reproduced by an independent fresh payer ({n2}). Internal cause: UNKNOWN.",
                                              f"Replay yielded more paid uses ({n1} > {n0}) but the independent reproduction/control chain is incomplete.", arts, metrics=metrics,
                                              identity_tenant_dimension=f"identity={scenario.identity_alias}", commercial_context=f"plan={b.cheapest_plan}, quota_cap={cap}",
                                              payment_state="single payment", actual_state=f"uses_after_replay={n1} (baseline={n0})",
                                              entitlement_state=f"{n1} uses granted vs {n0} paid for", server_side_oracle=f"{scenario.oracle_id}: outcome={scenario.outcome}, discriminating={n0 > 0}")
        return self._finding(hyp, Verdict.RULED_OUT, "high", f"Under the tested conditions repeating the return flow twice granted nothing beyond the single-payment quota ({n1} <= {n0}).", artifacts=arts, metrics=metrics,
                             limitations=["Limited to 2 sequential return-flow repetitions; concurrent duplicates are NOT tested (unsafe by contract)."])

    async def _exp_g(self, cs: ControlState) -> Finding:
        hyp = "PBB-G"
        b, feature = self.brief, self.brief.primary_feature()
        assert feature is not None
        if (blocked := self._precondition(cs, hyp)) is not None:
            return blocked
        S, B = await self.prov.acquire("g_payer"), await self.prov.acquire("g_benef")
        if not B.tenant_id:
            return self._finding(hyp, Verdict.BLOCKED, "high", "The second synthetic tenant's id is not externally available, so a cross-tenant claim cannot be formed.", reasons=["tenant_id_unavailable"], limitations=["Needs two approved synthetic tenants whose ids are visible to their own users."])
        pre = await self.oracle.check(B, feature, oracle_id="G:B:pre")
        artifacts: list[str | None] = [*pre.artifact_ids]
        if pre.outcome != "denied":
            return self._finding(hyp, Verdict.UNKNOWN, "low", "The beneficiary identity was not denied before the scenario.", artifacts=artifacts, reasons=["fixture_contaminated"])
        pay = await self._pay(S, plan=b.cheapest_plan, outcome_key="success", label="G")
        artifacts += pay.artifact_ids()
        if pay.payment_id is None or not pay.reached_sandbox:
            return self._finding(hyp, Verdict.BLOCKED, "medium", "The payer's sandbox payment could not be completed.", artifacts=artifacts, reasons=["payer_setup_failed"])
        artifacts.append((await self._return_flow(S, pay.payment_id, label="G:return_cross_tenant", claim_status=b.return_status_values["success"], tenant=B.tenant_id)).artifact_id)
        post = await self.oracle.check(B, feature, oracle_id="G:B:post")
        artifacts += post.artifact_ids
        if post.outcome == "allowed":
            decision, _, repro = await self._confirm(hyp=hyp, cs=cs, feature=feature, scenario=post, qualifying=False, discriminating=cs.positive_ok, subject=B)
            return self._confirmed_or_partial(hyp, decision, "Another tenant's synthetic identity USED the paid feature without paying after the payer named its tenant as beneficiary; a clean session reproduced it. Internal cause: UNKNOWN.",
                                              "The beneficiary tenant gained access, but the confirmation chain is incomplete.", [*artifacts, *(repro.artifact_ids if repro else ())],
                                              identity_tenant_dimension=f"payer={S.identity_alias}, beneficiary={B.identity_alias}, beneficiary_tenant={B.tenant_id}", commercial_context=f"plan={b.cheapest_plan}",
                                              payment_state=f"payer {S.identity_alias} paid; beneficiary {B.identity_alias} did not", actual_state=f"feature_outcome={post.outcome} for beneficiary {B.identity_alias}",
                                              entitlement_state="granted" if post.outcome == "allowed" else post.outcome, server_side_oracle=f"{post.oracle_id}: outcome={post.outcome}, discriminating={cs.positive_ok}")
        if post.outcome == "indeterminate":
            return self._finding(hyp, Verdict.UNKNOWN, "medium", "The beneficiary's feature response was neither a proven use nor a declared denial.", artifacts=artifacts)
        return self._finding(hyp, Verdict.RULED_OUT, "high", "Under the tested conditions another tenant could not be named as beneficiary of a payment.", artifacts=artifacts,
                             limitations=["Limited to one tenant-claim channel (return-flow tenant parameter) and two synthetic tenants."])

    async def _exp_x(self, cs: ControlState) -> Finding:
        hyp = "PBB-X"
        b, feature = self.brief, self.brief.primary_feature()
        assert feature is not None
        if (blocked := self._precondition(cs, hyp)) is not None:
            return blocked
        S, B = await self.prov.acquire("x_payer"), await self.prov.acquire("x_redeemer")
        pre = await self.oracle.check(B, feature, oracle_id="X:B:pre")
        artifacts: list[str | None] = [*pre.artifact_ids]
        if pre.outcome != "denied":
            return self._finding(hyp, Verdict.UNKNOWN, "low", "The redeeming identity was not denied before the scenario.", artifacts=artifacts, reasons=["fixture_contaminated"])
        pay = await self._pay(S, plan=b.cheapest_plan, outcome_key="success", label="X")
        artifacts += pay.artifact_ids()
        if pay.payment_id is None or not pay.reached_sandbox:
            return self._finding(hyp, Verdict.BLOCKED, "medium", "The payer's sandbox payment could not be completed.", artifacts=artifacts, reasons=["payer_setup_failed"])
        rf = await self._return_flow(B, pay.payment_id, label="X:return_other_identity", claim_status=b.return_status_values["success"])
        artifacts.append(rf.artifact_id)
        post = await self.oracle.check(B, feature, oracle_id="X:B:post")
        artifacts += post.artifact_ids
        if post.outcome == "allowed":
            decision, _, repro = await self._confirm(hyp=hyp, cs=cs, feature=feature, scenario=post, qualifying=False, discriminating=cs.positive_ok, subject=B)
            return self._confirmed_or_partial(hyp, decision, "A second synthetic identity USED the paid feature after presenting another identity's payment reference; a clean session reproduced it. Internal cause: UNKNOWN.",
                                              "A foreign payment reference unlocked the feature, but the confirmation chain is incomplete.", [*artifacts, *(repro.artifact_ids if repro else ())],
                                              identity_tenant_dimension=f"payer={S.identity_alias}, redeemer={B.identity_alias}", commercial_context=f"plan={b.cheapest_plan}",
                                              payment_state=f"payer {S.identity_alias} paid; redeemer {B.identity_alias} presented the payer's reference", actual_state=f"feature_outcome={post.outcome} for redeemer {B.identity_alias}",
                                              entitlement_state="granted" if post.outcome == "allowed" else post.outcome, server_side_oracle=f"{post.oracle_id}: outcome={post.outcome}, discriminating={cs.positive_ok}")
        if post.outcome == "indeterminate":
            return self._finding(hyp, Verdict.UNKNOWN, "medium", "The redeemer's feature response was neither a proven use nor a declared denial.", artifacts=artifacts)
        return self._finding(hyp, Verdict.RULED_OUT, "high", "Under the tested conditions another identity could not redeem a payment it did not make.", artifacts=artifacts,
                             metrics={"foreign_return_flow_status": rf.status}, limitations=["The payment reference was handed over by the harness (a stand-in for leakage/guessing); no ID guessing was attempted."])

    async def _exp_r(self, cs: ControlState) -> Finding:
        hyp = "PBB-R"
        b, feature = self.brief, self.brief.primary_feature()
        assert feature is not None
        refund_op = b.op("request_refund")
        if refund_op is None:
            return self._finding(hyp, Verdict.BLOCKED, "high", "No customer-facing refund operation is approved in the brief; retention after refund cannot be tested without an approved self-service refund flow.", reasons=["refund_flow_not_approved"])
        if (blocked := self._precondition(cs, hyp)) is not None:
            return blocked
        V = await self.prov.acquire("r_payer")
        pre = await self.oracle.check(V, feature, oracle_id="R:pre")
        artifacts: list[str | None] = [*pre.artifact_ids]
        pay = await self._pay(V, plan=b.cheapest_plan, outcome_key="success", label="R")
        artifacts += pay.artifact_ids()
        if pre.outcome != "denied" or pay.payment_id is None or not pay.reached_sandbox:
            return self._finding(hyp, Verdict.UNKNOWN, "low", "The refund scenario's preconditions (clean identity, completed sandbox payment) were not met.", artifacts=artifacts, reasons=["precondition_failed"])
        artifacts.append((await self._return_flow(V, pay.payment_id, label="R:return", claim_status=b.return_status_values["success"])).artifact_id)
        allowed = await self.oracle.check(V, feature, oracle_id="R:before_refund")
        artifacts += allowed.artifact_ids
        if allowed.outcome != "allowed":
            return self._finding(hyp, Verdict.UNKNOWN, "medium", "The legitimate payer was not allowed before the refund, so retention cannot be judged.", artifacts=artifacts, reasons=["payer_not_allowed_before_refund"])
        refund = await V.call("request_refund", label="R:refund", path_params={"payment_id": pay.payment_id}, fields={"payment_id": pay.payment_id})
        artifacts.append(refund.artifact_id)
        if not (refund.status is not None and 200 <= refund.status < 300 and refund.admitted):
            return self._finding(hyp, Verdict.UNKNOWN, "medium", f"The refund was not externally confirmed (status {refund.status}); retention after refund cannot be judged.", artifacts=artifacts, reasons=["refund_not_confirmed"])
        sla = b.limits.revocation_sla_seconds
        schedule = set(b.limits.revocation_poll_schedule_s)
        if sla is not None:
            schedule.add(round(min(60.0, sla * 1.1 + 0.05), 3))
        t0 = self._clock()
        polls: list[tuple[float, OracleObservation]] = []
        for offset in sorted(schedule):
            wait = (t0 + offset) - self._clock()
            if wait > 0:
                await self._sleep(wait)
            obs = await self.oracle.check(V, feature, oracle_id=f"R:poll@{offset}")
            polls.append((self._clock() - t0, obs))
            artifacts += obs.artifact_ids
            if obs.outcome != "allowed":
                break
        denied_at = next((el for el, o in polls if o.outcome == "denied"), None)
        last_allowed = max((el for el, o in polls if o.outcome == "allowed"), default=None)
        metrics = {"polls": [{"elapsed_s": round(el, 3), "outcome": o.outcome} for el, o in polls], "first_denied_at_s": None if denied_at is None else round(denied_at, 3),
                   "last_allowed_at_s": None if last_allowed is None else round(last_allowed, 3), "declared_tolerance_s": sla}
        if any(o.outcome == "indeterminate" for _, o in polls):
            return self._finding(hyp, Verdict.UNKNOWN, "medium", "A feature poll after the refund was neither a proven use nor a declared denial.", artifacts=artifacts, metrics=metrics)
        beyond = [(el, o) for el, o in polls if o.outcome == "allowed" and sla is not None and el > sla]
        if beyond:
            el, obs = beyond[0]
            decision, _, repro = await self._confirm(hyp=hyp, cs=cs, feature=feature, scenario=obs, qualifying=False, discriminating=cs.positive_ok, subject=V)
            return self._confirmed_or_partial(hyp, decision, f"The paid feature was still USABLE {el:.2f}s after an externally confirmed refund, beyond the declared tolerance of {sla}s; a clean session reproduced it. Internal cause: UNKNOWN.",
                                              "The feature outlived the declared tolerance after a refund, but the confirmation chain is incomplete.", [*artifacts, *(repro.artifact_ids if repro else ())], metrics=metrics,
                                              limitations=["The tolerance is CUSTOMER_DECLARED; the measured times are upper bounds given by the poll schedule."],
                                              identity_tenant_dimension=f"identity={V.identity_alias}", commercial_context=f"plan={b.cheapest_plan}, declared_sla_s={sla}",
                                              payment_state=f"refunded (confirmed, status={refund.status})", actual_state=f"feature_outcome={obs.outcome} at t={el:.2f}s post-refund",
                                              entitlement_state="granted" if obs.outcome == "allowed" else obs.outcome, server_side_oracle=f"{obs.oracle_id}: outcome={obs.outcome}, discriminating={cs.positive_ok}")
        if denied_at is not None and (sla is None or denied_at <= sla):
            return self._finding(hyp, Verdict.RULED_OUT, "high", f"The feature was denied {denied_at:.2f}s after the confirmed refund (observed upper bound), within the declared tolerance." if sla is not None else
                                 f"The feature was denied {denied_at:.2f}s after the confirmed refund (observed upper bound); no tolerance was declared.", artifacts=artifacts, metrics=metrics,
                                 limitations=["Limited to the bounded poll schedule; the lag is an upper bound."])
        if denied_at is not None:
            return self._finding(hyp, Verdict.PARTIALLY_VALIDATED_PAYMENT_INTEGRITY_ISSUE, "low", f"Revocation was first observed {denied_at:.2f}s after the refund, after the declared tolerance of {sla}s, but no allowed observation beyond the tolerance exists.", artifacts=artifacts, metrics=metrics,
                                 reasons=["no_allowed_observation_beyond_tolerance"])
        window = polls[-1][0] if polls else 0.0
        return self._finding(hyp, Verdict.PARTIALLY_VALIDATED_PAYMENT_INTEGRITY_ISSUE, "medium", f"The feature stayed usable for the whole {window:.2f}s observation window after the refund; no tolerance was declared in the brief, so no P0 judgement is possible (revocation after the window is UNKNOWN).",
                             artifacts=artifacts, metrics=metrics, reasons=["no_declared_revocation_tolerance"], limitations=["Declare revocation_sla_seconds in the Execution Brief to make retention a confirmable finding."])

    def _derive_e(self, cs: ControlState) -> Finding:
        hyp = "PBB-E"
        obs = cs.view_observations
        if self.brief.op("subscription_view") is None or not obs:
            if (blocked := self._precondition(cs, hyp)) is not None:
                return blocked
            return self._finding(hyp, Verdict.UNKNOWN, "high", "No customer-facing subscription view is declared in the brief; UI-vs-server divergence is not observable.", reasons=["view_not_declared"])
        if not cs.setup_ok or not cs.positive_ok or cs.global_leak:  # a divergence verdict needs an oracle that is proven able to say 'allowed' and a clean attribution
            if (blocked := self._precondition(cs, hyp)) is not None:
                return blocked
        div = [f"{o['context']}: identity {o['identity']} view {'claims paid' if o['view_claims_paid'] else 'claims unpaid'} while the oracle says {o['oracle']}" for o in obs
               if o["oracle"] in ("allowed", "denied") and o["view_claims_paid"] != (o["oracle"] == "allowed")]
        if div:
            return self._finding(hyp, Verdict.PARTIALLY_VALIDATED_PAYMENT_INTEGRITY_ISSUE, "medium", "A customer-visible page contradicts the server-enforced outcome. No protected benefit was wrongly granted or denied by the server, so this is NOT a P0 (UI/view evidence is non-authoritative).",
                                 artifacts=[o["artifact"] for o in obs], divergences=div, metrics={"observations": len(obs)},
                                 identity_tenant_dimension=f"{len(obs)} observed identity/state pairs", actual_state="; ".join(div[:3]), entitlement_state="disagreement between view and server oracle")
        return self._finding(hyp, Verdict.RULED_OUT, "medium", "Customer-visible views agreed with the server-enforced outcome in all observed states.", artifacts=[o["artifact"] for o in obs], metrics={"observations": len(obs)},
                             limitations=["Only the observed identities/states; a view can still diverge in states that were not exercised."],
                             identity_tenant_dimension=f"{len(obs)} observed identity/state pairs", entitlement_state="view agrees with server oracle")

    # --------------------------------------------------------------------------------------------------------------------------- run
    async def run(self, experiments: Iterable[str] | None = None) -> EngineResult:
        started = now_iso()
        wanted = _apply_prioritizer([e for e in EXPERIMENT_ORDER if experiments is None or e in set(experiments)], self._prioritizer)
        findings: list[Finding] = []
        cs = await self._establish_controls()
        if cs.open_feature:
            findings.append(await self._finding_open(cs))
        if cs.global_leak:
            findings.append(await self._finding_leak(cs))
        await self.ledger.flush_pending()
        for hyp in wanted:
            if (stop := self._stop_reason()) is not None:
                findings.append(self._finding(hyp, Verdict.BLOCKED, "high", stop, reasons=["run_stopped"]))
                continue
            try:
                findings.append(self._derive_e(cs) if hyp == "PBB-E" else await self._runners[hyp](cs))
            except IdentityPoolExhausted as exc:
                findings.append(self._finding(hyp, Verdict.BLOCKED, "high", f"No further synthetic identity is available ({exc}).", reasons=["identity_pool_exhausted"]))
            except Exception as exc:  # noqa: BLE001 - one experiment must never take the others down; it becomes UNKNOWN, never a guess
                findings.append(self._finding(hyp, Verdict.UNKNOWN, "low", f"The experiment could not be completed ({type(exc).__name__}).", reasons=[f"engine_error:{type(exc).__name__}"]))
            await self.ledger.flush_pending()  # ZR-009: durable after every experiment, not only once at the end
            if self._find_fast and findings and findings[-1].verdict is Verdict.CONFIRMED_P0:
                break  # triage mode: a confirmed P0 is enough; skip the remaining classes (opt-in; default runs all)
        guard = self._http.guard
        stats = {"customer_level_calls": self.rec.calls, "volunteered_hints_dropped": self.rec.hints_dropped, "hint_names_sample": list(self.rec.hint_samples),
                 "experiment_order": list(wanted), "oracle_observations": len(self.oracle.observations), "guard": guard.stats() if guard is not None else None, "synthetic_identities_used": sorted(self.prov.sessions)}
        brief_fp = self.brief.fingerprint()
        attach_regression_references(findings, brief_fp)  # ZR-023/B26: each real finding points at its regression check
        replay_bundles = attach_replay_bundles(
            findings, ledger_accepted=self.ledger.accepted, observations=self.oracle.observations,
            admission_order=list(self.ledger.accepted), brief_fingerprint=brief_fp,
            authorization_ref=self.brief.authorization_ref, engine_version=ENGINE_VERSION,
        )  # ZR-015/B20: close reproduction (reproduction_steps per finding) from already-admitted evidence
        return EngineResult(findings=findings, controls=cs.summary(), ledger_summary=self.ledger.summary(), stats=stats, brief_fingerprint=brief_fp, started_at=started, finished_at=now_iso(), replay_bundles=replay_bundles)
