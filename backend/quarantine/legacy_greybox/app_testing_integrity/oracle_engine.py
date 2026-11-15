"""app/testing/integrity/oracle_engine.py -- U1: deterministic, falsification-first Black-Box oracles.

LOCATION: this is PRODUCT code (it runs inside a real assessment through the guarded QAHttpClient, see
app/testing/modules/payment_integrity.py). tests/verification_infrastructure/oracle_engine.py is now only a
re-export shim so the benchmark/tests keep their import path. The engine speaks the "reference payment API
vocabulary" (route + field names of entitlement_target.py); mapping an arbitrary customer API onto it is the
next step (see docs/PAYMENT_INTEGRITY_PLATFORM.md, "Known limits") -- it is NOT claimed to work on any API.

Successor to black_box_prober.py. black_box_prober.py is NOT deleted or
replaced in place (phase_4_implementation_rules: "do not delete existing
functionality without proving replacement coverage") -- it stays as the
historical baseline this file was measured against, still covered by
test_black_box_method_validation.py. This file is the thing that actually
runs going forward; benchmark_lab.py exercises this module, not the old one.

WHY A NEW FILE, NOT AN EDIT: Phase-0/1 measured two independent false-positive
mechanisms in black_box_prober.py by running it against a purpose-built decoy
target (a free tier with an inert webhook -- no exploitable vulnerability at
all): 2 of its 4 oracles (BB-001, BB-004) reported "confirmed_p0" at "high"
confidence. Root causes, both structural, not one-off bugs:

  1. NO BASELINE GATING. "has_access == True after a webhook" was treated as
     proof of a bypass without first checking whether the SAME fresh identity
     already had access BEFORE any manipulation at all. Against a target that
     grants baseline/free-tier access to everyone, this is true regardless of
     what the webhook did.
  2. NO GRANT-SIGNAL VERIFICATION. "HTTP 200" was treated as "a grant
     happened". EntitlementTarget's own webhook handler distinguishes a real
     grant (`{"status": "entitlement_granted", ...}`) from an accepted-but-
     ignored event (`{"status": "ignored"}`) or an already-processed replay
     (`{"status": "already_processed"}`) in its response BODY -- the old
     prober checked only the status code, never the body's own claim about
     what it did.

Every oracle below applies BOTH fixes: (a) checks access for the SAME fresh
identity immediately before AND after the manipulation -- a per-probe causal
control, not a one-time global baseline that goes stale the moment a fresh
uuid4 identity is minted for the next probe -- and (b) requires the target's
own response body to affirmatively claim a grant, never just a 2xx code. An
observation that fails either check is OBSERVED_DIVERGENCE or
UNKNOWN_CRITICAL_EXPOSURE, never CONFIRMED_P0. See benchmark_lab.py's
FreeTierDecoyTarget scenario, which asserts zero CONFIRMED_P0 / zero
STRONGLY_SUSPECTED_P0 findings from this engine -- the regression test for
exactly the false-positive class this file exists to close.

BUG CATALOG COVERAGE: entitlement_target.py documents nine deliberate bugs,
A through I. black_box_prober.py's four oracles directly exercised B, C, F,
G; A was only incidentally exercised (never isolated as its own hypothesis);
D, E, H, I were not testable at all. This engine adds one oracle per letter,
nine total, plus a tenth (ORC-BASELINE) that is not a vulnerability oracle at
all but the baseline-gating check every other oracle consults before
classifying anything as CONFIRMED_P0.

GENUINELY BLACK-BOX: every oracle talks to the target only via QAHttpClient,
over real HTTP -- same discipline as black_box_prober.py, including that
file's own methodological caveat (the author of this engine also built the
target it probes against in the benchmark; every verdict is still derived
purely from observed HTTP responses, never from reading the target's Python
state, but the choice of which hypotheses to test cannot fully escape shared
authorship -- stated plainly, not hidden). The one deliberate, disclosed
exception: ORC-I's `_revoke_delay_seconds` request field is treated as
CUSTOMER_DECLARED (a documented test-support contract a real payment provider
sandbox would document the same way, e.g. a "test clock"), not OBSERVED --
see that oracle's own docstring for why pure HTTP alone cannot otherwise time
a window with no endpoint that exposes authoritative payment state.

Every oracle is PRE-REGISTERED (OracleSpec is built before the probe runs,
fixed regardless of outcome) so a verdict can never be quietly rationalized
after seeing the result -- see the <deterministic_oracles> requirement this
implements.
"""
from __future__ import annotations
from app.testing.purity.quarantine import refuse_in_pure_mode  # noqa: E402  (QUARANTINED: never loads)
refuse_in_pure_mode(__name__)

import asyncio
import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Awaitable, Callable

from app.testing.http_client import QAHttpClient
from app.testing.models import ResponseEvidence

GRANT_STATUS = "entitlement_granted"


def _granted(body: Any) -> bool:
    """The ONLY signal this engine accepts as proof a grant occurred. A 2xx
    status code alone (accepted-but-ignored, already-processed-replay) is
    deliberately NOT sufficient -- see the module docstring's fix #2."""
    return isinstance(body, dict) and body.get("status") == GRANT_STATUS


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class Verdict(str, Enum):
    """The five finding-level outcomes this engine can reach. A sixth state,
    BLOCKED (see Finding.blocked_reason), is deliberately NOT a member of
    this enum: it is not a claim about the target's security at all, only
    that this oracle's own setup precondition failed -- conflating it with
    RULED_OUT would silently turn "we could not check" into "we checked and
    it's fine", exactly the overclaim <reality_and_honesty> forbids."""

    CONFIRMED_P0 = "confirmed_p0"
    STRONGLY_SUSPECTED_P0 = "strongly_suspected_p0"
    RULED_OUT = "ruled_out"
    OBSERVED_DIVERGENCE = "observed_divergence"
    UNKNOWN_CRITICAL_EXPOSURE = "unknown_critical_exposure"


@dataclass(frozen=True)
class EvidenceItem:
    classification: str  # OBSERVED | CUSTOMER_DECLARED | INFERRED
    detail: str
    timestamp: str
    sha256: str  # first 16 hex chars of sha256(detail) -- tamper-evidence + stable cross-run diffing, not a security hash


def make_evidence(classification: str, detail: str) -> EvidenceItem:
    return EvidenceItem(classification=classification, detail=detail, timestamp=_now_iso(), sha256=hashlib.sha256(detail.encode("utf-8")).hexdigest()[:16])


@dataclass(frozen=True)
class OracleSpec:
    """Pre-registered BEFORE the probe runs -- see module docstring. Every
    field here is fixed text, independent of any single run's outcome."""

    oracle_id: str
    bug_class: str  # A..I per entitlement_target.py, or "BASELINE"
    invariant: str
    controlled_variable: str
    permitted_action_sequence: str
    expected_secure_outcome: str
    p0_confirmation_condition: str
    rule_out_condition: str
    stop_condition: str
    evidence_requirements: str
    # The two elements <deterministic_oracles> requires that earlier drafts of this
    # spec only implied inside other free-text fields. Explicit fields make
    # oracle-completeness a checkable property (benchmark_lab.py audits it),
    # not a claim. Defaults describe the engine-wide practice; specs override.
    baseline: str = "per-probe: has_access of the SAME fresh identity immediately BEFORE the manipulation, plus one engine-wide ORC-BASELINE check that gates every oracle"
    identity_and_tenant: str = "a fresh synthetic identity (uuid4 suffix) per probe, never reused across probes; tenant 'default' unless the oracle's own controlled variable is the tenant"


@dataclass
class Finding:
    spec: OracleSpec
    verdict: Verdict | None  # None iff blocked_reason is set
    confidence: str  # "high" | "medium" | "low" | "n/a" (n/a only when blocked)
    observed_behavior: str
    actual_protected_benefit_result: str
    dangerous_explanation: str
    benign_explanation: str
    evidence: list[EvidenceItem]
    duration_seconds: float
    blocked_reason: str | None = None

    @property
    def business_impact(self) -> str:
        return self.spec.invariant

    def to_dict(self) -> dict[str, Any]:
        return {
            "oracle_id": self.spec.oracle_id,
            "bug_class": self.spec.bug_class,
            "invariant": self.spec.invariant,
            "verdict": self.verdict.value if self.verdict else None,
            "blocked_reason": self.blocked_reason,
            "confidence": self.confidence,
            "business_impact": self.business_impact,
            "observed_behavior": self.observed_behavior,
            "actual_protected_benefit_result": self.actual_protected_benefit_result,
            "dangerous_explanation": self.dangerous_explanation,
            "benign_explanation": self.benign_explanation,
            "duration_seconds": round(self.duration_seconds, 4),
            "evidence": [
                {"classification": e.classification, "detail": e.detail, "timestamp": e.timestamp, "sha256": e.sha256}
                for e in self.evidence
            ],
        }


@dataclass
class EngineResult:
    findings: list[Finding]
    elapsed_seconds: float
    baseline_gated: bool
    expected_gated: bool | None

    def by_bug_class(self) -> dict[str, Finding]:
        return {f.spec.bug_class: f for f in self.findings}

    def to_dict(self) -> dict[str, Any]:
        return {
            "elapsed_seconds": round(self.elapsed_seconds, 4),
            "baseline_gated": self.baseline_gated,
            "expected_gated": self.expected_gated,
            "findings": [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------------
# Pre-registered oracle specs (fixed text, see OracleSpec's own docstring).
# ---------------------------------------------------------------------------

SPEC_BASELINE = OracleSpec(
    oracle_id="ORC-BASELINE", bug_class="BASELINE",
    invariant="A completely fresh, never-referenced identity must not already have access to the protected benefit before any payment-related action.",
    controlled_variable="none -- a fresh identity is checked with zero prior action",
    permitted_action_sequence="GET access/{fresh_user}",
    expected_secure_outcome="has_access is False",
    p0_confirmation_condition="n/a -- this oracle only gates every OTHER oracle's ability to claim CONFIRMED_P0; it never itself confirms a P0",
    rule_out_condition="has_access is False",
    stop_condition="one call",
    evidence_requirements="has_access value for the fresh identity -- OBSERVED",
)

SPEC_A = OracleSpec(
    oracle_id="ORC-A", bug_class="A",
    invariant="A webhook event must be authenticated (a valid provider signature); an unsigned or unverifiable event must never be processed as a real grant.",
    controlled_variable="webhook body carries no 'signature' field at all, for an otherwise well-formed 'succeeded' event against a genuinely CAPTURED payment",
    permitted_action_sequence="create payment -> capture -> check_access(fresh_user) -> POST webhook (status=succeeded, no signature) -> check_access(fresh_user)",
    expected_secure_outcome="401 invalid_signature, or at minimum no grant (access remains False)",
    p0_confirmation_condition="access_before is False AND webhook body claims entitlement_granted AND access_after is True",
    rule_out_condition="webhook rejected (401), or access_after is False",
    stop_condition="one call each; the outcome is deterministic per call, no retries",
    evidence_requirements="webhook HTTP status+body, access_before, access_after -- all OBSERVED",
)

SPEC_B = OracleSpec(
    oracle_id="ORC-B", bug_class="B",
    invariant="A webhook's own status CLAIM must never be trusted over the AUTHORITATIVE payment record; a payment that has not reached a final captured state must not yield a usable grant.",
    controlled_variable="payment is created but deliberately NEVER captured; webhook nonetheless claims status=succeeded",
    permitted_action_sequence="create payment (no capture) -> check_access(fresh_user) -> POST webhook (status=succeeded) -> check_access(fresh_user)",
    expected_secure_outcome="409 authoritative_status_mismatch, or at minimum no grant",
    p0_confirmation_condition="access_before is False AND webhook body claims entitlement_granted AND access_after is True",
    rule_out_condition="webhook rejected (4xx), or access_after is False",
    stop_condition="one call each",
    evidence_requirements="webhook HTTP status+body, access_before, access_after -- all OBSERVED",
)

SPEC_C = OracleSpec(
    oracle_id="ORC-C", bug_class="C",
    invariant="An identical payment-confirmation event (same event_id) delivered more than once must not produce a second grant.",
    controlled_variable="the exact same event body (including event_id) is POSTed twice in immediate succession",
    permitted_action_sequence="create payment -> capture -> POST webhook (event) -> POST webhook (same event) -> compare periods granted",
    expected_secure_outcome="the second delivery is a no-op: periods does not increase a second time",
    p0_confirmation_condition="the FIRST delivery is a genuine grant (entitlement_granted, periods==1) AND the second delivery is ALSO a genuine grant with periods==2",
    rule_out_condition="the second delivery reports already_processed, or periods does not increase past the first delivery's value",
    stop_condition="two calls, no more -- a third delivery would not add information",
    evidence_requirements="both webhook response bodies -- OBSERVED",
)

SPEC_D = OracleSpec(
    oracle_id="ORC-D", bug_class="D",
    invariant="A refunded payment's entitlement must be revoked -- access must not remain usable indefinitely after an authoritative refund.",
    controlled_variable="a full refund is issued for the payment backing an already-active entitlement, with NO revocation-lag delay",
    permitted_action_sequence="create payment -> capture -> grant_direct (establish a clean, correctly-obtained entitlement) -> check_access=True precondition -> POST refund -> check_access",
    expected_secure_outcome="access becomes False once the refund completes",
    p0_confirmation_condition="access_before_refund is True (real precondition) AND refund succeeds AND access_after_refund is STILL True",
    rule_out_condition="access_after_refund is False",
    stop_condition="one refund call; the outcome is read directly from the response plus one access check",
    evidence_requirements="access_before_refund, refund response, access_after_refund -- all OBSERVED",
)

SPEC_E = OracleSpec(
    oracle_id="ORC-E", bug_class="E",
    invariant="Two externally observable views of the SAME entitlement's status (an access check and an entitlement-detail lookup) must never disagree about whether it is usable.",
    controlled_variable="a refund is issued for an active entitlement; both the access-check endpoint and the entitlement-detail endpoint are read afterward",
    permitted_action_sequence="create payment -> capture -> grant_direct -> POST refund -> GET access/{user} AND GET entitlements/{user} -> compare",
    expected_secure_outcome="both views agree (both say inactive/no-access, or the system has not revoked either view yet -- but never one saying inactive while the other still grants use)",
    p0_confirmation_condition="entitlement-detail view says active=False (the system's own authoritative record says revoked) BUT the access-check view still says has_access=True (the benefit remains usable)",
    rule_out_condition="both views agree",
    stop_condition="one refund, one read of each endpoint",
    evidence_requirements="both endpoint responses post-refund -- OBSERVED",
)

SPEC_F = OracleSpec(
    oracle_id="ORC-F", bug_class="F",
    invariant="A granted product tier's price must not exceed the authoritative amount actually paid.",
    controlled_variable="payment amount is the CHEAPEST catalog tier's price; the webhook claims the MOST EXPENSIVE tier",
    permitted_action_sequence="create payment (cheapest price) -> capture -> check_access(fresh_user) -> POST webhook (product=enterprise) -> check_access(fresh_user)",
    expected_secure_outcome="409 amount_below_tier, or at minimum no grant of the claimed tier",
    p0_confirmation_condition="access_before is False AND webhook body claims entitlement_granted with tier==enterprise AND access_after is True",
    rule_out_condition="webhook rejected (4xx), or access_after is False",
    stop_condition="one call each",
    evidence_requirements="webhook HTTP status+body, access_before, access_after -- all OBSERVED",
)

SPEC_G = OracleSpec(
    oracle_id="ORC-G", bug_class="G",
    invariant="A granted entitlement's tenant must match the paying payment's OWN authoritative tenant -- a payment made under one tenant must not be cited to grant access claiming a different tenant.",
    controlled_variable="payment is created under tenant_probe_A; the webhook claims tenant_probe_B",
    permitted_action_sequence="create payment (tenant_probe_A) -> capture -> check_access(fresh_user) -> POST webhook (tenant_id=tenant_probe_B) -> check_access(fresh_user)",
    expected_secure_outcome="409 tenant_mismatch, or at minimum no grant",
    p0_confirmation_condition="access_before is False AND webhook body claims entitlement_granted AND access_after is True",
    rule_out_condition="webhook rejected (4xx), or access_after is False",
    stop_condition="one call each",
    evidence_requirements="webhook HTTP status+body, access_before, access_after -- all OBSERVED. NOTE: this target's HTTP access-check endpoint accepts no tenant_id parameter at all (confirmed by reading handle_http's routing), so this oracle cannot exercise the target's tenant-scoped access-check argument -- only the grant-time tenant check. Recorded as a capability limitation, not silently assumed equivalent.",
)

SPEC_H = OracleSpec(
    oracle_id="ORC-H", bug_class="H",
    invariant="A granted product tier's price must be matched in the SAME currency the catalog prices it in -- a numerically-equal amount in a different currency must not satisfy the price.",
    controlled_variable="payment amount is numerically equal to the most expensive tier's price, but paid in a DIFFERENT currency (JPY vs the catalog's USD)",
    permitted_action_sequence="create payment (99.99 JPY) -> capture -> check_access(fresh_user) -> POST webhook (product=enterprise) -> check_access(fresh_user)",
    expected_secure_outcome="409 currency_mismatch, or at minimum no grant of the claimed tier",
    p0_confirmation_condition="access_before is False AND webhook body claims entitlement_granted with tier==enterprise AND access_after is True, despite the currency mismatch",
    rule_out_condition="webhook rejected (4xx), or access_after is False",
    stop_condition="one call each",
    evidence_requirements="webhook HTTP status+body, access_before, access_after -- all OBSERVED",
)

SPEC_I = OracleSpec(
    oracle_id="ORC-I", bug_class="I",
    invariant="Once a paid entitlement's authoritative payment has moved to refunded, the entitlement must stop being usable within a bounded window -- not remain usable indefinitely because a derived cache lags behind the authoritative state.",
    controlled_variable="a customer-declared test-support delay (_revoke_delay_seconds) between the refund committing and any revocation logic applying -- isolates the LAG itself from whether revocation happens AT ALL (see ORC-D)",
    permitted_action_sequence="create payment -> capture -> grant_direct -> check_access=True precondition -> POST refund(_revoke_delay_seconds=D) [not yet awaited] -> sleep 0.5*D -> check_access (mid-window) -> await refund response -> sleep margin -> check_access (settled) -> control identity check",
    expected_secure_outcome="access is already False by the mid-window check, or at the least False by the settled check with no earlier True observed after the refund call was initiated",
    p0_confirmation_condition="mid-window check is True AND settled check is False -- the defining transient signature of a lag (as opposed to a permanent non-revocation, which ORC-D covers)",
    rule_out_condition="the mid-window check is already False",
    stop_condition="one timed sequence -- a flaky timing result is reported as UNKNOWN, never retried into a preferred answer",
    evidence_requirements="mid-window and settled access observations are OBSERVED; the delay's meaning (authoritative-commit-then-revocation-gap) is CUSTOMER_DECLARED, not independently verifiable -- this target exposes no endpoint that reports authoritative payment status externally",
)


from dataclasses import replace as _replace  # noqa: E402

SPEC_BASELINE = _replace(SPEC_BASELINE, baseline="none -- this oracle IS the baseline: one fresh identity, zero prior action")
SPEC_G = _replace(SPEC_G, identity_and_tenant="a fresh synthetic identity per probe; the payment is created under tenant_probe_A and the webhook claims tenant_probe_B -- both tenants are synthetic labels this engine invents, never real customer tenants")
SPEC_I = _replace(SPEC_I, baseline="per-probe: a control identity that NEVER had any entitlement is checked after the sequence; if it also has access the surface is open and persistence cannot be attributed to the refund")
SPEC_D = _replace(SPEC_D, baseline="per-probe: access_before_refund must be True (real precondition) AND a control identity that NEVER had any entitlement must be denied after the refund")
SPEC_E = _replace(SPEC_E, baseline="per-probe: access_before_refund must be True (real precondition) AND a control identity that NEVER had any entitlement must be denied after the refund")


def _perimeter_rejected(resp: Any) -> bool:
    """401/403 means the event was stopped at the AUTHENTICATION perimeter --
    before any business-logic control (authoritative status, amount, tenant,
    currency) could run. It is therefore NO evidence about those controls."""
    return getattr(resp, "status_code", None) in (401, 403)


class OracleEngine:
    """Runs all ten oracles (baseline + A..I) against one target, over real
    HTTP only. See module docstring for the false-positive fixes this
    engine applies that black_box_prober.py did not.

    `expected_gated`: optional CUSTOMER_DECLARED ground truth for whether the
    probed access surface is supposed to require payment at all.
      * None (default): unknown -- a fresh identity already having access is
        reported as OBSERVED_DIVERGENCE (suspicious, but not confirmed
        dangerous without knowing the customer's intent).
      * True: the customer has declared this surface IS supposed to be
        paid-only -- a fresh identity already having access is then itself
        CONFIRMED_P0 (the paywall does not exist), and every other oracle
        still cannot proceed past baseline gating (its OWN webhook-side
        manipulation was never exercised meaningfully once EVERYTHING already
        has access).
      * False: the customer has declared this surface is intentionally open
        (e.g. a real free tier) -- a fresh identity having access is RULED
        OUT, not a finding at all, and every other oracle proceeds normally
        (baseline gating does not suppress them, since "everyone has access"
        is the DECLARED correct state, not a bypass).

    `webhook_secret`: optional CUSTOMER_DECLARED test-mode webhook signing
    secret (real payment providers commonly issue exactly this to an
    integration/QA team's sandbox for this reason -- e.g. a test-mode
    webhook signing secret). When set, every oracle EXCEPT ORC-A (which
    deliberately sends an unsigned/forged event on purpose -- that is its
    entire hypothesis) signs its webhook body with it, using the identical
    canonical-JSON HMAC-SHA256 scheme EntitlementTarget.sign() uses. WITHOUT
    it (the default), a target that correctly enforces signatures (fixing
    bug A) makes every OTHER oracle's webhook rejected for THAT reason,
    degrading B/C/F/G/H to UNKNOWN_CRITICAL_EXPOSURE regardless of whether
    those bugs are separately still present -- an initial run of this engine
    against a target with ONLY signature enforcement turned on surfaced
    exactly that blind spot (see benchmark_lab.py's
    'signature_only_fixed' scenario, which is the regression test for it).
    Masking seven still-open bugs behind one fixed one is precisely the kind
    of tool blind spot this transformation exists to close.
    """

    def __init__(
        self,
        base_url: str | None = None,
        *,
        client: QAHttpClient | None = None,
        expected_gated: bool | None = None,
        timeout_seconds: float = 5.0,
        webhook_secret: bytes | str | None = None,
        path_prefix: str = "/api/v1",
    ) -> None:
        # `client`: inject the RUN's shared, guarded QAHttpClient (scope allowlist, request budget, rate limit,
        # kill switch all apply, and this engine does not close what it does not own). `base_url` builds a private
        # unguarded client -- for the benchmark and unit tests only.
        if client is not None:
            self._client, self._owns_client = client, False
        elif base_url is not None:
            self._client = QAHttpClient(base_url=base_url, timeout_seconds=timeout_seconds, proxy_url=None, headers={}, user_agent="oracle-engine/1.0")
            self._owns_client = True
        else:
            raise ValueError("OracleEngine needs either base_url or an injected client")
        # The ONE schema variation this engine adapts to on its own: a different mount prefix for the
        # otherwise-identical reference vocabulary (see the module docstring's LOCATION note). Anything deeper
        # (different route names, different field names) is out of scope -- see contract.py.
        self._prefix = path_prefix.rstrip("/") or ""
        self.expected_gated = expected_gated
        self.baseline_gated = False  # set by oracle_baseline(); consulted by every other oracle
        self._webhook_secret = webhook_secret.encode("utf-8") if isinstance(webhook_secret, str) else webhook_secret

    def _sign(self, body_without_signature: dict) -> str | None:
        if self._webhook_secret is None:
            return None
        canonical = json.dumps(body_without_signature, sort_keys=True).encode("utf-8")
        return hmac.new(self._webhook_secret, canonical, hashlib.sha256).hexdigest()

    def _webhook_body(self, **fields: Any) -> dict[str, Any]:
        """Builds a webhook payload, signed with `webhook_secret` when one was
        declared (see class docstring). Every oracle EXCEPT ORC-A uses this
        instead of a bare dict literal, so a target that correctly enforces
        signatures does not block testing every OTHER dimension."""
        body = dict(fields)
        signature = self._sign(body)
        if signature is not None:
            body["signature"] = signature
        return body

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    # -- low-level helpers --------------------------------------------------

    async def _check_access(self, user_id: str) -> bool | None:
        _, resp = await self._client.request("GET", f"{self._prefix}/access/{user_id}")
        if resp.status_code != 200 or not isinstance(resp.body, dict):
            return None
        return resp.body.get("has_access")

    async def _entitlement_detail(self, user_id: str) -> dict | None:
        _, resp = await self._client.request("GET", f"{self._prefix}/entitlements/{user_id}")
        return resp.body if resp.status_code == 200 and isinstance(resp.body, dict) else None

    async def _create_payment(self, amount: float, *, currency: str = "USD", tenant_id: str = "default") -> tuple[str | None, ResponseEvidence]:
        _, resp = await self._client.request("POST", f"{self._prefix}/payments", json_body={"amount": amount, "currency": currency, "tenant_id": tenant_id})
        payment_id = resp.body.get("id") if resp.status_code == 201 and isinstance(resp.body, dict) else None
        return payment_id, resp

    async def _create_and_capture(self, amount: float, *, currency: str = "USD", tenant_id: str = "default") -> tuple[str | None, str]:
        """Returns (payment_id, setup_note). payment_id is None iff setup failed -- callers turn that into a BLOCKED finding, never a crash."""
        payment_id, create_resp = await self._create_payment(amount, currency=currency, tenant_id=tenant_id)
        if payment_id is None:
            return None, f"create_payment failed: HTTP {create_resp.status_code}, body={create_resp.body}"
        _, capture_resp = await self._client.request("POST", f"{self._prefix}/payments/{payment_id}/capture")
        if capture_resp.status_code != 200:
            return None, f"capture failed: HTTP {capture_resp.status_code}, body={capture_resp.body}"
        return payment_id, "setup ok"

    def _blocked(self, spec: OracleSpec, reason: str, duration: float) -> Finding:
        return Finding(
            spec=spec, verdict=None, confidence="n/a",
            observed_behavior=f"BLOCKED before any test outcome could be observed: {reason}",
            actual_protected_benefit_result="unknown -- oracle did not complete",
            dangerous_explanation="unknown -- see phase_6 self-improvement: this P0 class remains BLOCKED because the stated setup precondition failed, not because it was found safe",
            benign_explanation="unknown", evidence=[make_evidence("OBSERVED", reason)],
            duration_seconds=duration, blocked_reason=reason,
        )

    def _gated_divergence(self, spec: OracleSpec, access_before: bool | None, duration: float, reason: str | None = None) -> Finding:
        """Baseline gating fired: the observation cannot be attributed to this oracle's manipulation."""
        note = reason or f"access_before={access_before} -- fresh identity already had access before this oracle's manipulation ran"
        return Finding(
            spec=spec, verdict=Verdict.OBSERVED_DIVERGENCE, confidence="low",
            observed_behavior=note,
            actual_protected_benefit_result=f"has_access={access_before}",
            dangerous_explanation=f"{spec.p0_confirmation_condition} could still be independently true, but cannot be attributed to this oracle's manipulation when the probed surface is already open",
            benign_explanation="see ORC-BASELINE's own finding: the probed surface already grants access to identities that never paid",
            evidence=[make_evidence("OBSERVED", note), make_evidence("INFERRED", "baseline gating: see ORC-BASELINE")],
            duration_seconds=duration,
        )

    def _perimeter_unknown(self, spec: OracleSpec, observed: str, access_after: bool | None, ev: list[EvidenceItem]) -> Finding:
        """The webhook was rejected at the authentication perimeter (401/403): the business-logic control this
        oracle targets was never exercised, so the honest verdict is UNKNOWN -- never RULED_OUT. Smallest safe
        improvement: declare a sandbox webhook_secret (see OracleEngine's docstring)."""
        return Finding(
            spec=spec, verdict=Verdict.UNKNOWN_CRITICAL_EXPOSURE, confidence="low",
            observed_behavior=observed, actual_protected_benefit_result=f"has_access={access_after}",
            dangerous_explanation="the control this oracle targets sits BEHIND the authentication perimeter and may be missing; unauthenticated probes cannot reach it",
            benign_explanation="the perimeter (webhook signature verification) correctly rejects unauthenticated events -- that is ORC-A's finding, not this oracle's",
            evidence=ev + [make_evidence("INFERRED", "rejected at the authentication perimeter (HTTP 401/403); pass webhook_secret (CUSTOMER_DECLARED sandbox secret) to test behind it")],
            duration_seconds=0.0,
        )

    def _grant_without_usage(self, spec: OracleSpec, observed: str, access_after: bool | None, ev: list[EvidenceItem], what: str) -> Finding:
        """The target RECORDED a grant (its own response body says entitlement_granted) but the benefit is NOT
        usable: a downstream control (typically an access-time re-check) denies it. That is a real defect -- a false
        entitlement state, visible to any consumer of the entitlement record that does not repeat the downstream
        check -- but it is not a P0 (no usable paid benefit) and it must not be reported as RULED_OUT either."""
        return Finding(
            spec=spec, verdict=Verdict.OBSERVED_DIVERGENCE, confidence="high",
            observed_behavior=observed, actual_protected_benefit_result=f"has_access={access_after}",
            dangerous_explanation=f"{what}; the entitlement RECORD now exists although its precondition failed. Any client, report or code path that trusts the record (an entitlement-detail view, a mobile app, an export) instead of the access decision would treat this identity as paid",
            benign_explanation="a defence-in-depth control at access time (an authoritative re-check) denies usage, so no paid benefit is actually usable -- which is why this is a divergence and not a P0",
            evidence=ev + [make_evidence("INFERRED", "grant recorded (response body) but usage denied (access check): false entitlement state without usable access")],
            duration_seconds=0.0,
        )

    async def _control_open(self) -> bool | None:
        """Per-probe control for the refund-side oracles: does an identity that NEVER had any entitlement have access right now?"""
        return await self._check_access(f"control_{uuid.uuid4().hex[:10]}")

    async def _timed(self, spec: OracleSpec, coro: Callable[[], Awaitable[Finding]]) -> Finding:
        start = time.perf_counter()
        try:
            finding = await coro()
        except Exception as exc:  # noqa: BLE001 -- backstop for anything a specific oracle didn't anticipate; see module docstring
            return self._blocked(spec, f"{type(exc).__name__}: {exc}", time.perf_counter() - start)
        finding.duration_seconds = time.perf_counter() - start
        return finding

    # -- ORC-BASELINE ---------------------------------------------------------

    async def oracle_baseline(self) -> Finding:
        async def go() -> Finding:
            user_id = f"baseline_{uuid.uuid4().hex[:10]}"
            access = await self._check_access(user_id)
            ev = [make_evidence("OBSERVED", f"fresh identity {user_id}: has_access={access} with zero payment/webhook/grant action")]
            if access is None:
                return self._blocked(
                    SPEC_BASELINE,
                    "the access-check endpoint did not return a usable has_access value (wrong path_prefix, "
                    "unreachable target, or a response shape this engine does not recognise) -- BLOCKED, not "
                    "RULED_OUT: an unreachable endpoint is not evidence the surface is safe",
                    0.0,
                )
            if access is True:
                if self.expected_gated is False:
                    return Finding(SPEC_BASELINE, Verdict.RULED_OUT, "high", f"has_access={access}", f"has_access={access}",
                                   "n/a -- customer declared this surface is intentionally open", "declared free/open tier", ev, 0.0)
                verdict = Verdict.CONFIRMED_P0 if self.expected_gated is True else Verdict.OBSERVED_DIVERGENCE
                confidence = "high" if self.expected_gated is True else "low"
                return Finding(
                    SPEC_BASELINE, verdict, confidence, f"has_access={access}", f"has_access={access}",
                    "if this surface is supposed to be paid-only, the paywall does not exist at all -- every other oracle's own manipulation is now unattributable (see baseline gating)",
                    "this surface may legitimately have a free/open tier by design" if self.expected_gated is None else "n/a -- customer declared this must be gated",
                    ev, 0.0,
                )
            return Finding(SPEC_BASELINE, Verdict.RULED_OUT, "high", f"has_access={access}", f"has_access={access}", "n/a", "fresh identities correctly start with no access", ev, 0.0)

        finding = await self._timed(SPEC_BASELINE, go)
        self.baseline_gated = finding.verdict == Verdict.OBSERVED_DIVERGENCE
        return finding

    def _gate(self, access_before: bool | None) -> bool:
        """True iff this probe's own result cannot be attributed (global baseline already gated, or this specific fresh identity already had access)."""
        return self.baseline_gated or access_before is True

    # -- ORC-A: signature enforcement -----------------------------------------

    async def oracle_signature_enforcement(self) -> Finding:
        async def go() -> Finding:
            payment_id, note = await self._create_and_capture(9.99)
            if payment_id is None:
                return self._blocked(SPEC_A, note, 0.0)
            user_id = f"sig_probe_{uuid.uuid4().hex[:10]}"
            access_before = await self._check_access(user_id)
            if self._gate(access_before):
                return self._gated_divergence(SPEC_A, access_before, 0.0)
            _, resp = await self._client.request(
                "POST", f"{self._prefix}/webhooks/payment-confirmed",
                json_body={"event_id": str(uuid.uuid4()), "payment_id": payment_id, "user_id": user_id, "status": "succeeded"},
            )
            access_after = await self._check_access(user_id)
            ev = [
                make_evidence("OBSERVED", f"webhook sent with no signature field; HTTP {resp.status_code}, body={resp.body}"),
                make_evidence("OBSERVED", f"access_before={access_before}, access_after={access_after}"),
            ]
            observed = f"HTTP {resp.status_code}, granted={_granted(resp.body)}, access_after={access_after}"
            if resp.status_code == 401:
                return Finding(SPEC_A, Verdict.RULED_OUT, "high", observed, f"has_access={access_after}", "n/a", "signature is enforced", ev, 0.0)
            if _granted(resp.body) and access_after is True:
                return Finding(
                    SPEC_A, Verdict.CONFIRMED_P0, "high", observed, f"has_access={access_after}",
                    "anyone who can reach the webhook endpoint with a guessable/observable payment_id and a fresh user_id can self-grant access with zero valid provider signature",
                    "none identified -- the response body explicitly confirms a grant", ev, 0.0,
                )
            if _granted(resp.body) and access_after is False:
                return self._grant_without_usage(SPEC_A, observed, access_after, ev, "an unsigned webhook was recorded as an entitlement grant")
            if access_after is False:
                return Finding(SPEC_A, Verdict.RULED_OUT, "medium", observed, f"has_access={access_after}", "n/a", "no grant resulted even without signature enforcement returning 401", ev, 0.0)
            return Finding(SPEC_A, Verdict.UNKNOWN_CRITICAL_EXPOSURE, "low", observed, f"has_access={access_after}", "unclear", "unclear", ev, 0.0)

        return await self._timed(SPEC_A, go)

    # -- ORC-B: trust boundary (claim vs authoritative) -----------------------

    async def oracle_trust_boundary(self) -> Finding:
        async def go() -> Finding:
            payment_id, create_resp = await self._create_payment(9.99)  # deliberately NOT captured
            if payment_id is None:
                return self._blocked(SPEC_B, f"create_payment failed: HTTP {create_resp.status_code}", 0.0)
            user_id = f"trust_probe_{uuid.uuid4().hex[:10]}"
            access_before = await self._check_access(user_id)
            if self._gate(access_before):
                return self._gated_divergence(SPEC_B, access_before, 0.0)
            _, resp = await self._client.request(
                "POST", f"{self._prefix}/webhooks/payment-confirmed",
                json_body=self._webhook_body(event_id=str(uuid.uuid4()), payment_id=payment_id, user_id=user_id, status="succeeded"),
            )
            access_after = await self._check_access(user_id)
            ev = [
                make_evidence("OBSERVED", f"payment created but never captured; webhook HTTP {resp.status_code}, body={resp.body}"),
                make_evidence("OBSERVED", f"access_before={access_before}, access_after={access_after}"),
            ]
            observed = f"HTTP {resp.status_code}, granted={_granted(resp.body)}, access_after={access_after}"
            if _perimeter_rejected(resp):
                return self._perimeter_unknown(SPEC_B, observed, access_after, ev)
            if _granted(resp.body) and access_after is True:
                return Finding(
                    SPEC_B, Verdict.CONFIRMED_P0, "high", observed, f"has_access={access_after}",
                    "a webhook's own unverified status claim is sufficient to grant a real paid benefit with zero matching final payment -- full paywall bypass",
                    "none identified -- the response body explicitly confirms a grant against a payment that was never captured", ev, 0.0,
                )
            if _granted(resp.body) and access_after is False:
                return self._grant_without_usage(SPEC_B, observed, access_after, ev, "a webhook status claim was recorded as an entitlement grant although the payment was never captured")
            if resp.status_code >= 400 or access_after is False:
                return Finding(SPEC_B, Verdict.RULED_OUT, "high", observed, f"has_access={access_after}", "n/a", "authoritative status is checked before granting", ev, 0.0)
            return Finding(SPEC_B, Verdict.UNKNOWN_CRITICAL_EXPOSURE, "low", observed, f"has_access={access_after}", "unclear", "unclear", ev, 0.0)

        return await self._timed(SPEC_B, go)

    # -- ORC-C: replay / idempotency ------------------------------------------

    async def oracle_replay(self) -> Finding:
        async def go() -> Finding:
            payment_id, note = await self._create_and_capture(9.99)
            if payment_id is None:
                return self._blocked(SPEC_C, note, 0.0)
            user_id = f"replay_probe_{uuid.uuid4().hex[:10]}"
            event = self._webhook_body(event_id=str(uuid.uuid4()), payment_id=payment_id, user_id=user_id, status="succeeded")
            _, first = await self._client.request("POST", f"{self._prefix}/webhooks/payment-confirmed", json_body=event)
            _, second = await self._client.request("POST", f"{self._prefix}/webhooks/payment-confirmed", json_body=event)
            ev = [make_evidence("OBSERVED", f"first={first.body}"), make_evidence("OBSERVED", f"second={second.body}")]
            observed = f"first_periods={first.body.get('periods') if isinstance(first.body, dict) else None}, second_periods={second.body.get('periods') if isinstance(second.body, dict) else None}"
            if not _granted(first.body):
                return Finding(SPEC_C, Verdict.UNKNOWN_CRITICAL_EXPOSURE, "low", observed, "n/a",
                               "cannot test replay of a grant that never happened in the first place", "unclear", ev, 0.0)
            first_periods, second_periods = first.body.get("periods"), second.body.get("periods")
            if isinstance(second.body, dict) and second.body.get("status") == "already_processed":
                return Finding(SPEC_C, Verdict.RULED_OUT, "high", observed, f"periods={first_periods}", "n/a", "replay was recognized and not reprocessed (already_processed)", ev, 0.0)
            if _granted(second.body) and isinstance(first_periods, int) and isinstance(second_periods, int) and second_periods == first_periods + 1:
                return Finding(
                    SPEC_C, Verdict.CONFIRMED_P0, "high", observed, f"periods: {first_periods} -> {second_periods}",
                    "one real payment yields unbounded repeated paid benefit via webhook redelivery -- every redelivery (a normal, expected occurrence for real payment providers) adds another period",
                    "none identified -- both deliveries are independently confirmed grants of the SAME event_id", ev, 0.0,
                )
            if second_periods == first_periods:
                return Finding(SPEC_C, Verdict.RULED_OUT, "medium", observed, f"periods={first_periods}", "n/a", "replay did not increase periods, even without an explicit already_processed marker", ev, 0.0)
            return Finding(SPEC_C, Verdict.UNKNOWN_CRITICAL_EXPOSURE, "low", observed, f"periods: {first_periods} -> {second_periods}", "unclear", "unclear", ev, 0.0)

        return await self._timed(SPEC_C, go)

    # -- ORC-D: refund non-revocation -----------------------------------------

    async def _grant_direct(self, amount: float, user_id: str, *, currency: str = "USD", tenant_id: str = "default") -> tuple[str | None, ResponseEvidence]:
        payment_id, note = await self._create_and_capture(amount, currency=currency, tenant_id=tenant_id)
        if payment_id is None:
            return None, ResponseEvidence(status_code=None, error=note)
        _, resp = await self._client.request("POST", f"{self._prefix}/entitlements/grant-direct", json_body={"user_id": user_id, "payment_id": payment_id, "tenant_id": tenant_id})
        return payment_id, resp

    async def oracle_refund_non_revocation(self) -> Finding:
        async def go() -> Finding:
            if self.baseline_gated:
                return self._gated_divergence(SPEC_D, None, 0.0, "the probed surface is open to fresh identities (see ORC-BASELINE): persistent access cannot be attributed to non-revocation")
            user_id = f"refund_probe_{uuid.uuid4().hex[:10]}"
            payment_id, grant_resp = await self._grant_direct(9.99, user_id)
            if payment_id is None:
                return self._blocked(SPEC_D, grant_resp.error or "grant_direct setup failed", 0.0)
            access_before = await self._check_access(user_id)
            ev = [make_evidence("OBSERVED", f"grant_direct HTTP {grant_resp.status_code}, access_before_refund={access_before}")]
            if not (grant_resp.status_code == 200 and access_before is True):
                return self._blocked(SPEC_D, f"grant_direct did not establish a usable entitlement (HTTP {grant_resp.status_code}, access_before={access_before})", 0.0)
            _, refund_resp = await self._client.request("POST", f"{self._prefix}/refunds", json_body={"paymentId": payment_id, "amount": 9.99})
            access_after = await self._check_access(user_id)
            control_after = await self._control_open()
            ev += [make_evidence("OBSERVED", f"refund HTTP {refund_resp.status_code} body={refund_resp.body}"), make_evidence("OBSERVED", f"access_after_refund={access_after}; control identity (never entitled) has_access={control_after}")]
            if control_after is True:
                return self._gated_divergence(SPEC_D, control_after, 0.0, "a control identity that NEVER had any entitlement also has access after the refund -- the surface is open, persistent access cannot be attributed to non-revocation")
            observed = f"refund_status={refund_resp.body.get('status') if isinstance(refund_resp.body, dict) else None}, access_after_refund={access_after}"
            if isinstance(refund_resp.body, dict) and refund_resp.body.get("status") in ("refunded", "partially_refunded") and access_after is True:
                return Finding(
                    SPEC_D, Verdict.CONFIRMED_P0, "high", observed, f"has_access={access_after}",
                    "a fully refunded payment's entitlement remains usable indefinitely -- the customer gets the money back AND keeps the paid benefit",
                    "none identified -- refund is confirmed and access remains unconditionally true", ev, 0.0,
                )
            if access_after is False:
                return Finding(SPEC_D, Verdict.RULED_OUT, "high", observed, f"has_access={access_after}", "n/a", "refund correctly revokes the entitlement", ev, 0.0)
            return Finding(SPEC_D, Verdict.UNKNOWN_CRITICAL_EXPOSURE, "low", observed, f"has_access={access_after}", "unclear", "unclear", ev, 0.0)

        return await self._timed(SPEC_D, go)

    # -- ORC-E: cross-endpoint truth divergence -------------------------------

    async def oracle_cross_endpoint_truth_divergence(self) -> Finding:
        async def go() -> Finding:
            if self.baseline_gated:
                return self._gated_divergence(SPEC_E, None, 0.0, "the probed surface is open to fresh identities (see ORC-BASELINE): a divergence between views cannot be attributed to refund handling")
            user_id = f"divergence_probe_{uuid.uuid4().hex[:10]}"
            payment_id, grant_resp = await self._grant_direct(9.99, user_id)
            if payment_id is None:
                return self._blocked(SPEC_E, grant_resp.error or "grant_direct setup failed", 0.0)
            access_before = await self._check_access(user_id)
            if not (grant_resp.status_code == 200 and access_before is True):
                return self._blocked(SPEC_E, f"grant_direct did not establish a usable entitlement (HTTP {grant_resp.status_code}, access_before={access_before})", 0.0)
            await self._client.request("POST", f"{self._prefix}/refunds", json_body={"paymentId": payment_id, "amount": 9.99})
            access_view = await self._check_access(user_id)
            detail_view = await self._entitlement_detail(user_id)
            detail_active = detail_view.get("active") if isinstance(detail_view, dict) else None
            control_after = await self._control_open()
            if control_after is True:
                return self._gated_divergence(SPEC_E, control_after, 0.0, "a control identity that NEVER had any entitlement also has access -- the surface is open, so the two views cannot be compared meaningfully")
            ev = [make_evidence("OBSERVED", f"post-refund access endpoint: has_access={access_view}"), make_evidence("OBSERVED", f"post-refund entitlement-detail endpoint: active={detail_active} (full body={detail_view})")]
            observed = f"access_view.has_access={access_view}, entitlement_detail.active={detail_active}"
            if detail_active is False and access_view is True:
                return Finding(
                    SPEC_E, Verdict.CONFIRMED_P0, "high", observed, f"has_access={access_view}",
                    "the system's own entitlement-detail view says this entitlement is inactive/revoked, yet the access-check view still allows the benefit to be used -- two authoritative-looking endpoints disagree, and the MORE PERMISSIVE one is what actually gates real usage",
                    "none identified for this exact pattern -- inactive-but-still-usable has no benign reading", ev, 0.0,
                )
            if detail_active is False and access_view is False:
                return Finding(SPEC_E, Verdict.RULED_OUT, "high", observed, f"has_access={access_view}", "n/a", "both views agree the entitlement is revoked", ev, 0.0)
            if detail_active is True and access_view is False:
                return Finding(
                    SPEC_E, Verdict.OBSERVED_DIVERGENCE, "high", observed, f"has_access={access_view}",
                    "none for usage: the benefit is NOT usable (access denied); the entitlement-detail view is merely stale, which can mislead support staff or a UI but grants nothing",
                    "a status/display view lagging or caching independently of the access decision -- a quality issue (P2), explicitly not a P0 because no paid benefit is usable", ev, 0.0,
                )
            return Finding(
                SPEC_E, Verdict.UNKNOWN_CRITICAL_EXPOSURE, "low", observed, f"has_access={access_view}",
                "cannot isolate bug E in this run: the entitlement-detail view does not yet show the entitlement as revoked at all, so this probe cannot tell divergence-after-revocation apart from non-revocation-at-all -- see ORC-D's own finding for whether revocation happens",
                "see ORC-D", ev, 0.0,
            )

        return await self._timed(SPEC_E, go)

    # -- ORC-F: amount-vs-tier -------------------------------------------------

    async def oracle_amount_binding(self) -> Finding:
        async def go() -> Finding:
            payment_id, note = await self._create_and_capture(9.99)  # cheapest catalog price
            if payment_id is None:
                return self._blocked(SPEC_F, note, 0.0)
            user_id = f"amount_probe_{uuid.uuid4().hex[:10]}"
            access_before = await self._check_access(user_id)
            if self._gate(access_before):
                return self._gated_divergence(SPEC_F, access_before, 0.0)
            _, resp = await self._client.request(
                "POST", f"{self._prefix}/webhooks/payment-confirmed",
                json_body=self._webhook_body(event_id=str(uuid.uuid4()), payment_id=payment_id, user_id=user_id, status="succeeded", product="enterprise"),
            )
            access_after = await self._check_access(user_id)
            granted_tier = resp.body.get("tier") if isinstance(resp.body, dict) else None
            ev = [make_evidence("OBSERVED", f"paid 9.99, claimed product=enterprise; HTTP {resp.status_code} body={resp.body}"), make_evidence("OBSERVED", f"access_before={access_before}, access_after={access_after}")]
            observed = f"HTTP {resp.status_code}, granted_tier={granted_tier!r}, access_after={access_after}"
            if _perimeter_rejected(resp):
                return self._perimeter_unknown(SPEC_F, observed, access_after, ev)
            if _granted(resp.body) and granted_tier == "enterprise" and access_after is True:
                return Finding(
                    SPEC_F, Verdict.CONFIRMED_P0, "high", observed, f"has_access={access_after}",
                    "the lowest-priced payment unlocks the highest-value product tier -- direct revenue loss, scales to every tier gap in the catalog",
                    "none identified -- response body explicitly confirms tier=enterprise granted for a 9.99 payment", ev, 0.0,
                )
            if _granted(resp.body) and granted_tier == "enterprise" and access_after is False:
                return self._grant_without_usage(SPEC_F, observed, access_after, ev, "a 9.99 payment was recorded as an enterprise-tier grant")
            if resp.status_code >= 400 or granted_tier != "enterprise":
                return Finding(SPEC_F, Verdict.RULED_OUT, "high", observed, f"has_access={access_after}", "n/a", "amount is checked against the claimed tier's price", ev, 0.0)
            return Finding(SPEC_F, Verdict.UNKNOWN_CRITICAL_EXPOSURE, "low", observed, f"has_access={access_after}", "unclear", "unclear", ev, 0.0)

        return await self._timed(SPEC_F, go)

    # -- ORC-G: tenant binding --------------------------------------------------

    async def oracle_tenant_binding(self) -> Finding:
        async def go() -> Finding:
            payment_id, note = await self._create_and_capture(9.99, tenant_id="tenant_probe_A")
            if payment_id is None:
                return self._blocked(SPEC_G, note, 0.0)
            user_id = f"tenant_probe_{uuid.uuid4().hex[:10]}"
            access_before = await self._check_access(user_id)
            if self._gate(access_before):
                return self._gated_divergence(SPEC_G, access_before, 0.0)
            _, resp = await self._client.request(
                "POST", f"{self._prefix}/webhooks/payment-confirmed",
                json_body=self._webhook_body(event_id=str(uuid.uuid4()), payment_id=payment_id, user_id=user_id, status="succeeded", tenant_id="tenant_probe_B"),
            )
            access_after = await self._check_access(user_id)
            ev = [make_evidence("OBSERVED", f"payment under tenant_probe_A; webhook claims tenant_probe_B; HTTP {resp.status_code} body={resp.body}"), make_evidence("OBSERVED", f"access_before={access_before}, access_after={access_after}")]
            observed = f"HTTP {resp.status_code}, granted={_granted(resp.body)}, access_after={access_after}"
            if _perimeter_rejected(resp):
                return self._perimeter_unknown(SPEC_G, observed, access_after, ev)
            if _granted(resp.body) and access_after is True:
                return Finding(
                    SPEC_G, Verdict.CONFIRMED_P0, "high", observed, f"has_access={access_after}",
                    "a payment made under one tenant can be cited to grant entitlement claiming an entirely different tenant -- cross-tenant entitlement leakage",
                    "none identified -- response body explicitly confirms a grant citing a tenant different from the payment's own", ev, 0.0,
                )
            if _granted(resp.body) and access_after is False:
                return self._grant_without_usage(SPEC_G, observed, access_after, ev, "a cross-tenant claim was recorded as an entitlement grant")
            if resp.status_code >= 400 or access_after is False:
                return Finding(SPEC_G, Verdict.RULED_OUT, "high", observed, f"has_access={access_after}", "n/a", "the claimed tenant is checked against the payment's own authoritative tenant", ev, 0.0)
            return Finding(SPEC_G, Verdict.UNKNOWN_CRITICAL_EXPOSURE, "low", observed, f"has_access={access_after}", "unclear", "unclear", ev, 0.0)

        return await self._timed(SPEC_G, go)

    # -- ORC-H: currency-vs-tier -------------------------------------------------

    async def oracle_currency_binding(self) -> Finding:
        async def go() -> Finding:
            payment_id, note = await self._create_and_capture(99.99, currency="JPY")  # numerically == enterprise USD price
            if payment_id is None:
                return self._blocked(SPEC_H, note, 0.0)
            user_id = f"currency_probe_{uuid.uuid4().hex[:10]}"
            access_before = await self._check_access(user_id)
            if self._gate(access_before):
                return self._gated_divergence(SPEC_H, access_before, 0.0)
            _, resp = await self._client.request(
                "POST", f"{self._prefix}/webhooks/payment-confirmed",
                json_body=self._webhook_body(event_id=str(uuid.uuid4()), payment_id=payment_id, user_id=user_id, status="succeeded", product="enterprise"),
            )
            access_after = await self._check_access(user_id)
            granted_tier = resp.body.get("tier") if isinstance(resp.body, dict) else None
            ev = [make_evidence("OBSERVED", f"paid 99.99 JPY, claimed product=enterprise (99.99 USD price); HTTP {resp.status_code} body={resp.body}"), make_evidence("OBSERVED", f"access_before={access_before}, access_after={access_after}")]
            observed = f"HTTP {resp.status_code}, granted_tier={granted_tier!r}, access_after={access_after}"
            if _perimeter_rejected(resp):
                return self._perimeter_unknown(SPEC_H, observed, access_after, ev)
            if _granted(resp.body) and granted_tier == "enterprise" and access_after is True:
                return Finding(
                    SPEC_H, Verdict.CONFIRMED_P0, "high", observed, f"has_access={access_after}",
                    "99.99 JPY (worth a small fraction of 99.99 USD) unlocks the tier priced at 99.99 USD -- a numeric-only amount check that ignores currency is trivially defeated by paying in the weakest available currency",
                    "none identified -- response body explicitly confirms tier=enterprise granted for a JPY payment", ev, 0.0,
                )
            if _granted(resp.body) and granted_tier == "enterprise" and access_after is False:
                return self._grant_without_usage(SPEC_H, observed, access_after, ev, "a JPY payment was recorded as an enterprise-tier grant")
            if resp.status_code >= 400 or granted_tier != "enterprise":
                return Finding(SPEC_H, Verdict.RULED_OUT, "high", observed, f"has_access={access_after}", "n/a", "currency is checked in addition to the numeric amount", ev, 0.0)
            return Finding(SPEC_H, Verdict.UNKNOWN_CRITICAL_EXPOSURE, "low", observed, f"has_access={access_after}", "unclear", "unclear", ev, 0.0)

        return await self._timed(SPEC_H, go)

    # -- ORC-I: revocation-lag window --------------------------------------------

    async def oracle_revocation_lag(self, delay_seconds: float = 0.30, margin_seconds: float = 0.10) -> Finding:
        async def go() -> Finding:
            if self.baseline_gated:
                return self._gated_divergence(SPEC_I, None, 0.0, "the probed surface is open to fresh identities (see ORC-BASELINE): a revocation window cannot be attributed")
            user_id = f"lag_probe_{uuid.uuid4().hex[:10]}"
            payment_id, grant_resp = await self._grant_direct(9.99, user_id)
            if payment_id is None:
                return self._blocked(SPEC_I, grant_resp.error or "grant_direct setup failed", 0.0)
            access_before = await self._check_access(user_id)
            if not (grant_resp.status_code == 200 and access_before is True):
                return self._blocked(SPEC_I, f"grant_direct did not establish a usable entitlement (HTTP {grant_resp.status_code}, access_before={access_before})", 0.0)

            refund_task = asyncio.ensure_future(
                self._client.request("POST", f"{self._prefix}/refunds", json_body={"paymentId": payment_id, "amount": 9.99, "_revoke_delay_seconds": delay_seconds})
            )
            await asyncio.sleep(delay_seconds * 0.5)
            mid_window_access = await self._check_access(user_id)
            _, refund_resp = await refund_task
            await asyncio.sleep(margin_seconds)
            settled_access = await self._check_access(user_id)
            control_after = await self._control_open()
            if control_after is True:
                return self._gated_divergence(SPEC_I, control_after, 0.0, "a control identity that NEVER had any entitlement also has access -- the surface is open, a revocation window cannot be attributed")

            ev = [
                make_evidence("CUSTOMER_DECLARED", f"_revoke_delay_seconds={delay_seconds}s: the declared gap between authoritative refund commit and revocation logic applying"),
                make_evidence("OBSERVED", f"refund HTTP {refund_resp.status_code} body={refund_resp.body}"),
                make_evidence("OBSERVED", f"mid_window_access={mid_window_access} (sampled {delay_seconds * 0.5:.3f}s into the declared {delay_seconds}s window)"),
                make_evidence("OBSERVED", f"settled_access={settled_access} (sampled {margin_seconds:.3f}s after the refund call returned)"),
            ]
            observed = f"mid_window_access={mid_window_access}, settled_access={settled_access}"
            if mid_window_access is True and settled_access is False:
                return Finding(
                    SPEC_I, Verdict.CONFIRMED_P0, "medium", observed, f"has_access={settled_access}",
                    "the paid benefit remains usable for the entire length of the revocation lag after every refund -- an attacker who can predict or trigger refunds gets a repeatable free-use window",
                    "none identified for this exact transient-then-denied pattern -- it is the defining signature of a lag, not of a permanent failure",
                    ev, 0.0,
                )
            if mid_window_access is False:
                return Finding(SPEC_I, Verdict.RULED_OUT, "high", observed, f"has_access={settled_access}", "n/a", "no observable window -- access was already denied inside the declared delay", ev, 0.0)
            if mid_window_access is True and settled_access is True:
                return Finding(
                    SPEC_I, Verdict.UNKNOWN_CRITICAL_EXPOSURE, "low", observed, f"has_access={settled_access}",
                    "cannot isolate a LAG from a PERMANENT non-revocation in this run -- access never became False even after the declared window plus margin",
                    "see ORC-D's own finding for whether revocation happens at all", ev, 0.0,
                )
            return Finding(SPEC_I, Verdict.UNKNOWN_CRITICAL_EXPOSURE, "low", observed, f"has_access={settled_access}", "unclear", "unclear", ev, 0.0)

        return await self._timed(SPEC_I, go)

    # -- orchestration -----------------------------------------------------------

    async def run_all(
        self,
        stop: Callable[[], str | None] | None = None,
        *,
        delay_seconds: float = 0.30,
        margin_seconds: float = 0.10,
    ) -> EngineResult:
        """Run baseline + A..I. `stop` is an optional cooperative probe (e.g. ScopeGuard.stop_reason): when it returns a
        reason, every not-yet-run oracle becomes a BLOCKED finding carrying that reason -- an interrupted assessment
        must read as "these classes were NOT checked", never as "these classes are fine"."""
        start = time.perf_counter()
        plan: list[tuple[OracleSpec, Callable[[], Awaitable[Finding]]]] = [
            (SPEC_A, self.oracle_signature_enforcement), (SPEC_B, self.oracle_trust_boundary), (SPEC_C, self.oracle_replay),
            (SPEC_D, self.oracle_refund_non_revocation), (SPEC_E, self.oracle_cross_endpoint_truth_divergence),
            (SPEC_F, self.oracle_amount_binding), (SPEC_G, self.oracle_tenant_binding), (SPEC_H, self.oracle_currency_binding),
            (SPEC_I, lambda: self.oracle_revocation_lag(delay_seconds=delay_seconds, margin_seconds=margin_seconds)),
        ]
        reason = stop() if stop else None
        findings: list[Finding] = [self._blocked(SPEC_BASELINE, f"stopped before running: {reason}", 0.0) if reason else await self.oracle_baseline()]
        for spec, oracle in plan:
            reason = stop() if stop else None
            findings.append(self._blocked(spec, f"stopped before running: {reason}", 0.0) if reason else await oracle())
        return EngineResult(findings=findings, elapsed_seconds=time.perf_counter() - start, baseline_gated=self.baseline_gated, expected_gated=self.expected_gated)
