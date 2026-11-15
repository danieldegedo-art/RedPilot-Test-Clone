"""A genuine black-box prober: everything below interacts with a target
ONLY through QAHttpClient (real HTTP over real sockets). It does not
import entitlement_target.py's classes, does not read EntitlementRecord
fields directly, does not inspect the target's Python state. The only
"white-box" fact this file relies on is which URL paths exist to probe --
a real external assessment would establish that via documentation,
crawling, or client-side code inspection; here it is CUSTOMER_DECLARED
(supplied by the test harness that stands in for the "customer" providing
the assessment contract), never treated as OBSERVED evidence of behavior.

METHODOLOGICAL CAVEAT, STATED PLAINLY: the author of this prober also
wrote the target it probes. A real black-box assessor would not have that
prior knowledge. This file mitigates that by deriving every VERDICT
(confirmed_p0 / ruled_out / unknown) purely from observed HTTP responses
compared against observed baselines -- never from "I know this flag is
False" -- but it cannot fully remove the bias of already knowing which
hypotheses are worth generating. Reported as a real limitation in the
final assessment, not hidden.
"""
from __future__ import annotations
from app.testing.purity.quarantine import refuse_in_pure_mode  # noqa: E402  (QUARANTINED: never loads)
refuse_in_pure_mode(__name__)

import asyncio
import uuid
from dataclasses import dataclass, field
from typing import Any

from app.testing.http_client import QAHttpClient


@dataclass
class Evidence:
    classification: str  # OBSERVED | CUSTOMER_DECLARED | INFERRED
    detail: str


@dataclass
class Finding:
    finding_id: str
    status: str  # confirmed_p0 | strongly_suspected_p0 | ruled_out | unknown_critical_exposure
    business_impact: str
    tested_invariant: str
    baseline: str
    controlled_variation: str
    expected_secure_behavior: str
    observed_behavior: str
    actual_protected_benefit_result: str
    evidence: list[Evidence] = field(default_factory=list)
    benign_explanations_considered: str = ""
    confidence: str = "medium"


class BlackBoxProber:
    def __init__(self, base_url: str) -> None:
        self._client = QAHttpClient(base_url=base_url, timeout_seconds=3.0, proxy_url=None, headers={}, user_agent="black-box-assurance/1.0")
        self.findings: list[Finding] = []

    async def aclose(self) -> None:
        await self._client.aclose()

    # -- Baseline construction (black-box: only via observed HTTP calls) --

    async def _make_payment(self, amount: float, tenant_id: str = "default", currency: str = "USD") -> str:
        _, resp = await self._client.request("POST", "/api/v1/payments", json_body={"amount": amount, "tenant_id": tenant_id, "currency": currency})
        assert resp.status_code == 201, f"baseline setup failed: create_payment returned {resp.status_code}"
        return resp.body["id"]

    async def _capture(self, payment_id: str) -> int:
        _, resp = await self._client.request("POST", f"/api/v1/payments/{payment_id}/capture")
        return resp.status_code

    async def _check_access(self, user_id: str) -> bool:
        _, resp = await self._client.request("GET", f"/api/v1/access/{user_id}")
        return resp.body["has_access"]

    async def establish_baselines(self) -> dict[str, Any]:
        """PHASE: baseline. Every value here is OBSERVED, not assumed."""
        anon_access = await self._check_access(f"anon_{uuid.uuid4().hex[:8]}")

        paid_user = f"paid_control_{uuid.uuid4().hex[:8]}"
        paid_payment_id = await self._make_payment(9.99)
        capture_status = await self._capture(paid_payment_id)
        _, grant_resp = await self._client.request(
            "POST", "/api/v1/entitlements/grant-direct", json_body={"user_id": paid_user, "payment_id": paid_payment_id}
        )
        paid_access = await self._check_access(paid_user)

        unpaid_user = f"unpaid_control_{uuid.uuid4().hex[:8]}"
        unpaid_payment_id = await self._make_payment(9.99)
        # deliberately NOT captured -- this is the "failed/pending" baseline
        _, unpaid_grant_resp = await self._client.request(
            "POST", "/api/v1/entitlements/grant-direct", json_body={"user_id": unpaid_user, "payment_id": unpaid_payment_id}
        )
        unpaid_access = await self._check_access(unpaid_user)

        return {
            "anonymous_has_access": anon_access,
            "paid_control_user": paid_user,
            "paid_control_payment_id": paid_payment_id,
            "paid_control_capture_status": capture_status,
            "paid_control_grant_status": grant_resp.status_code,
            "paid_control_has_access": paid_access,
            "unpaid_control_user": unpaid_user,
            "unpaid_control_payment_id": unpaid_payment_id,
            "unpaid_control_grant_status": unpaid_grant_resp.status_code,
            "unpaid_control_has_access": unpaid_access,
        }

    # -- Oracles: one per high-value hypothesis, black-box only -----------

    async def oracle_payment_to_entitlement_timing(self, baseline: dict) -> Finding:
        """Hypothesis: entitlement usable via webhook claim before/without
        a matching final payment."""
        payment_id = await self._make_payment(9.99)  # deliberately NOT captured
        user_id = f"timing_probe_{uuid.uuid4().hex[:8]}"
        _, webhook_resp = await self._client.request(
            "POST", "/api/v1/webhooks/payment-confirmed",
            json_body={"event_id": str(uuid.uuid4()), "payment_id": payment_id, "user_id": user_id, "status": "succeeded"},
        )
        access = await self._check_access(user_id)

        if webhook_resp.status_code == 200 and access is True:
            status, confidence = "confirmed_p0", "high"
            observed = f"webhook accepted (HTTP {webhook_resp.status_code}) for an uncaptured payment; access={access}"
        elif webhook_resp.status_code >= 400 and access is False:
            status, confidence = "ruled_out", "high"
            observed = f"webhook rejected (HTTP {webhook_resp.status_code}); access correctly False"
        else:
            status, confidence = "unknown_critical_exposure", "low"
            observed = f"webhook HTTP {webhook_resp.status_code}, access={access} -- does not cleanly match either expected pattern"

        return Finding(
            finding_id="BB-001", status=status,
            business_impact="Paid access usable with no final payment -- full paywall bypass",
            tested_invariant="A user may use a paid benefit only when a valid final payment exists",
            baseline=f"unpaid_control_has_access={baseline['unpaid_control_has_access']}",
            controlled_variation="webhook claims status=succeeded for a payment never captured",
            expected_secure_behavior="webhook rejected OR access remains False",
            observed_behavior=observed,
            actual_protected_benefit_result=f"has_access={access}",
            evidence=[Evidence("OBSERVED", f"HTTP {webhook_resp.status_code} from webhook endpoint"), Evidence("OBSERVED", f"access endpoint returned has_access={access}")],
            benign_explanations_considered="Could the grant be for a DIFFERENT, already-paid resource under the same user_id? Ruled out: user_id is freshly generated (uuid4) per probe, never reused.",
            confidence=confidence,
        )

    async def oracle_amount_binding(self, baseline: dict) -> Finding:
        """Hypothesis: paid benefit can exceed the selected price/tier."""
        payment_id = await self._make_payment(9.99)  # cheapest tier price, observed from catalog behavior in probe below
        await self._capture(payment_id)
        user_id = f"amount_probe_{uuid.uuid4().hex[:8]}"
        _, webhook_resp = await self._client.request(
            "POST", "/api/v1/webhooks/payment-confirmed",
            json_body={"event_id": str(uuid.uuid4()), "payment_id": payment_id, "user_id": user_id, "status": "succeeded", "product": "enterprise"},
        )
        granted_tier = webhook_resp.body.get("tier") if webhook_resp.status_code == 200 else None

        if webhook_resp.status_code == 200 and granted_tier == "enterprise":
            status, confidence, observed = "confirmed_p0", "high", f"paid 9.99, claimed product=enterprise, granted tier={granted_tier!r}"
        elif webhook_resp.status_code >= 400:
            status, confidence, observed = "ruled_out", "high", f"HTTP {webhook_resp.status_code} -- claim rejected"
        else:
            status, confidence, observed = "unknown_critical_exposure", "low", f"HTTP {webhook_resp.status_code}, tier={granted_tier!r}"

        return Finding(
            finding_id="BB-002", status=status,
            business_impact="Lowest-priced payment unlocks the highest-value product tier",
            tested_invariant="Granted product tier must not exceed what the authoritative paid amount covers",
            baseline="not directly comparable -- no control payment at each tier was established in this probe wave",
            controlled_variation="claim product=enterprise while authoritative paid amount is the smallest tested amount (9.99)",
            expected_secure_behavior="rejected, or granted tier capped at what 9.99 actually covers",
            observed_behavior=observed,
            actual_protected_benefit_result=f"granted_tier={granted_tier!r}",
            evidence=[Evidence("OBSERVED", f"webhook HTTP {webhook_resp.status_code}, body={webhook_resp.body}")],
            benign_explanations_considered="Could 9.99 legitimately be the enterprise price in some promo? Not ruled out externally -- catalog pricing itself is CUSTOMER_DECLARED, not independently observed here; noted as a residual unknown even for the confirmed case.",
            confidence=confidence,
        )

    async def oracle_replay(self, baseline: dict) -> Finding:
        """Hypothesis: replaying an identical webhook event produces
        duplicate effect."""
        payment_id = await self._make_payment(9.99)
        await self._capture(payment_id)
        user_id = f"replay_probe_{uuid.uuid4().hex[:8]}"
        event = {"event_id": str(uuid.uuid4()), "payment_id": payment_id, "user_id": user_id, "status": "succeeded"}
        _, first = await self._client.request("POST", "/api/v1/webhooks/payment-confirmed", json_body=event)
        _, second = await self._client.request("POST", "/api/v1/webhooks/payment-confirmed", json_body=event)
        first_periods = first.body.get("periods")
        second_periods = second.body.get("periods")

        if first_periods == 1 and second_periods == 2:
            status, confidence, observed = "confirmed_p0", "high", f"identical event_id granted periods={first_periods} then {second_periods}"
        elif second.body.get("status") == "already_processed" or second_periods == first_periods:
            status, confidence, observed = "ruled_out", "high", "replay recognized and not reprocessed"
        else:
            status, confidence, observed = "unknown_critical_exposure", "low", f"first={first.body}, second={second.body}"

        return Finding(
            finding_id="BB-003", status=status,
            business_impact="One real payment yields unbounded repeated paid benefit via webhook redelivery",
            tested_invariant="An identical payment reference must not produce a second grant",
            baseline="n/a -- single-event baseline not separately established",
            controlled_variation="identical event_id delivered twice",
            expected_secure_behavior="second delivery is a no-op",
            observed_behavior=observed,
            actual_protected_benefit_result=f"periods: {first_periods} -> {second_periods}",
            evidence=[Evidence("OBSERVED", f"first response: {first.body}"), Evidence("OBSERVED", f"second response: {second.body}")],
            benign_explanations_considered="Could 'periods' legitimately increment for an unrelated reason (e.g. a billing-cycle rollover)? Not plausible within the same synchronous test window with no time elapsed.",
            confidence=confidence,
        )

    async def oracle_tenant_binding(self, baseline: dict) -> Finding:
        """Hypothesis: a payment under tenant A can be cited to grant
        entitlement claiming tenant B."""
        payment_id = await self._make_payment(9.99, tenant_id="tenant_probe_A")
        await self._capture(payment_id)
        user_id = f"tenant_probe_{uuid.uuid4().hex[:8]}"
        _, webhook_resp = await self._client.request(
            "POST", "/api/v1/webhooks/payment-confirmed",
            json_body={"event_id": str(uuid.uuid4()), "payment_id": payment_id, "user_id": user_id, "status": "succeeded", "tenant_id": "tenant_probe_B"},
        )
        access = await self._check_access(user_id)

        if webhook_resp.status_code == 200 and access is True:
            status, confidence, observed = "confirmed_p0", "high", "grant succeeded citing a tenant_id different from the payment's own"
        elif webhook_resp.status_code >= 400:
            status, confidence, observed = "ruled_out", "high", f"HTTP {webhook_resp.status_code} -- cross-tenant claim rejected"
        else:
            status, confidence, observed = "unknown_critical_exposure", "low", f"HTTP {webhook_resp.status_code}, access={access}"

        return Finding(
            finding_id="BB-004", status=status,
            business_impact="Cross-tenant payment/entitlement binding failure",
            tested_invariant="Granted entitlement's tenant must match the paying payment's own tenant",
            baseline="n/a -- single-tenant probe, no cross-tenant control established in this wave",
            controlled_variation="payment created under tenant_probe_A; webhook claims tenant_probe_B",
            expected_secure_behavior="rejected due to tenant mismatch",
            observed_behavior=observed,
            actual_protected_benefit_result=f"has_access={access}",
            evidence=[Evidence("OBSERVED", f"webhook HTTP {webhook_resp.status_code}"), Evidence("OBSERVED", f"access={access}")],
            benign_explanations_considered="Could 'tenant_id' in the webhook be advisory/non-binding by design? Cannot be ruled out externally without customer confirmation -- see unknown exposures.",
            confidence=confidence,
        )

    async def run_all(self) -> dict[str, Any]:
        baseline = await self.establish_baselines()
        self.findings = [
            await self.oracle_payment_to_entitlement_timing(baseline),
            await self.oracle_amount_binding(baseline),
            await self.oracle_replay(baseline),
            await self.oracle_tenant_binding(baseline),
        ]
        return {"baseline": baseline, "findings": self.findings}
