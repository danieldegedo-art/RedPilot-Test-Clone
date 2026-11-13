"""Stripe Flow Module.

Only runs its real test cases when Recon detected a Stripe Checkout
integration (context.shared_state["stripe_detection"]); otherwise it emits
one INFO result explaining why it's skipped and returns.

STRIPE-001 calls your checkout-session-creation endpoint and checks the
response actually references a Stripe session -- straightforward
integration sanity check, same pattern as IntegrationTestModule.

STRIPE-002 / STRIPE-003 are the webhook-channel security pair: they send a
synthetic "checkout.session.completed" event claiming a successful payment
to your webhook endpoint, once with no Stripe-Signature header at all and
once with a syntactically-shaped but cryptographically-wrong one (this
suite has no way to compute a valid one -- it doesn't have your webhook
signing secret, by design, since that must never leave your server). A
correctly implemented handler verifies the signature before trusting
anything in the payload and rejects both -- the same "does the system
reject an untrusted credential" pattern as NegativeTestModule's
expired-token test, applied to Stripe's HMAC signature.

STRIPE-004 / STRIPE-005 / STRIPE-006 are the redirect-channel counterpart,
and arguably the single most important check in this whole module.
Stripe's own docs are explicit that the success-redirect must never be
trusted on its own: retrieve the Checkout Session server-side via Stripe's
API and confirm payment_status before granting anything (see
stripe.com/docs/payments/checkout/fulfill-orders). STRIPE-004 hits the
success page with a session_id that never went through a real checkout;
STRIPE-005 probes several invalid session_id shapes; STRIPE-006 calls
subscription activation directly with no verifiable payment reference at
all. None of these forge a working Stripe credential or extract anything
from Stripe -- they submit a request an attacker could trivially construct
(a guessed/fabricated id string) and check whether your OWN system
correctly refuses to trust it, exactly like every other negative test in
this suite. Finding the gap here means it gets reported and fixed; the
alternative -- not testing it -- is what leaves it silently exploitable.

Locating the success-redirect page (needed for STRIPE-004/005) tries, in
order: (1) Recon's detection (JS literal, then rendered HTML link -- see
recon/stripe_detector.py), (2) a manual 'stripe_success_redirect' override
under Settings -> API Contract, (3) probing the standard path patterns
real Stripe integrations commonly use. Each is labeled with its confidence
so a wrong guess is easy to spot and correct.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from app.testing.base import BaseTestModule
from app.testing.checkout_provider_testing import (
    CHECKOUT_PROVIDER_STRIPE,
    run_invalid_signature_case,
    run_unsigned_webhook_case,
)
from app.testing.enums import ResultStatus, TestCategory
from app.testing.models import ResponseEvidence, TestResult
from app.testing.recon.stripe_detector import StripeDetection
from app.testing.url_utils import path_of

_STANDARD_SUCCESS_PATHS = [
    "/subscription/success",
    "/subscribe/success",
    "/payment/success",
    "/checkout/success",
    "/checkout/complete",
    "/success",
]


def _classify_status(status_code: int | None) -> str:
    """Coarse classification shared by the redirect-channel tests: does
    this status code look like a clean rejection, a crash, or neither?"""
    if status_code in (400, 401, 402, 403, 404, 422):
        return "rejected"
    if status_code is not None and status_code >= 500:
        return "crashed"
    return "ambiguous"


class StripeFlowTestModule(BaseTestModule):
    module_id = "stripe_flow"
    display_name = "Stripe Flow Module"
    category = TestCategory.STRIPE_FLOW

    async def run(self) -> None:
        detection = self.context.shared_state.get("stripe_detection")
        if not isinstance(detection, StripeDetection) or not detection.detected:
            await self._emit_skipped()
            return

        await self._case_checkout_session_creation()
        await self._case_unsigned_webhook_rejected()
        await self._case_invalid_signature_rejected()

        success_path, resolution_source = await self._resolve_success_path()
        await self._emit_success_path_resolution(success_path, resolution_source)
        await self._case_success_redirect_verification(success_path, resolution_source)
        await self._case_session_id_validation(success_path)
        await self._case_activation_without_reference()

    # -- Setup / skip -----------------------------------------------------

    async def _emit_skipped(self) -> None:
        now = datetime.now(timezone.utc)
        await self.emit(
            TestResult(
                test_case_id="STRIPE-000",
                category=self.category,
                name="Stripe Flow tests skipped",
                description="No Stripe Checkout integration was detected for this Test Environment URL.",
                input_parameters={},
                expected="N/A - informational.",
                actual="Skipped: Recon found no Stripe signals (cookie, js.stripe.com script, or publishable key), or Recon did not run in this pass.",
                status=ResultStatus.INFO,
                recommendation=(
                    "If you know this target uses Stripe, ensure the Recon module is enabled in Settings -- it "
                    "always runs before this module when enabled (see MODULE_EXECUTION_ORDER)."
                ),
                started_at=now,
                finished_at=now,
                duration_ms=0.0,
            )
        )

    # -- STRIPE-001 ---------------------------------------------------------

    async def _case_checkout_session_creation(self) -> None:
        spec = self.context.endpoints.create_checkout_session
        payload = self.resolve_payload({"productId": "prod_standard_plan", "quantity": 1})

        def evaluate(resp: ResponseEvidence) -> tuple[ResultStatus, str]:
            if resp.status_code is not None and resp.status_code >= 500:
                return ResultStatus.FAIL, f"HTTP {resp.status_code} - the checkout-session endpoint crashed."
            if resp.status_code not in (200, 201):
                return ResultStatus.WARNING, (
                    f"HTTP {resp.status_code} - could not create a checkout session at {spec.path}; likely a path "
                    "misconfiguration (see recommendation) rather than a target bug."
                )
            if not isinstance(resp.body, dict):
                return ResultStatus.WARNING, f"HTTP {resp.status_code} but body is not JSON - cannot confirm a Stripe session was created."

            url = resp.body.get("url") or resp.body.get("checkoutUrl") or resp.body.get("checkout_url")
            session_id = resp.body.get("id") or resp.body.get("sessionId") or resp.body.get("session_id")
            if url and "checkout.stripe.com" in str(url):
                return ResultStatus.PASS, f"HTTP {resp.status_code} - returned a checkout.stripe.com URL."
            if session_id and str(session_id).startswith("cs_"):
                return ResultStatus.PASS, f"HTTP {resp.status_code} - returned a Stripe checkout session id."
            return ResultStatus.WARNING, (
                f"HTTP {resp.status_code} - response doesn't clearly look like a Stripe session (no "
                "checkout.stripe.com URL or cs_-prefixed id); confirm the endpoint/response shape manually."
            )

        await self.execute_case(
            test_case_id="STRIPE-001",
            name="Checkout session creation returns a Stripe session",
            description=(
                "Calls your checkout-session-creation endpoint and checks whether the response references an "
                "actual Stripe Checkout Session (a checkout.stripe.com URL or a cs_-prefixed session id)."
            ),
            method=spec.method,
            path=spec.path,
            input_parameters=payload,
            expected="HTTP 200/201 with a checkout.stripe.com URL or cs_-prefixed session id in the response.",
            evaluate=evaluate,
            recommendation=(
                "Confirm 'create_checkout_session' under Settings -> API Contract points at your real "
                "checkout-session endpoint -- Recon may not have discovered it automatically (see RECON-003)."
            ),
        )

    # -- STRIPE-002 / STRIPE-003 (webhook channel) ---------------------------

    async def _case_unsigned_webhook_rejected(self) -> None:
        spec = self.context.endpoints.stripe_webhook
        await run_unsigned_webhook_case(
            self, provider=CHECKOUT_PROVIDER_STRIPE, method=spec.method, path=spec.path, test_case_id="STRIPE-002"
        )

    async def _case_invalid_signature_rejected(self) -> None:
        spec = self.context.endpoints.stripe_webhook
        await run_invalid_signature_case(
            self, provider=CHECKOUT_PROVIDER_STRIPE, method=spec.method, path=spec.path, test_case_id="STRIPE-003"
        )

    # -- Success-path resolution (feeds STRIPE-004 / STRIPE-005) -------------

    async def _resolve_success_path(self) -> tuple[str, str]:
        detection = self.context.shared_state.get("stripe_detection")
        if isinstance(detection, StripeDetection) and detection.success_url:
            source_label = "client-side JS literal" if detection.success_url_source == "js" else "a rendered HTML link"
            return path_of(detection.success_url), f"Recon detected it via {source_label}"

        manual = self.context.endpoints.overrides.get("stripe_success_redirect")
        if manual is not None:
            return manual.path, "manual override configured under Settings -> API Contract"

        probe_session_id = "cs_qa_probe_" + uuid.uuid4().hex[:12]
        for candidate in _STANDARD_SUCCESS_PATHS:
            _, resp = await self.context.http.request("GET", candidate, params={"session_id": probe_session_id})
            if resp.error is None and resp.status_code is not None and resp.status_code not in (404, 501):
                return candidate, f"standard-path probe (first responsive candidate: {candidate}, HTTP {resp.status_code})"

        placeholder = self.context.endpoints.stripe_success_redirect.path
        return placeholder, "unverified placeholder -- no signal found from Recon, Settings, or path probing"

    async def _emit_success_path_resolution(self, success_path: str, source: str) -> None:
        now = datetime.now(timezone.utc)
        confident = source.startswith("Recon") or source.startswith("manual override")
        await self.emit(
            TestResult(
                test_case_id="STRIPE-RESOLVE",
                category=self.category,
                name="Success-redirect path resolved",
                description="Determines which URL to test as the post-checkout success/return page, before running STRIPE-004 and STRIPE-005.",
                input_parameters={},
                expected="N/A - informational.",
                actual=f"Testing success path: {success_path}\nResolved via: {source}",
                status=ResultStatus.INFO,
                recommendation=None if confident else (
                    "This path was guessed via a standard-pattern probe or an unverified placeholder, not "
                    "confirmed from your actual JS/HTML. If STRIPE-004/STRIPE-005 look wrong, configure "
                    "'stripe_success_redirect' under Settings -> API Contract with your real success-page path."
                ),
                started_at=now,
                finished_at=now,
                duration_ms=0.0,
            )
        )

    # -- STRIPE-004 -----------------------------------------------------------

    async def _case_success_redirect_verification(self, success_path: str, resolution_source: str) -> None:
        fake_session_id = "cs_test_" + uuid.uuid4().hex[:24]

        def evaluate(resp: ResponseEvidence) -> tuple[ResultStatus, str]:
            classification = _classify_status(resp.status_code)
            if classification == "rejected":
                return ResultStatus.PASS, f"HTTP {resp.status_code} - rejected at the HTTP layer."
            if classification == "crashed":
                return ResultStatus.FAIL, f"HTTP {resp.status_code} - crashed instead of validating cleanly."

            body_text = resp.body if isinstance(resp.body, str) else (str(resp.body) if resp.body is not None else "")
            lowered = body_text.lower()
            rejection_signals = ("invalid", "not found", "expired", "no such session", "could not verify", "error")
            success_signals = ("activated", "welcome", "subscription active", "payment successful", "thank you")
            has_rejection_signal = any(s in lowered for s in rejection_signals)
            has_success_signal = any(s in lowered for s in success_signals)

            if has_rejection_signal and not has_success_signal:
                return ResultStatus.PASS, f"HTTP {resp.status_code} - response content suggests the session was rejected."
            if has_success_signal:
                return ResultStatus.WARNING, (
                    f"HTTP {resp.status_code} - response content suggests a SUCCESS state for a session_id that "
                    f"never completed checkout ('{fake_session_id}'). This may just be a static SPA shell (real "
                    "validation could happen via a separate client-side API call this black-box test doesn't "
                    "see). Whether any subscription was created is UNKNOWN from outside; the externally valid follow-up is the "
                "Payment Integrity module's protected-feature oracle (a synthetic identity USES the paid feature)."
                )
            return ResultStatus.WARNING, (
                f"HTTP {resp.status_code} - ambiguous; could not determine from this response alone whether the "
                f"fake session was rejected. This stays UNKNOWN (never 'passed'): confirm externally with the Payment Integrity "
                f"module's protected-feature oracle, not by inspecting target internals."
            )

        await self.execute_case(
            test_case_id="STRIPE-004",
            name="Success-redirect is verified against Stripe before activation",
            description=(
                f"Calls the success-redirect page ({resolution_source}) directly with a session_id that never "
                "went through a real checkout. Stripe's own guidance is explicit: never trust this redirect "
                "alone -- retrieve the Session server-side via Stripe's API and check its payment_status before "
                "granting access. This is the single most critical check in the whole Stripe flow: if it's "
                "missing, anyone who can guess or fabricate a session_id-shaped string can activate a "
                "subscription for free."
            ),
            method="GET",
            path=success_path,
            params={"session_id": fake_session_id},
            expected="The system verifies the session_id against Stripe's API server-side and does not activate a subscription for a session that was never paid.",
            evaluate=evaluate,
            recommendation=(
                "On the success-redirect route (or the API call it triggers), retrieve the Checkout Session "
                "server-side via Stripe's API (stripe.checkout.Session.retrieve(session_id)) and confirm "
                "payment_status == 'paid' before activating anything. Prefer the webhook (STRIPE-002/003) as "
                "the authoritative fulfillment trigger; use the redirect only for the user-facing confirmation "
                "page, never as proof of payment on its own."
            ),
        )

    # -- STRIPE-005 -----------------------------------------------------------

    async def _case_session_id_validation(self, success_path: str) -> None:
        probes: list[tuple[str, str]] = [
            ("empty", ""),
            ("invalid_format", "not-a-valid-stripe-session-id"),
            ("well_formed_nonexistent", "cs_test_" + "0" * 24),
        ]

        started = datetime.now(timezone.utc)
        outcomes: list[tuple[str, str, str, str]] = []
        last_req, last_resp = None, None
        for label, session_id in probes:
            req, resp = await self.context.http.request("GET", success_path, params={"session_id": session_id})
            last_req, last_resp = req, resp
            if resp.error is not None:
                outcomes.append((label, session_id, "ERROR", f"transport error: {resp.error}"))
                continue
            classification = _classify_status(resp.status_code)
            if classification == "rejected":
                outcomes.append((label, session_id, "PASS", f"HTTP {resp.status_code} - rejected"))
            elif classification == "crashed":
                outcomes.append((label, session_id, "FAIL", f"HTTP {resp.status_code} - crashed"))
            else:
                outcomes.append((label, session_id, "AMBIGUOUS", f"HTTP {resp.status_code} - not clearly rejected"))
        finished = datetime.now(timezone.utc)

        verdicts = [o[2] for o in outcomes]
        if "FAIL" in verdicts or "ERROR" in verdicts:
            status = ResultStatus.FAIL if "FAIL" in verdicts else ResultStatus.ERROR
        elif "AMBIGUOUS" in verdicts:
            status = ResultStatus.WARNING
        else:
            status = ResultStatus.PASS

        actual = "\n".join(f"[{label}] session_id={session_id!r} -> {verdict}: {detail}" for label, session_id, verdict, detail in outcomes)
        probed_values = {label: session_id for label, session_id, *_ in outcomes}

        await self.emit(
            TestResult(
                test_case_id="STRIPE-005",
                category=self.category,
                name="Invalid session_id values are all rejected",
                description=(
                    "Calls the success-redirect page with an empty, malformed, and well-formed-but-nonexistent "
                    "session_id in turn, and checks that every one is rejected."
                ),
                input_parameters={"probed": probed_values},
                expected="HTTP 400/401/403/404/422 for every value -- none should be treated as a valid, paid session.",
                actual=actual,
                status=status,
                request=last_req,
                response=last_resp,
                recommendation=None if status == ResultStatus.PASS else (
                    "Validate session_id format before even querying Stripe, and confirm your code path handles "
                    "Stripe's 'resource not found' response correctly for a well-formed-but-fake id -- every "
                    "case above should be rejected, and a 5xx suggests the id isn't validated/sanitized before "
                    "use."
                ),
                started_at=started,
                finished_at=finished,
                duration_ms=(finished - started).total_seconds() * 1000,
            )
        )

    # -- STRIPE-006 -----------------------------------------------------------

    async def _case_activation_without_reference(self) -> None:
        spec = self.context.endpoints.create_subscription
        # NOT resolved: sessionId is deliberately fabricated and must never
        # have gone through a real Stripe Checkout -- that's the entire
        # point of this test. Resolving it against a discovered value could
        # accidentally substitute a real session reference.
        payload = {
            "planId": "plan_standard_monthly",
            "customerEmail": "qa-stripe-flow@example.com",
            "sessionId": "cs_test_qa_no_real_checkout_" + uuid.uuid4().hex[:8],
        }

        def evaluate(resp: ResponseEvidence) -> tuple[ResultStatus, str]:
            classification = _classify_status(resp.status_code)
            if classification == "rejected":
                return ResultStatus.PASS, f"HTTP {resp.status_code} - correctly rejected (no valid payment reference)."
            if classification == "crashed":
                return ResultStatus.FAIL, f"HTTP {resp.status_code} - crashed instead of validating cleanly."
            if resp.status_code in (200, 201):
                body_status = resp.body.get("status") if isinstance(resp.body, dict) else None
                if body_status in ("active", "activated", "trialing"):
                    return ResultStatus.FAIL, (
                        f"HTTP {resp.status_code} - subscription ACTIVATED (status='{body_status}') with no real "
                        "payment reference. This is the exact gap this test exists to catch."
                    )
                return ResultStatus.WARNING, f"HTTP {resp.status_code} - accepted but status is '{body_status}', not clearly active; verify manually."
            return ResultStatus.WARNING, f"HTTP {resp.status_code} - unexpected response."

        await self.execute_case(
            test_case_id="STRIPE-006",
            name="Subscription activation requires a verified payment reference",
            description=(
                "Calls the subscription-creation endpoint directly with a fabricated session reference that "
                "never went through Stripe Checkout, and no other proof of payment. A correctly implemented "
                "endpoint requires and server-side-verifies a real, paid Checkout Session (or equivalent "
                "PaymentIntent) before activating anything."
            ),
            method=spec.method,
            path=spec.path,
            input_parameters=payload,
            expected="HTTP 400/401/402/403/422 - rejected for lacking a verified payment reference.",
            evaluate=evaluate,
            recommendation=(
                "Require a session_id (or PaymentIntent id) on subscription creation, retrieve it from Stripe "
                "server-side, and confirm it's actually paid/complete -- and not already consumed by a prior "
                "subscription -- before activating. Never activate based on a client-supplied 'trust me, I "
                "paid' field."
            ),
        )
