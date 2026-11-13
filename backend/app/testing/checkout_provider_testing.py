"""Provider-parameterized webhook-signature-security testing.

The "does this endpoint verify a signature before trusting the payload,
or does it accept anything (or anything with A header present, whether or
not it verifies)" pattern (originally STRIPE-002/003, see
modules/stripe_flow.py) doesn't actually depend on Stripe at all once you
factor out three things: what a synthetic "payment succeeded" event looks
like in this provider's shape, what header name carries the signature, and
a syntactically-plausible-but-wrong signature value to send instead of a
real one. Every payment processor offering webhook notifications needs the
same defense, so this suite testing a SECOND (or third, ...) provider's
webhook endpoint should mean declaring those three things, not writing a
new module -- see modules/additional_webhook_security.py, the module that
consumes this for any provider declared under Settings ->
additional_webhook_providers.

stripe_flow.py's own STRIPE-002/003 now call the same two functions this
module exposes (see CHECKOUT_PROVIDER_STRIPE below) instead of duplicating
this logic -- same test ids, same evaluation thresholds and
recommendations' substance, wording now provider-parameterized rather than
byte-identical to the pre-refactor Stripe-only text (e.g. "payment
succeeded' event" instead of "'checkout.session.completed' event claiming
a successful payment") -- a deliberate, disclosed trade-off for removing
the duplication, not a silent one.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Protocol

from app.testing.base import BaseTestModule
from app.testing.enums import ResultStatus
from app.testing.models import ResponseEvidence, TestResult


class SyntheticEventBuilder(Protocol):
    def __call__(self, suffix: str) -> dict[str, Any]: ...


@dataclass(frozen=True)
class CheckoutProviderConfig:
    """Everything the webhook-signature-security pattern needs to know
    about one payment provider. Nothing here talks to the provider or the
    target -- it's pure declaration, evaluated the same way
    modules/stripe_flow.py already evaluates Stripe's."""

    provider_id: str  # short, stable, used in test_case_id prefixes -- e.g. "stripe", "adyen"
    display_name: str  # human-readable, used in result names/descriptions -- e.g. "Stripe", "Adyen"
    signature_header: str  # e.g. "Stripe-Signature", "hmacsignature"
    build_synthetic_event: SyntheticEventBuilder  # a plausible "payment succeeded" notification body in this provider's shape
    build_invalid_signature: Callable[[], str]  # syntactically-shaped, cryptographically-wrong -- never a real secret
    docs_hint: str = ""  # optional: SDK/verification-helper pointer for the recommendation text


def evaluate_webhook_rejection(resp: ResponseEvidence) -> tuple[ResultStatus, str]:
    """Shared verdict logic for both cases below -- identical to
    stripe_flow.py's original _evaluate_webhook_rejection (this was
    already 100% provider-agnostic; it never mentioned Stripe)."""
    if resp.status_code is not None and resp.status_code >= 500:
        return ResultStatus.FAIL, f"HTTP {resp.status_code} - signature-verification code crashed instead of cleanly rejecting."
    if resp.status_code in (400, 401, 403):
        return ResultStatus.PASS, f"HTTP {resp.status_code} - correctly rejected."
    if resp.status_code in (200, 201, 202):
        return ResultStatus.WARNING, (
            f"HTTP {resp.status_code} - could not confirm from the HTTP response alone whether this was rejected "
            "internally (some handlers intentionally return 2xx to any POST to avoid triggering the provider's "
            "retry logic). Verify manually that no subscription/order was actually activated by this synthetic event."
        )
    return ResultStatus.WARNING, f"HTTP {resp.status_code} - unexpected response."


async def run_unsigned_webhook_case(
    module: BaseTestModule, *, provider: CheckoutProviderConfig, method: str, path: str, test_case_id: str
) -> TestResult:
    payload = provider.build_synthetic_event("unsigned")
    return await module.execute_case(
        test_case_id=test_case_id,
        name=f"Unsigned {provider.display_name} webhook is rejected",
        description=(
            f"Sends a synthetic 'payment succeeded' event to your {provider.display_name} webhook endpoint with "
            f"NO {provider.signature_header} header. A correctly implemented handler verifies the signature "
            "before trusting anything in the payload and rejects requests missing one."
        ),
        method=method,
        path=path,
        input_parameters=payload,
        expected="HTTP 400/401/403 - rejected before the (fake) payment status is ever trusted.",
        evaluate=evaluate_webhook_rejection,
        recommendation=(
            f"Verify every incoming {provider.display_name} webhook's {provider.signature_header} header against "
            f"your webhook signing secret{(' (' + provider.docs_hint + ')') if provider.docs_hint else ''} before "
            "acting on the payload. Without this, anyone who can reach this endpoint's URL can grant themselves a "
            "subscription by POSTing a fake 'payment succeeded' event."
        ),
    )


async def run_invalid_signature_case(
    module: BaseTestModule, *, provider: CheckoutProviderConfig, method: str, path: str, test_case_id: str
) -> TestResult:
    payload = provider.build_synthetic_event("badsig")
    return await module.execute_case(
        test_case_id=test_case_id,
        name=f"{provider.display_name} webhook with an invalid signature is rejected",
        description=(
            "Same synthetic event as the unsigned case, but WITH a signature header -- shaped like a real one, "
            "cryptographically wrong. Confirms the handler actually verifies the signature cryptographically "
            "rather than just checking that the header is present."
        ),
        method=method,
        path=path,
        input_parameters=payload,
        headers={provider.signature_header: provider.build_invalid_signature()},
        expected="HTTP 400/401/403 - rejected because the signature doesn't verify against your signing secret.",
        evaluate=evaluate_webhook_rejection,
        recommendation=(
            "If this passed while the unsigned case also passed, the handler may only be checking that a "
            f"{provider.signature_header} header is present, not cryptographically verifying it."
        ),
    )


def _stripe_synthetic_event(suffix: str) -> dict[str, Any]:
    return {
        "id": f"evt_qa_test_{suffix}",
        "object": "event",
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "id": f"cs_qa_test_{suffix}",
                "object": "checkout.session",
                "payment_status": "paid",
                "status": "complete",
                "customer_email": "qa-stripe-flow@example.com",
                "metadata": {"qa_test": "true"},
            }
        },
    }


CHECKOUT_PROVIDER_STRIPE = CheckoutProviderConfig(
    provider_id="stripe",
    display_name="Stripe",
    signature_header="Stripe-Signature",
    build_synthetic_event=_stripe_synthetic_event,
    build_invalid_signature=lambda: "t=1700000000,v1=" + "0" * 64,  # syntactically Stripe-shaped, cryptographically meaningless
    docs_hint="e.g. stripe.Webhook.construct_event in Stripe's SDKs",
)


@dataclass(frozen=True)
class ManualWebhookProvider:
    """One operator-declared (Settings -> additional_webhook_providers)
    non-Stripe webhook endpoint to run the same signature-security pattern
    against -- see modules/additional_webhook_security.py. Recon has no
    fingerprint for this provider (that's specifically why it's declared
    manually instead of auto-detected, unlike Stripe), so there's nothing
    here for Recon to get wrong or need updating for a provider this
    project has never seen real traffic from."""

    provider_id: str
    display_name: str
    method: str
    path: str
    signature_header: str
    observed_via: str | None = None  # external provenance attestation (see ManualWebhookProviderSchema.observed_via)

    def to_provider_config(self) -> CheckoutProviderConfig:
        """A generic synthetic event body and a generic fake-signature
        value -- reasonable defaults for a provider whose exact payload
        shape this project doesn't know. If your provider's handler
        inspects the event body's shape before the signature check even
        runs (unusual, but see STRIPE-002/003's own note that a handler
        should reject on signature alone, before ever parsing payload
        semantics), tell it apart from a real payload precisely BECAUSE it
        won't match -- that's still a meaningful signal, not a false
        negative: a handler that reaches into an unverified body's fields
        before checking the signature is itself the kind of gap this
        pattern exists to catch."""
        return CheckoutProviderConfig(
            provider_id=self.provider_id,
            display_name=self.display_name,
            signature_header=self.signature_header,
            build_synthetic_event=lambda suffix: {
                "id": f"evt_qa_test_{suffix}",
                "type": "payment.succeeded",
                "data": {"status": "paid", "reference": f"qa_test_{suffix}", "metadata": {"qa_test": "true"}},
            },
            build_invalid_signature=lambda: "qa-test-invalid-signature-" + "0" * 32,
        )
