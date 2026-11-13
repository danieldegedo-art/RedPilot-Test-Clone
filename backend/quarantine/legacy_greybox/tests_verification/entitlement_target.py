"""Entitlement layer on top of ReferenceTarget -- extends the payment
lifecycle with what the payment-integrity mission actually cares about:
not "is the payment record correct" (axis 1/2 already cover that) but
"does something paid actually get GRANTED only when it should".

NINE DELIBERATE BUGS, each matching a specific mission hypothesis:

  BUG A (hypothesis 3, webhook integrity): signature verification is
  entirely skippable via require_webhook_signature (default False).

  BUG B (hypothesis 2, trust-boundary failure): the webhook grants
  entitlement based on the EVENT PAYLOAD's "status" claim without
  cross-checking the authoritative payment record.

  BUG C (hypothesis 7, idempotency/replay): no event_id dedup unless
  dedupe_webhook_events is enabled.

  BUG D (reconciliation, "Refunds... mit noch aktivem Paid Entitlement"):
  nothing listens for a refund and revokes the corresponding entitlement.

  BUG E (truth divergence): even with BUG D fixed, access_cache -- a
  DERIVED projection -- is not invalidated unless invalidate_cache_on_revoke
  is ALSO separately enabled.

  BUG F (hypothesis 8, amount/product integrity): the webhook grants
  whatever tier the CLAIM says ("product": "enterprise") without checking
  that the AUTHORITATIVE paid amount actually covers that tier's price --
  unless verify_amount_matches_tier is enabled. A $9.99 payment can claim
  "enterprise" ($99.99) and be granted it.

  BUG G (tenant isolation): the webhook does not check that the claimed
  tenant_id matches the payment's own authoritative tenant_id -- unless
  enforce_tenant_isolation is enabled. A payment made under tenant A can
  be cited to grant entitlement under a DIFFERENT claimed tenant_id.

  BUG H (hypothesis 8, CURRENCY half of amount/currency integrity): the
  authoritative paid amount is compared to the catalog price as a bare
  number, ignoring currency. 99.99 JPY numerically "covers" a 99.99 USD
  tier -- verify_amount_matches_tier alone does NOT catch this, which is
  the point: it is a distinct bug from BUG F, needing its own check
  (verify_currency_matches_tier).

  BUG I (revocation-lag window, truth divergence over TIME): between the
  AUTHORITATIVE payment record moving to "refunded" and the entitlement
  revocation actually being applied, check_access() -- which consults only
  the DERIVED access_cache -- still answers True. The window is real only
  once authoritative truth has ALREADY changed; an access check that
  merely runs before the refund completes is correctly answered True and
  is NOT this bug (an earlier revision of this project's own test
  conflated the two -- see test_gap_closure.py). Fixed by
  check_access_verifies_authoritative: the access decision re-checks the
  authoritative payment status instead of trusting the cache alone.

ONE DELIBERATELY CORRECT PATH, for contrast: grant_direct() -- checks
authoritative status, amount-vs-tier, AND tenant match unconditionally
(it is the internal/admin path this project's own audit found already
safe; adding two more dimensions to check does not change that verdict,
and this file keeps proving it rather than assuming it still holds).

SIGNATURE VERIFICATION: real HMAC-SHA256 over a canonical JSON
serialization of the body (signature field excluded), compared with
hmac.compare_digest (constant-time) -- not the placeholder equality
check earlier revisions of this file used. require_webhook_signature
still controls whether it's ENFORCED; the check itself, when it runs, is
now cryptographically real.
"""
from __future__ import annotations
from app.testing.purity.quarantine import refuse_in_pure_mode  # noqa: E402  (QUARANTINED: never loads)
refuse_in_pure_mode(__name__)

import hashlib
import hmac
import json
from dataclasses import dataclass

from reference_target import ReferenceTarget

PRODUCT_CATALOG: dict[str, float] = {"basic": 9.99, "pro": 29.99, "enterprise": 99.99}
CATALOG_CURRENCY = "USD"  # every price above is in this currency and ONLY this one


@dataclass
class EntitlementRecord:
    user_id: str
    active: bool = False
    paid_through_periods: int = 0
    granted_for_payment_id: str | None = None
    tier: str | None = None
    tenant_id: str | None = None


class EntitlementTarget:
    def __init__(
        self,
        *,
        require_webhook_signature: bool = False,
        dedupe_webhook_events: bool = False,
        verify_authoritative_status: bool = False,
        revoke_entitlement_on_refund: bool = False,
        invalidate_cache_on_revoke: bool = False,
        verify_amount_matches_tier: bool = False,
        enforce_tenant_isolation: bool = False,
        verify_currency_matches_tier: bool = False,
        check_access_verifies_authoritative: bool = False,
    ) -> None:
        self._inner = ReferenceTarget()
        self.entitlements: dict[str, EntitlementRecord] = {}
        self._processed_event_ids: set[str] = set()
        self.access_cache: dict[str, bool] = {}  # DERIVED (see truth_model.py)
        # All flags default OFF -- every bug is present by default,
        # matching "planted, not accidentally absent".
        self.require_webhook_signature = require_webhook_signature
        self.dedupe_webhook_events = dedupe_webhook_events
        self.verify_authoritative_status = verify_authoritative_status
        self.revoke_entitlement_on_refund = revoke_entitlement_on_refund
        self.invalidate_cache_on_revoke = invalidate_cache_on_revoke
        self.verify_amount_matches_tier = verify_amount_matches_tier
        self.enforce_tenant_isolation = enforce_tenant_isolation
        self.verify_currency_matches_tier = verify_currency_matches_tier
        self.check_access_verifies_authoritative = check_access_verifies_authoritative
        self._webhook_secret = b"whsec_test_only_do_not_use_in_prod"

    @property
    def payments(self):
        return self._inner.payments

    async def create_payment(self, amount: float, tenant_id: str = "default", currency: str = "USD") -> dict:
        _, body = await self._inner._create({"amount": amount})
        self._inner.payments[body["id"]]["tenant_id"] = tenant_id
        self._inner.payments[body["id"]]["currency"] = currency
        body["tenant_id"] = tenant_id
        body["currency"] = currency
        return body

    async def capture(self, payment_id: str) -> dict:
        _, body = await self._inner._capture(payment_id)
        return body

    def authoritative_status(self, payment_id: str) -> str | None:
        p = self._inner.payments.get(payment_id)
        return p["state"] if p else None

    def authoritative_amount(self, payment_id: str) -> float | None:
        p = self._inner.payments.get(payment_id)
        return float(p["amount"]) if p else None

    def authoritative_currency(self, payment_id: str) -> str | None:
        p = self._inner.payments.get(payment_id)
        return p.get("currency") if p else None

    def authoritative_tenant(self, payment_id: str) -> str | None:
        p = self._inner.payments.get(payment_id)
        return p.get("tenant_id") if p else None

    def sign(self, body_without_signature: dict) -> str:
        """Real signing, for tests to construct genuinely valid requests
        with -- exactly what a real provider's SDK would do on the
        sending side."""
        canonical = json.dumps(body_without_signature, sort_keys=True).encode("utf-8")
        return hmac.new(self._webhook_secret, canonical, hashlib.sha256).hexdigest()

    def _valid_signature(self, body: dict) -> bool:
        provided = body.get("signature")
        if not provided:
            return False
        body_without_sig = {k: v for k, v in body.items() if k != "signature"}
        expected = self.sign(body_without_sig)
        return hmac.compare_digest(expected, provided)

    def _grant(self, user_id: str, payment_id: str | None, *, tier: str | None = None, tenant_id: str | None = None) -> EntitlementRecord:
        record = self.entitlements.setdefault(user_id, EntitlementRecord(user_id=user_id))
        record.active = True
        record.paid_through_periods += 1
        record.granted_for_payment_id = payment_id
        record.tier = tier
        record.tenant_id = tenant_id
        self.access_cache[user_id] = True
        return record

    async def handle_webhook(self, body: dict) -> tuple[int, dict]:
        if self.require_webhook_signature and not self._valid_signature(body):
            return 401, {"error": "invalid_signature"}

        event_id = body.get("event_id")
        payment_id = body.get("payment_id")
        user_id = body.get("user_id")
        claimed_status = body.get("status")
        claimed_tier = body.get("product", "basic")
        claimed_tenant = body.get("tenant_id", "default")

        if self.dedupe_webhook_events:
            if event_id in self._processed_event_ids:
                return 200, {"status": "already_processed", "event_id": event_id}
            self._processed_event_ids.add(event_id)

        if claimed_status != "succeeded":
            return 200, {"status": "ignored"}

        if self.verify_authoritative_status:
            authoritative = self.authoritative_status(payment_id)
            if authoritative != "captured":
                return 409, {"error": "authoritative_status_mismatch", "claimed": claimed_status, "authoritative": authoritative}

        # BUG F / FIX: the claimed tier is granted as-is unless the
        # authoritative amount is checked against the catalog price.
        if self.verify_amount_matches_tier:
            paid = self.authoritative_amount(payment_id) or 0.0
            required = PRODUCT_CATALOG.get(claimed_tier)
            if required is None or paid < required:
                return 409, {"error": "amount_below_tier", "claimed_tier": claimed_tier, "paid": paid, "required": required}

        # BUG H / FIX: currency is a SEPARATE check from amount on purpose.
        if self.verify_currency_matches_tier:
            paid_currency = self.authoritative_currency(payment_id)
            if paid_currency != CATALOG_CURRENCY:
                return 409, {"error": "currency_mismatch", "paid_currency": paid_currency, "required_currency": CATALOG_CURRENCY}

        # BUG G / FIX: the claimed tenant_id is trusted as-is unless
        # checked against the payment's own authoritative tenant_id.
        if self.enforce_tenant_isolation:
            authoritative_tenant = self.authoritative_tenant(payment_id)
            if authoritative_tenant != claimed_tenant:
                return 409, {"error": "tenant_mismatch", "claimed": claimed_tenant, "authoritative": authoritative_tenant}

        record = self._grant(user_id, payment_id, tier=claimed_tier, tenant_id=claimed_tenant)
        return 200, {"status": "entitlement_granted", "user_id": user_id, "periods": record.paid_through_periods, "tier": record.tier}

    async def refund(self, payment_id: str, amount: float, *, revoke_delay_seconds: float = 0.0) -> tuple[int, dict]:
        """revoke_delay_seconds: an explicit await point BETWEEN the
        authoritative refund completing and the entitlement revocation
        being applied -- used by the concurrency test to open a real,
        not simulated, race window between this and check_access(), the
        same "real await, real interleaving" standard axis 1/2's races
        were held to."""
        _, body = await self._inner._refund_by_body({"paymentId": payment_id, "amount": amount})
        if self.revoke_entitlement_on_refund and body.get("status") in ("refunded", "partially_refunded"):
            if revoke_delay_seconds:
                import asyncio

                await asyncio.sleep(revoke_delay_seconds)
            for record in self.entitlements.values():
                if record.granted_for_payment_id == payment_id:
                    record.active = False
                    if self.invalidate_cache_on_revoke:
                        self.access_cache[record.user_id] = False
        return 200, body

    def check_access(self, user_id: str, tenant_id: str | None = None) -> bool:
        """BUG G also reaches here in a second form: without
        enforce_tenant_isolation, a caller can check access for a user_id
        while asserting ANY tenant_id (or none) and get the cached answer
        regardless of whether it matches the tenant the entitlement was
        actually granted under."""
        if self.enforce_tenant_isolation and tenant_id is not None:
            record = self.entitlements.get(user_id)
            if record is None or record.tenant_id != tenant_id:
                return False
        # BUG I / FIX: without check_access_verifies_authoritative, the
        # answer comes from the DERIVED cache alone. With it, the access
        # decision ALSO requires the AUTHORITATIVE payment record to still
        # say "captured" -- so an authoritative refund that has already
        # happened denies access immediately, regardless of whether the
        # entitlement revocation and cache invalidation have caught up yet.
        if self.check_access_verifies_authoritative:
            record = self.entitlements.get(user_id)
            if record is None or record.granted_for_payment_id is None:
                return False
            if self.authoritative_status(record.granted_for_payment_id) != "captured":
                return False
        return self.access_cache.get(user_id, False)

    async def grant_direct(self, user_id: str, payment_id: str, tier: str = "basic", tenant_id: str = "default") -> tuple[int, dict]:
        """The correctly-protected path: authoritative status, amount-vs-tier,
        AND tenant match, unconditionally -- re-verified here now that two
        more dimensions exist to check, not assumed to still be safe."""
        status = self.authoritative_status(payment_id)
        if status != "captured":
            return 409, {"error": "payment_not_final", "status": status}
        paid = self.authoritative_amount(payment_id) or 0.0
        required = PRODUCT_CATALOG.get(tier)
        if required is None or paid < required:
            return 409, {"error": "amount_below_tier", "tier": tier, "paid": paid, "required": required}
        authoritative_tenant = self.authoritative_tenant(payment_id)
        if authoritative_tenant != tenant_id:
            return 409, {"error": "tenant_mismatch", "requested": tenant_id, "authoritative": authoritative_tenant}
        paid_currency = self.authoritative_currency(payment_id)
        if paid_currency != CATALOG_CURRENCY:
            return 409, {"error": "currency_mismatch", "paid_currency": paid_currency, "required_currency": CATALOG_CURRENCY}
        record = self._grant(user_id, payment_id, tier=tier, tenant_id=tenant_id)
        return 200, {"status": "entitlement_granted", "user_id": user_id, "periods": record.paid_through_periods, "tier": record.tier}

    async def handle_http(self, method: str, path: str, body: dict | None) -> tuple[int, dict]:
        body = body or {}
        if path.rstrip("/") == "/api/v1/payments" and method == "POST":
            return 201, await self.create_payment(body.get("amount", 0), body.get("tenant_id", "default"), body.get("currency", "USD"))
        if path.rstrip("/").endswith("/capture") and method == "POST":
            payment_id = path.rstrip("/").split("/")[-2]
            return 200, await self.capture(payment_id)
        if path.rstrip("/") == "/api/v1/webhooks/payment-confirmed" and method == "POST":
            return await self.handle_webhook(body)
        if path.rstrip("/") == "/api/v1/refunds" and method == "POST":
            return await self.refund(body.get("paymentId"), body.get("amount", 0), revoke_delay_seconds=body.get("_revoke_delay_seconds", 0.0))
        if path.rstrip("/") == "/api/v1/entitlements/grant-direct" and method == "POST":
            return await self.grant_direct(body.get("user_id"), body.get("payment_id"), body.get("tier", "basic"), body.get("tenant_id", "default"))
        if path.startswith("/api/v1/access/") and method == "GET":
            user_id = path.rstrip("/").split("/")[-1]
            return 200, {"user_id": user_id, "has_access": self.check_access(user_id)}
        if path.startswith("/api/v1/entitlements/") and method == "GET":
            user_id = path.rstrip("/").split("/")[-1]
            record = self.entitlements.get(user_id)
            if record is None:
                return 200, {"user_id": user_id, "active": False, "paid_through_periods": 0}
            return 200, {"user_id": user_id, "active": record.active, "paid_through_periods": record.paid_through_periods, "tier": record.tier, "tenant_id": record.tenant_id}
        return 404, {"error": "not_found"}


async def _serve_entitlement_connection(target: EntitlementTarget, reader, writer) -> None:
    from reference_target import _read_http_request
    import json as _json

    try:
        method, path, body, _headers = await _read_http_request(reader)
        status_code, response_body = await target.handle_http(method, path, body)
    except Exception as exc:
        status_code, response_body = 400, {"error": "bad_request", "detail": str(exc)}
    payload = _json.dumps(response_body).encode("utf-8")
    response = (
        f"HTTP/1.1 {status_code} X\r\nContent-Type: application/json\r\n"
        f"Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n"
    ).encode("utf-8") + payload
    try:
        writer.write(response)
        await writer.drain()
    finally:
        writer.close()


async def start_entitlement_target(target: "EntitlementTarget | None" = None):
    import asyncio as _asyncio

    from reference_target import _TrackedServer

    target = target or EntitlementTarget()
    tracked = _TrackedServer(None)

    def _on_connect(reader, writer):
        task = _asyncio.ensure_future(_serve_entitlement_connection(target, reader, writer))
        tracked.tasks.add(task)
        task.add_done_callback(tracked.tasks.discard)

    server = await _asyncio.start_server(_on_connect, "127.0.0.1", 0)
    tracked._server = server
    port = server.sockets[0].getsockname()[1]
    return target, tracked, port
