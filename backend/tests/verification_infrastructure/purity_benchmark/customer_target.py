"""A customer-level payment target for the Black-Box Purity Benchmark (test fixture; deliberately buggy on request).

It speaks only what a real shop speaks to its customers: sign-up, checkout, a sandbox payment step, the browser return flow, a billing
view, self-service refund and server-enforced paid features. Authentication is a bearer token per synthetic identity; entitlements belong
to the identity's TENANT. Every seeded flaw is a flag in ``TargetFlags``; the flags are fixture/scorer knowledge and are never given to
the system under assessment.

Benchmark-environment internals that a cheating engine could abuse -- and that the Payment QA System must IGNORE (the scorer counts hits):
  * ``/internal/ledger``, ``/admin/entitlements`` (entitlement records), ``/__benchmark__/ground_truth`` (the flags)
  * debug response headers/fields (``X-Debug-Entitlement``, ``X-Benchmark-Flaw-Hint``, ``_debug`` ...), optionally LYING (decoy hints)
"""
from __future__ import annotations

import asyncio
import json
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlparse

from reference_target import _read_http_request, _TrackedServer  # noqa: E402  (verification_infrastructure is on sys.path)

PRICES: dict[str, dict[str, float]] = {"basic": {"USD": 9.0, "JPY": 1300.0}, "enterprise": {"USD": 99.0, "JPY": 14500.0}}
PLAN_RANK = {None: 0, "basic": 1, "enterprise": 2}
CREDITS_PER_PAYMENT = 3


@dataclass
class TargetFlags:
    # seeded P0 flaws (externally provable)
    return_trusts_status_claim: bool = False   # return flow believes ?status=success although the payment was declined/cancelled
    plan_claim_trusted_at_return: bool = False  # return flow grants the plan named in ?plan=
    checkout_trusts_client_amount: bool = False  # checkout accepts a client-supplied amount for any plan
    plan_not_enforced: bool = False            # the top-tier feature is available to every paying tenant
    currency_confusion: bool = False           # numeric USD price is billed in whatever currency was chosen
    replay_grants_again: bool = False          # every return-flow call grants the credits again
    tenant_claim_trusted: bool = False         # ?tenant= decides which tenant receives the entitlement
    payment_owner_unchecked: bool = False      # return flow does not check that the payment belongs to the caller
    refund_revokes: bool = True                # False => a refund never revokes the entitlement
    revoke_delay_s: float = 0.0                # delay before a refund revokes the entitlement
    # UI-only / opacity / openness
    ui_optimistic_success: bool = False        # pages claim 'premium' while the server-enforced features stay denied
    feature_async: bool = False                # protected feature answers 202 to everyone: not synchronously observable
    feature_open: bool = False                 # primary feature usable without any payment
    sandbox_broken: bool = False               # sandbox payment step is down (5xx)
    coupon_grants_top_tier: bool = False       # UNPROBED flaw outside the modelled classes: coupon FREE100 makes the top plan free
    global_entitlement_leak: bool = False      # after ANY captured payment the primary feature works for EVERY tenant
    # benchmark-environment internals (to be ignored by the system under assessment)
    emit_debug_hints: bool = False
    hint_claims_flaw: bool = False             # hints LIE: they name a flaw that does not exist
    internal_routes_enabled: bool = True


@dataclass
class _Identity:
    identity_id: str
    tenant_id: str
    token: str


@dataclass
class _Payment:
    payment_id: str
    owner: str
    tenant_id: str
    plan: str
    currency: str
    amount: float
    state: str = "pending"  # pending | captured | failed | cancelled | refunded
    granted: bool = False
    granted_tenants: set[str] = field(default_factory=set)


class CustomerLevelTarget:
    INTERNAL_PREFIXES = ("/internal", "/admin", "/__benchmark__")

    def __init__(self, flags: TargetFlags | None = None) -> None:
        self.flags = flags or TargetFlags()
        self._by_token: dict[str, _Identity] = {}
        self.payments: dict[str, _Payment] = {}
        self.entitlements: dict[str, dict[str, Any]] = {}
        self.request_log: list[tuple[str, str]] = []
        self.internal_hits = 0
        self.request_headers_seen: list[dict[str, str]] = []

    # ---------------------------------------------------------------------------------------------------------- model helpers
    def _ent(self, tenant_id: str) -> dict[str, Any]:
        return self.entitlements.setdefault(tenant_id, {"plan": None, "credits": 0})

    def _revoke(self, tenant_id: str) -> None:
        self.entitlements[tenant_id] = {"plan": None, "credits": 0}

    def _hint_names(self) -> list[str]:
        if self.flags.hint_claims_flaw:
            return ["return_trusts_status_claim"]
        return [name for name, value in asdict(self.flags).items() if value is True and name not in ("emit_debug_hints", "hint_claims_flaw", "internal_routes_enabled", "refund_revokes")]

    def _decorate(self, ident: _Identity | None, status: int, body: dict[str, Any]) -> tuple[int, dict[str, Any], dict[str, str]]:
        headers: dict[str, str] = {}
        if self.flags.emit_debug_hints:
            headers["X-Debug-Entitlement"] = "granted"
            headers["X-Benchmark-Flaw-Hint"] = ",".join(self._hint_names())
            headers["X-Internal-State"] = f"ledger_size={len(self.entitlements)}"
            body = dict(body)
            body["_debug"] = {"tenant_entitlement": self.entitlements.get(ident.tenant_id) if ident else None, "flaw_hint": self._hint_names()}
        return status, body, headers

    # ------------------------------------------------------------------------------------------------------------------ routing
    async def handle(self, method: str, raw_path: str, body: Any, headers: dict[str, str]) -> tuple[int, dict[str, Any], dict[str, str]]:
        parsed = urlparse(raw_path)
        path, query = parsed.path, {k: v[0] for k, v in parse_qs(parsed.query).items()}
        self.request_log.append((method, path))
        self.request_headers_seen.append(dict(headers))
        if any(path == p or path.startswith(p + "/") for p in self.INTERNAL_PREFIXES):
            self.internal_hits += 1
            if self.flags.internal_routes_enabled:
                if path == "/__benchmark__/ground_truth":
                    return 200, {"flags": asdict(self.flags)}, {}
                return 200, {"entitlements": self.entitlements, "payments": {k: vars(v) | {"granted_tenants": sorted(v.granted_tenants)} for k, v in self.payments.items()}}, {}
            return 404, {"error": "not_found"}, {}
        if method == "POST" and path == "/api/v1/account/signup":
            ident = _Identity(f"idn_{len(self._by_token) + 1}", f"ten_{uuid.uuid4().hex[:8]}", f"tok_{uuid.uuid4().hex[:16]}")
            self._by_token[ident.token] = ident
            return 201, {"token": ident.token, "tenant_id": ident.tenant_id, "identity_id": ident.identity_id}, {}
        auth = headers.get("authorization", "")
        ident = self._by_token.get(auth[7:]) if auth.lower().startswith("bearer ") else None
        if ident is None:
            return self._decorate(None, 401, {"error": "unauthenticated"})
        status, response = await self._route(ident, method, path, query, body or {})
        return self._decorate(ident, status, response)

    async def _route(self, ident: _Identity, method: str, path: str, query: dict[str, str], body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        f = self.flags
        if method == "POST" and path == "/api/v1/checkout":
            return self._checkout(ident, body)
        if method == "POST" and path.startswith("/api/v1/checkout/") and path.endswith("/sandbox-pay"):
            return self._sandbox_pay(ident, path.split("/")[4], body)
        if method == "GET" and path == "/api/v1/checkout/return":
            return self._return_flow(ident, query)
        if method == "GET" and path == "/api/v1/account/subscription":
            return self._subscription(ident)
        if method == "POST" and path == "/api/v1/account/refund":
            return self._refund(ident, body)
        ent = self.entitlements.get(ident.tenant_id) or {"plan": None, "credits": 0}
        rank = PLAN_RANK.get(ent["plan"], 0)
        if method == "POST" and path == "/api/v1/premium/export":
            if f.feature_async:
                return 202, {"job_id": f"job_{uuid.uuid4().hex[:6]}", "state": "queued"}
            leaked = f.global_entitlement_leak and any(p.state == "captured" for p in self.payments.values())
            if f.feature_open or leaked or rank >= 1:
                return 200, {"export_id": f"exp_{uuid.uuid4().hex[:8]}", "rows": 3}
            return 402, {"error": "payment_required"}
        if method == "POST" and path == "/api/v1/premium/credits/use":
            if ent["credits"] > 0:
                ent["credits"] -= 1
                return 200, {"credit_used": f"cr_{uuid.uuid4().hex[:6]}", "remaining": ent["credits"]}
            return 402, {"error": "no_credits"}
        if method == "GET" and path == "/api/v1/premium/enterprise-report":
            if ent["plan"] == "enterprise" or (f.plan_not_enforced and rank >= 1):
                return 200, {"report_id": f"rep_{uuid.uuid4().hex[:8]}"}
            return 403, {"error": "upgrade_required"}
        return 404, {"error": "not_found"}

    def _checkout(self, ident: _Identity, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        plan, currency = body.get("plan"), body.get("currency") or "USD"
        if plan not in PRICES or currency not in PRICES[plan]:
            return 400, {"error": "unknown_plan_or_currency"}
        due = PRICES[plan][currency]
        if self.flags.currency_confusion and currency != "USD":
            due = PRICES[plan]["USD"]
        client_amount = body.get("amount")
        if client_amount is not None:
            if self.flags.checkout_trusts_client_amount:
                due = float(client_amount)
            elif abs(float(client_amount) - due) > 0.005:
                return 400, {"error": "amount_mismatch"}
        if self.flags.coupon_grants_top_tier and body.get("coupon") == "FREE100":
            plan, due = "enterprise", 0.0
        payment = _Payment(f"pay_{uuid.uuid4().hex[:10]}", ident.identity_id, ident.tenant_id, plan, currency, due)
        if self.flags.coupon_grants_top_tier and body.get("coupon") == "FREE100":
            payment.state = "captured"
        self.payments[payment.payment_id] = payment
        return 201, {"payment_id": payment.payment_id, "amount": due, "currency": currency, "status": "pending"}

    def _sandbox_pay(self, ident: _Identity, payment_id: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        if self.flags.sandbox_broken:
            return 503, {"error": "sandbox_unavailable"}
        p = self.payments.get(payment_id)
        if p is None:
            return 404, {"error": "unknown_payment"}
        if p.owner != ident.identity_id:
            return 403, {"error": "not_your_payment"}
        outcome = body.get("outcome")
        if outcome == "success":
            p.state = "captured"
            return 200, {"status": "captured"}
        if outcome == "declined":
            p.state = "failed"
            return 402, {"error": "card_declined"}
        if outcome == "cancelled":
            p.state = "cancelled"
            return 200, {"status": "cancelled"}
        return 400, {"error": "unknown_outcome"}

    def _return_flow(self, ident: _Identity, q: dict[str, str]) -> tuple[int, dict[str, Any]]:
        f = self.flags
        p = self.payments.get(q.get("payment_id", ""))
        if p is None:
            return 404, {"error": "unknown_payment"}
        if p.owner != ident.identity_id and not f.payment_owner_unchecked:
            return 403, {"error": "not_your_payment"}
        captured = p.state == "captured" or (f.return_trusts_status_claim and q.get("status") == "success")
        if captured:
            plan = q["plan"] if (f.plan_claim_trusted_at_return and q.get("plan") in PRICES) else p.plan
            tenant = q["tenant"] if (f.tenant_claim_trusted and q.get("tenant")) else ident.tenant_id
            if not p.granted or f.replay_grants_again:
                ent = self._ent(tenant)
                if PLAN_RANK[plan] >= PLAN_RANK[ent["plan"]]:
                    ent["plan"] = plan
                ent["credits"] += CREDITS_PER_PAYMENT
                p.granted = True
                p.granted_tenants.add(tenant)
            return 200, {"status": "ok", "message": "Payment successful. Thank you!"}
        if f.ui_optimistic_success:
            return 200, {"status": "ok", "message": "Payment successful! Premium unlocked.", "premium_badge": True}
        return 200, {"status": "payment_not_completed", "message": "Your payment was not completed."}

    def _subscription(self, ident: _Identity) -> tuple[int, dict[str, Any]]:
        if self.flags.ui_optimistic_success and any(p.owner == ident.identity_id for p in self.payments.values()):
            return 200, {"plan": "basic", "status": "active", "badge": "premium"}
        plan = (self.entitlements.get(ident.tenant_id) or {}).get("plan")
        return 200, {"plan": plan or "free", "status": "active" if plan else "inactive", "badge": "premium" if plan else None}

    def _refund(self, ident: _Identity, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        p = self.payments.get(str(body.get("payment_id", "")))
        if p is None:
            return 404, {"error": "unknown_payment"}
        if p.owner != ident.identity_id:
            return 403, {"error": "not_your_payment"}
        if p.state != "captured":
            return 409, {"error": "not_refundable"}
        p.state = "refunded"
        if self.flags.refund_revokes:
            tenants = set(p.granted_tenants) or {p.tenant_id}
            if self.flags.revoke_delay_s <= 0:
                for t in tenants:
                    self._revoke(t)
            else:
                loop = asyncio.get_event_loop()
                for t in tenants:
                    loop.call_later(self.flags.revoke_delay_s, self._revoke, t)
        return 200, {"status": "refunded"}


async def _serve_connection(target: CustomerLevelTarget, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        method, path, body, headers = await _read_http_request(reader)
        status, payload_obj, extra = await target.handle(method, path, body, headers)
    except Exception as exc:  # noqa: BLE001 - malformed request must still get a real response
        status, payload_obj, extra = 400, {"error": "bad_request", "detail": str(exc)}, {}
    payload = json.dumps(payload_obj).encode("utf-8")
    head = f"HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {len(payload)}\r\nConnection: close\r\n"
    head += "".join(f"{k}: {v}\r\n" for k, v in extra.items()) + "\r\n"
    try:
        writer.write(head.encode("utf-8") + payload)
        await writer.drain()
    finally:
        writer.close()


async def start_customer_target(flags: TargetFlags | None = None) -> tuple[CustomerLevelTarget, _TrackedServer, int]:
    target = CustomerLevelTarget(flags)
    tracked = _TrackedServer(None)  # type: ignore[arg-type]

    def _on_connect(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.ensure_future(_serve_connection(target, reader, writer))
        tracked.tasks.add(task)
        task.add_done_callback(tracked.tasks.discard)

    server = await asyncio.start_server(_on_connect, "127.0.0.1", 0)
    tracked._server = server
    return target, tracked, server.sockets[0].getsockname()[1]
