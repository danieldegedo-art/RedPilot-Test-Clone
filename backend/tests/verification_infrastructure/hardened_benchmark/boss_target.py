#!/usr/bin/env python3
"""BOSS target 'Aurelia' -- an ultra-realistic enterprise paywall modeled on how real billing stacks
work (Stripe-style payment intents + signed webhooks; Stigg/Lago-style decoupled entitlement service
with multi-source, most-generous-wins resolution; trial + promo grants; a versioned migration endpoint
discoverable only by recon). It is deliberately much harder than the earlier decoys:

  * DECOUPLED billing vs entitlement: capturing a sandbox payment does NOT grant entitlement. The only
    *intended* path to enterprise is a provider webhook carrying a valid HMAC signature the target holds
    privately -> a black-box tester CANNOT forge it -> that path is an honest DEAD-END (stays BLOCKED;
    the engine must never 'confirm' through it).
  * RECON-TO-REACH: the vulnerable 'reconcile' endpoint is a v2beta route the normal UI never calls; it
    is only visible in GET /api/schema (authorized schema recon), mirroring the Wiz business-logic case
    where a JS/schema flag the UI never sent was the whole bug.
  * MULTI-SOURCE ENTITLEMENT: effective tier = most generous ACTIVE grant across {trial, promo, paid,
    migration}. Each primitive is individually harmless.
  * THE FLAW (findable black-box, no payment) is a DEPTH-4 chain with many rejections / ordering gates:
        trials  ->  vouchers  ->  grants/{trial_ref}/promo  ->  reconcile
    (enroll trial grant) (mint promo token) (promo bumps the trial grant to pro + marks it migratable)
    (reconcile 'most generous wins' mints an ENTERPRISE migration grant with NO captured payment).
    Alone each step yields at most 'pro'; only the full 4-step chain crosses to enterprise.
  * The voucher id is intentionally named 'token' to exercise the value-based (not name-based) credential
    filter in engine._harvest.

Honest expectation: the SHIPPED depth<=3 permutation composer MISSES this (the solution is length 4); the
upgraded guided forward-search composer FINDS it; the webhook path is never confirmable either way.

    PYTHONPATH=tests/verification_infrastructure/shims:tests/verification_infrastructure:. \
        python3 tests/verification_infrastructure/hardened_benchmark/run_boss.py
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import uuid
from typing import Any
from urllib.parse import parse_qs, urlparse

from app.enterprise_controls.scope import ScopeGuard, ScopePolicy
from app.testing.http_client import QAHttpClient
from app.testing.integrity.brief import ExecutionBrief
from app.testing.integrity.engine import PureBlackBoxEngine
from reference_target import _read_http_request, _TrackedServer

PFX = "/api"
# a free trial yields 'preview' (below any paid tier); 'pro' is the cheapest PAID tier (the primary
# oracle gate); 'enterprise' is the top tier. No intermediate step reaches 'pro' -- only the full chain.
_TIER_RANK = {None: 0, "preview": 1, "pro": 2, "enterprise": 3}


class AureliaTarget:
    """A decoupled billing + entitlement service. Grants are append-only; effective tier is the most
    generous ACTIVE grant. No endpoint ever discloses an internal secret; the webhook HMAC key stays here."""

    def __init__(self) -> None:
        self.by_token: dict[str, dict[str, str]] = {}
        self.orgs: dict[str, dict[str, Any]] = {}
        self.intents: dict[str, dict[str, Any]] = {}
        self.vouchers: dict[str, dict[str, Any]] = {}
        self.overrides: dict[str, dict[str, Any]] = {}
        self._sig_key = uuid.uuid4().hex.encode()   # provider's private webhook key -- never leaves the process
        self.request_log: list[tuple[str, str]] = []
        self.request_headers_seen: list[dict[str, str]] = []
        self.internal_hits = 0

    # --- entitlement resolution (most-generous-wins across active grants) ---
    def _effective(self, org: dict[str, Any]) -> str | None:
        best = None
        for g in org["grants"]:
            if g["state"] == "active" and _TIER_RANK[g["tier"]] > _TIER_RANK[best]:
                best = g["tier"]
        return best

    async def handle(self, method, raw_path, body, headers):
        p = urlparse(raw_path).path
        q = {k: v[0] for k, v in parse_qs(urlparse(raw_path).query).items()}
        body = body or {}
        self.request_log.append((method, p))
        self.request_headers_seen.append(dict(headers))

        # --- unauthenticated surface ---
        if method == "POST" and p == f"{PFX}/signup":
            oid, tok = f"o_{uuid.uuid4().hex[:8]}", f"tok_{uuid.uuid4().hex[:16]}"
            self.orgs[oid] = {"grants": []}
            self.by_token[tok] = {"org": oid}
            return 201, {"token": tok, "tenant_id": oid}, {}
        if method == "GET" and p == f"{PFX}/catalog":
            return 200, {"plans": [
                {"code": "pro", "price_id": "pr_pro", "amount": 99.0},
                {"code": "enterprise", "price_id": "pr_ent", "amount": 999.0}]}, {}
        if method == "GET" and p == f"{PFX}/schema":
            # authorized schema recon: the v2beta migration route the UI never calls is only visible here
            return 200, {"api_versions": ["v1", "v2beta"], "routes": [
                f"{PFX}/trials", f"{PFX}/vouchers", f"{PFX}/grants/{{grant_ref}}/promo",
                f"{PFX}/reconcile", f"{PFX}/webhooks/billing"]}, {}

        # --- provider webhook: signed settlement. The ONLY intended path to a paid enterprise grant. ---
        if method == "POST" and p == f"{PFX}/webhooks/billing":
            sig = headers.get("x-aurelia-signature", "")
            raw = json.dumps(body, sort_keys=True).encode()
            good = hmac.new(self._sig_key, raw, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(sig, good):
                return 401, {"error": "bad_signature"}, {}   # black-box cannot forge -> dead-end
            intent = self.intents.get(body.get("payment_id", ""))
            if intent and intent["captured"]:
                self.orgs[intent["org"]]["grants"].append(
                    {"source": "paid", "tier": intent["plan"], "state": "active", "migratable": False})
            return 200, {"status": "processed"}, {}

        # --- everything below requires the identity's bearer ---
        auth = headers.get("authorization", "")
        ident = self.by_token.get(auth[7:]) if auth.lower().startswith("bearer ") else None
        if ident is None:
            return 401, {"error": "unauthenticated"}, {}
        oid = ident["org"]
        org = self.orgs[oid]

        # --- payment intents (decoupled: capture != entitlement) ---
        if method == "POST" and p == f"{PFX}/checkout":
            if body.get("plan") not in ("pro", "enterprise"):
                return 400, {"error": "unknown_plan"}, {}
            pid = f"pi_{uuid.uuid4().hex[:8]}"
            self.intents[pid] = {"org": oid, "plan": body["plan"], "captured": False}
            return 201, {"payment_id": pid, "status": "requires_confirmation"}, {}
        if method == "POST" and p.startswith(f"{PFX}/checkout/") and p.endswith("/confirm"):
            intent = self.intents.get(p.split("/")[-2])
            if intent is None or intent["org"] != oid:
                return 404, {"error": "unknown_payment"}, {}
            if body.get("outcome") == "success":
                intent["captured"] = True
                # test-mode: a captured sandbox payment provisions the matching paid grant synchronously
                # (in production the same grant also arrives via the signed webhook below). This is the
                # LEGITIMATE path -- a paid control identity reaches its tier by actually paying for it.
                if not any(g["source"] == "paid" and g["tier"] == intent["plan"] and g["state"] == "active" for g in org["grants"]):
                    org["grants"].append({"source": "paid", "tier": intent["plan"], "state": "active", "migratable": False})
                return 200, {"status": "captured"}, {}
            return 402, {"error": "declined"}, {}
        if method == "GET" and p == f"{PFX}/checkout/return":
            intent = self.intents.get(q.get("payment_id", ""))
            if intent is None or intent["org"] != oid:
                return 404, {"error": "unknown_payment"}, {}
            return 200, {"status": "captured" if intent["captured"] else "pending"}, {}

        # --- aux primitives (each individually harmless) ---
        if method == "POST" and p == f"{PFX}/trials":
            gref = f"g_{uuid.uuid4().hex[:8]}"
            org["grants"].append({"ref": gref, "source": "trial", "tier": "preview", "state": "active", "migratable": False})
            return 201, {"trial_ref": gref, "tier": "preview"}, {}
        if method == "POST" and p == f"{PFX}/vouchers":
            vtok = f"vc_{uuid.uuid4().hex[:12]}"
            self.vouchers[vtok] = {"org": oid, "used": False}
            return 201, {"token": vtok, "kind": "promo"}, {}      # id named 'token' on purpose
        if method == "POST" and p.startswith(f"{PFX}/grants/") and p.endswith("/promo"):
            gref = p.split("/")[-2]
            grant = next((g for g in org["grants"] if g.get("ref") == gref), None)
            if grant is None:
                return 404, {"error": "unknown_grant"}, {}
            vtok = body.get("voucher")
            if vtok is None:
                return 422, {"error": "missing_field", "field": "voucher"}, {}
            v = self.vouchers.get(vtok)
            if v is None or v["org"] != oid:
                return 403, {"error": "voucher_not_yours"}, {}
            if v["used"]:
                return 409, {"error": "voucher_spent"}, {}
            v["used"] = True
            # harmless on its own: the promo does NOT raise the tier (stays 'preview', below any paid
            # gate). It only attaches a loyalty override and marks the grant 'migratable' -- the latent
            # hazard that the reconcile step will over-honor.
            grant["migratable"] = True
            oref = f"ov_{uuid.uuid4().hex[:8]}"
            self.overrides[oref] = {"org": oid, "grant": gref}
            return 201, {"override_ref": oref, "tier": "preview"}, {}
        if method == "POST" and p == f"{PFX}/reconcile":
            basis = body.get("basis")
            if basis is None:
                return 422, {"error": "missing_field", "field": "basis"}, {}
            ov = self.overrides.get(basis)
            if ov is None or ov["org"] != oid:
                return 409, {"error": "no_basis"}, {}
            grant = next((g for g in org["grants"] if g.get("ref") == ov["grant"]), None)
            if grant is None or not grant.get("migratable"):
                return 409, {"error": "not_migratable"}, {}
            # BUG: 'most generous wins' migration mints an ENTERPRISE grant from a promo-boosted trial,
            # never re-checking that a qualifying payment was captured.
            org["grants"].append({"source": "migration", "tier": "enterprise", "state": "active", "migratable": False})
            return 200, {"status": "reconciled", "tier": "enterprise"}, {}

        # --- paid features (gated on effective tier) ---
        if method == "GET" and p == f"{PFX}/insights/enterprise":
            return (200, {"dossier_id": "d_x"}, {}) if self._effective(org) == "enterprise" else (402, {"error": "upgrade_required"}, {})
        if method == "GET" and p == f"{PFX}/insights/pro":
            return (200, {"report_id": "r_x"}, {}) if _TIER_RANK[self._effective(org)] >= _TIER_RANK["pro"] else (402, {"error": "upgrade_required"}, {})
        if method == "POST" and p == f"{PFX}/refund":
            for g in org["grants"]:
                g["state"] = "revoked"
            return 200, {"status": "ok"}, {}
        return 404, {"error": "not_found"}, {}


def boss_brief(base_url: str) -> dict[str, Any]:
    return {
        "authorization_ref": "BENCH-BOSS-AURELIA", "authorized_by": "qa", "environment": "benchmark",
        "target_kind": "controlled_benchmark", "attested_synthetic_data": True, "attested_sandbox_payments": True,
        "allow_signup": True, "primary_currency": "USD", "allowed_hosts": [base_url.split("//", 1)[1]],
        "surface": {
            "signup": {"method": "POST", "path": f"{PFX}/signup", "observed_via": "product_ui"},
            "catalog": {"method": "GET", "path": f"{PFX}/catalog", "observed_via": "authorized_browser_trace"},
            "schema_recon": {"method": "GET", "path": f"{PFX}/schema", "observed_via": "public_api_reference"},
            "start_checkout": {"method": "POST", "path": f"{PFX}/checkout", "observed_via": "authorized_browser_trace"},
            "sandbox_pay": {"method": "POST", "path": f"{PFX}/checkout/{{payment_id}}/confirm", "observed_via": "authorized_browser_trace"},
            "return_flow": {"method": "GET", "path": f"{PFX}/checkout/return", "observed_via": "authorized_browser_trace"},
            "enroll_trial": {"method": "POST", "path": f"{PFX}/trials", "observed_via": "authorized_browser_trace"},
            "mint_voucher": {"method": "POST", "path": f"{PFX}/vouchers", "observed_via": "authorized_browser_trace"},
            "apply_promo": {"method": "POST", "path": f"{PFX}/grants/{{trial_ref}}/promo", "observed_via": "authorized_browser_trace"},
            "reconcile": {"method": "POST", "path": f"{PFX}/reconcile", "observed_via": "public_api_reference"},
            "settle_webhook": {"method": "POST", "path": f"{PFX}/webhooks/billing", "observed_via": "public_api_reference"},
            "subscription_view": {"method": "GET", "path": f"{PFX}/insights/pro", "observed_via": "product_ui"},
            "request_refund": {"method": "POST", "path": f"{PFX}/refund", "observed_via": "product_ui"},
        },
        "plans": {"pro": {"prices": {"USD": 99.0}}, "enterprise": {"prices": {"USD": 999.0}}},
        "features": {
            "pro_insights": {"method": "GET", "path": f"{PFX}/insights/pro", "proof_field": "report_id", "requires_plan": "pro", "observed_via": "product_ui"},
            "enterprise_insights": {"method": "GET", "path": f"{PFX}/insights/enterprise", "proof_field": "dossier_id", "requires_plan": "enterprise", "observed_via": "product_ui"},
        },
        "declared_paid_features": ["pro_insights", "enterprise_insights"],
        "limits": {"max_requests": 5000, "max_requests_per_second": 50, "revocation_sla_seconds": 1.0,
                   "revocation_poll_schedule_s": [0.0, 0.1], "quota_probe_cap": 3, "timeout_seconds": 10},
    }


async def _start():
    target = AureliaTarget()
    tracked = _TrackedServer(None)  # type: ignore[arg-type]

    def _on(reader, writer):
        t = asyncio.ensure_future(_serve(target, reader, writer))
        tracked.tasks.add(t)
        t.add_done_callback(tracked.tasks.discard)

    server = await asyncio.start_server(_on, "127.0.0.1", 0)
    tracked._server = server
    return target, tracked, server.sockets[0].getsockname()[1]


async def _serve(target, reader, writer):
    try:
        method, path, body, headers = await _read_http_request(reader)
        status, obj, extra = await target.handle(method, path, body, headers)
    except Exception as exc:  # noqa: BLE001
        status, obj, extra = 400, {"error": "bad", "detail": str(exc)}, {}
    payload = json.dumps(obj).encode("utf-8")
    head = f"HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {len(payload)}\r\nConnection: close\r\n\r\n"
    try:
        writer.write(head.encode("utf-8") + payload)
        await writer.drain()
    finally:
        writer.close()


async def probe_boss_truth() -> bool:
    """Drive the intended 4-step solution in-process to confirm a real no-payment enterprise bypass exists."""
    t = AureliaTarget()

    async def c(method, path, token=None, body=None):
        h = {"authorization": f"Bearer {token}"} if token else {}
        s, r, _ = await t.handle(method, path, body or {}, h)
        return s, r

    _s, who = await c("POST", f"{PFX}/signup"); tok = who["token"]
    _s, tr = await c("POST", f"{PFX}/trials", tok); gref = tr["trial_ref"]
    _s, vc = await c("POST", f"{PFX}/vouchers", tok); vtok = vc["token"]
    _s, ov = await c("POST", f"{PFX}/grants/{gref}/promo", tok, {"voucher": vtok}); oref = ov["override_ref"]
    await c("POST", f"{PFX}/reconcile", tok, {"basis": oref})
    # the reconcile over-grants enterprise; the primary oracle (cheapest paid gate = pro_insights) now opens
    s_e, r_e = await c("GET", f"{PFX}/insights/enterprise", tok)
    s_p, r_p = await c("GET", f"{PFX}/insights/pro", tok)
    assert s_e == 200 and "dossier_id" in r_e, "chain should over-grant enterprise"
    return s_p == 200 and "report_id" in r_p


async def run_engine(**kw) -> tuple[bool, Any]:
    target, server, port = await _start()
    base = f"http://127.0.0.1:{port}"
    http = None
    try:
        brief = ExecutionBrief.from_dict(boss_brief(base), env={})
        guard = ScopeGuard(ScopePolicy.for_environment(base, max_requests=brief.limits.max_requests, max_requests_per_second=brief.limits.max_requests_per_second))
        http = QAHttpClient(base, brief.limits.timeout_seconds, None, {}, "qa-pure-black-box-engine/1.0", max_retries=0, guard=guard, stateless=True)
        engine = PureBlackBoxEngine(http, brief, base_url=base, enable_channel_probe=True, enable_chain_probe=True, **kw)
        result = await engine.run(None)
        p0 = [f for f in result.findings if f.verdict.value == "CONFIRMED_P0"]
        return bool(p0), result
    finally:
        if http is not None and hasattr(http, "aclose"):
            await http.aclose()
        await server.aclose()
