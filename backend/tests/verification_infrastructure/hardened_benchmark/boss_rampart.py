#!/usr/bin/env python3
"""Target 'Rampart' -- a signed-webhook paywall with a REAL, real-world vulnerability, built to answer the
honest question: can the engine take down a cryptographically-signed webhook? The answer is yes -- but ONLY
because the webhook is MISCONFIGURED, exactly how signed webhooks actually fall in the wild (never by breaking
HMAC):

  * LEAKED SIGNING SECRET (misconfig): a debug/config endpoint discoverable by recon exposes the webhook
    signing secret (cf. real CVEs where the secret leaks via responses, config, or JS bundles).
  * SIGNATURE-ALONE GRANTS (business-logic flaw): a validly-signed `paid` event provisions the enterprise
    tier with NO captured payment (the webhook is trusted as sole source of truth).

So the engine beats it by: recon -> harvest the leaked secret -> construct a valid Standard-Webhooks
signature -> forge a `paid` event. It never breaks the crypto; it exploits the misconfiguration.

HONEST CONTROL: the OTHER bosses (Aurelia..Obelisk) all keep their webhook secret PRIVATE (never leaked) and
their webhooks stay unbeaten -- proving the engine only succeeds when the secret is genuinely obtainable. The
`whsig` gauntlet family's `unsolvable` variant (secret not leaked) is the same boundary: 0.

    PYTHONPATH=tests/verification_infrastructure/shims:tests/verification_infrastructure:. \
        python3 tests/verification_infrastructure/hardened_benchmark/run_rampart.py
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import time
import uuid
from typing import Any
from urllib.parse import parse_qs, urlparse

from app.enterprise_controls.scope import ScopeGuard, ScopePolicy
from app.testing.http_client import QAHttpClient
from app.testing.integrity.brief import ExecutionBrief
from app.testing.integrity.engine import PureBlackBoxEngine
from reference_target import _read_http_request, _TrackedServer

PFX = "/api"
_TIER_RANK = {None: 0, "preview": 1, "pro": 2, "enterprise": 3}


class RampartTarget:
    def __init__(self, leak_secret: bool = True) -> None:
        self.by_token: dict[str, dict[str, str]] = {}
        self.orgs: dict[str, dict[str, Any]] = {}
        self.intents: dict[str, dict[str, Any]] = {}
        self.leak_secret = leak_secret
        self._wsecret = uuid.uuid4().hex   # webhook signing secret (leaked via /config/debug iff leak_secret)
        self.request_log: list[tuple[str, str]] = []
        self.request_headers_seen: list[dict[str, str]] = []
        self.internal_hits = 0

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

        if method == "POST" and p == f"{PFX}/signup":
            oid, tok = f"o_{uuid.uuid4().hex[:8]}", f"tok_{uuid.uuid4().hex[:16]}"
            self.orgs[oid] = {"grants": []}
            self.by_token[tok] = {"org": oid}
            return 201, {"token": tok, "tenant_id": oid}, {}
        if method == "GET" and p == f"{PFX}/catalog":
            return 200, {"plans": [{"code": "pro", "price_id": "pr_pro", "amount": 99.0},
                                   {"code": "enterprise", "price_id": "pr_ent", "amount": 999.0}]}, {}
        if method == "GET" and p == f"{PFX}/config":
            # MISCONFIG: a public config/manifest that accidentally ships the webhook signing secret.
            cfg = {"service": "rampart", "build": "preview", "settlement_webhook": f"{PFX}/webhooks/billing",
                   "signature_scheme": "standard-webhooks v1 hmac-sha256 over id.timestamp.body"}
            if self.leak_secret:
                cfg["endpoint_secret"] = self._wsecret
            return 200, cfg, {}

        auth = headers.get("authorization", "")
        ident = self.by_token.get(auth[7:]) if auth.lower().startswith("bearer ") else None
        if ident is None:
            return 401, {"error": "unauthenticated"}, {}
        oid = ident["org"]
        org = self.orgs[oid]

        if method == "GET" and p == f"{PFX}/status":
            return 200, {"tier": self._effective(org), "note": "server-verified"}, {}
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
                if not any(g["source"] == "paid" and g["tier"] == intent["plan"] and g["state"] == "active" for g in org["grants"]):
                    org["grants"].append({"source": "paid", "tier": intent["plan"], "state": "active", "migratable": False})
                return 200, {"status": "captured"}, {}
            return 402, {"error": "declined"}, {}
        if method == "GET" and p == f"{PFX}/checkout/return":
            intent = self.intents.get(q.get("payment_id", ""))
            if intent is None or intent["org"] != oid:
                return 404, {"error": "unknown_payment"}, {}
            return 200, {"status": "captured" if intent["captured"] else "pending"}, {}

        if method == "POST" and p == f"{PFX}/webhooks/billing":
            wid = headers.get("webhook-id", "")
            ts = headers.get("webhook-timestamp", "")
            sig = headers.get("webhook-signature", "")
            signed = f"{wid}.{ts}.{json.dumps(body, sort_keys=True)}".encode()
            good = "v1," + base64.b64encode(hmac.new(self._wsecret.encode(), signed, hashlib.sha256).digest()).decode()
            if not (sig and hmac.compare_digest(sig, good)):
                return 401, {"error": "bad_signature"}, {}
            # BUG: a validly-signed event is trusted as sole proof of payment -> grants enterprise, no capture.
            org["grants"].append({"source": "webhook", "tier": "enterprise", "state": "active", "migratable": False})
            return 200, {"status": "processed", "tier": "enterprise"}, {}

        if method == "GET" and p == f"{PFX}/insights/pro":
            return (200, {"report_id": "r_x"}, {}) if _TIER_RANK[self._effective(org)] >= _TIER_RANK["pro"] else (402, {"error": "upgrade_required"}, {})
        if method == "GET" and p == f"{PFX}/insights/enterprise":
            return (200, {"dossier_id": "d_x"}, {}) if self._effective(org) == "enterprise" else (402, {"error": "upgrade_required"}, {})
        if method == "POST" and p == f"{PFX}/refund":
            for g in org["grants"]:
                g["state"] = "revoked"
            return 200, {"status": "ok"}, {}
        return 404, {"error": "not_found"}, {}


def rampart_brief(base_url: str) -> dict[str, Any]:
    return {
        "authorization_ref": "BENCH-BOSS-RAMPART", "authorized_by": "qa", "environment": "benchmark",
        "target_kind": "controlled_benchmark", "attested_synthetic_data": True, "attested_sandbox_payments": True,
        "allow_signup": True, "primary_currency": "USD", "allowed_hosts": [base_url.split("//", 1)[1]],
        "surface": {
            "signup": {"method": "POST", "path": f"{PFX}/signup", "observed_via": "product_ui"},
            "catalog": {"method": "GET", "path": f"{PFX}/catalog", "observed_via": "authorized_browser_trace"},
            "config_recon": {"method": "GET", "path": f"{PFX}/config", "observed_via": "public_api_reference"},
            "status_view": {"method": "GET", "path": f"{PFX}/status", "observed_via": "product_ui"},
            "start_checkout": {"method": "POST", "path": f"{PFX}/checkout", "observed_via": "authorized_browser_trace"},
            "sandbox_pay": {"method": "POST", "path": f"{PFX}/checkout/{{payment_id}}/confirm", "observed_via": "authorized_browser_trace"},
            "return_flow": {"method": "GET", "path": f"{PFX}/checkout/return", "observed_via": "authorized_browser_trace"},
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


async def _start(leak_secret: bool = True):
    target = RampartTarget(leak_secret=leak_secret)
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


async def probe_rampart_truth(leak_secret: bool = True) -> bool:
    """Drive the intended bypass in-process: read the leaked secret, forge a valid signed `paid` event."""
    t = RampartTarget(leak_secret=leak_secret)

    async def c(method, path, token=None, body=None, hdr=None):
        h = {"authorization": f"Bearer {token}"} if token else {}
        if hdr:
            h.update(hdr)
        s, r, extra = await t.handle(method, path, body or {}, h)
        return s, r

    _s, who = await c("POST", f"{PFX}/signup"); tok = who["token"]
    _s, cfg = await c("GET", f"{PFX}/config", tok)
    secret = cfg.get("endpoint_secret") or t._wsecret   # a real insider/prober has it; black-box only if leaked
    evt = {"event": "paid", "plan": "enterprise"}
    wid, ts = f"evt_{uuid.uuid4().hex}", str(int(time.time()))
    sig = "v1," + base64.b64encode(hmac.new(secret.encode(), f"{wid}.{ts}.{json.dumps(evt, sort_keys=True)}".encode(), hashlib.sha256).digest()).decode()
    await c("POST", f"{PFX}/webhooks/billing", tok, evt, {"webhook-id": wid, "webhook-timestamp": ts, "webhook-signature": sig})
    s_p, r_p = await c("GET", f"{PFX}/insights/pro", tok)
    return s_p == 200 and "report_id" in r_p


async def run_engine(leak_secret: bool = True, **kw) -> tuple[bool, Any]:
    target, server, port = await _start(leak_secret=leak_secret)
    base = f"http://127.0.0.1:{port}"
    http = None
    try:
        brief = ExecutionBrief.from_dict(rampart_brief(base), env={})
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
