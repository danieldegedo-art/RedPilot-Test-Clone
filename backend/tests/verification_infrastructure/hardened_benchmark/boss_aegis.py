#!/usr/bin/env python3
"""BOSS target 'Aegis' -- the hardest target in the suite (depth-8), modeling defenses BEYOND the usual
zero-trust stack: DPoP / HTTP-Message-Signatures-style FRESHNESS-BOUND request signing on TWO separate
steps. Each signed step issues a single-use server NONCE (challenge-response) and requires a signature over
`nonce.timestamp.path` using the caller's provisioned key, within a time window.

Defenses (researched: RFC 9449 DPoP, RFC 9421 HTTP Message Signatures, Standard-Webhooks):
  * TWO FRESHNESS-SIGNED STEPS: both `stage_reconcile` and `apply_reconcile` require {nonce, ts, request_sig}
    where request_sig = HMAC_SHA256_hex(signing_key, f"{nonce}.{ts}.{path}"). The server hands the single-use
    nonce back in its 422 `challenge` (like a DPoP-Nonce), checks ts is within +/-300s, verifies the signature,
    and consumes the nonce (replay-proof). A client that cannot sign a FRESH canonical request cannot proceed.
  * SIGNED WEBHOOK (source of truth): the intended paid path is a provider webhook HMAC-signed with a SERVER
    secret -> unforgeable black-box -> honest DEAD-END.
  * NEVER TRUST THE CLIENT: GET /status is server-verified; client claims are ignored.
  * reverse-engineered route + step-up capability (Location header) + multi-reference (order + ticket).

THE FINDABLE BYPASS (DEPTH-8, no payment, each step individually harmless):
    provision_key -> open_order -> enroll_trial -> mint_voucher -> apply_promo -> open_handle
      -> stage_reconcile(freshness-signed) -> apply_reconcile(freshness-signed)

Honest expectation: a composer that signs only STATIC canonical forms MISSES (it can't bind the server nonce +
fresh timestamp); a composer that constructs a FRESH canonical signature FINDS it; the webhook stays a dead-end.

    PYTHONPATH=tests/verification_infrastructure/shims:tests/verification_infrastructure:. \
        python3 tests/verification_infrastructure/hardened_benchmark/run_aegis.py
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


class AegisTarget:
    def __init__(self) -> None:
        self.by_token: dict[str, dict[str, str]] = {}
        self.orgs: dict[str, dict[str, Any]] = {}
        self.intents: dict[str, dict[str, Any]] = {}
        self.vouchers: dict[str, dict[str, Any]] = {}
        self.overrides: dict[str, dict[str, Any]] = {}
        self.handles: dict[str, dict[str, Any]] = {}
        self.orders: dict[str, dict[str, Any]] = {}
        self.migrations: dict[str, dict[str, Any]] = {}
        self.signing_keys: dict[str, str] = {}
        self.nonces: dict[str, dict[str, bool]] = {}   # per-org issued challenge nonces -> consumed?
        self.gateway = f"gw-{uuid.uuid4().hex[:6]}"
        self._sig_key = uuid.uuid4().hex.encode()      # provider webhook secret -- never leaves the process
        self.request_log: list[tuple[str, str]] = []
        self.request_headers_seen: list[dict[str, str]] = []
        self.internal_hits = 0

    def _effective(self, org: dict[str, Any]) -> str | None:
        best = None
        for g in org["grants"]:
            if g["state"] == "active" and _TIER_RANK[g["tier"]] > _TIER_RANK[best]:
                best = g["tier"]
        return best

    def _sig_gate(self, oid: str, p: str, body: dict[str, Any]):
        """DPoP/HTTP-sig-style freshness gate. Returns None if OK (and consumes the nonce), else an error tuple."""
        live = self.nonces.setdefault(oid, {})
        nonce = body.get("nonce")
        if nonce is None or nonce not in live or live[nonce]:
            c = f"ch_{uuid.uuid4().hex[:12]}"
            live[c] = False
            return 422, {"error": "missing_field", "field": "nonce", "challenge": c, "note": "sign nonce.ts.path"}, {}
        ts = body.get("ts")
        if ts is None:
            return 422, {"error": "missing_field", "field": "ts"}, {}
        try:
            tsi = int(ts)
        except (TypeError, ValueError):
            tsi = -10 ** 12
        if abs(int(time.time()) - tsi) > 300:
            return 422, {"error": "invalid_field", "field": "ts"}, {}
        sig = body.get("request_sig")
        if sig is None:
            return 422, {"error": "missing_field", "field": "request_sig"}, {}
        sk = self.signing_keys.get(oid)
        expected = hmac.new((sk or "").encode(), f"{nonce}.{ts}.{p}".encode(), hashlib.sha256).hexdigest() if sk else None
        if not sk or not hmac.compare_digest(str(sig), expected):
            return 422, {"error": "invalid_field", "field": "request_sig"}, {}
        live[nonce] = True   # single-use: consume
        return None

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
            return 200, {"service": "aegis", "api_versions": ["v1", "v6"],
                         "signing": {"alg": "HMAC_SHA256_HEX", "input": "nonce.ts.path", "field": "request_sig"},
                         "endpoints": {"settlement": {"gateway": self.gateway, "verb": "commit"}}}, {}

        if method == "POST" and p == f"{PFX}/webhooks/billing":
            wid = headers.get("webhook-id", ""); ts = headers.get("webhook-timestamp", ""); sig = headers.get("webhook-signature", "")
            signed = f"{wid}.{ts}.{json.dumps(body, sort_keys=True)}".encode()
            good = "v1," + base64.b64encode(hmac.new(self._sig_key, signed, hashlib.sha256).digest()).decode()
            if not (sig and hmac.compare_digest(sig, good)):
                return 401, {"error": "bad_signature"}, {}
            intent = self.intents.get(body.get("payment_id", ""))
            if intent and intent["captured"]:
                self.orgs[intent["org"]]["grants"].append({"source": "paid", "tier": intent["plan"], "state": "active", "migratable": False})
            return 200, {"status": "processed"}, {}

        auth = headers.get("authorization", "")
        ident = self.by_token.get(auth[7:]) if auth.lower().startswith("bearer ") else None
        if ident is None:
            return 401, {"error": "unauthenticated"}, {}
        oid = ident["org"]
        org = self.orgs[oid]

        if method == "GET" and p == f"{PFX}/status":
            return 200, {"tier": self._effective(org), "note": "server-verified; client claims ignored"}, {}

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

        if method == "POST" and p == f"{PFX}/keys":
            sk = f"sk_{uuid.uuid4().hex}"
            self.signing_keys[oid] = sk
            return 201, {"signing_key": sk, "alg": "HMAC_SHA256_HEX"}, {}
        if method == "POST" and p == f"{PFX}/orders":
            oref = f"ord_{uuid.uuid4().hex[:8]}"
            self.orders[oref] = {"org": oid}
            return 201, {"order_ref": oref}, {}
        if method == "POST" and p == f"{PFX}/trials":
            gref = f"g_{uuid.uuid4().hex[:8]}"
            org["grants"].append({"ref": gref, "source": "trial", "tier": "preview", "state": "active", "migratable": False})
            return 201, {"trial_ref": gref, "tier": "preview"}, {}
        if method == "POST" and p == f"{PFX}/vouchers":
            vtok = f"vc_{uuid.uuid4().hex[:12]}"
            self.vouchers[vtok] = {"org": oid, "used": False}
            return 201, {"token": vtok, "kind": "promo"}, {}
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
            grant["migratable"] = True
            oref = f"ov_{uuid.uuid4().hex[:8]}"
            self.overrides[oref] = {"org": oid, "grant": gref}
            return 201, {"override_ref": oref, "tier": "preview"}, {}
        if method == "POST" and p == f"{PFX}/handles":
            cap = f"h_{uuid.uuid4().hex[:10]}"
            self.handles[cap] = {"org": oid, "used": False}
            return 201, {"status": "issued"}, {"Location": f"{PFX}/handles/{cap}"}
        if method == "POST" and p == f"{PFX}/reconcile/stage":
            basis = body.get("basis")
            ov = self.overrides.get(basis) if basis else None
            if ov is None or ov["org"] != oid:
                return 422, {"error": "invalid_field" if basis is not None else "missing_field", "field": "basis"}, {}
            handle = body.get("handle")
            h = self.handles.get(handle) if handle else None
            if h is None or h["org"] != oid or h["used"]:
                return 422, {"error": "invalid_field" if handle is not None else "missing_field", "field": "handle"}, {}
            gate = self._sig_gate(oid, p, body)   # FRESHNESS-SIGNED step #1
            if gate is not None:
                return gate
            grant = next((g for g in org["grants"] if g.get("ref") == ov["grant"]), None)
            if grant is None or not grant.get("migratable"):
                return 409, {"error": "not_migratable"}, {}
            h["used"] = True
            mref = f"mig_{uuid.uuid4().hex[:8]}"
            self.migrations[mref] = {"org": oid}
            return 201, {"migration_ref": mref}, {}
        if method == "POST" and p == f"{PFX}/{self.gateway}/commit":
            ticket = body.get("ticket")
            mig = self.migrations.get(ticket) if ticket else None
            if mig is None or mig["org"] != oid:
                return 422, {"error": "invalid_field" if ticket is not None else "missing_field", "field": "ticket"}, {}
            order = body.get("order")
            od = self.orders.get(order) if order else None
            if od is None or od["org"] != oid:
                return 422, {"error": "invalid_field" if order is not None else "missing_field", "field": "order"}, {}
            gate = self._sig_gate(oid, p, body)   # FRESHNESS-SIGNED step #2
            if gate is not None:
                return gate
            # BUG: once staged + signed, commit trusts the ticket instead of re-checking a captured payment.
            org["grants"].append({"source": "migration", "tier": "enterprise", "state": "active", "migratable": False})
            return 200, {"status": "committed", "tier": "enterprise"}, {}

        if method == "GET" and p == f"{PFX}/insights/pro":
            return (200, {"report_id": "r_x"}, {}) if _TIER_RANK[self._effective(org)] >= _TIER_RANK["pro"] else (402, {"error": "upgrade_required"}, {})
        if method == "GET" and p == f"{PFX}/insights/enterprise":
            return (200, {"dossier_id": "d_x"}, {}) if self._effective(org) == "enterprise" else (402, {"error": "upgrade_required"}, {})
        if method == "POST" and p == f"{PFX}/refund":
            for g in org["grants"]:
                g["state"] = "revoked"
            return 200, {"status": "ok"}, {}
        return 404, {"error": "not_found"}, {}


def aegis_brief(base_url: str) -> dict[str, Any]:
    return {
        "authorization_ref": "BENCH-BOSS-AEGIS", "authorized_by": "qa", "environment": "benchmark",
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
            "provision_key": {"method": "POST", "path": f"{PFX}/keys", "observed_via": "public_api_reference"},
            "open_order": {"method": "POST", "path": f"{PFX}/orders", "observed_via": "authorized_browser_trace"},
            "enroll_trial": {"method": "POST", "path": f"{PFX}/trials", "observed_via": "authorized_browser_trace"},
            "mint_voucher": {"method": "POST", "path": f"{PFX}/vouchers", "observed_via": "authorized_browser_trace"},
            "apply_promo": {"method": "POST", "path": f"{PFX}/grants/{{trial_ref}}/promo", "observed_via": "authorized_browser_trace"},
            "open_handle": {"method": "POST", "path": f"{PFX}/handles", "observed_via": "authorized_browser_trace"},
            "stage_reconcile": {"method": "POST", "path": f"{PFX}/reconcile/stage", "observed_via": "public_api_reference"},
            "apply_reconcile": {"method": "POST", "path": f"{PFX}/{{gateway}}/commit", "observed_via": "public_api_reference"},
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
    target = AegisTarget()
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
    lines = [f"HTTP/1.1 {status} X", "Content-Type: application/json", f"Content-Length: {len(payload)}"]
    for hk, hv in (extra or {}).items():
        lines.append(f"{hk}: {hv}")
    lines.append("Connection: close")
    head = "\r\n".join(lines) + "\r\n\r\n"
    try:
        writer.write(head.encode("utf-8") + payload)
        await writer.drain()
    finally:
        writer.close()


async def probe_aegis_truth() -> bool:
    """Drive the intended depth-8 solution in-process, FRESHNESS-signing both the stage and commit steps."""
    t = AegisTarget()

    async def c(method, path, token=None, body=None):
        h = {"authorization": f"Bearer {token}"} if token else {}
        s, r, extra = await t.handle(method, path, body or {}, h)
        return s, r, extra

    async def signed_call(path, token, sk, fields):
        _s, chal, _ = await c("POST", path, token, dict(fields))        # 1st call -> server hands back a nonce
        nonce = chal["challenge"]
        ts = str(int(time.time()))
        sig = hmac.new(sk.encode(), f"{nonce}.{ts}.{path}".encode(), hashlib.sha256).hexdigest()
        return await c("POST", path, token, {**fields, "nonce": nonce, "ts": ts, "request_sig": sig})

    _s, who, _ = await c("POST", f"{PFX}/signup"); tok = who["token"]
    _s, cfg, _ = await c("GET", f"{PFX}/config"); gw = cfg["endpoints"]["settlement"]["gateway"]
    _s, ky, _ = await c("POST", f"{PFX}/keys", tok); sk = ky["signing_key"]
    _s, od, _ = await c("POST", f"{PFX}/orders", tok); order = od["order_ref"]
    _s, tr, _ = await c("POST", f"{PFX}/trials", tok); gref = tr["trial_ref"]
    _s, vc, _ = await c("POST", f"{PFX}/vouchers", tok); vtok = vc["token"]
    _s, ov, _ = await c("POST", f"{PFX}/grants/{gref}/promo", tok, {"voucher": vtok}); oref = ov["override_ref"]
    _s, _hb, extra = await c("POST", f"{PFX}/handles", tok); cap = extra["Location"].rsplit("/", 1)[-1]
    _s, mg, _ = await signed_call(f"{PFX}/reconcile/stage", tok, sk, {"basis": oref, "handle": cap})
    mref = mg["migration_ref"]
    await signed_call(f"{PFX}/{gw}/commit", tok, sk, {"ticket": mref, "order": order})
    s_e, r_e, _ = await c("GET", f"{PFX}/insights/enterprise", tok)
    s_p, r_p, _ = await c("GET", f"{PFX}/insights/pro", tok)
    assert s_e == 200 and "dossier_id" in r_e, "chain should over-grant enterprise"
    return s_p == 200 and "report_id" in r_p


async def run_engine(**kw) -> tuple[bool, Any]:
    target, server, port = await _start()
    base = f"http://127.0.0.1:{port}"
    http = None
    try:
        brief = ExecutionBrief.from_dict(aegis_brief(base), env={})
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
