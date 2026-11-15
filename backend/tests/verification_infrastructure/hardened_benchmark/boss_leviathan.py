#!/usr/bin/env python3
"""BOSS target 'Leviathan' (depth-11) -- the deepest, most-defended target in the suite. It layers EVERY
control from the researched PSPs and can only be bypassed by a record-length chain that exercises recon,
reverse engineering, asymmetric + content-digest + freshness signing, two infra-control bypasses, AND a
REPLAY-AWARE forged webhook. Each piece individually is harmless.

Controls & their (real-world) weaknesses modeled here:
  * ASYMMETRIC + CONTENT-DIGEST + FRESHNESS signing on the stage step (RFC 9449/9421) -- defeated only by a
    correctly-constructed Ed25519 signature over nonce.ts.content_digest.path with a registered key.
  * FRAUD / SCA step-up: the stage requires a `risk_clearance`, obtained by CLAIMING an SCA exemption
    (`sca_exemption`) whose accepted value leaks in public config (cf. "improperly claiming an exemption",
    pci-proxy) -- a real Radar/SCA bypass, not defeating the ML.
  * MFA / PASSKEY step-up: the stage requires a `device_assertion`, minted by a WEAK device-attestation path
    (`none` attestation issues trust to any device) -- a real passkey/device-trust bypass.
  * REPLAY-AWARE SIGNED WEBHOOK settlement: the final step forges a Standard-Webhooks event with a FRESH
    timestamp and a UNIQUE idempotency key bound into the signature, using a webhook secret leaked in config.

THE FINDABLE BYPASS (DEPTH-11, no payment):
    register_key -> bind_customer -> attest_device -> open_order -> clear_risk -> enroll_trial
      -> mint_voucher -> apply_promo -> open_handle -> stage_reconcile(digest+asym signed)
      -> finalize_settlement(replay-aware forged webhook)

Honest scope: AES-256-at-rest and SOC/NIST are NOT modeled as beatable -- encryption-at-rest and compliance
governance have no paywall-bypass surface through a payment API; faking a "crack" would be dishonest.

    PYTHONPATH=tests/verification_infrastructure/shims:tests/verification_infrastructure:. \
        python3 tests/verification_infrastructure/hardened_benchmark/run_leviathan.py
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

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from app.enterprise_controls.scope import ScopeGuard, ScopePolicy
from app.testing.http_client import QAHttpClient
from app.testing.integrity.brief import ExecutionBrief
from app.testing.integrity.engine import PureBlackBoxEngine
from reference_target import _read_http_request, _TrackedServer

PFX = "/api"
_TIER_RANK = {None: 0, "preview": 1, "pro": 2, "enterprise": 3}
_SKIP = ("content_digest", "request_sig")
_ACCEPTED_EXEMPTION = "trusted_beneficiary"


def _digest_of(body: dict[str, Any]) -> str:
    biz = {k: v for k, v in body.items() if k not in _SKIP}
    return base64.b64encode(hashlib.sha256(json.dumps(biz, sort_keys=True).encode()).digest()).decode()


class LeviathanTarget:
    def __init__(self) -> None:
        self.by_token: dict[str, dict[str, str]] = {}
        self.orgs: dict[str, dict[str, Any]] = {}
        self.intents: dict[str, dict[str, Any]] = {}
        self.vouchers: dict[str, dict[str, Any]] = {}
        self.overrides: dict[str, dict[str, Any]] = {}
        self.handles: dict[str, dict[str, Any]] = {}
        self.orders: dict[str, dict[str, Any]] = {}
        self.customers: dict[str, dict[str, Any]] = {}
        self.assertions: dict[str, dict[str, Any]] = {}
        self.clearances: dict[str, dict[str, Any]] = {}
        self.migrations: dict[str, dict[str, Any]] = {}
        self.pubkeys: dict[str, str] = {}
        self.nonces: dict[str, dict[str, bool]] = {}
        self.used_idem: set[str] = set()
        self._wsecret = uuid.uuid4().hex   # webhook signing secret -- LEAKED via public config (misconfig)
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
        live = self.nonces.setdefault(oid, {})
        nonce = body.get("nonce")
        if nonce is None or nonce not in live or live[nonce]:
            c = f"ch_{uuid.uuid4().hex[:12]}"
            live[c] = False
            return 422, {"error": "missing_field", "field": "nonce", "challenge": c, "note": "ed25519 sign nonce.ts.content_digest.path"}, {}
        ts = body.get("ts")
        if ts is None:
            return 422, {"error": "missing_field", "field": "ts"}, {}
        try:
            tsi = int(ts)
        except (TypeError, ValueError):
            tsi = -10 ** 12
        if abs(int(time.time()) - tsi) > 300:
            return 422, {"error": "invalid_field", "field": "ts"}, {}
        cd = body.get("content_digest")
        if cd is None:
            return 422, {"error": "missing_field", "field": "content_digest"}, {}
        if str(cd) != _digest_of(body):
            return 422, {"error": "invalid_field", "field": "content_digest"}, {}
        sig = body.get("request_sig")
        if sig is None:
            return 422, {"error": "missing_field", "field": "request_sig"}, {}
        pub_b64 = self.pubkeys.get(oid)
        if not pub_b64:
            return 422, {"error": "invalid_field", "field": "request_sig", "detail": "no_registered_key"}, {}
        try:
            Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64)).verify(base64.b64decode(str(sig)), f"{nonce}.{ts}.{cd}.{p}".encode())
        except (InvalidSignature, ValueError, Exception):  # noqa: BLE001
            return 422, {"error": "invalid_field", "field": "request_sig"}, {}
        live[nonce] = True
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
            # MISCONFIG: public config ships the webhook secret AND the accepted SCA-exemption value.
            return 200, {"service": "leviathan", "api_versions": ["v1", "v9"],
                         "signing": {"alg": "Ed25519", "input": "nonce.ts.content_digest.path"},
                         "settlement_webhook": f"{PFX}/webhooks/settle",
                         "webhook_scheme": "standard-webhooks v1 hmac-sha256 over id.timestamp.idempotency.body",
                         "endpoint_secret": self._wsecret,
                         "accepted_exemption": _ACCEPTED_EXEMPTION}, {}

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

        if method == "POST" and p == f"{PFX}/keys/register":
            pk = body.get("public_key")
            if pk is None:
                return 422, {"error": "missing_field", "field": "public_key"}, {}
            try:
                Ed25519PublicKey.from_public_bytes(base64.b64decode(str(pk)))
            except Exception:  # noqa: BLE001
                return 422, {"error": "invalid_field", "field": "public_key"}, {}
            self.pubkeys[oid] = str(pk)
            return 201, {"key_id": f"k_{uuid.uuid4().hex[:8]}"}, {}
        if method == "POST" and p == f"{PFX}/customers":
            cref = f"cus_{uuid.uuid4().hex[:8]}"; self.customers[cref] = {"org": oid}
            return 201, {"customer_ref": cref}, {}
        if method == "POST" and p == f"{PFX}/devices/attest":
            # WEAK ATTESTATION: trust ('none' attestation) issued to any device -> step-up bypass material.
            aref = f"dev_{uuid.uuid4().hex[:10]}"; self.assertions[aref] = {"org": oid}
            return 201, {"device_assertion": aref, "attestation": "none"}, {}
        if method == "POST" and p == f"{PFX}/orders":
            oref = f"ord_{uuid.uuid4().hex[:8]}"; self.orders[oref] = {"org": oid}
            return 201, {"order_ref": oref}, {}
        if method == "POST" and p == f"{PFX}/risk/clear":
            # SCA/fraud gate: a claimed exemption (value leaked in config) skips the real challenge.
            ex = body.get("sca_exemption")
            if ex is None:
                return 422, {"error": "missing_field", "field": "sca_exemption"}, {}
            if ex != _ACCEPTED_EXEMPTION:
                return 403, {"error": "exemption_rejected"}, {}
            cref = f"rc_{uuid.uuid4().hex[:8]}"; self.clearances[cref] = {"org": oid}
            return 201, {"risk_clearance": cref}, {}
        if method == "POST" and p == f"{PFX}/trials":
            gref = f"g_{uuid.uuid4().hex[:8]}"
            org["grants"].append({"ref": gref, "source": "trial", "tier": "preview", "state": "active", "migratable": False})
            return 201, {"trial_ref": gref, "tier": "preview"}, {}
        if method == "POST" and p == f"{PFX}/vouchers":
            vtok = f"vc_{uuid.uuid4().hex[:12]}"; self.vouchers[vtok] = {"org": oid, "used": False}
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
            oref = f"ov_{uuid.uuid4().hex[:8]}"; self.overrides[oref] = {"org": oid, "grant": gref}
            return 201, {"override_ref": oref, "tier": "preview"}, {}
        if method == "POST" and p == f"{PFX}/handles":
            cap = f"h_{uuid.uuid4().hex[:10]}"; self.handles[cap] = {"org": oid, "used": False}
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
            da = body.get("device_assertion")
            if da is None or (self.assertions.get(da) or {}).get("org") != oid:
                return 422, {"error": "invalid_field" if da is not None else "missing_field", "field": "device_assertion"}, {}
            rc = body.get("risk_clearance")
            if rc is None or (self.clearances.get(rc) or {}).get("org") != oid:
                return 422, {"error": "invalid_field" if rc is not None else "missing_field", "field": "risk_clearance"}, {}
            gate = self._sig_gate(oid, p, body)   # digest-bound Ed25519 freshness signature
            if gate is not None:
                return gate
            grant = next((g for g in org["grants"] if g.get("ref") == ov["grant"]), None)
            if grant is None or not grant.get("migratable"):
                return 409, {"error": "not_migratable"}, {}
            h["used"] = True
            mref = f"mig_{uuid.uuid4().hex[:8]}"; self.migrations[mref] = {"org": oid}
            return 201, {"migration_ref": mref}, {}
        if method == "POST" and p == f"{PFX}/webhooks/settle":
            # REPLAY-AWARE signed webhook: idempotency-key + fresh timestamp + HMAC over id.ts.idem.body.
            idem = headers.get("idempotency-key", "")
            if not idem:
                return 400, {"error": "idempotency_key_required", "field": "idempotency-key"}, {}
            if idem in self.used_idem:
                return 409, {"error": "duplicate_idempotency"}, {}
            wid = headers.get("webhook-id", ""); wts = headers.get("webhook-timestamp", ""); sig = headers.get("webhook-signature", "")
            try:
                fresh = abs(int(time.time()) - int(wts)) <= 300
            except (TypeError, ValueError):
                fresh = False
            if not fresh:
                return 401, {"error": "stale_signature"}, {}
            good = "v1," + base64.b64encode(hmac.new(self._wsecret.encode(), f"{wid}.{wts}.{idem}.{json.dumps(body, sort_keys=True)}".encode(), hashlib.sha256).digest()).decode()
            if not (sig and hmac.compare_digest(sig, good)):
                return 401, {"error": "bad_signature"}, {}
            mref = body.get("migration_ref")
            mig = self.migrations.get(mref) if mref else None
            if mig is None or mig["org"] != oid:
                return 422, {"error": "invalid_field" if mref is not None else "missing_field", "field": "migration_ref"}, {}
            cu = self.customers.get(body.get("customer_ref", "")) if body.get("customer_ref") else None
            if cu is None or cu["org"] != oid:
                return 422, {"error": "invalid_field" if body.get("customer_ref") is not None else "missing_field", "field": "customer_ref"}, {}
            od = self.orders.get(body.get("order_ref", "")) if body.get("order_ref") else None
            if od is None or od["org"] != oid:
                return 422, {"error": "invalid_field" if body.get("order_ref") is not None else "missing_field", "field": "order_ref"}, {}
            self.used_idem.add(idem)   # single-use (replay block), consumed only on an actual settle
            # BUG: a validly-signed settlement event is trusted as proof of payment -> grants enterprise.
            org["grants"].append({"source": "webhook", "tier": "enterprise", "state": "active", "migratable": False})
            return 200, {"status": "settled", "tier": "enterprise"}, {}

        if method == "GET" and p == f"{PFX}/insights/pro":
            return (200, {"report_id": "r_x"}, {}) if _TIER_RANK[self._effective(org)] >= _TIER_RANK["pro"] else (402, {"error": "upgrade_required"}, {})
        if method == "GET" and p == f"{PFX}/insights/enterprise":
            return (200, {"dossier_id": "d_x"}, {}) if self._effective(org) == "enterprise" else (402, {"error": "upgrade_required"}, {})
        if method == "POST" and p == f"{PFX}/refund":
            for g in org["grants"]:
                g["state"] = "revoked"
            return 200, {"status": "ok"}, {}
        return 404, {"error": "not_found"}, {}


def leviathan_brief(base_url: str) -> dict[str, Any]:
    return {
        "authorization_ref": "BENCH-BOSS-LEVIATHAN", "authorized_by": "qa", "environment": "benchmark",
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
            "register_key": {"method": "POST", "path": f"{PFX}/keys/register", "observed_via": "public_api_reference"},
            "bind_customer": {"method": "POST", "path": f"{PFX}/customers", "observed_via": "authorized_browser_trace"},
            "attest_device": {"method": "POST", "path": f"{PFX}/devices/attest", "observed_via": "authorized_browser_trace"},
            "open_order": {"method": "POST", "path": f"{PFX}/orders", "observed_via": "authorized_browser_trace"},
            "clear_risk": {"method": "POST", "path": f"{PFX}/risk/clear", "observed_via": "public_api_reference"},
            "enroll_trial": {"method": "POST", "path": f"{PFX}/trials", "observed_via": "authorized_browser_trace"},
            "mint_voucher": {"method": "POST", "path": f"{PFX}/vouchers", "observed_via": "authorized_browser_trace"},
            "apply_promo": {"method": "POST", "path": f"{PFX}/grants/{{trial_ref}}/promo", "observed_via": "authorized_browser_trace"},
            "open_handle": {"method": "POST", "path": f"{PFX}/handles", "observed_via": "authorized_browser_trace"},
            "stage_reconcile": {"method": "POST", "path": f"{PFX}/reconcile/stage", "observed_via": "public_api_reference"},
            "finalize_settlement": {"method": "POST", "path": f"{PFX}/webhooks/settle", "observed_via": "public_api_reference"},
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
    target = LeviathanTarget()
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


async def probe_leviathan_truth() -> bool:
    """Drive the intended depth-11 solution in-process, forging a fresh, idempotent, signed settlement event."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    t = LeviathanTarget()
    priv = Ed25519PrivateKey.generate()
    pub_b64 = base64.b64encode(priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()

    async def c(method, path, token=None, body=None, hdr=None):
        h = {"authorization": f"Bearer {token}"} if token else {}
        if hdr:
            h.update(hdr)
        s, r, extra = await t.handle(method, path, body or {}, h)
        return s, r, extra

    _s, who, _ = await c("POST", f"{PFX}/signup"); tok = who["token"]
    _s, cfg, _ = await c("GET", f"{PFX}/config", tok)
    secret, exemption = cfg["endpoint_secret"], cfg["accepted_exemption"]
    await c("POST", f"{PFX}/keys/register", tok, {"public_key": pub_b64})
    _s, cu, _ = await c("POST", f"{PFX}/customers", tok); cust = cu["customer_ref"]
    _s, dv, _ = await c("POST", f"{PFX}/devices/attest", tok); da = dv["device_assertion"]
    _s, od, _ = await c("POST", f"{PFX}/orders", tok); order = od["order_ref"]
    _s, rk, _ = await c("POST", f"{PFX}/risk/clear", tok, {"sca_exemption": exemption}); rc = rk["risk_clearance"]
    _s, tr, _ = await c("POST", f"{PFX}/trials", tok); gref = tr["trial_ref"]
    _s, vc, _ = await c("POST", f"{PFX}/vouchers", tok); vtok = vc["token"]
    _s, ov, _ = await c("POST", f"{PFX}/grants/{gref}/promo", tok, {"voucher": vtok}); oref = ov["override_ref"]
    _s, _hb, extra = await c("POST", f"{PFX}/handles", tok); cap = extra["Location"].rsplit("/", 1)[-1]
    spath = f"{PFX}/reconcile/stage"
    _s, chal, _ = await c("POST", spath, tok, {"basis": oref, "handle": cap, "device_assertion": da, "risk_clearance": rc})
    nonce = chal["challenge"]; sts = str(int(time.time()))
    sbody = {"basis": oref, "handle": cap, "device_assertion": da, "risk_clearance": rc, "nonce": nonce, "ts": sts}
    cd = _digest_of(sbody)
    ssig = base64.b64encode(priv.sign(f"{nonce}.{sts}.{cd}.{spath}".encode())).decode()
    _s, mg, _ = await c("POST", spath, tok, {**sbody, "content_digest": cd, "request_sig": ssig})
    mref = mg["migration_ref"]
    # forge a fresh, idempotent, signed settlement event
    evt = {"event": "settle", "migration_ref": mref, "customer_ref": cust, "order_ref": order}
    wid, wts, idem = f"evt_{uuid.uuid4().hex}", str(int(time.time())), f"idk_{uuid.uuid4().hex}"
    wsig = "v1," + base64.b64encode(hmac.new(secret.encode(), f"{wid}.{wts}.{idem}.{json.dumps(evt, sort_keys=True)}".encode(), hashlib.sha256).digest()).decode()
    await c("POST", f"{PFX}/webhooks/settle", tok, evt, {"webhook-id": wid, "webhook-timestamp": wts, "webhook-signature": wsig, "idempotency-key": idem})
    s_p, r_p, _ = await c("GET", f"{PFX}/insights/pro", tok)
    return s_p == 200 and "report_id" in r_p


async def run_engine(**kw) -> tuple[bool, Any]:
    target, server, port = await _start()
    base = f"http://127.0.0.1:{port}"
    http = None
    try:
        brief = ExecutionBrief.from_dict(leviathan_brief(base), env={})
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
