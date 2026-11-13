#!/usr/bin/env python3
"""BOSS target 'Sentinel' (depth-12, NEEDLE) -- the hardest target in the suite and a different KIND of
hard from Leviathan. Leviathan stacked many weak controls; Sentinel implements a LONG, correct ceremony in
which EVERY control is sound EXCEPT ONE deeply-buried flaw. It tests whether the engine finds the single
real hole at the end of a 12-step chain WITHOUT false-alarming on the hardened rest.

THE ONE FLAW (algorithm-confusion / scheme-downgrade):
  The settlement authority publishes its Ed25519 PUBLIC key in /config (public keys are public -- normal).
  The CORRECT settlement scheme verifies an Ed25519 signature over `nonce.ts.path` with that authority key,
  which an external caller cannot forge (it never holds the authority PRIVATE key) -> dead-end.
  A LEGACY compat scheme was left enabled (the misconfig): the server ALSO accepts an HMAC-SHA256 signature
  that uses the RAW BYTES of its own published Ed25519 public key as the HMAC secret. This is the classic
  RS->HS / scheme-downgrade confusion that Stripe's webhook docs explicitly warn against: "To prevent
  downgrade attacks, ignore all schemes that aren't v1." (docs.stripe.com/webhooks). Because the public key
  is public, forging the HMAC needs no stolen secret -- it only beats a server that wrongly verifies with
  its own published public key. That is a REAL, black-box-reachable vulnerability, not broken crypto.

EVERYTHING ELSE IS CORRECT (the FP-resistance test -- the engine must probe these and NOT confirm):
  * stage_reconcile: a correct Ed25519 digest+freshness gate (RFC 9421/9449) the engine satisfies LEGITIMATELY
    with ITS OWN registered key -- not a flaw, just the real signing ceremony.
  * the settlement's CORRECT ed25519 scheme -- unforgeable from outside.
  * /webhooks/notify: a correct Standard-Webhooks receiver whose signing secret is NEVER published -> the
    engine's forge-a-webhook path finds no secret and cannot beat it (unlike Leviathan, nothing leaks here),
    and it grants nothing regardless.

THE FINDABLE BYPASS (depth-12, no payment):
    register_key -> bind_customer -> attest_device -> open_order -> enroll_pm -> enroll_trial
      -> mint_voucher -> apply_promo -> open_handle -> request_authorization
      -> stage_reconcile(correct Ed25519 digest+freshness, OWN key) -> finalize_settlement(ALG-CONFUSION)

CONTROL (needle removed): with legacy_enabled=False the settlement accepts ONLY the correct ed25519 scheme,
so the bypass disappears and the engine must find NOTHING (0) -- the proof that this is the single flaw and
the engine does not false-confirm on the hardened target.

Honest scope: AES-256-at-rest, SOC/NIST governance, and the correct webhook/ed25519 paths are NOT modeled as
beatable. The ONE modeled flaw is a genuine protocol misconfiguration reachable black-box. (See the honest
key-management family for the AES-at-rest-via-detokenization angle.)

    PYTHONPATH=tests/verification_infrastructure/shims:tests/verification_infrastructure:. \
        python3 tests/verification_infrastructure/hardened_benchmark/run_sentinel.py
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
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from app.enterprise_controls.scope import ScopeGuard, ScopePolicy
from app.testing.http_client import QAHttpClient
from app.testing.integrity.brief import ExecutionBrief
from app.testing.integrity.engine import PureBlackBoxEngine
from reference_target import _read_http_request, _TrackedServer

PFX = "/api"
_TIER_RANK = {None: 0, "preview": 1, "pro": 2, "enterprise": 3}
_SKIP = ("content_digest", "request_sig")


def _digest_of(body: dict[str, Any]) -> str:
    biz = {k: v for k, v in body.items() if k not in _SKIP}
    return base64.b64encode(hashlib.sha256(json.dumps(biz, sort_keys=True).encode()).digest()).decode()


class SentinelTarget:
    def __init__(self, legacy_enabled: bool = True) -> None:
        self.legacy_enabled = legacy_enabled
        self.by_token: dict[str, dict[str, str]] = {}
        self.orgs: dict[str, dict[str, Any]] = {}
        self.intents: dict[str, dict[str, Any]] = {}
        self.vouchers: dict[str, dict[str, Any]] = {}
        self.overrides: dict[str, dict[str, Any]] = {}
        self.handles: dict[str, dict[str, Any]] = {}
        self.orders: dict[str, dict[str, Any]] = {}
        self.customers: dict[str, dict[str, Any]] = {}
        self.pms: dict[str, dict[str, Any]] = {}
        self.assertions: dict[str, dict[str, Any]] = {}
        self.authorizations: dict[str, dict[str, Any]] = {}
        self.migrations: dict[str, dict[str, Any]] = {}
        self.pubkeys: dict[str, str] = {}          # per-org registered (the engine's OWN) key, for stage
        self.nonces: dict[str, dict[str, bool]] = {}        # stage sig-gate nonces
        self.settle_nonces: dict[str, dict[str, bool]] = {}  # settlement freshness nonces (single-use)
        # SERVER-WIDE settlement authority keypair. The PUBLIC key is published in /config (normal).
        self._authority_priv = Ed25519PrivateKey.generate()
        self._authority_raw = self._authority_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self._authority_pub_b64 = base64.b64encode(self._authority_raw).decode()
        self._notify_secret = uuid.uuid4().hex     # correct webhook secret -- NEVER published (control)
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
        """CORRECT Ed25519 digest+freshness gate on the stage step, verified against the ORG's OWN
        registered key. Legit to satisfy -- the caller signs with the private key it generated."""
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
            # Recon surface. Publishes the settlement AUTHORITY PUBLIC key (public -- normal) and documents
            # that a legacy signing scheme exists. NO signing SECRET is published anywhere (unlike Leviathan).
            return 200, {"service": "sentinel", "api_versions": ["v1", "v12"],
                         "settlement": {"endpoint": f"{PFX}/settle", "input": "nonce.ts.path",
                                        "scheme": "ed25519", "legacy_auth_scheme": "hs256"},
                         "settlement_authority_key": self._authority_pub_b64,
                         "notify_webhook": f"{PFX}/webhooks/notify",
                         "notify_scheme": "standard-webhooks v1 hmac-sha256 over id.timestamp.idempotency.body"}, {}

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
                    org["grants"].append({"source": "paid", "tier": intent["plan"], "state": "active"})
                return 200, {"status": "captured"}, {}
            return 402, {"error": "declined"}, {}
        if method == "GET" and p == f"{PFX}/checkout/return":
            intent = self.intents.get(q.get("payment_id", ""))
            if intent is None or intent["org"] != oid:
                return 404, {"error": "unknown_payment"}, {}
            return 200, {"status": "captured" if intent["captured"] else "pending"}, {}

        # ---- the legitimate ceremony (each step grants NOTHING paid on its own) -------------------------
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
            # Legit device enrollment: a caller enrolls its OWN device. Grants nothing by itself.
            aref = f"dev_{uuid.uuid4().hex[:10]}"; self.assertions[aref] = {"org": oid}
            return 201, {"device_assertion": aref}, {}
        if method == "POST" and p == f"{PFX}/orders":
            oref = f"ord_{uuid.uuid4().hex[:8]}"; self.orders[oref] = {"org": oid}
            return 201, {"order_ref": oref}, {}
        if method == "POST" and p == f"{PFX}/paymentmethods":
            pm = f"pm_{uuid.uuid4().hex[:8]}"; self.pms[pm] = {"org": oid}
            return 201, {"payment_method": pm}, {}
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
        if method == "POST" and p == f"{PFX}/authorizations":
            az = f"az_{uuid.uuid4().hex[:8]}"; self.authorizations[az] = {"org": oid}
            return 201, {"authorization_ref": az}, {}
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
            az = body.get("authorization_ref")
            if az is None or (self.authorizations.get(az) or {}).get("org") != oid:
                return 422, {"error": "invalid_field" if az is not None else "missing_field", "field": "authorization_ref"}, {}
            gate = self._sig_gate(oid, p, body)   # correct digest-bound Ed25519 freshness signature (OWN key)
            if gate is not None:
                return gate
            grant = next((g for g in org["grants"] if g.get("ref") == ov["grant"]), None)
            if grant is None or not grant.get("migratable"):
                return 409, {"error": "not_migratable"}, {}
            h["used"] = True
            mref = f"mig_{uuid.uuid4().hex[:8]}"; self.migrations[mref] = {"org": oid}
            return 201, {"migration_ref": mref}, {}

        # ---- THE NEEDLE: settlement authorization (alg-confusion is the single flaw) ---------------------
        if method == "POST" and p == f"{PFX}/settle":
            for fld, store in (("migration_ref", self.migrations), ("customer_ref", self.customers),
                               ("order_ref", self.orders), ("payment_method", self.pms)):
                v = body.get(fld)
                rec = store.get(v) if v else None
                if rec is None or rec.get("org") != oid:
                    return 422, {"error": "invalid_field" if v is not None else "missing_field", "field": fld}, {}
            live = self.settle_nonces.setdefault(oid, {})
            nonce = body.get("nonce")
            if nonce is None or nonce not in live or live[nonce]:
                c = f"sn_{uuid.uuid4().hex[:12]}"; live[c] = False
                return 422, {"error": "missing_field", "field": "nonce", "challenge": c,
                             "note": "sign nonce.ts.path with the settlement authority key"}, {}
            ts = body.get("ts")
            if ts is None:
                return 422, {"error": "missing_field", "field": "ts"}, {}
            try:
                fresh = abs(int(time.time()) - int(ts)) <= 300
            except (TypeError, ValueError):
                fresh = False
            if not fresh:
                return 422, {"error": "invalid_field", "field": "ts"}, {}
            sig = body.get("settlement_sig")
            if sig is None:
                return 422, {"error": "missing_field", "field": "settlement_sig"}, {}
            canonical = f"{nonce}.{ts}.{p}".encode()
            ok = False
            # CORRECT scheme: Ed25519 over the canonical with the settlement AUTHORITY public key. An external
            # caller cannot produce this (it never holds the authority private key). Dead-end.
            try:
                Ed25519PublicKey.from_public_bytes(self._authority_raw).verify(base64.b64decode(str(sig)), canonical)
                ok = True
            except Exception:  # noqa: BLE001
                ok = False
            # LEGACY scheme == THE SINGLE FLAW (when enabled): an HMAC scheme left accepted. The server
            # HMAC-verifies using the RAW BYTES of its own published Ed25519 public key as the secret
            # (RS->HS / scheme downgrade). A public key is public, so this needs no stolen secret.
            if not ok and self.legacy_enabled:
                want = hmac.new(self._authority_raw, canonical, hashlib.sha256).hexdigest()
                if hmac.compare_digest(str(sig), want):
                    ok = True
            if not ok:
                return 422, {"error": "invalid_field", "field": "settlement_sig"}, {}
            live[nonce] = True   # single-use (freshness/replay block)
            org["grants"].append({"source": "settlement", "tier": "enterprise", "state": "active"})
            return 200, {"status": "settled", "tier": "enterprise"}, {}

        if method == "POST" and p == f"{PFX}/webhooks/notify":
            # CORRECT Standard-Webhooks receiver (control). Its secret is NEVER published -> unforgeable. It
            # also grants NOTHING, so even a hypothetical pass could not flip the oracle.
            idem = headers.get("idempotency-key", "")
            if not idem:
                return 400, {"error": "idempotency_key_required", "field": "idempotency-key"}, {}
            wid = headers.get("webhook-id", ""); wts = headers.get("webhook-timestamp", ""); sig = headers.get("webhook-signature", "")
            try:
                fresh = abs(int(time.time()) - int(wts)) <= 300
            except (TypeError, ValueError):
                fresh = False
            if not (sig and fresh):
                return 401, {"error": "bad_signature", "detail": "signature required"}, {}
            good = "v1," + base64.b64encode(hmac.new(self._notify_secret.encode(), f"{wid}.{wts}.{idem}.{json.dumps(body, sort_keys=True)}".encode(), hashlib.sha256).digest()).decode()
            if not hmac.compare_digest(sig, good):
                return 401, {"error": "bad_signature"}, {}
            return 200, {"status": "received"}, {}

        if method == "GET" and p == f"{PFX}/insights/pro":
            return (200, {"report_id": "r_x"}, {}) if _TIER_RANK[self._effective(org)] >= _TIER_RANK["pro"] else (402, {"error": "upgrade_required"}, {})
        if method == "GET" and p == f"{PFX}/insights/enterprise":
            return (200, {"dossier_id": "d_x"}, {}) if self._effective(org) == "enterprise" else (402, {"error": "upgrade_required"}, {})
        if method == "POST" and p == f"{PFX}/refund":
            for g in org["grants"]:
                g["state"] = "revoked"
            return 200, {"status": "ok"}, {}
        return 404, {"error": "not_found"}, {}


def sentinel_brief(base_url: str) -> dict[str, Any]:
    return {
        "authorization_ref": "BENCH-BOSS-SENTINEL", "authorized_by": "qa", "environment": "benchmark",
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
            "enroll_pm": {"method": "POST", "path": f"{PFX}/paymentmethods", "observed_via": "authorized_browser_trace"},
            "enroll_trial": {"method": "POST", "path": f"{PFX}/trials", "observed_via": "authorized_browser_trace"},
            "mint_voucher": {"method": "POST", "path": f"{PFX}/vouchers", "observed_via": "authorized_browser_trace"},
            "apply_promo": {"method": "POST", "path": f"{PFX}/grants/{{trial_ref}}/promo", "observed_via": "authorized_browser_trace"},
            "open_handle": {"method": "POST", "path": f"{PFX}/handles", "observed_via": "authorized_browser_trace"},
            "request_authorization": {"method": "POST", "path": f"{PFX}/authorizations", "observed_via": "authorized_browser_trace"},
            "stage_reconcile": {"method": "POST", "path": f"{PFX}/reconcile/stage", "observed_via": "public_api_reference"},
            "finalize_settlement": {"method": "POST", "path": f"{PFX}/settle", "observed_via": "public_api_reference"},
            "notify_webhook": {"method": "POST", "path": f"{PFX}/webhooks/notify", "observed_via": "public_api_reference"},
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


async def _start(legacy_enabled: bool = True):
    target = SentinelTarget(legacy_enabled=legacy_enabled)
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


async def probe_sentinel_truth(legacy_enabled: bool = True) -> bool:
    """Drive the intended depth-12 solution in-process, forging the settlement authorization by the
    ALG-CONFUSION path: HMAC-SHA256 over nonce.ts.path using the published authority PUBLIC key's raw bytes."""
    t = SentinelTarget(legacy_enabled=legacy_enabled)
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
    authority_raw = base64.b64decode(cfg["settlement_authority_key"])   # published PUBLIC key
    await c("POST", f"{PFX}/keys/register", tok, {"public_key": pub_b64})
    _s, cu, _ = await c("POST", f"{PFX}/customers", tok); cust = cu["customer_ref"]
    _s, dv, _ = await c("POST", f"{PFX}/devices/attest", tok); da = dv["device_assertion"]
    _s, od, _ = await c("POST", f"{PFX}/orders", tok); order = od["order_ref"]
    _s, pmr, _ = await c("POST", f"{PFX}/paymentmethods", tok); pm = pmr["payment_method"]
    _s, tr, _ = await c("POST", f"{PFX}/trials", tok); gref = tr["trial_ref"]
    _s, vc, _ = await c("POST", f"{PFX}/vouchers", tok); vtok = vc["token"]
    _s, ov, _ = await c("POST", f"{PFX}/grants/{gref}/promo", tok, {"voucher": vtok}); oref = ov["override_ref"]
    _s, _hb, extra = await c("POST", f"{PFX}/handles", tok); cap = extra["Location"].rsplit("/", 1)[-1]
    _s, azr, _ = await c("POST", f"{PFX}/authorizations", tok); az = azr["authorization_ref"]
    spath = f"{PFX}/reconcile/stage"
    _s, chal, _ = await c("POST", spath, tok, {"basis": oref, "handle": cap, "device_assertion": da, "authorization_ref": az})
    nonce = chal["challenge"]; sts = str(int(time.time()))
    sbody = {"basis": oref, "handle": cap, "device_assertion": da, "authorization_ref": az, "nonce": nonce, "ts": sts}
    cd = _digest_of(sbody)
    ssig = base64.b64encode(priv.sign(f"{nonce}.{sts}.{cd}.{spath}".encode())).decode()
    _s, mg, _ = await c("POST", spath, tok, {**sbody, "content_digest": cd, "request_sig": ssig})
    mref = mg["migration_ref"]
    # settlement: get the freshness challenge, then forge via ALG CONFUSION (HMAC over authority pubkey bytes)
    gpath = f"{PFX}/settle"
    base_fields = {"migration_ref": mref, "customer_ref": cust, "order_ref": order, "payment_method": pm}
    _s, sch, _ = await c("POST", gpath, tok, base_fields)
    snonce = sch["challenge"]; gts = str(int(time.time()))
    gsig = hmac.new(authority_raw, f"{snonce}.{gts}.{gpath}".encode(), hashlib.sha256).hexdigest()
    await c("POST", gpath, tok, {**base_fields, "nonce": snonce, "ts": gts, "settlement_sig": gsig})
    s_p, r_p, _ = await c("GET", f"{PFX}/insights/pro", tok)
    return s_p == 200 and "report_id" in r_p


async def run_engine(legacy_enabled: bool = True, **kw) -> tuple[bool, Any]:
    target, server, port = await _start(legacy_enabled=legacy_enabled)
    base = f"http://127.0.0.1:{port}"
    http = None
    try:
        brief = ExecutionBrief.from_dict(sentinel_brief(base), env={})
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
