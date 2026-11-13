#!/usr/bin/env python3
"""BOSS target 'Olympus' (depth-16, TWO SERVICES, SSRF hop) -- the capstone that puts every prior boss in the
shadow. A public GATEWAY (service A, NIST 800-207 policy-enforcement point, deny-by-default) fronts an
INTERNAL-ONLY settlement authority (service B) that is NOT reachable from outside. The single no-payment bypass
exists only when a 16-step chain threads through FIVE independently load-bearing flaws spread across BOTH
services, reverse-engineers an internal capability-URL that is visible only after chaining, forges the gateway's
own authorization, and -- via an SSRF/API7 flaw -- relays a forged settlement into the internal service,
signing over the RELAYED inner path.

Research-grounded (results/PROVIDER_RESEARCH.md rounds 1-3):
  * SSRF / OWASP API7:2023 (the cross-service hop): service A's `gateway_forward` forwards to a client-supplied
    internal path and returns the inner response ("displays the response", API7 scenario #2). CORRECT behavior
    allowlists the forward target (OWASP SSRF cheat sheet: "Match the host against an allowlist"). The FLAW
    (ssrf_open) is the missing allowlist -> the engine reaches the internal-only settlement route.
  * Gateway authorization (forge class): `gateway_forward` requires an HMAC over the forward target using a
    gateway secret leaked in config -- the engine forges it (a real misconfiguration).
  * Internal service B (capability URL, visible only through chaining): B's route `/internal/<cap>/settle` is
    revealed ONLY by the detokenize step; B's settlement uses the ALGORITHM-CONFUSION scheme (HMAC over the raw
    bytes of the published Ed25519 public key), signed over the INNER forwarded path -- not A's path.
  * plus the mandate (pending-pull), dunning (self-credit), and the full Ed25519 digest+freshness ceremony
    (RFC 9421/9449) on the stage step -- every capability built across Aurelia..Pantheon, at once.

THE FINDABLE BYPASS (depth-16, no payment, across two services):
    register_key -> bind_customer -> open_order -> enroll_pm -> create_mandate -> pull_payment(mandate flaw)
      -> enroll_trial -> mint_voucher -> apply_promo -> apply_credit(dunning flaw) -> open_handle
      -> attest_device -> reveal_key(detokenize -> internal route) -> register_gateway_client
      -> stage_reconcile(Ed25519 digest+freshness, OWN key)
      -> gateway_forward(forge gateway auth + SSRF to internal B + alg-confusion settle over the inner path)

CONTROLS: removing ANY one of the five flaws (ssrf_open / legacy_enabled / reveal_authz_broken / mandate_lax /
credit_lax) breaks the chain -> engine finds nothing. The all-correct variant -> 0.

Honest scope: this forces ONE new, general, SSRF-grounded capability -- signing a request over the RELAYED/
forwarded inner path (not the gateway path). Everything else composes existing capabilities. "Harder than
Stripe" means MORE layered defense-in-depth around the one logic path, not breaking Stripe's crypto (unbreakable
black-box). AES itself and SOC/NIST stay out of scope.

    PYTHONPATH=tests/verification_infrastructure/shims:tests/verification_infrastructure:. \
        python3 tests/verification_infrastructure/hardened_benchmark/run_olympus.py
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
_DENY_DECOYS = {f"{PFX}/admin", f"{PFX}/internal", f"{PFX}/debug", f"{PFX}/console", f"{PFX}/ops",
                f"{PFX}/root", f"{PFX}/metrics", f"{PFX}/gateway/admin", f"{PFX}/internal/settle"}
_ALLOWLISTED_FORWARD = "/internal/health"   # the ONLY forward target a correct gateway permits


def _digest_of(body: dict[str, Any]) -> str:
    biz = {k: v for k, v in body.items() if k not in _SKIP}
    return base64.b64encode(hashlib.sha256(json.dumps(biz, sort_keys=True).encode()).digest()).decode()


class OlympusTarget:
    def __init__(self, *, ssrf_open: bool = True, legacy_enabled: bool = True, reveal_authz_broken: bool = True,
                 mandate_lax: bool = True, credit_lax: bool = True) -> None:
        self.ssrf_open = ssrf_open                      # API7: gateway forward-target allowlist missing
        self.legacy_enabled = legacy_enabled            # alg-confusion at the internal service
        self.reveal_authz_broken = reveal_authz_broken  # detokenize flaw (reveals internal route)
        self.mandate_lax = mandate_lax                  # pending-mandate pull flaw
        self.credit_lax = credit_lax                    # self-credit dunning flaw
        self.by_token, self.orgs = {}, {}
        self.intents, self.vouchers, self.overrides, self.handles = {}, {}, {}, {}
        self.orders, self.customers, self.pms, self.assertions, self.mandates = {}, {}, {}, {}, {}
        self.bases, self.migrations, self.issued_notes, self.gw_clients = {}, {}, {}, {}
        self.pubkeys: dict[str, str] = {}
        self.routes: dict[str, str] = {}   # oid -> revealed internal B route (capability URL)
        self.nonces: dict[str, dict[str, bool]] = {}
        self.settle_nonces: dict[str, dict[str, bool]] = {}
        self._authority_priv = Ed25519PrivateKey.generate()
        self._authority_raw = self._authority_priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self._authority_pub_b64 = base64.b64encode(self._authority_raw).decode()
        self._gateway_secret = uuid.uuid4().hex   # LEAKED in config (misconfig) -> gateway auth forgeable
        self._notify_secret = uuid.uuid4().hex    # correct webhook secret -- NEVER published
        self.request_log, self.request_headers_seen, self.internal_hits = [], [], 0

    def _effective(self, org):
        best = None
        for g in org["grants"]:
            if g["state"] == "active" and _TIER_RANK[g["tier"]] > _TIER_RANK[best]:
                best = g["tier"]
        return best

    def _sig_gate(self, oid: str, p: str, body: dict[str, Any]):
        live = self.nonces.setdefault(oid, {})
        nonce = body.get("nonce")
        if nonce is None or nonce not in live or live[nonce]:
            c = f"ch_{uuid.uuid4().hex[:12]}"; live[c] = False
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

    def _settle_internal(self, oid: str, inner_path: str, body: dict[str, Any]):
        """Service B (internal settlement authority). Reached ONLY via the gateway forward. Its route is a
        capability URL; its signature uses algorithm-confusion over the INNER path."""
        self.internal_hits += 1
        org = self.orgs[oid]
        segs = inner_path.strip("/").split("/")
        if not (len(segs) == 3 and segs[0] == "internal" and segs[2] == "settle"):
            return 404, {"error": "not_found", "detail": "no internal route"}
        if self.routes.get(oid) != inner_path:
            return 403, {"error": "forbidden", "detail": "unknown internal capability"}
        mref = body.get("migration_ref"); mig = self.migrations.get(mref) if mref else None
        if mig is None or mig["org"] != oid:
            return 422, {"error": "invalid_field" if mref is not None else "missing_field", "field": "migration_ref"}
        basis = body.get("settlement_basis"); sb = self.bases.get(basis) if basis else None
        if sb is None or sb["org"] != oid:
            return 422, {"error": "invalid_field" if basis is not None else "missing_field", "field": "settlement_basis"}
        od = self.orders.get(body.get("order_ref", "")) if body.get("order_ref") else None
        if od is None or od["org"] != oid:
            return 422, {"error": "invalid_field" if body.get("order_ref") is not None else "missing_field", "field": "order_ref"}
        live = self.settle_nonces.setdefault(oid, {})
        nonce = body.get("nonce")
        if nonce is None or nonce not in live or live[nonce]:
            c = f"sn_{uuid.uuid4().hex[:12]}"; live[c] = False
            return 422, {"error": "missing_field", "field": "nonce", "challenge": c, "note": "sign nonce.ts.<inner-path> with the settlement authority key"}
        ts = body.get("ts")
        if ts is None:
            return 422, {"error": "missing_field", "field": "ts"}
        try:
            fresh = abs(int(time.time()) - int(ts)) <= 300
        except (TypeError, ValueError):
            fresh = False
        if not fresh:
            return 422, {"error": "invalid_field", "field": "ts"}
        sig = body.get("settlement_sig")
        if sig is None:
            return 422, {"error": "missing_field", "field": "settlement_sig"}
        canonical = f"{nonce}.{ts}.{inner_path}".encode()
        ok = False
        try:
            Ed25519PublicKey.from_public_bytes(self._authority_raw).verify(base64.b64decode(str(sig)), canonical)
            ok = True
        except Exception:  # noqa: BLE001
            ok = False
        if not ok and self.legacy_enabled:
            want = hmac.new(self._authority_raw, canonical, hashlib.sha256).hexdigest()
            if hmac.compare_digest(str(sig), want):
                ok = True
        if not ok:
            return 422, {"error": "invalid_field", "field": "settlement_sig"}
        live[nonce] = True
        org["grants"].append({"source": "settlement", "tier": "enterprise", "state": "active"})
        return 200, {"status": "settled", "tier": "enterprise"}

    async def handle(self, method, raw_path, body, headers):
        p = urlparse(raw_path).path
        q = {k: v[0] for k, v in parse_qs(urlparse(raw_path).query).items()}
        body = body or {}
        self.request_log.append((method, p)); self.request_headers_seen.append(dict(headers))

        if method == "POST" and p == f"{PFX}/signup":
            oid, tok = f"o_{uuid.uuid4().hex[:8]}", f"tok_{uuid.uuid4().hex[:16]}"
            self.orgs[oid] = {"grants": []}; self.by_token[tok] = {"org": oid}
            return 201, {"token": tok, "tenant_id": oid}, {}
        if method == "GET" and p == f"{PFX}/catalog":
            return 200, {"plans": [{"code": "pro", "price_id": "pr_pro", "amount": 99.0},
                                   {"code": "enterprise", "price_id": "pr_ent", "amount": 999.0}]}, {}
        if method == "GET" and p == f"{PFX}/config":
            # publishes the authority PUBLIC key + the gateway's own signing secret (misconfig). No internal
            # route and no vault here -- the internal route is revealed only by chaining to the detokenize step.
            return 200, {"service": "olympus", "api_versions": ["v3", "v16"],
                         "gateway": {"forward": f"{PFX}/gateway/forward",
                                     "auth": "hmac-sha256 over the forward target", "gateway_secret": self._gateway_secret,
                                     "note": "forward targets are allowlisted to internal health only"},
                         "settlement_authority_key": self._authority_pub_b64,
                         "settlement_scheme": "ed25519", "legacy_auth_scheme": "hs256",
                         "notify_webhook": f"{PFX}/webhooks/notify"}, {}

        auth = headers.get("authorization", "")
        ident = self.by_token.get(auth[7:]) if auth.lower().startswith("bearer ") else None
        if ident is None:
            return 401, {"error": "unauthenticated"}, {}
        oid = ident["org"]; org = self.orgs[oid]

        if p in _DENY_DECOYS:
            return 403, {"error": "forbidden", "detail": "access denied by policy"}, {}

        if method == "GET" and p == f"{PFX}/status":
            return 200, {"tier": self._effective(org), "note": "server-verified"}, {}
        if method == "POST" and p == f"{PFX}/checkout":
            if body.get("plan") not in ("pro", "enterprise"):
                return 400, {"error": "unknown_plan"}, {}
            pid = f"pi_{uuid.uuid4().hex[:8]}"; self.intents[pid] = {"org": oid, "plan": body["plan"], "captured": False}
            return 201, {"payment_id": pid, "status": "requires_confirmation"}, {}
        if method == "POST" and p.startswith(f"{PFX}/checkout/") and p.endswith("/confirm"):
            intent = self.intents.get(p.split("/")[-2])
            if intent is None or intent["org"] != oid:
                return 404, {"error": "unknown_payment"}, {}
            if body.get("outcome") == "success":
                intent["captured"] = True
                if not any(g.get("source") == "paid" and g["tier"] == intent["plan"] and g["state"] == "active" for g in org["grants"]):
                    org["grants"].append({"source": "paid", "tier": intent["plan"], "state": "active"})
                return 200, {"status": "captured"}, {}
            return 402, {"error": "declined"}, {}
        if method == "GET" and p == f"{PFX}/checkout/return":
            intent = self.intents.get(q.get("payment_id", ""))
            if intent is None or intent["org"] != oid:
                return 404, {"error": "unknown_payment"}, {}
            return 200, {"status": "captured" if intent["captured"] else "pending"}, {}

        # ---- legitimate ceremony (each grants nothing paid alone) ----------------------------------------
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
        if method == "POST" and p == f"{PFX}/orders":
            oref = f"ord_{uuid.uuid4().hex[:8]}"; self.orders[oref] = {"org": oid}
            return 201, {"order_ref": oref}, {}
        if method == "POST" and p == f"{PFX}/paymentmethods":
            pm = f"pm_{uuid.uuid4().hex[:8]}"; self.pms[pm] = {"org": oid}
            return 201, {"payment_method": pm}, {}
        if method == "POST" and p == f"{PFX}/mandates":
            mref = f"mnd_{uuid.uuid4().hex[:8]}"; self.mandates[mref] = {"org": oid, "status": "pending_submission"}
            return 201, {"mandate_ref": mref, "status": "pending_submission"}, {}
        if method == "POST" and p == f"{PFX}/payments":
            cu = self.customers.get(body.get("customer_ref", "")) if body.get("customer_ref") else None
            if cu is None or cu["org"] != oid:
                return 422, {"error": "invalid_field" if body.get("customer_ref") is not None else "missing_field", "field": "customer_ref"}, {}
            pm = self.pms.get(body.get("payment_method", "")) if body.get("payment_method") else None
            if pm is None or pm["org"] != oid:
                return 422, {"error": "invalid_field" if body.get("payment_method") is not None else "missing_field", "field": "payment_method"}, {}
            mref = body.get("mandate_ref"); m = self.mandates.get(mref) if mref else None
            if m is None or m["org"] != oid:
                return 422, {"error": "invalid_field" if mref is not None else "missing_field", "field": "mandate_ref"}, {}
            if not self.mandate_lax and m["status"] != "active":
                return 409, {"error": "mandate_not_active"}, {}
            bref = f"bas_{uuid.uuid4().hex[:8]}"; self.bases[bref] = {"org": oid}
            return 201, {"settlement_basis": bref, "status": "collected"}, {}
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
            oref = f"ov_{uuid.uuid4().hex[:8]}"; self.overrides[oref] = {"org": oid, "grant": gref}
            return 201, {"override_ref": oref, "tier": "preview"}, {}
        if method == "POST" and p.startswith(f"{PFX}/overrides/") and p.endswith("/credit"):
            oref = p.split("/")[-2]; ov = self.overrides.get(oref)
            if ov is None or ov["org"] != oid:
                return 404, {"error": "unknown_override"}, {}
            if not self.credit_lax:
                cn = body.get("credit_note")
                if cn is None:
                    return 422, {"error": "missing_field", "field": "credit_note"}, {}
                note = self.issued_notes.get(cn)
                if note is None or note.get("org") != oid:
                    return 403, {"error": "invalid_credit_note"}, {}
            grant = next((g for g in org["grants"] if g.get("ref") == ov["grant"]), None)
            if grant is None:
                return 409, {"error": "grant_gone"}, {}
            grant["migratable"] = True
            return 200, {"status": "credited", "migratable": True}, {}
        if method == "POST" and p == f"{PFX}/handles":
            cap = f"h_{uuid.uuid4().hex[:10]}"; self.handles[cap] = {"org": oid, "used": False}
            return 201, {"status": "issued"}, {"Location": f"{PFX}/handles/{cap}"}
        if method == "POST" and p == f"{PFX}/devices/attest":
            aref = f"dev_{uuid.uuid4().hex[:10]}"; self.assertions[aref] = {"org": oid}
            return 201, {"device_assertion": aref}, {}
        if method == "POST" and p == f"{PFX}/vault/reveal":
            # detokenize flaw: reveals the INTERNAL settlement route (a capability URL only visible by chaining)
            if not self.reveal_authz_broken:
                if body.get("vault_grant") is None:
                    return 403, {"error": "forbidden", "detail": "vault_grant required"}, {}
                return 403, {"error": "forbidden"}, {}
            route = f"/internal/cap{uuid.uuid4().hex[:12]}/settle"; self.routes[oid] = route
            return 200, {"forward_path": route, "note": "internal settlement capability route"}, {}
        if method == "POST" and p == f"{PFX}/gateway/clients":
            gc = f"gc_{uuid.uuid4().hex[:8]}"; self.gw_clients[gc] = {"org": oid}
            return 201, {"gateway_client": gc}, {}
        if method == "POST" and p == f"{PFX}/reconcile/stage":
            basis = body.get("basis"); ov = self.overrides.get(basis) if basis else None
            if ov is None or ov["org"] != oid:
                return 422, {"error": "invalid_field" if basis is not None else "missing_field", "field": "basis"}, {}
            handle = body.get("handle"); h = self.handles.get(handle) if handle else None
            if h is None or h["org"] != oid or h["used"]:
                return 422, {"error": "invalid_field" if handle is not None else "missing_field", "field": "handle"}, {}
            da = body.get("device_assertion")
            if da is None or (self.assertions.get(da) or {}).get("org") != oid:
                return 422, {"error": "invalid_field" if da is not None else "missing_field", "field": "device_assertion"}, {}
            gate = self._sig_gate(oid, p, body)
            if gate is not None:
                return gate
            grant = next((g for g in org["grants"] if g.get("ref") == ov["grant"]), None)
            if grant is None or not grant.get("migratable"):
                return 409, {"error": "not_migratable"}, {}
            h["used"] = True
            mref = f"mig_{uuid.uuid4().hex[:8]}"; self.migrations[mref] = {"org": oid}
            return 201, {"migration_ref": mref}, {}

        # ---- SERVICE A: the gateway forward (SSRF hop to internal service B) -----------------------------
        if method == "POST" and p == f"{PFX}/gateway/forward":
            gc = self.gw_clients.get(body.get("gateway_client", "")) if body.get("gateway_client") else None
            if gc is None or gc["org"] != oid:
                return 422, {"error": "invalid_field" if body.get("gateway_client") is not None else "missing_field", "field": "gateway_client"}, {}
            fwd = body.get("forward_path")
            if fwd is None:
                return 422, {"error": "missing_field", "field": "forward_path"}, {}
            gsig = body.get("gateway_sig")
            if gsig is None:
                return 422, {"error": "missing_field", "field": "gateway_sig", "note": "hmac-sha256(gateway_secret, forward_path)"}, {}
            want = hmac.new(self._gateway_secret.encode(), str(fwd).encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(str(gsig), want):
                return 403, {"error": "bad_gateway_signature"}, {}
            # SSRF/API7: a CORRECT gateway allowlists the forward target; the flaw is the missing allowlist.
            if not self.ssrf_open and str(fwd) != _ALLOWLISTED_FORWARD:
                return 403, {"error": "forward_target_not_allowed", "detail": "allowlist violation"}, {}
            if str(fwd) == _ALLOWLISTED_FORWARD:
                return 200, {"status": "ok", "service": "internal-health"}, {}
            # forward the (inner) request to service B and RETURN B's response (API7: raw response back)
            st, obj = self._settle_internal(oid, str(fwd), body)
            return st, obj, {}

        if method == "POST" and p == f"{PFX}/webhooks/notify":
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
        return 403, {"error": "forbidden", "detail": "no route"}, {}


def olympus_brief(base_url: str) -> dict[str, Any]:
    return {
        "authorization_ref": "BENCH-BOSS-OLYMPUS", "authorized_by": "qa", "environment": "benchmark",
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
            "open_order": {"method": "POST", "path": f"{PFX}/orders", "observed_via": "authorized_browser_trace"},
            "enroll_pm": {"method": "POST", "path": f"{PFX}/paymentmethods", "observed_via": "authorized_browser_trace"},
            "create_mandate": {"method": "POST", "path": f"{PFX}/mandates", "observed_via": "public_api_reference"},
            "pull_payment": {"method": "POST", "path": f"{PFX}/payments", "observed_via": "public_api_reference"},
            "enroll_trial": {"method": "POST", "path": f"{PFX}/trials", "observed_via": "authorized_browser_trace"},
            "mint_voucher": {"method": "POST", "path": f"{PFX}/vouchers", "observed_via": "authorized_browser_trace"},
            "apply_promo": {"method": "POST", "path": f"{PFX}/grants/{{trial_ref}}/promo", "observed_via": "authorized_browser_trace"},
            "apply_credit": {"method": "POST", "path": f"{PFX}/overrides/{{override_ref}}/credit", "observed_via": "public_api_reference"},
            "open_handle": {"method": "POST", "path": f"{PFX}/handles", "observed_via": "authorized_browser_trace"},
            "attest_device": {"method": "POST", "path": f"{PFX}/devices/attest", "observed_via": "authorized_browser_trace"},
            "reveal_key": {"method": "POST", "path": f"{PFX}/vault/reveal", "observed_via": "public_api_reference"},
            "register_gateway_client": {"method": "POST", "path": f"{PFX}/gateway/clients", "observed_via": "public_api_reference"},
            "stage_reconcile": {"method": "POST", "path": f"{PFX}/reconcile/stage", "observed_via": "public_api_reference"},
            "gateway_forward": {"method": "POST", "path": f"{PFX}/gateway/forward", "observed_via": "public_api_reference"},
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


async def _start(**flags):
    target = OlympusTarget(**flags)
    tracked = _TrackedServer(None)  # type: ignore[arg-type]

    def _on(reader, writer):
        t = asyncio.ensure_future(_serve(target, reader, writer))
        tracked.tasks.add(t); t.add_done_callback(tracked.tasks.discard)

    server = await asyncio.start_server(_on, "127.0.0.1", 0)
    tracked._server = server
    return target, tracked, server.sockets[0].getsockname()[1]


async def _serve(target, reader, writer):
    try:
        method, path, body, headers = await _read_http_request(reader)
        out = await target.handle(method, path, body, headers)
        status, obj, extra = out if len(out) == 3 else (out[0], out[1], {})
    except Exception as exc:  # noqa: BLE001
        status, obj, extra = 400, {"error": "bad", "detail": str(exc)}, {}
    payload = json.dumps(obj).encode("utf-8")
    lines = [f"HTTP/1.1 {status} X", "Content-Type: application/json", f"Content-Length: {len(payload)}"]
    for hk, hv in (extra or {}).items():
        lines.append(f"{hk}: {hv}")
    lines.append("Connection: close")
    head = "\r\n".join(lines) + "\r\n\r\n"
    try:
        writer.write(head.encode("utf-8") + payload); await writer.drain()
    finally:
        writer.close()


async def probe_olympus_truth(**flags) -> bool:
    t = OlympusTarget(**flags)
    priv = Ed25519PrivateKey.generate()
    pub_b64 = base64.b64encode(priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()

    async def c(method, path, token=None, body=None, hdr=None):
        h = {"authorization": f"Bearer {token}"} if token else {}
        if hdr:
            h.update(hdr)
        out = await t.handle(method, path, body or {}, h)
        s, r = out[0], out[1]
        return s, r

    _s, who = await c("POST", f"{PFX}/signup"); tok = who["token"]
    _s, cfg = await c("GET", f"{PFX}/config", tok)
    gwsecret = cfg["gateway"]["gateway_secret"]; authority_raw = base64.b64decode(cfg["settlement_authority_key"])
    await c("POST", f"{PFX}/keys/register", tok, {"public_key": pub_b64})
    _s, cu = await c("POST", f"{PFX}/customers", tok); cust = cu["customer_ref"]
    _s, od = await c("POST", f"{PFX}/orders", tok); order = od["order_ref"]
    _s, pmr = await c("POST", f"{PFX}/paymentmethods", tok); pm = pmr["payment_method"]
    _s, md = await c("POST", f"{PFX}/mandates", tok); mref = md["mandate_ref"]
    _s, pay = await c("POST", f"{PFX}/payments", tok, {"customer_ref": cust, "payment_method": pm, "mandate_ref": mref})
    if "settlement_basis" not in pay:
        return False
    basis = pay["settlement_basis"]
    _s, tr = await c("POST", f"{PFX}/trials", tok); gref = tr["trial_ref"]
    _s, vc = await c("POST", f"{PFX}/vouchers", tok); vtok = vc["token"]
    _s, ov = await c("POST", f"{PFX}/grants/{gref}/promo", tok, {"voucher": vtok}); oref = ov["override_ref"]
    _s, cr = await c("POST", f"{PFX}/overrides/{oref}/credit", tok, {"amount": 1})
    if not cr.get("migratable"):
        return False
    _s, hb = await c("POST", f"{PFX}/handles", tok)
    # (Location header carries the handle; the in-process prober re-derives it from state)
    cap = next(iter(k for k, v in t.handles.items() if v["org"] == t.by_token[tok]["org"]))
    _s, dv = await c("POST", f"{PFX}/devices/attest", tok); da = dv["device_assertion"]
    _s, rv = await c("POST", f"{PFX}/vault/reveal", tok, {"ref": "settlement"})
    if "forward_path" not in rv:
        return False
    fwd = rv["forward_path"]
    _s, gcr = await c("POST", f"{PFX}/gateway/clients", tok); gcid = gcr["gateway_client"]
    spath = f"{PFX}/reconcile/stage"
    _s, chal = await c("POST", spath, tok, {"basis": oref, "handle": cap, "device_assertion": da})
    nonce = chal["challenge"]; sts = str(int(time.time()))
    sbody = {"basis": oref, "handle": cap, "device_assertion": da, "nonce": nonce, "ts": sts}
    cd = _digest_of(sbody)
    ssig = base64.b64encode(priv.sign(f"{nonce}.{sts}.{cd}.{spath}".encode())).decode()
    _s, mg = await c("POST", spath, tok, {**sbody, "content_digest": cd, "request_sig": ssig})
    if "migration_ref" not in mg:
        return False
    mref2 = mg["migration_ref"]
    gsig = hmac.new(gwsecret.encode(), fwd.encode(), hashlib.sha256).hexdigest()
    base_fwd = {"gateway_client": gcid, "forward_path": fwd, "gateway_sig": gsig,
                "migration_ref": mref2, "settlement_basis": basis, "order_ref": order}
    _s, sch = await c("POST", f"{PFX}/gateway/forward", tok, base_fwd)
    if "challenge" not in sch:
        return False   # a flaw is hardened (e.g. SSRF allowlist enforced) -> no reachable bypass
    snonce = sch["challenge"]; gts = str(int(time.time()))
    isig = hmac.new(authority_raw, f"{snonce}.{gts}.{fwd}".encode(), hashlib.sha256).hexdigest()
    await c("POST", f"{PFX}/gateway/forward", tok, {**base_fwd, "nonce": snonce, "ts": gts, "settlement_sig": isig})
    s_p, r_p = await c("GET", f"{PFX}/insights/pro", tok)
    return s_p == 200 and "report_id" in r_p


async def run_engine(flags: dict | None = None, **kw) -> tuple[bool, Any]:
    target, server, port = await _start(**(flags or {}))
    base = f"http://127.0.0.1:{port}"
    http = None
    try:
        brief = ExecutionBrief.from_dict(olympus_brief(base), env={})
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
