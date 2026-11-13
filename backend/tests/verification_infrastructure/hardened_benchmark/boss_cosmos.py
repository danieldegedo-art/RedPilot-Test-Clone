#!/usr/bin/env python3
"""BOSS target 'Cosmos' (depth-18, MULTI-SERVICE MESH + ASYNC webhook-callback hop) -- the securest target in
the suite, built to put everything before it in the shadow. A deny-by-default service MESH (NIST 800-204B:
"the entire network and all microservices are untrusted"; ~99% of routes/services return 403/404) where the
single no-payment bypass is a depth-18 chain that tunnels the public gateway (SSRF/API7) into an internal QUEUE,
enqueues a settlement job, and then completes settlement by FORGING the provider's ASYNC webhook CALLBACK --
which must carry the QUEUE-ISSUED correlation id as its webhook-id (at-least-once dedup binding).

Every defense from the attached research (and the mesh research) is implemented CORRECTLY as the fortress -- so
it is "harder than Stripe" by layered correctness, not by breaking crypto:
  * server-side truth + entitlement re-verification (secure-paywall doc): only the settlement receiver grants.
  * raw-body HMAC + timestamp freshness (±300s) + event-id dedup (webhook/replay doc, Svix, Nylas).
  * IDOR ownership checks on every ref; tenant-scoped (IDOR/DB-isolation doc).
  * race-atomic state + unique-constraint idempotency: one correlation -> one grant (race + unique-constraint docs).
  * zero-trust mesh: gateway edge-auth + per-service re-authz; OWASP "gateway checks do not establish that a
    downstream operation is authorized" and "signature verification alone is insufficient".

The ONE reachable flaw is the honest real-world fall: the async-callback signing SECRET is leaked (misconfig),
so the engine forges a correlation-bound, fresh, idempotent callback -- exactly how signed webhooks fall in
practice. A correctly-secret callback stays unforgeable (the control).

THE FINDABLE BYPASS (depth-18, no payment, across the mesh):
    register_key -> bind_customer -> open_order -> enroll_pm -> create_mandate -> pull_payment(mandate flaw)
      -> enroll_trial -> mint_voucher -> apply_promo -> apply_credit(dunning flaw) -> open_handle -> attest_device
      -> reveal_key(detokenize -> internal queue route) -> register_gateway_client
      -> stage_reconcile(Ed25519 digest+freshness, OWN key) -> provision_queue_token
      -> gateway_forward(SSRF -> queue.enqueue -> correlation id) -> callback_ingest(forge correlation-bound callback)

CONTROLS: removing ANY one of the five flaws (ssrf_open / callback_secret_leaked / reveal_authz_broken /
mandate_lax / credit_lax) breaks the chain -> engine finds nothing. All-correct -> 0.

Forces ONE honest new capability (MISS->fix->FIND): forge an async callback USING a harvested/issued correlation
id as the webhook-id (not a fresh one) -- async at-least-once correlation binding (Nylas/Svix grounded).

    PYTHONPATH=tests/verification_infrastructure/shims:tests/verification_infrastructure:. \
        python3 tests/verification_infrastructure/hardened_benchmark/run_cosmos.py
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
# a deny-by-default MESH: many internal service namespaces, all refused (zero-trust, NIST 800-204B)
_MESH_SERVICES = ["admin", "ledger", "treasury", "ops", "audit", "kms", "fraud", "identity", "billing-core",
                  "risk", "reconciler", "disputes", "payouts", "vault-admin"]
_DENY_PREFIXES = tuple(f"{PFX}/svc/{s}" for s in _MESH_SERVICES) + (f"{PFX}/admin", f"{PFX}/debug", f"{PFX}/internal")
_ALLOWLISTED_FORWARD = "/svc/health/ping"   # the ONLY forward target a correct gateway permits


def _digest_of(body: dict[str, Any]) -> str:
    biz = {k: v for k, v in body.items() if k not in _SKIP}
    return base64.b64encode(hashlib.sha256(json.dumps(biz, sort_keys=True).encode()).digest()).decode()


class CosmosTarget:
    def __init__(self, *, ssrf_open: bool = True, callback_secret_leaked: bool = True,
                 reveal_authz_broken: bool = True, mandate_lax: bool = True, credit_lax: bool = True) -> None:
        self.ssrf_open = ssrf_open
        self.callback_secret_leaked = callback_secret_leaked
        self.reveal_authz_broken = reveal_authz_broken
        self.mandate_lax = mandate_lax
        self.credit_lax = credit_lax
        self.by_token, self.orgs = {}, {}
        self.intents, self.vouchers, self.overrides, self.handles = {}, {}, {}, {}
        self.orders, self.customers, self.pms, self.assertions, self.mandates = {}, {}, {}, {}, {}
        self.bases, self.migrations, self.issued_notes, self.gw_clients, self.queue_tokens = {}, {}, {}, {}, {}
        self.pubkeys: dict[str, str] = {}
        self.queue_routes: dict[str, str] = {}      # oid -> revealed internal queue route (capability URL)
        self.pending: dict[str, dict[str, Any]] = {}  # correlation_id -> pending settlement job
        self.used_idem: set[str] = set()
        self.nonces: dict[str, dict[str, bool]] = {}
        self._authority_priv = Ed25519PrivateKey.generate()
        self._authority_raw = self._authority_priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self._authority_pub_b64 = base64.b64encode(self._authority_raw).decode()
        self._gateway_secret = uuid.uuid4().hex      # leaked in config -> gateway forward auth forgeable
        self._callback_secret = uuid.uuid4().hex     # the async-callback signing secret (leaked iff flag set)
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

    def _queue_enqueue(self, oid: str, inner_path: str, body: dict[str, Any]):
        """Internal QUEUE service (reached only via the gateway forward / SSRF). Enqueues a settlement job and
        issues a CORRELATION id + the public callback route. Re-authorizes independently (OWASP: the gateway
        does not authorize downstream operations)."""
        self.internal_hits += 1
        segs = inner_path.strip("/").split("/")
        if not (len(segs) == 4 and segs[0] == "svc" and segs[1] == "queue" and segs[3] == "enqueue"):
            return 404, {"error": "not_found", "detail": "no internal route"}
        if self.queue_routes.get(oid) != inner_path:
            return 403, {"error": "forbidden", "detail": "unknown queue capability"}
        qt = self.queue_tokens.get(body.get("queue_token", ""))
        if qt is None or qt["org"] != oid:
            return 422, {"error": "invalid_field" if body.get("queue_token") is not None else "missing_field", "field": "queue_token"}
        mref = body.get("migration_ref"); mig = self.migrations.get(mref) if mref else None
        if mig is None or mig["org"] != oid:
            return 422, {"error": "invalid_field" if mref is not None else "missing_field", "field": "migration_ref"}
        basis = body.get("settlement_basis"); sb = self.bases.get(basis) if basis else None
        if sb is None or sb["org"] != oid:
            return 422, {"error": "invalid_field" if basis is not None else "missing_field", "field": "settlement_basis"}
        corr = f"corr_{uuid.uuid4().hex[:16]}"
        self.pending[corr] = {"org": oid, "migration_ref": mref, "basis": basis, "settled": False}
        return 200, {"status": "enqueued", "correlation_id": corr, "callback_route": f"{PFX}/callbacks/settle",
                     "note": "deliver a signed callback referencing correlation_id to complete settlement"}

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
            cfg = {"service": "cosmos-gateway", "api_versions": ["v4", "v18"],
                   "mesh_services": _MESH_SERVICES,
                   "gateway": {"forward": f"{PFX}/gateway/forward", "auth": "hmac-sha256 over the forward target",
                               "gateway_secret": self._gateway_secret,
                               "note": "forward targets are allowlisted to internal health only"},
                   "settlement_authority_key": self._authority_pub_b64,
                   "callback": {"ingest": f"{PFX}/callbacks/settle",
                                "scheme": "standard-webhooks v1 hmac-sha256 over webhook-id.timestamp.idempotency.body",
                                "note": "webhook-id MUST equal the queue-issued correlation_id (at-least-once dedup)"}}
            if self.callback_secret_leaked:
                cfg["callback"]["callback_secret"] = self._callback_secret   # THE misconfig (leaked secret)
            return 200, cfg, {}

        auth = headers.get("authorization", "")
        ident = self.by_token.get(auth[7:]) if auth.lower().startswith("bearer ") else None
        if ident is None:
            return 401, {"error": "unauthenticated"}, {}
        oid = ident["org"]; org = self.orgs[oid]

        # deny-by-default mesh: every internal service namespace is refused at the edge
        if p.startswith(_DENY_PREFIXES):
            return 403, {"error": "forbidden", "detail": "access denied by mesh policy"}, {}

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

        # ---- legitimate ceremony ------------------------------------------------------------------------
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
            # detokenize flaw: reveals the INTERNAL QUEUE route (capability URL, visible only through chaining)
            if not self.reveal_authz_broken:
                if body.get("vault_grant") is None:
                    return 403, {"error": "forbidden", "detail": "vault_grant required"}, {}
                return 403, {"error": "forbidden"}, {}
            route = f"/svc/queue/q{uuid.uuid4().hex[:12]}/enqueue"; self.queue_routes[oid] = route
            return 200, {"forward_path": route, "note": "internal queue capability route (forward target)"}, {}
        if method == "POST" and p == f"{PFX}/gateway/clients":
            gc = f"gc_{uuid.uuid4().hex[:8]}"; self.gw_clients[gc] = {"org": oid}
            return 201, {"gateway_client": gc}, {}
        if method == "POST" and p == f"{PFX}/queue/tokens":
            qt = f"qt_{uuid.uuid4().hex[:10]}"; self.queue_tokens[qt] = {"org": oid}
            return 201, {"queue_token": qt}, {}
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

        # ---- SERVICE A: gateway forward (SSRF hop into the internal queue) -------------------------------
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
            if not self.ssrf_open and str(fwd) != _ALLOWLISTED_FORWARD:
                return 403, {"error": "forward_target_not_allowed", "detail": "allowlist violation"}, {}
            if str(fwd) == _ALLOWLISTED_FORWARD:
                return 200, {"status": "ok", "service": "internal-health"}, {}
            st, obj = self._queue_enqueue(oid, str(fwd), body)
            return st, obj, {}

        # ---- the ASYNC CALLBACK receiver (public) -- settlement completes here ---------------------------
        if method == "POST" and p == f"{PFX}/callbacks/settle":
            # at-least-once signed callback. CORRECT: verify sig over raw body incl. webhook-id==correlation,
            # fresh ts, unique idem, then grant idempotently. The ONLY flaw is the leaked signing secret.
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
            # verify signature BEFORE acting (Nylas: verify before storing the id)
            good = "v1," + base64.b64encode(hmac.new(self._callback_secret.encode(), f"{wid}.{wts}.{idem}.{json.dumps(body, sort_keys=True)}".encode(), hashlib.sha256).digest()).decode()
            if not (sig and hmac.compare_digest(sig, good)):
                return 401, {"error": "bad_signature"}, {}
            # webhook-id MUST equal a known, pending correlation id (at-least-once dedup binding)
            job = self.pending.get(wid)
            if job is None or job["org"] != oid:
                return 422, {"error": "unknown_correlation", "field": "webhook-id"}, {}
            # body refs must be owned (IDOR ownership check)
            od = self.orders.get(body.get("order_ref", "")) if body.get("order_ref") else None
            if od is None or od["org"] != oid:
                return 422, {"error": "invalid_field" if body.get("order_ref") is not None else "missing_field", "field": "order_ref"}, {}
            if body.get("migration_ref") != job["migration_ref"] or body.get("settlement_basis") != job["basis"]:
                return 422, {"error": "correlation_mismatch", "field": "migration_ref"}, {}
            self.used_idem.add(idem)   # unique-constraint idempotency: one correlation -> one grant
            if not job["settled"]:
                job["settled"] = True
                org["grants"].append({"source": "async_settlement", "tier": "enterprise", "state": "active"})
            return 200, {"status": "settled", "tier": "enterprise"}, {}

        if method == "GET" and p == f"{PFX}/insights/pro":
            return (200, {"report_id": "r_x"}, {}) if _TIER_RANK[self._effective(org)] >= _TIER_RANK["pro"] else (402, {"error": "upgrade_required"}, {})
        if method == "GET" and p == f"{PFX}/insights/enterprise":
            return (200, {"dossier_id": "d_x"}, {}) if self._effective(org) == "enterprise" else (402, {"error": "upgrade_required"}, {})
        if method == "POST" and p == f"{PFX}/refund":
            for g in org["grants"]:
                g["state"] = "revoked"
            return 200, {"status": "ok"}, {}
        return 403, {"error": "forbidden", "detail": "no route"}, {}


def cosmos_brief(base_url: str) -> dict[str, Any]:
    return {
        "authorization_ref": "BENCH-BOSS-COSMOS", "authorized_by": "qa", "environment": "benchmark",
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
            "provision_queue_token": {"method": "POST", "path": f"{PFX}/queue/tokens", "observed_via": "public_api_reference"},
            "gateway_forward": {"method": "POST", "path": f"{PFX}/gateway/forward", "observed_via": "public_api_reference"},
            "callback_ingest": {"method": "POST", "path": f"{PFX}/callbacks/settle", "observed_via": "public_api_reference"},
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
    target = CosmosTarget(**flags)
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


async def probe_cosmos_truth(**flags) -> bool:
    t = CosmosTarget(**flags)
    priv = Ed25519PrivateKey.generate()
    pub_b64 = base64.b64encode(priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()

    async def c(method, path, token=None, body=None, hdr=None):
        h = {"authorization": f"Bearer {token}"} if token else {}
        if hdr:
            h.update(hdr)
        out = await t.handle(method, path, body or {}, h)
        return out[0], out[1]

    _s, who = await c("POST", f"{PFX}/signup"); tok = who["token"]
    _s, cfg = await c("GET", f"{PFX}/config", tok)
    gwsecret = cfg["gateway"]["gateway_secret"]
    cbsecret = cfg["callback"].get("callback_secret")
    if cbsecret is None:
        return False
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
    _s, _hb = await c("POST", f"{PFX}/handles", tok)
    cap = next(iter(k for k, v in t.handles.items() if v["org"] == t.by_token[tok]["org"]))
    _s, dv = await c("POST", f"{PFX}/devices/attest", tok); da = dv["device_assertion"]
    _s, rv = await c("POST", f"{PFX}/vault/reveal", tok, {"ref": "settlement"})
    if "forward_path" not in rv:
        return False
    qroute = rv["forward_path"]
    _s, gcr = await c("POST", f"{PFX}/gateway/clients", tok); gcid = gcr["gateway_client"]
    _s, qtk = await c("POST", f"{PFX}/queue/tokens", tok); qtoken = qtk["queue_token"]
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
    gsig = hmac.new(gwsecret.encode(), qroute.encode(), hashlib.sha256).hexdigest()
    enq_body = {"gateway_client": gcid, "forward_path": qroute, "gateway_sig": gsig,
                "queue_token": qtoken, "migration_ref": mref2, "settlement_basis": basis}
    _s, enq = await c("POST", f"{PFX}/gateway/forward", tok, enq_body)
    if "correlation_id" not in enq:
        return False
    corr = enq["correlation_id"]
    cb_body = {"migration_ref": mref2, "settlement_basis": basis, "order_ref": order}
    wts = str(int(time.time())); idem = f"idk_{uuid.uuid4().hex}"
    wsig = "v1," + base64.b64encode(hmac.new(cbsecret.encode(), f"{corr}.{wts}.{idem}.{json.dumps(cb_body, sort_keys=True)}".encode(), hashlib.sha256).digest()).decode()
    await c("POST", f"{PFX}/callbacks/settle", tok, cb_body,
            {"webhook-id": corr, "webhook-timestamp": wts, "idempotency-key": idem, "webhook-signature": wsig})
    s_p, r_p = await c("GET", f"{PFX}/insights/pro", tok)
    return s_p == 200 and "report_id" in r_p


async def run_engine(flags: dict | None = None, **kw) -> tuple[bool, Any]:
    target, server, port = await _start(**(flags or {}))
    base = f"http://127.0.0.1:{port}"
    http = None
    try:
        brief = ExecutionBrief.from_dict(cosmos_brief(base), env={})
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
