#!/usr/bin/env python3
"""BOSS target 'Chronos' (depth-22, double async-callback prefix + a DEEP in-chain TOCTOU race) -- the deepest and
hardest target in the suite. It takes Pangaea's forge prefix (SSRF -> forged callback corr-1 -> reconciler gated by
NUMERIC business-logic + cross-tenant BOLA, issuing corr-2) and, instead of a single forged settlement, makes the
terminal grant a CONCURRENCY / TOCTOU race that is reachable only AFTER the full prefix:

  * The reconciler (corr-2) opens a settlement that must be ARMED (provision_settlement_client -> arm_settlement).
  * claim_settlement_slot is a ONE-SHOT-per-identity claim with a check-then-act window. A single sequential claim
    records one slot (below the grant quorum) and locks; the paywall holds. Only a BOUNDED SIMULTANEOUS BURST of
    claims -- all passing the "not yet claimed" check before any write lands -- overruns the one-shot and crosses
    the quorum, granting enterprise. The claim needs corr-2 + the armed ref, so the race is DEEP: it cannot be
    bursted standalone, only after establishing the ~21-step forge prefix (PortSwigger limit-overrun, at depth).

Every prior flaw is retained and load-bearing (SSRF gateway hop, detokenize, pending-mandate pull, self-credit
dunning, leaked async-callback secret for corr-1, numeric free-adjust, cross-tenant BOLA); every other defense is
implemented CORRECTLY. The race step uses only plain authenticated inputs drawn from the prefix context (no
per-call signature), so a bounded burst can replay it -- an atomic (correct) one-shot is unbeaten.

THE FINDABLE depth-22 CHAIN (no payment):
    register_key -> bind_customer -> open_order -> enroll_pm -> create_mandate -> pull_payment(mandate)
      -> enroll_trial -> mint_voucher -> apply_promo -> apply_credit(dunning) -> open_handle -> attest_device
      -> reveal_key(detokenize) -> register_gateway_client -> stage_reconcile(Ed25519) -> provision_queue_token
      -> gateway_forward(SSRF -> enqueue -> corr1) -> callback_ingest(forge corr1 -> reconciler job + corr2)
      -> reconcile_dispatch(numeric free + BOLA beneficiary -> corr2) -> provision_settlement_client(corr2)
      -> arm_settlement(client + corr2) -> claim_settlement_slot(DEEP TOCTOU burst -> quorum -> enterprise)

    PYTHONPATH=tests/verification_infrastructure/shims:tests/verification_infrastructure:. \
        python3 tests/verification_infrastructure/hardened_benchmark/run_chronos.py [--controls]
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
_MESH = ["admin", "ledger", "treasury", "ops", "audit", "kms", "fraud", "identity", "risk", "disputes", "payouts"]
_DENY = tuple(f"{PFX}/svc/{s}" for s in _MESH) + (f"{PFX}/admin", f"{PFX}/debug", f"{PFX}/internal")
_ALLOWLISTED_FORWARD = "/svc/health/ping"
_QUORUM = 2   # a single sequential claim records 1 (< quorum); only a concurrent burst crosses it


def _digest_of(body: dict[str, Any]) -> str:
    biz = {k: v for k, v in body.items() if k not in _SKIP}
    return base64.b64encode(hashlib.sha256(json.dumps(biz, sort_keys=True).encode()).digest()).decode()


class ChronosTarget:
    def __init__(self, *, ssrf_open: bool = True, callback_secret_leaked: bool = True, reveal_authz_broken: bool = True,
                 mandate_lax: bool = True, credit_lax: bool = True, numeric_trusts_client: bool = True,
                 bola_open: bool = True, race_window: bool = True) -> None:
        self.ssrf_open = ssrf_open
        self.callback_secret_leaked = callback_secret_leaked
        self.reveal_authz_broken = reveal_authz_broken
        self.mandate_lax = mandate_lax
        self.credit_lax = credit_lax
        self.numeric_trusts_client = numeric_trusts_client
        self.bola_open = bola_open
        self.race_window = race_window                        # the DEEP TOCTOU, load-bearing
        self.by_token, self.orgs = {}, {}
        self.intents, self.vouchers, self.overrides, self.handles = {}, {}, {}, {}
        self.orders, self.customers, self.pms, self.assertions, self.mandates = {}, {}, {}, {}, {}
        self.bases, self.migrations, self.issued_notes, self.gw_clients, self.queue_tokens = {}, {}, {}, {}, {}
        self.benefits: dict[str, dict[str, Any]] = {}
        self.settle_clients: dict[str, dict[str, Any]] = {}
        self.armed: dict[str, dict[str, Any]] = {}            # armed settlements: {org, corr2, slots, claimed}
        self.pubkeys, self.queue_routes = {}, {}
        self.pending1: dict[str, dict[str, Any]] = {}
        self.pending2: dict[str, dict[str, Any]] = {}
        self.used_idem: set[str] = set()
        self.nonces: dict[str, dict[str, bool]] = {}
        self._authority_priv = Ed25519PrivateKey.generate()
        self._authority_raw = self._authority_priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self._authority_pub_b64 = base64.b64encode(self._authority_raw).decode()
        self._gateway_secret = uuid.uuid4().hex
        self._callback_secret = uuid.uuid4().hex
        self.request_log, self.request_headers_seen, self.internal_hits = [], [], 0

    def _effective(self, org):
        best = None
        for g in org["grants"]:
            if g["state"] == "active" and _TIER_RANK[g["tier"]] > _TIER_RANK[best]:
                best = g["tier"]
        return best

    def _sig_gate(self, oid, p, body):
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

    def _verify_callback(self, headers, body, pending):
        idem = headers.get("idempotency-key", "")
        if not idem:
            return None, (400, {"error": "idempotency_key_required", "field": "idempotency-key"})
        if idem in self.used_idem:
            return None, (409, {"error": "duplicate_idempotency"})
        wid = headers.get("webhook-id", ""); wts = headers.get("webhook-timestamp", ""); sig = headers.get("webhook-signature", "")
        try:
            fresh = abs(int(time.time()) - int(wts)) <= 300
        except (TypeError, ValueError):
            fresh = False
        if not fresh:
            return None, (401, {"error": "stale_signature"})
        good = "v1," + base64.b64encode(hmac.new(self._callback_secret.encode(), f"{wid}.{wts}.{idem}.{json.dumps(body, sort_keys=True)}".encode(), hashlib.sha256).digest()).decode()
        if not (sig and hmac.compare_digest(sig, good)):
            return None, (401, {"error": "bad_signature"})
        job = pending.get(wid)
        if job is None:
            return None, (422, {"error": "unknown_correlation", "field": "webhook-id"})
        self.used_idem.add(idem)
        return job, None

    async def handle(self, method, raw_path, body, headers):
        p = urlparse(raw_path).path
        q = {k: v[0] for k, v in parse_qs(urlparse(raw_path).query).items()}
        body = body or {}
        self.request_log.append((method, p)); self.request_headers_seen.append(dict(headers))

        if method == "POST" and p == f"{PFX}/signup":
            oid, tok = f"o_{uuid.uuid4().hex[:8]}", f"tok_{uuid.uuid4().hex[:16]}"
            self.orgs[oid] = {"grants": [], "paid": False}; self.by_token[tok] = {"org": oid}
            return 201, {"token": tok, "tenant_id": oid}, {}
        if method == "GET" and p == f"{PFX}/catalog":
            return 200, {"plans": [{"code": "pro", "price_id": "pr_pro", "amount": 99.0},
                                   {"code": "enterprise", "price_id": "pr_ent", "amount": 999.0, "currency": "USD"}]}, {}
        if method == "GET" and p == f"{PFX}/config":
            cfg = {"service": "chronos-gateway", "mesh_services": _MESH,
                   "gateway": {"forward": f"{PFX}/gateway/forward", "gateway_secret": self._gateway_secret,
                               "note": "forward targets allowlisted to internal health only"},
                   "settlement_authority_key": self._authority_pub_b64,
                   "callback": {"ingest": f"{PFX}/callbacks/enqueue",
                                "note": "webhook-id MUST equal the issued correlation id"},
                   "reconcile": f"{PFX}/reconcile/dispatch", "settlement": f"{PFX}/settlement/claim"}
            if self.callback_secret_leaked:
                cfg["callback"]["callback_secret"] = self._callback_secret
            return 200, cfg, {}

        auth = headers.get("authorization", "")
        ident = self.by_token.get(auth[7:]) if auth.lower().startswith("bearer ") else None
        if ident is None:
            return 401, {"error": "unauthenticated"}, {}
        oid = ident["org"]; org = self.orgs[oid]
        if p.startswith(_DENY):
            return 403, {"error": "forbidden", "detail": "mesh policy"}, {}

        if method == "GET" and p == f"{PFX}/status":
            return 200, {"tier": self._effective(org)}, {}
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
                intent["captured"] = True; org["paid"] = True
                if not any(g.get("source") == "paid" and g["tier"] == intent["plan"] and g["state"] == "active" for g in org["grants"]):
                    org["grants"].append({"source": "paid", "tier": intent["plan"], "state": "active"})
                bref = f"ben_{uuid.uuid4().hex[:10]}"; self.benefits[bref] = {"org": oid, "paid": True}
                return 200, {"status": "captured", "beneficiary_ref": bref}, {}
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
                if (self.issued_notes.get(cn) or {}).get("org") != oid:
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
            if not self.reveal_authz_broken:
                return 403, {"error": "forbidden", "detail": "vault_grant required"}, {}
            route = f"/svc/queue/q{uuid.uuid4().hex[:12]}/enqueue"; self.queue_routes[oid] = route
            return 200, {"forward_path": route, "note": "internal queue capability route"}, {}
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

        if method == "POST" and p == f"{PFX}/gateway/forward":
            gc = self.gw_clients.get(body.get("gateway_client", "")) if body.get("gateway_client") else None
            if gc is None or gc["org"] != oid:
                return 422, {"error": "invalid_field" if body.get("gateway_client") is not None else "missing_field", "field": "gateway_client"}, {}
            fwd = body.get("forward_path")
            if fwd is None:
                return 422, {"error": "missing_field", "field": "forward_path"}, {}
            gsig = body.get("gateway_sig")
            if gsig is None:
                return 422, {"error": "missing_field", "field": "gateway_sig", "note": "hmac(gateway_secret, forward_path)"}, {}
            if not hmac.compare_digest(str(gsig), hmac.new(self._gateway_secret.encode(), str(fwd).encode(), hashlib.sha256).hexdigest()):
                return 403, {"error": "bad_gateway_signature"}, {}
            if not self.ssrf_open and str(fwd) != _ALLOWLISTED_FORWARD:
                return 403, {"error": "forward_target_not_allowed"}, {}
            if str(fwd) == _ALLOWLISTED_FORWARD:
                return 200, {"status": "ok", "service": "internal-health"}, {}
            segs = str(fwd).strip("/").split("/")
            if not (len(segs) == 4 and segs[0] == "svc" and segs[1] == "queue" and segs[3] == "enqueue") or self.queue_routes.get(oid) != str(fwd):
                return 404, {"error": "not_found"}, {}
            qt = self.queue_tokens.get(body.get("queue_token", ""))
            if qt is None or qt["org"] != oid:
                return 422, {"error": "invalid_field" if body.get("queue_token") is not None else "missing_field", "field": "queue_token"}, {}
            mig = self.migrations.get(body.get("migration_ref", ""))
            if mig is None or mig["org"] != oid:
                return 422, {"error": "invalid_field" if body.get("migration_ref") is not None else "missing_field", "field": "migration_ref"}, {}
            sb = self.bases.get(body.get("settlement_basis", ""))
            if sb is None or sb["org"] != oid:
                return 422, {"error": "invalid_field" if body.get("settlement_basis") is not None else "missing_field", "field": "settlement_basis"}, {}
            corr = f"corr1_{uuid.uuid4().hex[:14]}"; self.pending1[corr] = {"org": oid, "migration_ref": body["migration_ref"], "basis": body["settlement_basis"]}
            return 200, {"status": "enqueued", "correlation_id": corr, "callback_route": f"{PFX}/callbacks/enqueue"}, {}

        # HOP 1: callback_ingest (forge corr-1) -> opens the reconciler (issues corr-2)
        if method == "POST" and p == f"{PFX}/callbacks/enqueue":
            job, err = self._verify_callback(headers, body, self.pending1)
            if err:
                return err[0], err[1], {}
            if job["org"] != oid:
                return 422, {"error": "unknown_correlation", "field": "webhook-id"}, {}
            corr2 = f"corr2_{uuid.uuid4().hex[:14]}"; self.pending2[corr2] = {"org": oid, "migration_ref": job["migration_ref"], "basis": job["basis"], "reconciled": False}
            return 200, {"status": "reconciler_opened", "reconcile_correlation": corr2, "reconcile_route": f"{PFX}/reconcile/dispatch"}, {}

        # reconciler: NUMERIC (free adjust) + BOLA (foreign beneficiary) gates; issues the settle correlation (corr-2)
        if method == "POST" and p == f"{PFX}/reconcile/dispatch":
            rc = body.get("reconcile_correlation"); job = self.pending2.get(rc) if rc else None
            if job is None or job["org"] != oid:
                return 422, {"error": "invalid_field" if rc is not None else "missing_field", "field": "reconcile_correlation"}, {}
            adj = body.get("adjust_amount")
            if adj is None:
                return 422, {"error": "missing_field", "field": "adjust_amount"}, {}
            try:
                adjf = float(adj)
            except (TypeError, ValueError):
                return 422, {"error": "invalid_field", "field": "adjust_amount"}, {}
            if self.numeric_trusts_client:
                if adjf > 0:
                    return 402, {"error": "payment_required", "detail": "net due"}, {}
            else:
                if adjf <= 0:
                    return 422, {"error": "invalid_field", "field": "adjust_amount", "detail": "must be positive"}, {}
                return 402, {"error": "payment_required"}, {}
            ben = body.get("beneficiary_ref"); br = self.benefits.get(ben) if ben else None
            if br is None or not br.get("paid"):
                return 422, {"error": "invalid_field" if ben is not None else "missing_field", "field": "beneficiary_ref"}, {}
            if not self.bola_open and br["org"] != oid:
                return 403, {"error": "not_beneficiary_owner"}, {}
            job["reconciled"] = True
            return 200, {"status": "reconciled", "settle_correlation": rc, "settle_route": f"{PFX}/settlement/clients"}, {}

        # settlement client -- needs corr-2 (so it is part of the deep prefix)
        if method == "POST" and p == f"{PFX}/settlement/clients":
            sc = body.get("settle_correlation"); job = self.pending2.get(sc) if sc else None
            if job is None or job["org"] != oid or not job.get("reconciled"):
                return 422, {"error": "invalid_field" if sc is not None else "missing_field", "field": "settle_correlation"}, {}
            scid = f"sc_{uuid.uuid4().hex[:10]}"; self.settle_clients[scid] = {"org": oid, "corr2": sc}
            return 201, {"settlement_client": scid, "arm_route": f"{PFX}/settlement/arm"}, {}

        # arm the settlement -- needs the settlement client + corr-2; initializes the one-shot slot
        if method == "POST" and p == f"{PFX}/settlement/arm":
            scid = body.get("settlement_client"); sc = self.settle_clients.get(scid) if scid else None
            if sc is None or sc["org"] != oid:
                return 422, {"error": "invalid_field" if scid is not None else "missing_field", "field": "settlement_client"}, {}
            corr = body.get("settle_correlation"); job = self.pending2.get(corr) if corr else None
            if job is None or job["org"] != oid or not job.get("reconciled") or corr != sc["corr2"]:
                return 422, {"error": "invalid_field" if corr is not None else "missing_field", "field": "settle_correlation"}, {}
            aref = f"arm_{uuid.uuid4().hex[:10]}"; self.armed[aref] = {"org": oid, "corr2": corr, "slots": 0, "claimed": False}
            return 201, {"armed_ref": aref, "claim_route": f"{PFX}/settlement/claim", "quorum": _QUORUM}, {}

        # DEEP TOCTOU: a one-shot-per-identity claim with a check-then-act window. A single claim records one slot
        # (below the quorum) and locks; only a bounded SIMULTANEOUS burst overruns the one-shot to cross the quorum.
        # Inputs are plain (armed_ref + corr-2), both established by the prefix -> the race is deep, not standalone.
        if method == "POST" and p == f"{PFX}/settlement/claim":
            aref = body.get("armed_ref"); a = self.armed.get(aref) if aref else None
            if a is None or a["org"] != oid:
                return 422, {"error": "invalid_field" if aref is not None else "missing_field", "field": "armed_ref"}, {}
            corr = body.get("settle_correlation"); job = self.pending2.get(corr) if corr else None
            if job is None or job["org"] != oid or not job.get("reconciled") or corr != a["corr2"]:
                return 422, {"error": "invalid_field" if corr is not None else "missing_field", "field": "settle_correlation"}, {}
            if self.race_window:
                if not a["claimed"]:
                    await asyncio.sleep(0.05)      # check-then-act window (models a DB round-trip)
                    a["slots"] += 1
                    a["claimed"] = True
                else:
                    return 409, {"error": "slot_already_claimed"}, {}
            else:
                if a["claimed"]:
                    return 409, {"error": "slot_already_claimed"}, {}
                a["claimed"] = True
                a["slots"] += 1
            if a["slots"] >= _QUORUM and not any(g.get("source") == "settle_overrun" and g["state"] == "active" for g in org["grants"]):
                org["grants"].append({"source": "settle_overrun", "tier": "enterprise", "state": "active"})
            return 200, {"status": "claimed", "slots": a["slots"]}, {}

        if method == "GET" and p == f"{PFX}/insights/pro":
            return (200, {"report_id": "r_x"}, {}) if _TIER_RANK[self._effective(org)] >= _TIER_RANK["pro"] else (402, {"error": "upgrade_required"}, {})
        if method == "GET" and p == f"{PFX}/insights/enterprise":
            return (200, {"dossier_id": "d_x"}, {}) if self._effective(org) == "enterprise" else (402, {"error": "upgrade_required"}, {})
        if method == "POST" and p == f"{PFX}/refund":
            for g in org["grants"]:
                g["state"] = "revoked"
            return 200, {"status": "ok"}, {}
        return 403, {"error": "forbidden", "detail": "no route"}, {}


def chronos_brief(base_url: str) -> dict[str, Any]:
    return {
        "authorization_ref": "BENCH-BOSS-CHRONOS", "authorized_by": "qa", "environment": "benchmark",
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
            "callback_ingest": {"method": "POST", "path": f"{PFX}/callbacks/enqueue", "observed_via": "public_api_reference"},
            "reconcile_dispatch": {"method": "POST", "path": f"{PFX}/reconcile/dispatch", "observed_via": "public_api_reference"},
            "provision_settlement_client": {"method": "POST", "path": f"{PFX}/settlement/clients", "observed_via": "public_api_reference"},
            "arm_settlement": {"method": "POST", "path": f"{PFX}/settlement/arm", "observed_via": "public_api_reference"},
            "claim_settlement_slot": {"method": "POST", "path": f"{PFX}/settlement/claim", "observed_via": "public_api_reference"},
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
    target = ChronosTarget(**flags)
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
        writer.write(head.encode("utf-8") + payload); await writer.drain()
    finally:
        writer.close()


async def probe_chronos_truth(**flags) -> bool:
    """Drive the intended depth-22 chain and win the DEEP TOCTOU with a simultaneous burst of claims."""
    t = ChronosTarget(**flags)
    priv = Ed25519PrivateKey.generate()
    pub_b64 = base64.b64encode(priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()

    async def c(method, path, token=None, body=None, hdr=None):
        h = {"authorization": f"Bearer {token}"} if token else {}
        if hdr:
            h.update(hdr)
        s, r, _ = await t.handle(method, path, body or {}, h)
        return s, r

    _s, vwho = await c("POST", f"{PFX}/signup"); vtok = vwho["token"]
    _s, vco = await c("POST", f"{PFX}/checkout", vtok, {"plan": "enterprise"}); vpid = vco["payment_id"]
    _s, vcap = await c("POST", f"{PFX}/checkout/{vpid}/confirm", vtok, {"outcome": "success"})
    vben = vcap["beneficiary_ref"]
    _s, who = await c("POST", f"{PFX}/signup"); tok = who["token"]
    _s, cfg = await c("GET", f"{PFX}/config", tok)
    gwsecret = cfg["gateway"]["gateway_secret"]; cbsecret = cfg["callback"].get("callback_secret")
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
    _s, vc = await c("POST", f"{PFX}/vouchers", tok); vtok2 = vc["token"]
    _s, ov = await c("POST", f"{PFX}/grants/{gref}/promo", tok, {"voucher": vtok2}); oref = ov["override_ref"]
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
    _s, enq = await c("POST", f"{PFX}/gateway/forward", tok, {"gateway_client": gcid, "forward_path": qroute, "gateway_sig": gsig, "queue_token": qtoken, "migration_ref": mref2, "settlement_basis": basis})
    if "correlation_id" not in enq:
        return False
    corr1 = enq["correlation_id"]

    def cb(corr, cbody):
        wts = str(int(time.time())); idem = f"idk_{uuid.uuid4().hex}"
        sig = "v1," + base64.b64encode(hmac.new(cbsecret.encode(), f"{corr}.{wts}.{idem}.{json.dumps(cbody, sort_keys=True)}".encode(), hashlib.sha256).digest()).decode()
        return {"webhook-id": corr, "webhook-timestamp": wts, "idempotency-key": idem, "webhook-signature": sig}
    body1 = {"migration_ref": mref2, "settlement_basis": basis, "order_ref": order}
    _s, r1 = await c("POST", f"{PFX}/callbacks/enqueue", tok, body1, cb(corr1, body1))
    if "reconcile_correlation" not in r1:
        return False
    corr2 = r1["reconcile_correlation"]
    _s, rd = await c("POST", f"{PFX}/reconcile/dispatch", tok, {"reconcile_correlation": corr2, "adjust_amount": -100, "beneficiary_ref": vben})
    if rd.get("status") != "reconciled":
        return False
    _s, scr = await c("POST", f"{PFX}/settlement/clients", tok, {"settle_correlation": corr2})
    scid = scr.get("settlement_client")
    if scid is None:
        return False
    _s, ar = await c("POST", f"{PFX}/settlement/arm", tok, {"settlement_client": scid, "settle_correlation": corr2})
    armed = ar.get("armed_ref")
    if armed is None:
        return False
    # the DEEP TOCTOU: a simultaneous burst of claims overruns the one-shot and crosses the quorum
    await asyncio.gather(*[c("POST", f"{PFX}/settlement/claim", tok, {"armed_ref": armed, "settle_correlation": corr2}) for _ in range(12)], return_exceptions=True)
    s_p, r_p = await c("GET", f"{PFX}/insights/pro", tok)
    return s_p == 200 and "report_id" in r_p


async def run_engine(flags: dict | None = None, race: bool = True, **kw) -> tuple[bool, Any]:
    target, server, port = await _start(**(flags or {}))
    base = f"http://127.0.0.1:{port}"
    http = None
    try:
        brief = ExecutionBrief.from_dict(chronos_brief(base), env={})
        guard = ScopeGuard(ScopePolicy.for_environment(base, max_requests=brief.limits.max_requests, max_requests_per_second=brief.limits.max_requests_per_second))
        http = QAHttpClient(base, brief.limits.timeout_seconds, None, {}, "qa-pure-black-box-engine/1.0", max_retries=0, guard=guard, stateless=True)
        engine = PureBlackBoxEngine(http, brief, base_url=base, enable_channel_probe=True, enable_chain_probe=True, enable_race_probe=race, race_burst=12, **kw)
        result = await engine.run(None)
        p0 = [f for f in result.findings if f.verdict.value == "CONFIRMED_P0"]
        return bool(p0), result
    finally:
        if http is not None and hasattr(http, "aclose"):
            await http.aclose()
        await server.aclose()
