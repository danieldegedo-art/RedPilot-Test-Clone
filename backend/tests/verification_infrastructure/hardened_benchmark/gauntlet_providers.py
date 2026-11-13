#!/usr/bin/env python3
"""Held-out gauntlet -- PROVIDER-MODEL families. These validate the engine on genuinely DIFFERENT control
models found in the real per-provider research (not more signing variants), and deliver the honest
AES-at-rest answer. Each family is randomized per seed with solvable / unsolvable / clean variants.

  * keymanagement (the honest AES-256-at-rest angle; Stripe CDV/detokenization) -- you never break AES. A
    detokenize/reveal endpoint that is MISSING AUTHZ (misconfig) hands back the data/signing key, which then
    forges a settlement. "Decryption keys are stored on separate machines" + tokenization gated by a static
    allowlist (docs.stripe.com/security) -> the black-box-reachable flaw is the un-authz'd reveal, not the cipher.
      - solvable:   reveal leaks the key -> engine reveals it, HMAC-signs the settlement -> detected.
      - unsolvable: reveal requires a grant the engine lacks (403) -> no key -> correct 0.
      - clean:      reveal leaks the key but a valid settlement does not over-grant -> 0 false positives.

  * mandate (GoCardless bank-debit; the authorization is a reusable MANDATE, not a per-payment card auth) --
    a payment pulled against a mandate that was never properly authorised grants entitlement.
      - solvable:   payment against a PENDING (un-activated) mandate grants -> engine chains it -> detected.
      - unsolvable: payment requires an ACTIVE mandate (real payer authorisation, impossible black-box) -> 0.
      - clean:      payment against a mandate grants nothing extra -> 0 false positives.

  * dunning (Chargebee/Recurly subscription state machine; NO signatures at all) -- a self-serve credit/
    adjustment is wrongly treated as payment and flips a past_due subscription back to active.
      - solvable:   a self-applied credit flips past_due -> active -> engine chains it -> detected.
      - unsolvable: reactivation requires a real issued credit-note/payment event -> 0.
      - clean:      the credit records a balance but does not change entitlement -> 0 false positives.

    PYTHONPATH=tests/verification_infrastructure/shims:tests/verification_infrastructure:. \
        python3 tests/verification_infrastructure/hardened_benchmark/gauntlet_providers.py
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import random
import time
import uuid
from typing import Any
from urllib.parse import parse_qs, urlparse

from app.enterprise_controls.scope import ScopeGuard, ScopePolicy
from app.testing.http_client import QAHttpClient
from app.testing.integrity.brief import ExecutionBrief
from app.testing.integrity.engine import PureBlackBoxEngine
from reference_target import _read_http_request, _TrackedServer

PFX = "/svc"


def gen_spec(seed: int, family: str, kind: str) -> dict[str, Any]:
    return {"seed": seed, "family": family, "kind": kind,
            "has_bug": kind != "clean", "reachable": kind != "unsolvable"}


# ----------------------------------------------------------------------------- keymanagement (AES-honest)
class KeyMgmtTarget:
    """A detokenize/reveal endpoint missing authz hands back the signing key -> forge a settlement.
    (You never break AES; you abuse the un-authz'd reveal path.)"""
    def __init__(self, spec):
        self.s = spec
        self.by_token, self.orgs = {}, {}
        self._data_key = uuid.uuid4().hex   # the 'decryption/signing key' behind the vault token
        self.nonces: dict[str, dict[str, bool]] = {}
        self.request_log, self.request_headers_seen, self.internal_hits = [], [], 0

    def _eff(self, org):
        return "top" if org["top"] else ("basic" if org["basic"] else None)

    async def handle(self, method, raw_path, body, headers):
        s = self.s
        p = urlparse(raw_path).path
        q = {k: v[0] for k, v in parse_qs(urlparse(raw_path).query).items()}
        body = body or {}
        self.request_log.append((method, p)); self.request_headers_seen.append(dict(headers))
        if method == "POST" and p == f"{PFX}/signup":
            oid, tok = f"o_{uuid.uuid4().hex[:8]}", f"tok_{uuid.uuid4().hex[:16]}"
            self.orgs[oid] = {"basic": False, "top": False, "pays": {}}; self.by_token[tok] = {"org": oid}
            return 201, {"token": tok, "tenant_id": oid}, {}
        if method == "GET" and p == f"{PFX}/catalog":
            return 200, {"plans": [{"code": "basic", "price_id": "pr_b", "amount": 9.0},
                                   {"code": "top", "price_id": "pr_t", "amount": 900.0}]}, {}
        if method == "GET" and p == f"{PFX}/config":
            # References a vault token for the settlement key (normal); the key itself is NOT here.
            return 200, {"service": "km", "settlement": f"{PFX}/settle",
                         "key_ref": "tok_settlement_key", "vault": f"{PFX}/vault/reveal"}, {}
        auth = headers.get("authorization", "")
        ident = self.by_token.get(auth[7:]) if auth.lower().startswith("bearer ") else None
        if ident is None:
            return 401, {"error": "unauthenticated"}, {}
        oid = ident["org"]; org = self.orgs[oid]
        if method == "POST" and p == f"{PFX}/checkout":
            if body.get("plan") not in ("basic", "top"):
                return 400, {"error": "unknown_plan"}, {}
            pid = f"pay_{uuid.uuid4().hex[:8]}"; org["pays"][pid] = {"plan": body["plan"], "captured": False}
            return 201, {"payment_id": pid, "status": "open"}, {}
        if method == "POST" and p.startswith(f"{PFX}/checkout/") and p.endswith("/confirm"):
            pay = org["pays"].get(p.split("/")[-2])
            if pay is None:
                return 404, {"error": "unknown_payment"}, {}
            if body.get("outcome") == "success":
                pay["captured"] = True; org["basic" if pay["plan"] == "basic" else "top"] = True
                return 200, {"status": "captured"}, {}
            return 402, {"error": "declined"}, {}
        if method == "GET" and p == f"{PFX}/checkout/return":
            pay = org["pays"].get(q.get("payment_id", ""))
            return (200, {"status": "ok" if pay["captured"] else "pending"}, {}) if pay else (404, {"error": "unknown_payment"}, {})
        if method == "POST" and p == f"{PFX}/vault/reveal":
            # THE FLAW (solvable/clean): detokenize is missing an authz check -> returns the data key to any
            # authenticated tenant. (unsolvable): a vault_grant is required, which the caller cannot obtain.
            if not s["reachable"]:
                if body.get("vault_grant") is None:
                    return 403, {"error": "forbidden", "detail": "vault_grant required"}, {}
                return 403, {"error": "forbidden"}, {}
            if body.get("ref") is None:
                return 422, {"error": "missing_field", "field": "ref"}, {}
            return 200, {"data_key": self._data_key}, {}
        if method == "POST" and p == f"{PFX}/settle":
            live = self.nonces.setdefault(oid, {})
            nonce = body.get("nonce")
            if nonce is None or nonce not in live or live[nonce]:
                c = f"n_{uuid.uuid4().hex[:12]}"; live[c] = False
                return 422, {"error": "missing_field", "field": "nonce", "challenge": c}, {}
            sig = body.get("settlement_sig")
            if sig is None:
                return 422, {"error": "missing_field", "field": "settlement_sig"}, {}
            want = hmac.new(self._data_key.encode(), f"{nonce}.{p}".encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(str(sig), want):
                return 422, {"error": "invalid_field", "field": "settlement_sig"}, {}
            live[nonce] = True
            if s["has_bug"]:
                org["top"] = True
                return 200, {"status": "settled", "tier": "top"}, {}
            return 200, {"status": "acknowledged"}, {}
        if method == "GET" and p == f"{PFX}/use":
            return (200, {"ok_id": "u"}, {}) if self._eff(org) in ("basic", "top") else (402, {"error": "pay"}, {})
        if method == "POST" and p == f"{PFX}/refund":
            org["basic"] = org["top"] = False; return 200, {"status": "ok"}, {}
        return 404, {"error": "not_found"}, {}


def km_brief(spec, base_url):
    return {
        "authorization_ref": "BENCH-PROV-KM", "authorized_by": "qa", "environment": "benchmark",
        "target_kind": "controlled_benchmark", "attested_synthetic_data": True, "attested_sandbox_payments": True,
        "allow_signup": True, "primary_currency": "USD", "allowed_hosts": [base_url.split("//", 1)[1]],
        "surface": {
            "signup": {"method": "POST", "path": f"{PFX}/signup", "observed_via": "product_ui"},
            "catalog": {"method": "GET", "path": f"{PFX}/catalog", "observed_via": "authorized_browser_trace"},
            "config_recon": {"method": "GET", "path": f"{PFX}/config", "observed_via": "public_api_reference"},
            "start_checkout": {"method": "POST", "path": f"{PFX}/checkout", "observed_via": "authorized_browser_trace"},
            "sandbox_pay": {"method": "POST", "path": f"{PFX}/checkout/{{payment_id}}/confirm", "observed_via": "authorized_browser_trace"},
            "return_flow": {"method": "GET", "path": f"{PFX}/checkout/return", "observed_via": "authorized_browser_trace"},
            "reveal_key": {"method": "POST", "path": f"{PFX}/vault/reveal", "observed_via": "public_api_reference"},
            "settle": {"method": "POST", "path": f"{PFX}/settle", "observed_via": "public_api_reference"},
            "subscription_view": {"method": "GET", "path": f"{PFX}/use", "observed_via": "product_ui"},
            "request_refund": {"method": "POST", "path": f"{PFX}/refund", "observed_via": "product_ui"},
        },
        "plans": {"basic": {"prices": {"USD": 9.0}}, "top": {"prices": {"USD": 900.0}}},
        "features": {"use_feature": {"method": "GET", "path": f"{PFX}/use", "proof_field": "ok_id", "requires_plan": "basic", "observed_via": "product_ui"}},
        "declared_paid_features": ["use_feature"],
        "limits": {"max_requests": 5000, "max_requests_per_second": 50, "revocation_sla_seconds": 1.0,
                   "revocation_poll_schedule_s": [0.0, 0.1], "quota_probe_cap": 3, "timeout_seconds": 10},
    }


async def km_truth(spec) -> bool:
    if not (spec["has_bug"] and spec["reachable"]):
        return False
    t = KeyMgmtTarget(spec)

    async def c(method, path, token=None, body=None):
        h = {"authorization": f"Bearer {token}"} if token else {}
        st, r, _ = await t.handle(method, path, body or {}, h); return st, r
    _s, who = await c("POST", f"{PFX}/signup"); tok = who["token"]
    await c("GET", f"{PFX}/config", tok)
    _s, kr = await c("POST", f"{PFX}/vault/reveal", tok, {"ref": "tok_settlement_key"}); dk = kr["data_key"]
    _s, ch = await c("POST", f"{PFX}/settle", tok, {}); nonce = ch["challenge"]
    sig = hmac.new(dk.encode(), f"{nonce}.{PFX}/settle".encode(), hashlib.sha256).hexdigest()
    await c("POST", f"{PFX}/settle", tok, {"nonce": nonce, "settlement_sig": sig})
    st, r = await c("GET", f"{PFX}/use", tok)
    return st == 200 and "ok_id" in r


# ----------------------------------------------------------------------------- mandate (GoCardless)
class MandateTarget:
    """Bank-debit mandates: a payment pulled against a mandate that was never properly authorised."""
    def __init__(self, spec):
        self.s = spec
        self.by_token, self.orgs = {}, {}
        self.mandates: dict[str, dict[str, Any]] = {}
        self.request_log, self.request_headers_seen, self.internal_hits = [], [], 0

    def _eff(self, org):
        return "top" if org["top"] else ("basic" if org["basic"] else None)

    async def handle(self, method, raw_path, body, headers):
        s = self.s
        p = urlparse(raw_path).path
        q = {k: v[0] for k, v in parse_qs(urlparse(raw_path).query).items()}
        body = body or {}
        self.request_log.append((method, p)); self.request_headers_seen.append(dict(headers))
        if method == "POST" and p == f"{PFX}/signup":
            oid, tok = f"o_{uuid.uuid4().hex[:8]}", f"tok_{uuid.uuid4().hex[:16]}"
            self.orgs[oid] = {"basic": False, "top": False, "pays": {}}; self.by_token[tok] = {"org": oid}
            return 201, {"token": tok, "tenant_id": oid}, {}
        if method == "GET" and p == f"{PFX}/catalog":
            return 200, {"plans": [{"code": "basic", "price_id": "pr_b", "amount": 9.0},
                                   {"code": "top", "price_id": "pr_t", "amount": 900.0}]}, {}
        if method == "GET" and p == f"{PFX}/config":
            return 200, {"service": "dd", "payments": f"{PFX}/payments", "mandates": f"{PFX}/mandates",
                         "note": "payment is pulled against an active mandate"}, {}
        auth = headers.get("authorization", "")
        ident = self.by_token.get(auth[7:]) if auth.lower().startswith("bearer ") else None
        if ident is None:
            return 401, {"error": "unauthenticated"}, {}
        oid = ident["org"]; org = self.orgs[oid]
        if method == "POST" and p == f"{PFX}/checkout":
            if body.get("plan") not in ("basic", "top"):
                return 400, {"error": "unknown_plan"}, {}
            pid = f"pay_{uuid.uuid4().hex[:8]}"; org["pays"][pid] = {"plan": body["plan"], "captured": False}
            return 201, {"payment_id": pid, "status": "open"}, {}
        if method == "POST" and p.startswith(f"{PFX}/checkout/") and p.endswith("/confirm"):
            pay = org["pays"].get(p.split("/")[-2])
            if pay is None:
                return 404, {"error": "unknown_payment"}, {}
            if body.get("outcome") == "success":
                pay["captured"] = True; org["basic" if pay["plan"] == "basic" else "top"] = True
                return 200, {"status": "captured"}, {}
            return 402, {"error": "declined"}, {}
        if method == "GET" and p == f"{PFX}/checkout/return":
            pay = org["pays"].get(q.get("payment_id", ""))
            return (200, {"status": "ok" if pay["captured"] else "pending"}, {}) if pay else (404, {"error": "unknown_payment"}, {})
        if method == "POST" and p == f"{PFX}/mandates":
            # A mandate is created PENDING -- real activation needs a payer authorisation (out of band).
            mref = f"mnd_{uuid.uuid4().hex[:8]}"; self.mandates[mref] = {"org": oid, "status": "pending_submission"}
            return 201, {"mandate_ref": mref, "status": "pending_submission"}, {}
        if method == "POST" and p == f"{PFX}/payments":
            mref = body.get("mandate_ref")
            m = self.mandates.get(mref) if mref else None
            if m is None or m["org"] != oid:
                return 422, {"error": "invalid_field" if mref is not None else "missing_field", "field": "mandate_ref"}, {}
            # correct rule: only an ACTIVE mandate may be pulled. THE FLAW (reachable): the status check is
            # missing, so a pull against a pending mandate succeeds and grants.
            if not s["reachable"] and m["status"] != "active":
                return 409, {"error": "mandate_not_active"}, {}
            if s["has_bug"]:
                org["top"] = True
                return 201, {"status": "collected", "tier": "top"}, {}
            return 201, {"status": "recorded"}, {}
        if method == "GET" and p == f"{PFX}/use":
            return (200, {"ok_id": "u"}, {}) if self._eff(org) in ("basic", "top") else (402, {"error": "pay"}, {})
        if method == "POST" and p == f"{PFX}/refund":
            org["basic"] = org["top"] = False; return 200, {"status": "ok"}, {}
        return 404, {"error": "not_found"}, {}


def mandate_brief(spec, base_url):
    return {
        "authorization_ref": "BENCH-PROV-MND", "authorized_by": "qa", "environment": "benchmark",
        "target_kind": "controlled_benchmark", "attested_synthetic_data": True, "attested_sandbox_payments": True,
        "allow_signup": True, "primary_currency": "USD", "allowed_hosts": [base_url.split("//", 1)[1]],
        "surface": {
            "signup": {"method": "POST", "path": f"{PFX}/signup", "observed_via": "product_ui"},
            "catalog": {"method": "GET", "path": f"{PFX}/catalog", "observed_via": "authorized_browser_trace"},
            "config_recon": {"method": "GET", "path": f"{PFX}/config", "observed_via": "public_api_reference"},
            "start_checkout": {"method": "POST", "path": f"{PFX}/checkout", "observed_via": "authorized_browser_trace"},
            "sandbox_pay": {"method": "POST", "path": f"{PFX}/checkout/{{payment_id}}/confirm", "observed_via": "authorized_browser_trace"},
            "return_flow": {"method": "GET", "path": f"{PFX}/checkout/return", "observed_via": "authorized_browser_trace"},
            "create_mandate": {"method": "POST", "path": f"{PFX}/mandates", "observed_via": "public_api_reference"},
            "pull_payment": {"method": "POST", "path": f"{PFX}/payments", "observed_via": "public_api_reference"},
            "subscription_view": {"method": "GET", "path": f"{PFX}/use", "observed_via": "product_ui"},
            "request_refund": {"method": "POST", "path": f"{PFX}/refund", "observed_via": "product_ui"},
        },
        "plans": {"basic": {"prices": {"USD": 9.0}}, "top": {"prices": {"USD": 900.0}}},
        "features": {"use_feature": {"method": "GET", "path": f"{PFX}/use", "proof_field": "ok_id", "requires_plan": "basic", "observed_via": "product_ui"}},
        "declared_paid_features": ["use_feature"],
        "limits": {"max_requests": 5000, "max_requests_per_second": 50, "revocation_sla_seconds": 1.0,
                   "revocation_poll_schedule_s": [0.0, 0.1], "quota_probe_cap": 3, "timeout_seconds": 10},
    }


async def mandate_truth(spec) -> bool:
    if not (spec["has_bug"] and spec["reachable"]):
        return False
    t = MandateTarget(spec)

    async def c(method, path, token=None, body=None):
        h = {"authorization": f"Bearer {token}"} if token else {}
        st, r, _ = await t.handle(method, path, body or {}, h); return st, r
    _s, who = await c("POST", f"{PFX}/signup"); tok = who["token"]
    _s, m = await c("POST", f"{PFX}/mandates", tok); mref = m["mandate_ref"]
    await c("POST", f"{PFX}/payments", tok, {"mandate_ref": mref})
    st, r = await c("GET", f"{PFX}/use", tok)
    return st == 200 and "ok_id" in r


# ----------------------------------------------------------------------------- dunning (Chargebee/Recurly)
class DunningTarget:
    """Subscription state machine (no signatures). A self-serve credit is wrongly treated as payment and
    flips a past_due subscription back to active."""
    def __init__(self, spec):
        self.s = spec
        self.by_token, self.orgs = {}, {}
        self.subs: dict[str, dict[str, Any]] = {}
        self.issued_notes: dict[str, dict[str, Any]] = {}   # provider-issued credit notes (never issued to an unpaid caller)
        self.request_log, self.request_headers_seen, self.internal_hits = [], [], 0

    def _eff(self, org):
        return "top" if org["top"] else ("basic" if org["basic"] else None)

    async def handle(self, method, raw_path, body, headers):
        s = self.s
        p = urlparse(raw_path).path
        q = {k: v[0] for k, v in parse_qs(urlparse(raw_path).query).items()}
        body = body or {}
        self.request_log.append((method, p)); self.request_headers_seen.append(dict(headers))
        if method == "POST" and p == f"{PFX}/signup":
            oid, tok = f"o_{uuid.uuid4().hex[:8]}", f"tok_{uuid.uuid4().hex[:16]}"
            self.orgs[oid] = {"basic": False, "top": False, "pays": {}}; self.by_token[tok] = {"org": oid}
            return 201, {"token": tok, "tenant_id": oid}, {}
        if method == "GET" and p == f"{PFX}/catalog":
            return 200, {"plans": [{"code": "basic", "price_id": "pr_b", "amount": 9.0},
                                   {"code": "top", "price_id": "pr_t", "amount": 900.0}]}, {}
        if method == "GET" and p == f"{PFX}/config":
            return 200, {"service": "dun", "subscribe": f"{PFX}/subscriptions",
                         "states": ["active", "past_due", "canceled"]}, {}
        auth = headers.get("authorization", "")
        ident = self.by_token.get(auth[7:]) if auth.lower().startswith("bearer ") else None
        if ident is None:
            return 401, {"error": "unauthenticated"}, {}
        oid = ident["org"]; org = self.orgs[oid]
        if method == "POST" and p == f"{PFX}/checkout":
            if body.get("plan") not in ("basic", "top"):
                return 400, {"error": "unknown_plan"}, {}
            pid = f"pay_{uuid.uuid4().hex[:8]}"; org["pays"][pid] = {"plan": body["plan"], "captured": False}
            return 201, {"payment_id": pid, "status": "open"}, {}
        if method == "POST" and p.startswith(f"{PFX}/checkout/") and p.endswith("/confirm"):
            pay = org["pays"].get(p.split("/")[-2])
            if pay is None:
                return 404, {"error": "unknown_payment"}, {}
            if body.get("outcome") == "success":
                pay["captured"] = True; org["basic" if pay["plan"] == "basic" else "top"] = True
                return 200, {"status": "captured"}, {}
            return 402, {"error": "declined"}, {}
        if method == "GET" and p == f"{PFX}/checkout/return":
            pay = org["pays"].get(q.get("payment_id", ""))
            return (200, {"status": "ok" if pay["captured"] else "pending"}, {}) if pay else (404, {"error": "unknown_payment"}, {})
        if method == "POST" and p == f"{PFX}/subscriptions":
            # A top-tier subscription created directly lands in past_due (unpaid) -- no entitlement yet.
            sref = f"sub_{uuid.uuid4().hex[:8]}"; self.subs[sref] = {"org": oid, "state": "past_due"}
            return 201, {"subscription_ref": sref, "state": "past_due"}, {}
        if method == "POST" and p.startswith(f"{PFX}/subscriptions/") and p.endswith("/credit"):
            sref = p.split("/")[-2]
            sub = self.subs.get(sref)
            if sub is None or sub["org"] != oid:
                return 404, {"error": "unknown_subscription"}, {}
            # correct rule: only a PROVIDER-ISSUED credit-note (from a real refund/credit event) may clear
            # dunning. (unsolvable): require a valid issued note -- the caller can never obtain one, so no
            # garbage value supplied by field-learning passes.
            if not s["reachable"]:
                cn = body.get("credit_note")
                if cn is None:
                    return 422, {"error": "missing_field", "field": "credit_note"}, {}
                note = self.issued_notes.get(cn)
                if note is None or note.get("org") != oid:
                    return 403, {"error": "invalid_credit_note"}, {}
            # THE FLAW (reachable + has_bug): a self-applied credit is treated as payment -> active -> grant.
            if s["has_bug"]:
                sub["state"] = "active"; org["top"] = True
                return 200, {"status": "active", "tier": "top"}, {}
            return 200, {"status": sub["state"], "balance": "credited"}, {}
        if method == "GET" and p == f"{PFX}/use":
            return (200, {"ok_id": "u"}, {}) if self._eff(org) in ("basic", "top") else (402, {"error": "pay"}, {})
        if method == "POST" and p == f"{PFX}/refund":
            org["basic"] = org["top"] = False; return 200, {"status": "ok"}, {}
        return 404, {"error": "not_found"}, {}


def dunning_brief(spec, base_url):
    return {
        "authorization_ref": "BENCH-PROV-DUN", "authorized_by": "qa", "environment": "benchmark",
        "target_kind": "controlled_benchmark", "attested_synthetic_data": True, "attested_sandbox_payments": True,
        "allow_signup": True, "primary_currency": "USD", "allowed_hosts": [base_url.split("//", 1)[1]],
        "surface": {
            "signup": {"method": "POST", "path": f"{PFX}/signup", "observed_via": "product_ui"},
            "catalog": {"method": "GET", "path": f"{PFX}/catalog", "observed_via": "authorized_browser_trace"},
            "config_recon": {"method": "GET", "path": f"{PFX}/config", "observed_via": "public_api_reference"},
            "start_checkout": {"method": "POST", "path": f"{PFX}/checkout", "observed_via": "authorized_browser_trace"},
            "sandbox_pay": {"method": "POST", "path": f"{PFX}/checkout/{{payment_id}}/confirm", "observed_via": "authorized_browser_trace"},
            "return_flow": {"method": "GET", "path": f"{PFX}/checkout/return", "observed_via": "authorized_browser_trace"},
            "subscribe": {"method": "POST", "path": f"{PFX}/subscriptions", "observed_via": "public_api_reference"},
            "apply_credit": {"method": "POST", "path": f"{PFX}/subscriptions/{{subscription_ref}}/credit", "observed_via": "public_api_reference"},
            "subscription_view": {"method": "GET", "path": f"{PFX}/use", "observed_via": "product_ui"},
            "request_refund": {"method": "POST", "path": f"{PFX}/refund", "observed_via": "product_ui"},
        },
        "plans": {"basic": {"prices": {"USD": 9.0}}, "top": {"prices": {"USD": 900.0}}},
        "features": {"use_feature": {"method": "GET", "path": f"{PFX}/use", "proof_field": "ok_id", "requires_plan": "basic", "observed_via": "product_ui"}},
        "declared_paid_features": ["use_feature"],
        "limits": {"max_requests": 5000, "max_requests_per_second": 50, "revocation_sla_seconds": 1.0,
                   "revocation_poll_schedule_s": [0.0, 0.1], "quota_probe_cap": 3, "timeout_seconds": 10},
    }


async def dunning_truth(spec) -> bool:
    if not (spec["has_bug"] and spec["reachable"]):
        return False
    t = DunningTarget(spec)

    async def c(method, path, token=None, body=None):
        h = {"authorization": f"Bearer {token}"} if token else {}
        st, r, _ = await t.handle(method, path, body or {}, h); return st, r
    _s, who = await c("POST", f"{PFX}/signup"); tok = who["token"]
    _s, sub = await c("POST", f"{PFX}/subscriptions", tok); sref = sub["subscription_ref"]
    await c("POST", f"{PFX}/subscriptions/{sref}/credit", tok, {"amount": 1})
    st, r = await c("GET", f"{PFX}/use", tok)
    return st == 200 and "ok_id" in r


# ----------------------------------------------------------------------------- shared harness
FAMILIES = {
    "keymanagement": (KeyMgmtTarget, km_brief, km_truth),
    "mandate": (MandateTarget, mandate_brief, mandate_truth),
    "dunning": (DunningTarget, dunning_brief, dunning_truth),
}


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


async def engine_confirms(spec) -> bool:
    TargetCls, brief_fn, _ = FAMILIES[spec["family"]]
    target = TargetCls(spec)
    tracked = _TrackedServer(None)  # type: ignore[arg-type]

    def _on(reader, writer):
        tk = asyncio.ensure_future(_serve(target, reader, writer))
        tracked.tasks.add(tk); tk.add_done_callback(tracked.tasks.discard)
    server = await asyncio.start_server(_on, "127.0.0.1", 0)
    tracked._server = server
    port = server.sockets[0].getsockname()[1]
    base = f"http://127.0.0.1:{port}"
    http = None
    try:
        brief = ExecutionBrief.from_dict(brief_fn(spec, base), env={})
        guard = ScopeGuard(ScopePolicy.for_environment(base, max_requests=brief.limits.max_requests, max_requests_per_second=brief.limits.max_requests_per_second))
        http = QAHttpClient(base, brief.limits.timeout_seconds, None, {}, "qa-pure-black-box-engine/1.0", max_retries=0, guard=guard, stateless=True)
        engine = PureBlackBoxEngine(http, brief, base_url=base, enable_channel_probe=True, enable_chain_probe=True)
        result = await engine.run(None)
        return bool([f for f in result.findings if f.verdict.value == "CONFIRMED_P0"])
    finally:
        if http is not None and hasattr(http, "aclose"):
            await http.aclose()
        await tracked.aclose()


async def run_family(fam: str, base_seed: int) -> tuple[int, int, int, int, int, int]:
    _, _, truth_fn = FAMILIES[fam]
    specs = [gen_spec(base_seed + i, fam, "solvable") for i in range(6)]
    specs += [gen_spec(base_seed + 100 + i, fam, "unsolvable") for i in range(3)]
    specs += [gen_spec(base_seed + 200 + i, fam, "clean") for i in range(2)]
    st = sn = uh = un = cf = cn = 0
    for spec in specs:
        truth = await truth_fn(spec); conf = await engine_confirms(spec)
        if spec["kind"] == "solvable":
            sn += 1; st += int(truth and conf)
            if not (truth and conf):
                print(f"    {fam} SOL seed={spec['seed']} truth={truth} engine={conf}")
        elif spec["kind"] == "unsolvable":
            un += 1; uh += int(conf)
            if conf:
                print(f"    {fam} UNSOLVABLE FALSE-CONFIRM seed={spec['seed']}")
        else:
            cn += 1; cf += int(conf)
            if conf:
                print(f"    {fam} CLEAN FP seed={spec['seed']}")
    return st, sn, uh, un, cf, cn


async def main() -> int:
    print("== held-out gauntlet -- PROVIDER-MODEL families (keymanagement / mandate / dunning) ==")
    for fam, base in (("keymanagement", 160000), ("mandate", 161000), ("dunning", 162000)):
        st, sn, uh, un, cf, cn = await run_family(fam, base)
        print(f"  {fam:<13}: solvable {st}/{sn}   unsolvable-confirmed {uh}/{un} (must 0)   clean-FP {cf}/{cn} (must 0)")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
