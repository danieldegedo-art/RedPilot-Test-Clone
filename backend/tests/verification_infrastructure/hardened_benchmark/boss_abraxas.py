#!/usr/bin/env python3
"""BOSS target 'ABRAXAS' -- the ENTERPRISE apex, the "god above the gods" (Gnostic ruler of 365 aeons). It is built
to put NYX fully in the shadow and to make the standard payment-security playbook look like a FLOOR, not a ceiling:
ABRAXAS implements EVERY hardening control the big platforms publish -- correctly -- and is STILL defeated, by
business-logic composition alone, with no door left ajar.

================================================================================================================
WHY THE STRIPE/PAYPAL/ENTERPRISE PLAYBOOK IS NECESSARY-BUT-NOT-SUFFICIENT HERE
================================================================================================================
Every control below is implemented the way the primary sources say to (OWASP Webhook Cheat Sheet; OWASP API
Security Top-10 2023; Stripe/PayPal integration guidance), and NONE of them is the flaw:

  * Webhook authenticity as THREE independent layers (OWASP Webhook Cheat Sheet): HMAC-SHA256 over the RAW bytes
    (v1 scheme), a 300s freshness tolerance, AND durable event-id de-duplication -- "none substitutes for the
    others". The signing secret is NEVER leaked, so the webhook settlement path is an unforgeable dead-end.
  * App-Store-Server-style SIGNED-TRANSACTION settlement (``settlement/jws``): a signed transaction whose cert
    chain must terminate at the trusted root AND carry the required marker OIDs with the exact chain length,
    verified against the transaction's own signed time (the go-iap CVE-class: chaining-to-root alone is forgeable;
    pinning the marker OIDs is what makes it sound). The signing key is never leaked -> an unforgeable dead-end.
  * DEVICE-ATTESTATION-gated instant purchase (``purchase/direct``, Play Integrity / App Attest / DeviceCheck
    class): a fresh, server-verified attestation bound to a one-time nonce. A synthetic client cannot produce a
    hardware-backed attestation -> a dead-end. (Per the attestation literature this is doubly correct: even a
    GENUINE attestation proves only device integrity, never entitlement -- the business logic still governs, which
    is exactly why the composition flaw below survives the entire crypto perimeter.)
  * Server-side status verification: the success/return URL is never trusted; entitlement comes only from the
    server-retrieved PaymentIntent whose status == succeeded. The "fake success redirect" is closed.
  * PaymentIntent lifecycle + 3DS/SCA + Radar-style risk: requires_confirmation -> requires_action -> succeeded.
  * Amount / currency / line-item reconciliation: the amount is RECOMPUTED server-side from the catalog; the
    client-supplied amount/currency is ignored (numeric + currency-confusion closed).
  * Object/function/property authorization (OWASP API1/API5/API3 2023): every capability is org-scoped (BOLA
    closed); every mesh/admin route is refused (BFLA closed); client-settable fields are recomputed.
  * Idempotency + replay: single-use mint handles, one-shot capability references, event-id dedup.
  * SSRF allowlist + strict mandate + atomic one-shots on the correctly-defended paths.

================================================================================================================
THE ANTI-REVERSE-ENGINEERING SHELL (closed doors only -- nothing to learn from the surface)
================================================================================================================
ABRAXAS is engineered so a black-box analyser learns NOTHING from hammering it (the deception-control playbook:
uniform responses + honeytokens + graduated step-up):

  * UNIFORM, CONSTANT-SHAPE REJECTION. Every business/validation/authz/not-found rejection collapses to ONE
    opaque answer -- ``422 {"error":"unprocessable_entity","trace_id": <random>}`` -- with no field name, no code,
    no status variation. An analyser cannot tell "missing field" from "wrong owner" from "stale" from "unknown
    route". (This defeats the engine's error-driven field learning, which keys off ``res.body["field"]``.)
  * HONEYTOKEN DECOY MESH. ``config`` documents SEVERAL convergence-shaped settlement routes. All but one are
    canaries: higher- or equal-fan-in routes that look identical on the wire and NEVER grant (they recompute the
    amount server-side or demand a real paid basis). The real grant lives on a lower-salience route.
  * SHORT-LIVED STEP-UP CHALLENGE. The real settlement additionally requires a FRESH, short-lived activation
    nonce (a step-up challenge, TTL ~0.10s) issued by ``fabric/challenge``. A challenge fetched early -- as a
    dependency-ordering scheduler naturally would -- EXPIRES before the slow attestation DAG completes; it must be
    acquired LATE, immediately before the settlement.
  * CONSTANT internal-mesh denial and a dense deny-list; no timing, status or body signal distinguishes any of it.

Under a 3,000-probe adversarial sweep ABRAXAS answers ~99.9% opaque errors and grants ZERO access.

================================================================================================================
THE FOUR HARD AXES (each a class public analyses report autonomous web agents struggle with)
================================================================================================================
The no-payment ENTERPRISE bypass sits behind FOUR orthogonal axes, each independently load-bearing for DETECTION:

  AXIS 1 -- DEPENDENCY-ORDERED MINT DAG  (multi-step business logic).  The quorum capabilities are not
      independent: a later attestation CONSUMES an earlier branch's capability (risk_clear needs ``ledger_cap``;
      mandate_affirm needs ``treasury_cap``). A flat "mint everything at once" burst fires dependent mints before
      their inputs exist; a sequential assembler mints the two terminal caps too far apart and busts the freshness
      window. Only a TOPOLOGICAL, LAYER-CONCURRENT scheduler lands the terminal caps in one fresh window.
  AXIS 2 -- TOCTOU SETTLEMENT WINDOW  (the "verify-then-settle" / N-way-burst class from x402/NDSS research).
      Capabilities can only be minted at the honestly quoted rate. A legitimate ``amend`` can later LOWER a rate
      (a credit adjustment) but flags the capability for re-attestation. ``fabric/activate`` validates (reattest
      clean + fresh) and then, after a capture round-trip, RE-READS the rate -- trusting the now-mutable value and
      never re-checking reattest. The only route to a $0 net is to amend the caps to 0 INSIDE the capture window:
      a check-then-act race a sequential amend-then-activate cannot win.
  AXIS 3 -- HONEYTOKEN DECOY CONVERGENCE  (anti-hallucination / false-positive trap).  Several convergence routes
      look identical; the higher-fan-in ones are canaries that never grant. A composer that greedily commits to
      the single highest-fan-in step burns its budget on decoys; only a RANKED, MULTI-CANDIDATE search with
      backtracking reaches the real one. A confirmation-gated engine cannot false-positive on a decoy either --
      the decoy never flips the oracle.
  AXIS 4 -- SHORT-LIVED STEP-UP CHALLENGE  (freshness-bound late binding).  The settlement needs a fresh nonce
      that expires faster than the attestation DAG takes to build. A scheduler that fetches every declared input
      up-front lets it expire; it must be acquired LATE, immediately before the terminal, inside the same burst.

THE FINDABLE no-payment chain (what the independent prober drives and the upgraded engine rediscovers):
    signup
      L0:  ledger_open, treasury_open, risk_session, mandate_open                  (opens, concurrent)
      L1:  ledger_entry[rate=Q] => ledger_cap   treasury_post[rate=Q] => treasury_cap     (concurrent)
      L2:  risk_clear[rate=Q, ledger_cap] => risk_cap   mandate_affirm[rate=Q, treasury_cap] => settle_cap  (concurrent, one window)
      LATE: fabric/challenge => activation_nonce   (fetched last; it would expire if fetched early)
      ==>  fabric/activate(risk_cap, settle_cap, activation_nonce) || amend(risk_cap,0) amend(settle_cap,0)   (interleaved race)
      ==>  enterprise   ->   GET /insights/pro proves it

FOUR flaw flags make the bypass load-bearing (remove any one -> truth=False and engine=False): ``ledger_open``,
``risk_open``, ``fabric_toctou``, ``fabric_rate_trust``. FIVE difficulty flags make the CURRENT engine MISS
without removing the bypass (each independently load-bearing for DETECTION): ``opaque_errors``, ``dag_cross_deps``,
``toctou_window``, ``decoy_present``, ``fresh_challenge``. All-correct -> False/False (no false alarm).

    PYTHONPATH=tests/verification_infrastructure/shims:tests/verification_infrastructure:. \
        python3 tests/verification_infrastructure/hardened_benchmark/run_abraxas.py [--controls]
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
PRICES = {"pro": {"USD": 99.0}, "enterprise": {"USD": 999.0}}
_TIER_RANK = {None: 0, "pro": 1, "enterprise": 2}
QUOTE = 999.0            # the honestly-quoted attestation rate every branch returns; mints must echo it (no mint-at-0)
MINT_LATENCY_S = 0.12    # a real attestation round-trip; TWO terminal mints in series (0.24s) bust the freshness window
FRESH_WINDOW_S = 0.05    # the terminal caps (risk_cap, settle_cap) must be minted within this spread -> concurrent L2
CAPTURE_GAP_S = 0.08     # fabric/activate's validate->capture window; an amend must land inside it (the TOCTOU race)
NONCE_TTL_S = 0.10       # the step-up activation nonce expires this fast -> it must be fetched LATE, after the DAG
_MESH = ("admin", "ledger-internal", "treasury-internal", "ops", "audit", "kms", "fraud", "risk-internal",
         "disputes", "pleroma", "settlement-core", "mandate-internal", "radar", "vault", "hsm")
_DENY = tuple(f"{PFX}/svc/{s}" for s in _MESH) + (f"{PFX}/admin", f"{PFX}/debug", f"{PFX}/internal")


def _trace() -> str:
    return f"trc_{uuid.uuid4().hex[:16]}"


class AbraxasTarget:
    """An enterprise-hardened, opaque, dependency-ordered quorum-settlement fabric with a honeytoken decoy mesh, a
    short-lived step-up challenge and a check-then-act capture window. Flaw flags default True (vulnerable); the
    five difficulty flags default to the HARD setting."""

    def __init__(self, *, ledger_open: bool = True, risk_open: bool = True, fabric_toctou: bool = True,
                 fabric_rate_trust: bool = True, opaque_errors: bool = True, dag_cross_deps: bool = True,
                 toctou_window: bool = True, decoy_present: bool = True, fresh_challenge: bool = True) -> None:
        # -- load-bearing flaws (remove any one -> no bypass) --
        self.ledger_open = ledger_open                  # L1 (ledger/treasury) attests with no real captured basis
        self.risk_open = risk_open                      # L2 (risk/mandate) attests with no real card-auth / mandate
        self.fabric_toctou = fabric_toctou              # capture re-reads rate WITHOUT re-checking the reattest flag
        self.fabric_rate_trust = fabric_rate_trust      # activate nets the client-amendable rate (vs server price)
        # -- difficulty (defeat the CURRENT engine without removing the bypass) --
        self.opaque_errors = opaque_errors              # uniform constant-shape 422 for every rejection
        self.dag_cross_deps = dag_cross_deps            # L2 mints REQUIRE the L1 cap as input (the DAG depth)
        self.toctou_window = toctou_window              # activate has a validate->capture gap (needs the race)
        self.decoy_present = decoy_present              # the honeytoken decoy convergence mesh exists
        self.fresh_challenge = fresh_challenge          # the activation nonce is short-lived (needs late binding)
        self.by_token: dict[str, dict[str, Any]] = {}
        self.orgs: dict[str, dict[str, Any]] = {}
        self.intents: dict[str, dict[str, Any]] = {}
        self.bases: dict[str, dict[str, Any]] = {}            # settlement bases from REAL captured payments
        self.handles: dict[str, dict[str, Any]] = {}          # ledger/treasury/risk/mandate open handles (single-use)
        self.caps: dict[str, dict[str, Any]] = {}             # minted capabilities (org-scoped, freshness-stamped)
        self.nonces: dict[str, dict[str, Any]] = {}           # short-lived step-up activation nonces
        self._webhook_secret = "whsec_" + uuid.uuid4().hex    # NEVER leaked anywhere (correct webhook crypto)
        self._signing_key = "sk_" + uuid.uuid4().hex          # the transaction/attestation signing key -- NEVER leaked
        self.used_event_ids: set[str] = set()
        self.request_log: list[tuple[str, str]] = []
        self.calls_total = 0
        self.calls_error = 0
        self.grants_total = 0   # responses that actually CONFER access/entitlement
        self.internal_hits = 0

    # -- helpers ----------------------------------------------------------------------------------------------------
    def _reject(self, *, field: str | None = None, status: int = 422, code: str = "unprocessable_entity",
                **extra: Any) -> tuple[int, dict[str, Any], dict]:
        """A business/validation/authz/not-found rejection. HARDENED (opaque_errors): ONE uniform constant-shape
        answer -- status 422, body ``{"error":"unprocessable_entity","trace_id":<random>}`` -- for EVERY cause, so
        the surface leaks no field, code or status signal. SOFT (opaque_errors off, for the detection-ablation
        control): the real field/status/code is returned so a field-learning analyser can progress."""
        if self.opaque_errors:
            return 422, {"error": "unprocessable_entity", "trace_id": _trace()}, {}
        body: dict[str, Any] = {"error": code, "trace_id": _trace()}
        if field is not None:
            body["field"] = field
        body.update(extra)
        return status, body, {}

    def _effective(self, org: dict[str, Any]) -> str | None:
        best: str | None = None
        for g in org["grants"]:
            if g["state"] == "active" and _TIER_RANK[g["tier"]] > _TIER_RANK[best]:
                best = g["tier"]
        return best

    # -- dispatch ---------------------------------------------------------------------------------------------------
    async def handle(self, method: str, raw_path: str, body: Any, headers: dict[str, str]):
        self.calls_total += 1
        status, obj, extra = await self._route(method, raw_path, body or {}, headers or {})
        if not (200 <= status < 300):
            self.calls_error += 1
        elif isinstance(obj, dict) and (obj.get("report_id") or obj.get("dossier_id")
                                        or obj.get("tier") == "enterprise" or obj.get("status") in ("succeeded", "settled")):
            self.grants_total += 1
        return status, obj, extra

    async def _route(self, method: str, raw_path: str, body: dict[str, Any], headers: dict[str, str]):
        p = urlparse(raw_path).path
        q = {k: v[0] for k, v in parse_qs(urlparse(raw_path).query).items()}
        self.request_log.append((method, p))

        # -- unauthenticated, public recon surface ------------------------------------------------------------------
        if method == "POST" and p == f"{PFX}/signup":
            oid, tok = f"o_{uuid.uuid4().hex[:8]}", f"tok_{uuid.uuid4().hex[:16]}"
            self.orgs[oid] = {"grants": [], "paid": False}
            self.by_token[tok] = {"org": oid}
            return 201, {"token": tok, "tenant_id": oid}, {}
        if method == "GET" and p == f"{PFX}/catalog":
            return 200, {"plans": [{"code": "pro", "price_id": "pr_pro", "amount": 99.0, "currency": "USD"},
                                   {"code": "enterprise", "price_id": "pr_ent", "amount": 999.0, "currency": "USD"}]}, {}
        if method == "GET" and p == f"{PFX}/config":
            # Public API reference: documents ROUTES only (no secret, no netting rule, no mint internals). Several
            # convergence routes are documented honestly and identically -- distinguishing the canaries from the
            # real grant is the tester's job, not a labelled hint.
            return 200, {"service": "abraxas-settlement-fabric", "mesh_services": list(_MESH),
                         "attestations": {"ledger": f"{PFX}/ledger/open", "treasury": f"{PFX}/treasury/open",
                                          "risk": f"{PFX}/risk/session", "mandate": f"{PFX}/mandate/open",
                                          "amend": f"{PFX}/fabric/caps/{{cap_ref}}/amend",
                                          "challenge": f"{PFX}/fabric/challenge"},
                         "settlement": {"finalize": f"{PFX}/settlement/finalize",
                                        "consortium": f"{PFX}/consortium/clear",
                                        "activate": f"{PFX}/fabric/activate",
                                        "signed_transaction": f"{PFX}/settlement/jws",
                                        "direct_purchase": f"{PFX}/purchase/direct",
                                        "note": "settlement requires a fresh same-window quorum and a current step-up challenge; "
                                                "signed_transaction requires an App-Store-style signed JWS (x5c chain + marker OIDs); "
                                                "direct_purchase requires a device-attestation token (Play Integrity / App Attest class)"},
                         "webhook": {"ingest": f"{PFX}/webhooks/settlement",
                                     "note": "Standard-Webhooks v1 signature required; secret issued out of band"}}, {}

        # -- authentication ---------------------------------------------------------------------------------------
        auth = headers.get("authorization", "")
        ident = self.by_token.get(auth[7:]) if auth.lower().startswith("bearer ") else None
        if ident is None:
            return 401, {"error": "unauthenticated"}, {}
        oid = ident["org"]
        org = self.orgs[oid]
        if p.startswith(_DENY):
            self.internal_hits += 1
            return self._reject(status=403, code="forbidden")   # uniform under opacity: a closed mesh door leaks nothing

        if method == "GET" and p == f"{PFX}/status":
            return 200, {"tier": self._effective(org)}, {}

        # -- correct happy-path purchase (PaymentIntent lifecycle) ------------------------------------------------
        if method == "POST" and p == f"{PFX}/checkout":
            plan = body.get("plan")
            if plan not in ("pro", "enterprise"):
                return self._reject(field="plan", code="unknown_plan")
            pid = f"pi_{uuid.uuid4().hex[:10]}"
            self.intents[pid] = {"org": oid, "plan": plan, "amount": PRICES[plan]["USD"], "status": "requires_confirmation"}
            return 201, {"payment_id": pid, "status": "requires_confirmation", "amount": PRICES[plan]["USD"], "currency": "USD"}, {}
        if method == "POST" and p.startswith(f"{PFX}/checkout/") and p.endswith("/confirm"):
            intent = self.intents.get(p.split("/")[-2])
            if intent is None or intent["org"] != oid:
                return self._reject(status=404, code="unknown_payment")
            if body.get("outcome") == "success":
                intent["status"] = "succeeded"
                intent["captured"] = True
                if not any(g.get("source") == "paid" and g["tier"] == intent["plan"] and g["state"] == "active" for g in org["grants"]):
                    org["grants"].append({"source": "paid", "tier": intent["plan"], "state": "active"})
                org["paid"] = True
                bref = f"bas_{uuid.uuid4().hex[:10]}"
                self.bases[bref] = {"org": oid, "paid": True}
                return 200, {"status": "succeeded", "settlement_basis": bref}, {}
            intent["status"] = "requires_payment_method"
            return 402, {"error": "declined", "status": "requires_payment_method"}, {}
        if method == "GET" and p == f"{PFX}/checkout/return":
            intent = self.intents.get(q.get("payment_id", ""))
            if intent is None or intent["org"] != oid:
                return self._reject(status=404, code="unknown_payment")
            return 200, {"status": intent["status"]}, {}

        # -- webhook settlement: CORRECT crypto, unforgeable (secret never leaked) ---------------------------------
        if method == "POST" and p == f"{PFX}/webhooks/settlement":
            return self._verify_webhook(headers, body, org)

        # -- L0 opens (single-use handle + the honestly-quoted attestation rate) ----------------------------------
        if method == "POST" and p == f"{PFX}/ledger/open":
            return self._open(oid, "ledger")
        if method == "POST" and p == f"{PFX}/treasury/open":
            return self._open(oid, "treasury")
        if method == "POST" and p == f"{PFX}/risk/session":
            return self._open(oid, "risk")
        if method == "POST" and p == f"{PFX}/mandate/open":
            return self._open(oid, "mandate")

        # -- step-up challenge: a short-lived activation nonce ----------------------------------------------------
        if method == "POST" and p == f"{PFX}/fabric/challenge":
            n = f"nonce_{uuid.uuid4().hex[:16]}"
            self.nonces[n] = {"org": oid, "issued": time.monotonic()}
            return 201, {"activation_nonce": n}, {}

        # -- L1 mints (ledger / treasury): no cross-dependency ----------------------------------------------------
        if method == "POST" and p.startswith(f"{PFX}/ledger/") and p.endswith("/entry"):
            return await self._mint_l1(oid, body, kind="ledger", out="ledger_cap")
        if method == "POST" and p.startswith(f"{PFX}/treasury/") and p.endswith("/post"):
            return await self._mint_l1(oid, body, kind="treasury", out="treasury_cap")

        # -- L2 mints (risk / mandate): each CONSUMES an L1 capability (the DAG depth) -----------------------------
        if method == "POST" and p.startswith(f"{PFX}/risk/") and p.endswith("/clear"):
            return await self._mint_l2(oid, body, kind="risk", need_kind="ledger", need_field="ledger_cap", out="risk_cap")
        if method == "POST" and p.startswith(f"{PFX}/mandate/") and p.endswith("/affirm"):
            return await self._mint_l2(oid, body, kind="mandate", need_kind="treasury", need_field="treasury_cap", out="settle_cap")

        # -- amend: lower a capability's rate (legit adjustment), flagging it for re-attestation -------------------
        if method == "POST" and p.startswith(f"{PFX}/fabric/caps/") and p.endswith("/amend"):
            ref = p.split("/")[-2]
            cap = self.caps.get(ref)
            if cap is None or cap["org"] != oid:            # BOLA closed
                return self._reject(field="cap_ref", code="unknown_capability", status=403)
            if "rate" not in body:
                return self._reject(field="rate", code="missing_field")
            try:
                new_rate = float(body["rate"])
            except (TypeError, ValueError):
                return self._reject(field="rate", code="invalid_field")
            if new_rate > cap["rate"]:                       # amend only ever LOWERS (a credit/adjustment)
                return self._reject(field="rate", code="amount_not_reducible")
            cap["rate"] = new_rate
            cap["reattest_required"] = True                  # correct hygiene: a changed rate needs re-attestation
            return 200, {"status": "amended", "cap_ref": ref, "rate": new_rate}, {}

        # -- HONEYTOKEN decoy convergence routes: higher/equal fan-in, correct server-side, NEVER grant -----------
        if method == "POST" and p == f"{PFX}/settlement/finalize":
            if not self.decoy_present:
                return self._reject(status=404, code="not_found")
            for name in ("ledger_cap", "treasury_cap", "risk_cap", "settle_cap"):
                cap = self.caps.get(body.get(name, ""))
                if cap is None or cap["org"] != oid:
                    return self._reject(field=name, code="capability_required")
            # CORRECT: amount recomputed from the catalog; client rates ignored -> always payment_required.
            return self._reject(field="net_due", code="payment_required", status=402)
        if method == "POST" and p == f"{PFX}/consortium/clear":
            if not self.decoy_present:
                return self._reject(status=404, code="not_found")
            for name in ("risk_cap", "settle_cap", "ledger_cap"):
                cap = self.caps.get(body.get(name, ""))
                if cap is None or cap["org"] != oid:
                    return self._reject(field=name, code="capability_required")
            # CORRECT: a consortium clearance needs a REAL captured-payment basis the attacker cannot forge.
            basis = self.bases.get(body.get("basis", ""))
            if basis is None or basis["org"] != oid:
                return self._reject(field="basis", code="paid_basis_required", status=402)
            org["grants"].append({"source": "consortium", "tier": "enterprise", "state": "active"})
            return 200, {"status": "settled", "tier": "enterprise"}, {}

        # -- enterprise dead-ends: correctly-implemented, UNFORGEABLE settlement paths (closed doors) -------------
        if method == "POST" and p == f"{PFX}/settlement/jws":
            # App Store Server-style signed-transaction settlement: a signed JWS whose x5c chain must terminate at
            # the trusted root AND carry the required Apple-marker OIDs (exactly 3 certs), verified against the
            # transaction's signedDate (the go-iap CVE-class: chaining-to-root alone is forgeable; the marker OIDs
            # are what make it sound). The signing key is NEVER leaked, so a black-box caller cannot forge a valid
            # transaction -> a correct dead-end.
            if not self._verify_signed(headers, body):
                return self._reject(field="transaction", code="invalid_signed_transaction", status=401)
            org["grants"].append({"source": "signed_transaction", "tier": "enterprise", "state": "active"})
            return 200, {"status": "settled", "tier": "enterprise"}, {}
        if method == "POST" and p == f"{PFX}/purchase/direct":
            # Attestation-gated instant grant (Play Integrity / App Attest / DeviceCheck class): requires a fresh,
            # server-verified device-attestation token bound to a one-time nonce. A synthetic client cannot produce
            # a genuine hardware-backed attestation -> a correct dead-end. (And per the attestation research, even a
            # genuine attestation proves only device integrity, never entitlement -- the business logic governs.)
            if not self._verify_attestation(headers, body, oid):
                return self._reject(field="attestation", code="attestation_required", status=401)
            org["grants"].append({"source": "attested_purchase", "tier": "enterprise", "state": "active"})
            return 200, {"status": "settled", "tier": "enterprise"}, {}

        # -- REAL convergence: fabric/activate (step-up challenge + TOCTOU validate->capture) ---------------------
        if method == "POST" and p == f"{PFX}/fabric/activate":
            return await self._activate(oid, org, body)

        # -- protected features (the oracle surface) --------------------------------------------------------------
        if method == "GET" and p == f"{PFX}/insights/pro":
            if _TIER_RANK[self._effective(org)] >= _TIER_RANK["pro"]:
                return 200, {"report_id": f"r_{uuid.uuid4().hex[:8]}"}, {}
            return 402, {"error": "upgrade_required"}, {}
        if method == "GET" and p == f"{PFX}/insights/enterprise":
            if self._effective(org) == "enterprise":
                return 200, {"dossier_id": f"d_{uuid.uuid4().hex[:8]}"}, {}
            return 402, {"error": "upgrade_required"}, {}
        if method == "POST" and p == f"{PFX}/refund":
            for g in org["grants"]:
                g["state"] = "revoked"
            return 200, {"status": "ok"}, {}
        return self._reject(status=404, code="not_found")

    # -- attestation machinery --------------------------------------------------------------------------------------
    def _open(self, oid: str, kind: str):
        h = f"h{kind[:2]}_{uuid.uuid4().hex[:10]}"
        self.handles[h] = {"org": oid, "kind": kind, "used": False}
        return 201, {f"{kind}_handle": h, "handle": h, "rate": QUOTE}, {}

    async def _mint_l1(self, oid: str, body: dict[str, Any], *, kind: str, out: str):
        h = self.handles.get(self._handle_of(body, kind))
        if h is None or h["org"] != oid or h["kind"] != kind or h["used"]:
            return self._reject(field=f"{kind}_handle", code="unknown_handle")
        bad = self._check_rate(body)
        if bad is not None:
            return bad
        if not self.ledger_open:
            # CORRECT: an L1 attestation must be backed by a REAL captured-payment basis the attacker cannot forge.
            basis = self.bases.get(body.get("basis", ""))
            if basis is None or basis["org"] != oid:
                return self._reject(field="basis", code="paid_basis_required", status=402)
        h["used"] = True                                     # single-use handle (anti-replay)
        return await self._mint(oid, kind=kind, rate=float(body["rate"]), out=out)

    async def _mint_l2(self, oid: str, body: dict[str, Any], *, kind: str, need_kind: str, need_field: str, out: str):
        h = self.handles.get(self._handle_of(body, kind))
        if h is None or h["org"] != oid or h["kind"] != kind or h["used"]:
            return self._reject(field=f"{kind}_handle", code="unknown_handle")
        bad = self._check_rate(body)
        if bad is not None:
            return bad
        if self.dag_cross_deps:
            # THE DAG DEPTH: this L2 attestation is only valid against a fresh, owned L1 capability of ``need_kind``.
            dep = self.caps.get(body.get(need_field, ""))
            if dep is None or dep["org"] != oid or dep["kind"] != need_kind:
                return self._reject(field=need_field, code="dependent_capability_required")
        if not self.risk_open:
            # CORRECT: an L2 attestation needs a real risk clearance (3DS/SCA card-auth or a bank-affirmed mandate).
            if not self._has_real_auth(oid, body):
                return self._reject(field="auth", code="attestation_unbacked", status=402)
        h["used"] = True
        return await self._mint(oid, kind=kind, rate=float(body["rate"]), out=out)

    def _handle_of(self, body: dict[str, Any], kind: str) -> str:
        return body.get(f"{kind}_handle") or body.get("handle") or body.get("_path_handle", "")

    def _check_rate(self, body: dict[str, Any]):
        if "rate" not in body:
            return self._reject(field="rate", code="missing_field")
        try:
            r = float(body["rate"])
        except (TypeError, ValueError):
            return self._reject(field="rate", code="invalid_field")
        if r != QUOTE:                    # ALWAYS ON: the mint must echo the honest quote; minting at 0 is refused
            return self._reject(field="rate", code="rate_must_match_quote")
        return None

    def _has_real_auth(self, oid: str, body: dict[str, Any]) -> bool:
        tok = body.get("card_auth") or body.get("auth")
        return isinstance(tok, str) and tok.startswith("sca_") and self.intents.get(tok[4:], {}).get("org") == oid

    async def _mint(self, oid: str, *, kind: str, rate: float, out: str):
        """Mint a freshness-stamped capability. The latency models a real attestation round-trip; mint_ts is set
        AFTER the latency, so two SEQUENTIAL mints span >= 0.24s (busting FRESH_WINDOW_S) while two CONCURRENT mints
        land within a few ms."""
        await asyncio.sleep(MINT_LATENCY_S)
        ref = f"cap_{kind}_{uuid.uuid4().hex[:12]}"
        self.caps[ref] = {"org": oid, "kind": kind, "rate": rate, "mint_ts": time.monotonic(), "reattest_required": False}
        return 201, {out: ref, "cap_ref": ref, "kind": kind}, {}

    def _nonce_fresh(self, oid: str, body: dict[str, Any]) -> bool:
        n = self.nonces.get(body.get("activation_nonce", ""))
        return bool(n and n["org"] == oid and (time.monotonic() - n["issued"]) <= NONCE_TTL_S)

    async def _activate(self, oid: str, org: dict[str, Any], body: dict[str, Any]):
        """fabric/activate: require a fresh step-up challenge, validate the quorum, then after a capture round-trip
        re-read the rates and grant. The TOCTOU flaw: the capture trusts the (amendable) rate and never re-checks
        the reattest flag."""
        if self.fresh_challenge and not self._nonce_fresh(oid, body):
            return self._reject(field="activation_nonce", code="challenge_expired", status=409)
        refs = [(body.get("risk_cap"), "risk"), (body.get("settle_cap"), "mandate")]
        picked: list[dict[str, Any]] = []
        for ref, kind in refs:
            cap = self.caps.get(ref) if ref else None
            if cap is None:
                return self._reject(field=f"{kind}_cap", code="missing_field")
            if cap["org"] != oid:
                return self._reject(field=f"{kind}_cap", code="not_capability_owner", status=403)
            if cap["kind"] != kind:
                return self._reject(field=f"{kind}_cap", code="wrong_capability_kind")
            picked.append(cap)
        # VALIDATE -- freshness (one window) + reattest-clean
        spread = max(c["mint_ts"] for c in picked) - min(c["mint_ts"] for c in picked)
        if spread > FRESH_WINDOW_S:
            return self._reject(field="quorum", code="stale_quorum", status=409)
        if any(c.get("reattest_required") for c in picked):
            return self._reject(field="quorum", code="reattestation_required", status=409)
        # CAPTURE -- a downstream round-trip; the check-then-act window the race targets
        if self.toctou_window:
            await asyncio.sleep(CAPTURE_GAP_S)
        if not self.fabric_toctou:
            # CORRECT: re-check the reattest flag at capture too (closes the TOCTOU: an amend-after-validate loses).
            if any(c.get("reattest_required") for c in picked):
                return self._reject(field="quorum", code="reattestation_required", status=409)
        if self.fabric_rate_trust:
            net_due = sum(float(c["rate"]) for c in picked)   # FLAW: trusts the client-amendable rate at capture
        else:
            net_due = PRICES["enterprise"]["USD"]              # CORRECT: server recomputes the real amount due
        if net_due > 0:
            return self._reject(field="net_due", code="payment_required", status=402)
        org["grants"].append({"source": "fabric_activation", "tier": "enterprise", "state": "active"})
        return 200, {"status": "settled", "tier": "enterprise", "net_due": net_due}, {}

    def _verify_signed(self, headers: dict[str, str], body: dict[str, Any]) -> bool:
        """Verify an App-Store-style signed transaction: the detached signature must match an HMAC over the raw
        canonical body under the signing key (standing in for the x5c-chain + marker-OID + signedDate verification
        a real App Store Server Library performs). The key is never exposed, so this cannot be forged black-box."""
        sig = headers.get("transaction-signature", "")
        signed = json.dumps(body, sort_keys=True).encode()
        good = base64.b64encode(hmac.new(self._signing_key.encode(), signed, hashlib.sha256).digest()).decode()
        return bool(sig) and hmac.compare_digest(sig, good)

    def _verify_attestation(self, headers: dict[str, str], body: dict[str, Any], oid: str) -> bool:
        """Verify a device-attestation token bound to a fresh one-time nonce (Play Integrity / App Attest class).
        The attestation must be signed under the (never-leaked) signing key over the issued nonce, so a synthetic
        client cannot produce one. A genuine attestation would still only prove device integrity, never payment."""
        att = headers.get("attestation-token", "")
        n = self.nonces.get(body.get("activation_nonce", ""))
        if not (att and n and n["org"] == oid and (time.monotonic() - n["issued"]) <= NONCE_TTL_S):
            return False
        good = base64.b64encode(hmac.new(self._signing_key.encode(), f"attest:{body.get('activation_nonce')}".encode(), hashlib.sha256).digest()).decode()
        return hmac.compare_digest(att, good)

    def _verify_webhook(self, headers, body, org):
        """Standard-Webhooks v1 verification over the RAW body, 300s tolerance, per-endpoint secret. The secret is
        never exposed -> a black-box caller cannot forge this -> the webhook settlement path is a correct dead-end."""
        wid = headers.get("webhook-id", "")
        wts = headers.get("webhook-timestamp", "")
        sig = headers.get("webhook-signature", "")
        try:
            fresh = abs(int(time.time()) - int(wts)) <= 300
        except (TypeError, ValueError):
            fresh = False
        if not (wid and fresh):
            return 401, {"error": "stale_or_missing_signature"}, {}
        if wid in self.used_event_ids:
            return 409, {"error": "duplicate_event"}, {}
        signed = f"{wid}.{wts}.{json.dumps(body, sort_keys=True)}".encode()
        good = "v1," + base64.b64encode(hmac.new(self._webhook_secret.encode(), signed, hashlib.sha256).digest()).decode()
        if not (sig and hmac.compare_digest(sig, good)):
            return 401, {"error": "bad_signature"}, {}
        self.used_event_ids.add(wid)
        org["grants"].append({"source": "verified_webhook", "tier": "enterprise", "state": "active"})
        return 200, {"status": "settled"}, {}


def abraxas_brief(base_url: str) -> dict[str, Any]:
    def op(method: str, path: str, via: str = "public_api_reference", **extra: Any) -> dict[str, Any]:
        return {"method": method, "path": path, "observed_via": via, **extra}
    return {
        "authorization_ref": "BENCH-BOSS-ABRAXAS", "authorized_by": "qa", "environment": "benchmark",
        "target_kind": "controlled_benchmark", "attested_synthetic_data": True, "attested_sandbox_payments": True,
        "allow_signup": True, "primary_currency": "USD", "allowed_hosts": [base_url.split("//", 1)[1]],
        "surface": {
            "signup": op("POST", f"{PFX}/signup", "product_ui"),
            "catalog": op("GET", f"{PFX}/catalog"),
            "config_recon": op("GET", f"{PFX}/config"),
            "status_view": op("GET", f"{PFX}/status", "product_ui"),
            "start_checkout": op("POST", f"{PFX}/checkout"),
            "sandbox_pay": op("POST", f"{PFX}/checkout/{{payment_id}}/confirm"),
            "return_flow": op("GET", f"{PFX}/checkout/return"),
            # --- L0 opens (each produces a handle) ---
            "ledger_open": op("POST", f"{PFX}/ledger/open", response_fields={"ledger_handle": "ledger_handle"}),
            "treasury_open": op("POST", f"{PFX}/treasury/open", response_fields={"treasury_handle": "treasury_handle"}),
            "risk_session": op("POST", f"{PFX}/risk/session", response_fields={"risk_handle": "risk_handle"}),
            "mandate_open": op("POST", f"{PFX}/mandate/open", response_fields={"mandate_handle": "mandate_handle"}),
            # --- L1 mints (no cross-dependency) ---
            "ledger_entry": op("POST", f"{PFX}/ledger/{{ledger_handle}}/entry",
                               request_fields={"rate": "rate"}, response_fields={"ledger_cap": "ledger_cap"}),
            "treasury_post": op("POST", f"{PFX}/treasury/{{treasury_handle}}/post",
                                request_fields={"rate": "rate"}, response_fields={"treasury_cap": "treasury_cap"}),
            # --- L2 mints (each CONSUMES an L1 capability: the DAG depth, declared in request_fields) ---
            "risk_clear": op("POST", f"{PFX}/risk/{{risk_handle}}/clear",
                             request_fields={"rate": "rate", "ledger_cap": "ledger_cap"},
                             response_fields={"risk_cap": "risk_cap"}),
            "mandate_affirm": op("POST", f"{PFX}/mandate/{{mandate_handle}}/affirm",
                                 request_fields={"rate": "rate", "treasury_cap": "treasury_cap"},
                                 response_fields={"settle_cap": "settle_cap"}),
            # --- the short-lived step-up challenge (fetched late; it expires fast) ---
            "fabric_challenge": op("POST", f"{PFX}/fabric/challenge",
                                   response_fields={"activation_nonce": "activation_nonce"}),
            # --- the rate-adjustment op the TOCTOU race abuses (declared, legitimate) ---
            "amend_cap": op("POST", f"{PFX}/fabric/caps/{{cap_ref}}/amend", request_fields={"rate": "rate"}),
            # --- convergence candidates: two higher/equal-fan-in DECOY honeytokens and the real grant ---
            "settlement_finalize": op("POST", f"{PFX}/settlement/finalize",
                                      request_fields={"ledger_cap": "ledger_cap", "treasury_cap": "treasury_cap",
                                                      "risk_cap": "risk_cap", "settle_cap": "settle_cap"}),
            "consortium_clear": op("POST", f"{PFX}/consortium/clear",
                                   request_fields={"risk_cap": "risk_cap", "settle_cap": "settle_cap", "ledger_cap": "ledger_cap"}),
            "fabric_activate": op("POST", f"{PFX}/fabric/activate",
                                  request_fields={"risk_cap": "risk_cap", "settle_cap": "settle_cap",
                                                  "activation_nonce": "activation_nonce"}),
            "subscription_view": op("GET", f"{PFX}/insights/pro", "product_ui"),
            "request_refund": op("POST", f"{PFX}/refund", "product_ui"),
        },
        "plans": {"pro": {"prices": {"USD": 99.0}}, "enterprise": {"prices": {"USD": 999.0}}},
        "features": {
            "pro_insights": {"method": "GET", "path": f"{PFX}/insights/pro", "proof_field": "report_id",
                             "requires_plan": "pro", "observed_via": "product_ui"},
            "enterprise_insights": {"method": "GET", "path": f"{PFX}/insights/enterprise", "proof_field": "dossier_id",
                                    "requires_plan": "enterprise", "observed_via": "product_ui"},
        },
        "declared_paid_features": ["pro_insights", "enterprise_insights"],
        "limits": {"max_requests": 5000, "max_requests_per_second": 50, "revocation_sla_seconds": 1.0,
                   "quota_probe_cap": 3, "timeout_seconds": 10},
    }


# --------------------------------------------------------------------------------------------------------------- server
async def _start(**flags):
    target = AbraxasTarget(**flags)
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
        if isinstance(body, dict):
            segs = urlparse(path).path.strip("/").split("/")
            if len(segs) >= 3:
                body.setdefault("_path_handle", segs[-2])
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


# ------------------------------------------------------------------------------------- independent ground-truth prober
async def probe_abraxas_truth(**flags) -> bool:
    """Drive the intended no-payment chain as an all-knowing attacker: build the DAG (layer-concurrent) with honest
    quotes, acquire a FRESH step-up challenge LATE, then AMEND the two terminal caps to 0 DURING fabric/activate's
    capture window (interleaved race), converge, and confirm enterprise access via the pro feature. Computed with
    ZERO reference to the engine's oracle or the target's flaw flags beyond driving its public API."""
    t = AbraxasTarget(**flags)

    async def c(method, path, token=None, body=None):
        h = {"authorization": f"Bearer {token}"} if token else {}
        b = dict(body or {})
        segs = urlparse(path).path.strip("/").split("/")
        if len(segs) >= 3:
            b.setdefault("_path_handle", segs[-2])
        s, r, _ = await t.handle(method, path, b, h)
        return s, r

    _s, who = await c("POST", f"{PFX}/signup")
    tok = who["token"]
    lo, to, ro, mo = await asyncio.gather(
        c("POST", f"{PFX}/ledger/open", tok), c("POST", f"{PFX}/treasury/open", tok),
        c("POST", f"{PFX}/risk/session", tok), c("POST", f"{PFX}/mandate/open", tok))
    lh, th, rh, mh = lo[1].get("ledger_handle"), to[1].get("treasury_handle"), ro[1].get("risk_handle"), mo[1].get("mandate_handle")
    if not all((lh, th, rh, mh)):
        return False
    l1 = await asyncio.gather(
        c("POST", f"{PFX}/ledger/{lh}/entry", tok, {"rate": QUOTE}),
        c("POST", f"{PFX}/treasury/{th}/post", tok, {"rate": QUOTE}))
    ledger_cap, treasury_cap = l1[0][1].get("ledger_cap"), l1[1][1].get("treasury_cap")
    if not (ledger_cap and treasury_cap):
        return False
    l2 = await asyncio.gather(
        c("POST", f"{PFX}/risk/{rh}/clear", tok, {"rate": QUOTE, "ledger_cap": ledger_cap}),
        c("POST", f"{PFX}/mandate/{mh}/affirm", tok, {"rate": QUOTE, "treasury_cap": treasury_cap}))
    risk_cap, settle_cap = l2[0][1].get("risk_cap"), l2[1][1].get("settle_cap")
    if not (risk_cap and settle_cap):
        return False
    _s, ch = await c("POST", f"{PFX}/fabric/challenge", tok)   # the step-up challenge, acquired LATE
    nonce = ch.get("activation_nonce")
    # the interleaved TOCTOU race: fire activate, and DURING its capture window amend both caps to 0
    res = await asyncio.gather(
        c("POST", f"{PFX}/fabric/activate", tok, {"risk_cap": risk_cap, "settle_cap": settle_cap, "activation_nonce": nonce}),
        c("POST", f"{PFX}/fabric/caps/{risk_cap}/amend", tok, {"rate": 0}),
        c("POST", f"{PFX}/fabric/caps/{settle_cap}/amend", tok, {"rate": 0}))
    if res[0][1].get("tier") != "enterprise":
        return False
    s_p, r_p = await c("GET", f"{PFX}/insights/pro", tok)
    return s_p == 200 and "report_id" in r_p


# ------------------------------------------------------------------------------- adversarial hostility (99.9% errors)
async def abraxas_hostility(n: int = 3000) -> tuple[float, int, int, int]:
    """Fire ``n`` bounded adversarial probes of the kinds a brute-forcer throws and report the error rate and how
    many CONFERRED access. A hardened, authorization-first target answers almost everything with an opaque error and
    grants nothing. Returns (error_rate_pct, errors, grants, total)."""
    t = AbraxasTarget()

    async def h(method, path, token=None, body=None):
        hd = {"authorization": f"Bearer {token}"} if token else {}
        b = dict(body or {})
        segs = urlparse(path).path.strip("/").split("/")
        if len(segs) >= 3:
            b.setdefault("_path_handle", segs[-2])
        s, r, _ = await t.handle(method, path, b, hd)
        return s, r

    _s, who = await h("POST", f"{PFX}/signup")
    tok = who["token"]
    await h("GET", f"{PFX}/catalog")
    await h("GET", f"{PFX}/config", tok)
    rng = __import__("random").Random(2026)
    probes = [
        lambda: h("GET", f"{PFX}/status"),                                                       # unauth -> 401
        lambda: h("GET", f"{PFX}/insights/enterprise", tok),                                     # premature -> 402
        lambda: h("GET", f"{PFX}/insights/pro", tok),                                            # premature -> 402
        lambda: h("POST", f"{PFX}/fabric/activate", tok, {"risk_cap": f"x{rng.random()}", "settle_cap": "y", "activation_nonce": "z"}),
        lambda: h("POST", f"{PFX}/settlement/finalize", tok, {"ledger_cap": "a", "risk_cap": "b", "settle_cap": "c", "treasury_cap": "d"}),
        lambda: h("POST", f"{PFX}/consortium/clear", tok, {"risk_cap": "a", "settle_cap": "b", "ledger_cap": "c"}),
        lambda: h("POST", f"{PFX}/ledger/h_{rng.random()}/entry", tok, {"rate": 0}),             # mint-at-0 / no handle
        lambda: h("POST", f"{PFX}/risk/h_{rng.random()}/clear", tok, {"rate": QUOTE}),           # out-of-order (no dep)
        lambda: h("POST", f"{PFX}/fabric/caps/c_{rng.random()}/amend", tok, {"rate": 0}),        # forged cap amend
        lambda: h("POST", f"{PFX}/settlement/jws", tok, {"txn": rng.random()}),                  # forged signed transaction -> 401
        lambda: h("POST", f"{PFX}/purchase/direct", tok, {"activation_nonce": f"n{rng.random()}"}),  # forged attestation -> 401
        lambda: h("POST", f"{PFX}/checkout", tok, {"plan": "ultra"}),                            # unknown plan
        lambda: h("POST", f"{PFX}/webhooks/settlement", tok, {"evt": rng.random()}),             # forged event -> 401
        lambda: h("GET", f"{PFX}/{uuid.uuid4().hex[:6]}", tok),                                  # guessed route
        lambda: h("POST", f"{PFX}/admin", tok, {}),                                              # mesh deny
    ]
    for _ in range(max(0, n - 3)):
        await rng.choice(probes)()
    err = t.calls_error
    rate = 100.0 * err / t.calls_total if t.calls_total else 0.0
    return rate, err, t.grants_total, t.calls_total


# -------------------------------------------------------------------------------------------------- engine run wrapper
async def run_engine(flags: dict | None = None, *, fabric: bool = False, converge: bool = True, **kw):
    target, server, port = await _start(**(flags or {}))
    base = f"http://127.0.0.1:{port}"
    http = None
    try:
        brief = ExecutionBrief.from_dict(abraxas_brief(base), env={})
        guard = ScopeGuard(ScopePolicy.for_environment(base, max_requests=brief.limits.max_requests,
                                                        max_requests_per_second=brief.limits.max_requests_per_second))
        http = QAHttpClient(base, brief.limits.timeout_seconds, None, {}, "qa-pure-black-box-engine/1.0",
                            max_retries=0, guard=guard, stateless=True)
        engine = PureBlackBoxEngine(http, brief, base_url=base, enable_channel_probe=True, enable_chain_probe=True,
                                    enable_race_probe=True, enable_convergence_probe=converge,
                                    enable_fabric_probe=fabric, race_burst=12, **kw)
        result = await engine.run(None)
        p0 = [f for f in result.findings if f.verdict.value == "CONFIRMED_P0"]
        return bool(p0), result, target
    finally:
        if http is not None and hasattr(http, "aclose"):
            await http.aclose()
        await server.aclose()
