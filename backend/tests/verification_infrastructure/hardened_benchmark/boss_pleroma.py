#!/usr/bin/env python3
"""BOSS target 'PLEROMA' -- the RECONCILIATION apex, the Gnostic "fullness" that contains and transcends every lesser
aeon (ABRAXAS is one power within it). It is built to put ABRAXAS fully in the shadow: it keeps ABRAXAS's ENTIRE
enterprise crypto/attestation/scope perimeter -- implemented CORRECTLY, so every one of those routes is an
unforgeable dead-end that NEVER grants -- and then adds a whole new domain the previous bosses never modelled: the
USAGE-METERING + ENTITLEMENT-RECONCILIATION business logic that sits on top of any perimeter (Metronome / Orb /
Lago / Stripe Billing+Entitlements / Apple App Store Server / Microsoft Marketplace metering).

================================================================================================================
WHY THE WHOLE ENTERPRISE/SOVEREIGN PERIMETER IS NECESSARY-BUT-NOT-SUFFICIENT HERE
================================================================================================================
Every control ABRAXAS implements is implemented here too, and CORRECTLY -- and NONE of them is the flaw:

  * The ABRAXAS convergence/fabric routes (settlement/finalize, consortium/clear, fabric/activate) are present and
    CORRECT: they recompute the amount server-side and/or demand a real captured-payment basis, so they NEVER grant
    to an unbacked caller. ABRAXAS's load-bearing rate-trust/TOCTOU flaw is CLOSED here -> the B50 settlement-fabric
    probe composes its DAG, races its amend, backtracks the decoys ... and is correctly turned away at every one.
  * App-Store-style signed-transaction settlement (settlement/jws), device-attestation purchase (purchase/direct)
    and Standard-Webhooks settlement (webhooks/settlement): correct crypto, keys never leaked -> unforgeable.
  * Server-side status verification, PaymentIntent lifecycle, amount/currency recomputation, BOLA/BFLA scoping,
    the dense internal-mesh deny-list, and the uniform opaque-422 anti-RE shell -- all retained, all correct.
  * S1 payment-versus-payment ATOMIC settlement (settlement/atomic, CLS-class: all-or-nothing, needs two real legs)
    and S3 ZERO-KNOWLEDGE per-meter usage proof (settlement/zkproof, needs a valid per-meter proof) -- both correct
    dead-ends. Per the ZK-metering literature a per-meter proof is sound per meter and CANNOT aggregate across
    meters; here the proof path simply never grants to an unbacked caller.

================================================================================================================
THE NEW DOMAIN: ASYNCHRONOUS MULTI-AUTHORITY RECONCILIATION (where real billing leaks)
================================================================================================================
Real usage-billing is not one oracle; it is several asynchronous authorities that are only EVENTUALLY consistent.
The irreversible good (entitlement) is released by a FAST/BLIND authority and the AUTHORITATIVE one reconciles
later -- or into a closed period, or never. PLEROMA models that gap faithfully, grounded in primary docs:

  * Orb "query-based billing": the invoice is a QUERY over an immutable event log; amendments are applied as a
    READ-PATH OVERLAY; billing activity for a CLOSED accounting period becomes a CATCH-UP ADJUSTMENT to the next
    open period (docs.withorb.com/architecture/query-based-billing).
  * Microsoft Marketplace metering: the publisher must only emit usage ABOVE the base fee, so the metering
    authority is STRUCTURALLY BLIND to base usage; reconciliation is a first-class state with a 'Mismatch' between
    submitted and processed quantity (learn.microsoft.com .../marketplace-metering-service-apis).
  * Stripe Entitlements: a permission is created on first activation and PERSISTS while the subscription is active;
    feature changes propagate only at the next billing cycle (docs.stripe.com/billing/entitlements).

THE FINDABLE no-payment ENTERPRISE chain (what the independent prober drives and the upgraded engine rediscovers):
    signup
      period/open                         -> period P (state=open; authoritative net_due = enterprise price)
      usage/{P}/overlay(rate=0)           -> F1: a client-declared ZERO-RATE credit overlay, trusted with no paid
                                                 basis (Orb read-path overlay / Stripe "amend") -> cached net_due 0
      period/{P}/close                    -> F2: closing LOCKS the unbacked overlay into the period's authoritative
                                                 aggregate (the closed-period catch-up blindness) -> frozen net_due 0
      settlement/reconcile(period=P)      -> F3: reconcile TRUSTS the frozen aggregate instead of re-deriving from
                                                 real bases; F4: it FINALIZES an enterprise grant on net_due<=0 even
                                                 though ZERO real payment was ever captured
      -> enterprise (finalized, active)   ->   GET /insights/pro proves it. No payment is ever made.

FOUR flaw flags make the bypass load-bearing (remove any one -> truth=False AND engine=False):
    ``overlay_unbacked``, ``close_locks_overlay``, ``reconcile_trusts_aggregate``, ``reconcile_grants_without_basis``.
TWO difficulty flags make the CURRENT engine (incl. the B50 fabric probe) MISS without removing the bypass:
    ``opaque_errors`` (uniform constant-shape 422) and ``reconcile_requires_close`` (settlement only reconciles a
    CLOSED period, forcing the overlay->close->reconcile ORDER). The grant step consumes a SINGLE period handle --
    not a >=2-capability convergence -- so the convergence/fabric composers never even select it. All-correct ->
    False/False (no false alarm).

    PYTHONPATH=tests/verification_infrastructure/shims:tests/verification_infrastructure:. \
        python3 tests/verification_infrastructure/hardened_benchmark/run_pleroma.py [--controls]
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
ENT = PRICES["enterprise"]["USD"]
QUOTE = 999.0            # the honestly-quoted attestation rate the (correct) ABRAXAS mint dead-ends still require
MINT_LATENCY_S = 0.02    # a small, real attestation round-trip for the correct dead-end mint ops
_MESH = ("admin", "ledger-internal", "treasury-internal", "ops", "audit", "kms", "fraud", "risk-internal",
         "disputes", "abraxas", "settlement-core", "mandate-internal", "radar", "vault", "hsm", "reconciler")
_DENY = tuple(f"{PFX}/svc/{s}" for s in _MESH) + (f"{PFX}/admin", f"{PFX}/debug", f"{PFX}/internal")


def _trace() -> str:
    return f"trc_{uuid.uuid4().hex[:16]}"


class PleromaTarget:
    """An enterprise-hardened usage-metering + entitlement-reconciliation fabric. The entire ABRAXAS crypto
    perimeter is present and CORRECT (never grants); the one load-bearing bypass lives in the asynchronous
    reconciliation gap. Flaw flags default True (vulnerable); the two difficulty flags default to the HARD setting."""

    def __init__(self, *, overlay_unbacked: bool = True, close_locks_overlay: bool = True,
                 reconcile_trusts_aggregate: bool = True, reconcile_grants_without_basis: bool = True,
                 opaque_errors: bool = True, reconcile_requires_close: bool = True) -> None:
        # -- load-bearing flaws (remove any one -> no bypass) --
        self.overlay_unbacked = overlay_unbacked                      # overlay credit trusted with no paid basis (Orb/Stripe amend)
        self.close_locks_overlay = close_locks_overlay                # close locks an unbacked overlay into the authoritative aggregate
        self.reconcile_trusts_aggregate = reconcile_trusts_aggregate  # reconcile trusts the frozen cache, not a re-derivation
        self.reconcile_grants_without_basis = reconcile_grants_without_basis  # finalize on net_due<=0 with no real captured basis
        # -- difficulty (defeat the CURRENT engine without removing the bypass) --
        self.opaque_errors = opaque_errors                            # uniform constant-shape 422 for every rejection
        self.reconcile_requires_close = reconcile_requires_close      # reconcile only operates on a CLOSED period (forces the order)
        self.by_token: dict[str, dict[str, Any]] = {}
        self.orgs: dict[str, dict[str, Any]] = {}
        self.intents: dict[str, dict[str, Any]] = {}
        self.bases: dict[str, dict[str, Any]] = {}            # settlement bases from REAL captured payments
        self.handles: dict[str, dict[str, Any]] = {}          # correct ABRAXAS-style mint handles (single-use)
        self.caps: dict[str, dict[str, Any]] = {}             # correct ABRAXAS-style minted capabilities
        self.periods: dict[str, dict[str, Any]] = {}          # billing periods (open -> overlay -> close -> reconcile)
        self._webhook_secret = "whsec_" + uuid.uuid4().hex    # NEVER leaked (correct webhook crypto)
        self._signing_key = "sk_" + uuid.uuid4().hex          # transaction/attestation signing key -- NEVER leaked
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
        the surface leaks no field, code or status signal. SOFT (opaque_errors off, detection-ablation control): the
        real field/status/code is returned so a field-learning analyser can progress."""
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

    def _org_has_real_basis(self, oid: str) -> bool:
        return any(b["org"] == oid and b.get("paid") for b in self.bases.values())

    # -- dispatch ---------------------------------------------------------------------------------------------------
    async def handle(self, method: str, raw_path: str, body: Any, headers: dict[str, str]):
        self.calls_total += 1
        status, obj, extra = await self._route(method, raw_path, body or {}, headers or {})
        if not (200 <= status < 300):
            self.calls_error += 1
        elif isinstance(obj, dict) and (obj.get("report_id") or obj.get("dossier_id")
                                        or obj.get("tier") == "enterprise" or obj.get("status") in ("succeeded", "settled", "finalized")):
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
            # Public API reference: documents ROUTES only (no secret, no netting rule, no reconcile internals).
            return 200, {"service": "pleroma-reconciliation-fabric", "mesh_services": list(_MESH),
                         "metering": {"period_open": f"{PFX}/period/open", "overlay": f"{PFX}/usage/{{period}}/overlay",
                                      "period_close": f"{PFX}/period/{{period}}/close", "reconcile": f"{PFX}/settlement/reconcile",
                                      "note": "usage is billed per accounting period; a closed period's late activity becomes a "
                                              "catch-up adjustment; settlement reconciles a closed period's net amount due"},
                         "settlement": {"finalize": f"{PFX}/settlement/finalize", "consortium": f"{PFX}/consortium/clear",
                                        "atomic_pvp": f"{PFX}/settlement/atomic", "zk_proof": f"{PFX}/settlement/zkproof",
                                        "signed_transaction": f"{PFX}/settlement/jws", "direct_purchase": f"{PFX}/purchase/direct",
                                        "note": "signed_transaction requires an App-Store-style signed JWS; direct_purchase a "
                                                "device-attestation token; atomic settlement is payment-versus-payment (two real legs); "
                                                "zk_proof requires a valid per-meter usage proof"},
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

        # -- correct happy-path purchase (PaymentIntent lifecycle; mints a REAL settlement basis) -----------------
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
                self.bases[bref] = {"org": oid, "paid": True, "amount": intent["amount"]}
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

        # == THE RECONCILIATION LIFECYCLE (the one load-bearing bypass lives in the gap between its authorities) ===
        if method == "POST" and p == f"{PFX}/period/open":
            per = f"per_{uuid.uuid4().hex[:12]}"
            # authoritative net_due starts at the enterprise commitment; a real paid basis (checkout) is how it is
            # honestly discharged. overlay_rate is the client read-path overlay; frozen is set at close.
            self.periods[per] = {"org": oid, "state": "open", "overlay_rate": None, "frozen_net_due": None}
            return 201, {"period": per, "state": "open"}, {}

        if method == "POST" and p.startswith(f"{PFX}/usage/") and p.endswith("/overlay"):
            per = self.periods.get(self._path_seg(body, p))
            if per is None or per["org"] != oid:
                return self._reject(field="period", code="unknown_period", status=403)
            if per["state"] != "open":
                return self._reject(field="period", code="period_not_open", status=409)
            if "rate" not in body:
                return self._reject(field="rate", code="missing_field")
            try:
                rate = float(body["rate"])
            except (TypeError, ValueError):
                return self._reject(field="rate", code="invalid_field")
            if not self.overlay_unbacked:
                # CORRECT: a credit overlay must be backed by a REAL captured-payment basis the attacker cannot forge
                # (a client-declared credit is not money). Without one, the overlay is refused.
                basis = self.bases.get(body.get("basis", ""))
                if basis is None or basis["org"] != oid:
                    return self._reject(field="basis", code="paid_basis_required", status=402)
            per["overlay_rate"] = rate   # FLAW (overlay_unbacked): the client-declared overlay rate is trusted
            return 200, {"status": "overlaid", "period": self._path_seg(body, p), "overlay_rate": rate}, {}

        if method == "POST" and p.startswith(f"{PFX}/period/") and p.endswith("/close"):
            per = self.periods.get(self._path_seg(body, p))
            if per is None or per["org"] != oid:
                return self._reject(field="period", code="unknown_period", status=403)
            if per["state"] != "open":
                return self._reject(field="period", code="period_not_open", status=409)
            per["state"] = "closed"
            if per["overlay_rate"] is not None and self.close_locks_overlay:
                # FLAW (close_locks_overlay): closing LOCKS the unbacked client overlay into the period's
                # authoritative aggregate -> the closed period's net_due is frozen at the overlay value.
                per["frozen_net_due"] = per["overlay_rate"]
            else:
                # CORRECT: an unbacked overlay on a closing period is a CATCH-UP adjustment deferred to the next
                # period (Orb's closed-period semantics); it does NOT reduce THIS period's authoritative net_due.
                per["frozen_net_due"] = ENT
            return 200, {"status": "closed", "period": self._path_seg(body, p)}, {}

        if method == "POST" and p == f"{PFX}/settlement/reconcile":
            per = self.periods.get(body.get("period", ""))
            if per is None or per["org"] != oid:
                return self._reject(field="period", code="unknown_period", status=403)
            if self.reconcile_requires_close and per["state"] != "closed":
                # DIFFICULTY: reconcile only a CLOSED period (forces overlay->close->reconcile ordering).
                return self._reject(field="period", code="period_not_closed", status=409)
            if self.reconcile_trusts_aggregate:
                net_due = per["frozen_net_due"] if per["frozen_net_due"] is not None else ENT  # FLAW: trusts the cache
            else:
                # CORRECT: re-derive the authoritative net amount due from REAL captured bases only; the client
                # overlay is ignored. With no real payment this is the full enterprise commitment.
                paid = sum(b.get("amount", 0.0) for b in self.bases.values() if b["org"] == oid and b.get("paid"))
                net_due = max(0.0, ENT - paid)
            if net_due > 0:
                return self._reject(field="net_due", code="payment_required", status=402)
            if not self.reconcile_grants_without_basis and not self._org_has_real_basis(oid):
                # CORRECT: a non-positive net due with ZERO real captured payment is not "paid up" -- finalization
                # requires at least one genuine captured basis in the period.
                return self._reject(field="basis", code="no_real_settlement_basis", status=402)
            org["grants"].append({"source": "reconciliation", "tier": "enterprise", "state": "active"})
            return 200, {"status": "finalized", "tier": "enterprise", "net_due": net_due}, {}

        # == CORRECT ABRAXAS-CLASS DEAD-ENDS (present so the current engine engages them -- and is turned away) ====
        # ABRAXAS-style mint ops: correct, ALWAYS require a real captured basis -> an unbacked caller cannot mint,
        # so the convergence/fabric composers cannot assemble the decoy quorums below.
        if method == "POST" and p == f"{PFX}/ledger/entry":
            return self._correct_mint(oid, body, "ledger_cap")
        if method == "POST" and p == f"{PFX}/treasury/post":
            return self._correct_mint(oid, body, "treasury_cap")
        if method == "POST" and p == f"{PFX}/risk/clear":
            return self._correct_mint(oid, body, "risk_cap")
        if method == "POST" and p == f"{PFX}/mandate/affirm":
            return self._correct_mint(oid, body, "settle_cap")

        # Decoy / correct convergence routes: they require caps that cannot be minted without a real basis, and they
        # recompute server-side regardless -> they NEVER grant to an unbacked caller (so B50 backtracks and misses).
        if method == "POST" and p in (f"{PFX}/settlement/finalize", f"{PFX}/consortium/clear", f"{PFX}/settlement/atomic"):
            for name in ("ledger_cap", "treasury_cap", "risk_cap", "settle_cap"):
                if name in body:
                    cap = self.caps.get(body.get(name, ""))
                    if cap is None or cap["org"] != oid:
                        return self._reject(field=name, code="capability_required")
            # CORRECT: all of these require a real captured-payment basis the attacker cannot forge.
            basis = self.bases.get(body.get("basis", ""))
            if basis is None or basis["org"] != oid:
                return self._reject(field="basis", code="paid_basis_required", status=402)
            org["grants"].append({"source": "settlement", "tier": "enterprise", "state": "active"})
            return 200, {"status": "settled", "tier": "enterprise"}, {}

        # S3 ZK per-meter usage proof: correct verification, unforgeable -> a dead-end for an unbacked caller.
        if method == "POST" and p == f"{PFX}/settlement/zkproof":
            if not self._verify_zkproof(headers, body, oid):
                return self._reject(field="proof", code="invalid_usage_proof", status=401)
            org["grants"].append({"source": "zkproof", "tier": "enterprise", "state": "active"})
            return 200, {"status": "settled", "tier": "enterprise"}, {}

        # Enterprise dead-ends: App-Store signed transaction + device attestation (correct crypto, never leaked).
        if method == "POST" and p == f"{PFX}/settlement/jws":
            if not self._verify_signed(headers, body):
                return self._reject(field="transaction", code="invalid_signed_transaction", status=401)
            org["grants"].append({"source": "signed_transaction", "tier": "enterprise", "state": "active"})
            return 200, {"status": "settled", "tier": "enterprise"}, {}
        if method == "POST" and p == f"{PFX}/purchase/direct":
            if not self._verify_attestation(headers, body, oid):
                return self._reject(field="attestation", code="attestation_required", status=401)
            org["grants"].append({"source": "attested_purchase", "tier": "enterprise", "state": "active"})
            return 200, {"status": "settled", "tier": "enterprise"}, {}

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

    # -- machinery --------------------------------------------------------------------------------------------------
    @staticmethod
    def _path_seg(body: dict[str, Any], path: str) -> str:
        """The resource id in a ``/collection/{id}/action`` path -- the segment before the final action segment."""
        segs = urlparse(path).path.strip("/").split("/")
        return segs[-2] if len(segs) >= 2 else ""

    def _correct_mint(self, oid: str, body: dict[str, Any], out: str):
        """An ABRAXAS-class mint, implemented CORRECTLY: it ALWAYS requires a real captured-payment basis, so an
        unbacked caller can never mint a capability (and thus never assemble the decoy convergence quorums)."""
        basis = self.bases.get(body.get("basis", ""))
        if basis is None or basis["org"] != oid:
            return self._reject(field="basis", code="paid_basis_required", status=402)
        ref = f"cap_{uuid.uuid4().hex[:12]}"
        self.caps[ref] = {"org": oid, "kind": out}
        return 201, {out: ref, "cap_ref": ref}, {}

    def _verify_zkproof(self, headers: dict[str, str], body: dict[str, Any], oid: str) -> bool:
        proof = headers.get("usage-proof", "")
        good = base64.b64encode(hmac.new(self._signing_key.encode(), f"zk:{oid}".encode(), hashlib.sha256).digest()).decode()
        return bool(proof) and hmac.compare_digest(proof, good)

    def _verify_signed(self, headers: dict[str, str], body: dict[str, Any]) -> bool:
        sig = headers.get("transaction-signature", "")
        signed = json.dumps(body, sort_keys=True).encode()
        good = base64.b64encode(hmac.new(self._signing_key.encode(), signed, hashlib.sha256).digest()).decode()
        return bool(sig) and hmac.compare_digest(sig, good)

    def _verify_attestation(self, headers: dict[str, str], body: dict[str, Any], oid: str) -> bool:
        att = headers.get("attestation-token", "")
        good = base64.b64encode(hmac.new(self._signing_key.encode(), f"attest:{oid}".encode(), hashlib.sha256).digest()).decode()
        return bool(att) and hmac.compare_digest(att, good)

    def _verify_webhook(self, headers, body, org):
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


def pleroma_brief(base_url: str) -> dict[str, Any]:
    def op(method: str, path: str, via: str = "public_api_reference", **extra: Any) -> dict[str, Any]:
        return {"method": method, "path": path, "observed_via": via, **extra}
    return {
        "authorization_ref": "BENCH-BOSS-PLEROMA", "authorized_by": "qa", "environment": "benchmark",
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
            # --- the reconciliation lifecycle (open -> overlay -> close -> reconcile) ---
            "period_open": op("POST", f"{PFX}/period/open", response_fields={"period": "period"}),
            "usage_overlay": op("POST", f"{PFX}/usage/{{period}}/overlay", request_fields={"rate": "rate"}),
            "period_close": op("POST", f"{PFX}/period/{{period}}/close"),
            "settlement_reconcile": op("POST", f"{PFX}/settlement/reconcile", request_fields={"period": "period"}),
            # --- correct ABRAXAS-class mint dead-ends (402 without a real basis) and their convergence decoys ---
            "ledger_entry": op("POST", f"{PFX}/ledger/entry", response_fields={"ledger_cap": "ledger_cap"}),
            "treasury_post": op("POST", f"{PFX}/treasury/post", response_fields={"treasury_cap": "treasury_cap"}),
            "risk_clear": op("POST", f"{PFX}/risk/clear", response_fields={"risk_cap": "risk_cap"}),
            "mandate_affirm": op("POST", f"{PFX}/mandate/affirm", response_fields={"settle_cap": "settle_cap"}),
            "settlement_finalize": op("POST", f"{PFX}/settlement/finalize",
                                      request_fields={"ledger_cap": "ledger_cap", "treasury_cap": "treasury_cap",
                                                      "risk_cap": "risk_cap", "settle_cap": "settle_cap"}),
            "consortium_clear": op("POST", f"{PFX}/consortium/clear",
                                   request_fields={"risk_cap": "risk_cap", "settle_cap": "settle_cap", "ledger_cap": "ledger_cap"}),
            "settlement_atomic": op("POST", f"{PFX}/settlement/atomic",
                                    request_fields={"ledger_cap": "ledger_cap", "treasury_cap": "treasury_cap"}),
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
    target = PleromaTarget(**flags)
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


# ------------------------------------------------------------------------------------- independent ground-truth prober
async def probe_pleroma_truth(**flags) -> bool:
    """Drive the intended no-payment chain as an all-knowing attacker: open a billing period, apply a client-declared
    ZERO-RATE credit overlay (no paid basis), CLOSE the period so the unbacked overlay is locked into the authoritative
    aggregate, RECONCILE the closed period (which trusts the frozen aggregate and finalizes an enterprise grant with no
    real captured basis), and confirm enterprise access via the pro feature. Computed with ZERO reference to the
    engine's oracle or the target's flaw flags beyond driving its public API."""
    t = PleromaTarget(**flags)

    async def c(method, path, token=None, body=None):
        h = {"authorization": f"Bearer {token}"} if token else {}
        s, r, _ = await t.handle(method, path, body or {}, h)
        return s, r

    _s, who = await c("POST", f"{PFX}/signup")
    tok = who["token"]
    _s, po = await c("POST", f"{PFX}/period/open", tok)
    per = po.get("period")
    if not per:
        return False
    _s, _ov = await c("POST", f"{PFX}/usage/{per}/overlay", tok, {"rate": 0})
    _s, _cl = await c("POST", f"{PFX}/period/{per}/close", tok)
    _s, fin = await c("POST", f"{PFX}/settlement/reconcile", tok, {"period": per})
    if fin.get("tier") != "enterprise":
        return False
    s_p, r_p = await c("GET", f"{PFX}/insights/pro", tok)
    return s_p == 200 and "report_id" in r_p


# ------------------------------------------------------------------------------- adversarial hostility (99.9% errors)
async def pleroma_hostility(n: int = 3000) -> tuple[float, int, int, int]:
    """Fire ``n`` bounded adversarial probes of the kinds a brute-forcer throws and report the error rate and how
    many CONFERRED access. A hardened, authorization-first target answers almost everything with an opaque error and
    grants nothing. Returns (error_rate_pct, errors, grants, total)."""
    t = PleromaTarget()

    async def h(method, path, token=None, body=None):
        hd = {"authorization": f"Bearer {token}"} if token else {}
        s, r, _ = await t.handle(method, path, body or {}, hd)
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
        lambda: h("POST", f"{PFX}/settlement/reconcile", tok, {"period": f"per_{rng.random()}"}),  # forged period
        lambda: h("POST", f"{PFX}/settlement/reconcile", tok, {}),                               # no period
        lambda: h("POST", f"{PFX}/usage/per_{rng.random()}/overlay", tok, {"rate": 0}),          # overlay unknown period
        lambda: h("POST", f"{PFX}/period/per_{rng.random()}/close", tok),                        # close unknown period
        lambda: h("POST", f"{PFX}/ledger/entry", tok, {"rate": 0}),                              # mint w/o basis -> 402
        lambda: h("POST", f"{PFX}/settlement/finalize", tok, {"ledger_cap": "a", "risk_cap": "b", "treasury_cap": "c", "settle_cap": "d"}),
        lambda: h("POST", f"{PFX}/consortium/clear", tok, {"risk_cap": "a", "settle_cap": "b", "ledger_cap": "c"}),
        lambda: h("POST", f"{PFX}/settlement/atomic", tok, {"ledger_cap": "a", "treasury_cap": "b"}),
        lambda: h("POST", f"{PFX}/settlement/zkproof", tok, {"meter": rng.random()}),            # forged zk proof -> 401
        lambda: h("POST", f"{PFX}/settlement/jws", tok, {"txn": rng.random()}),                  # forged signed txn -> 401
        lambda: h("POST", f"{PFX}/purchase/direct", tok, {"n": rng.random()}),                   # forged attestation -> 401
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
async def run_engine(flags: dict | None = None, *, reconciliation: bool = False, **kw):
    target, server, port = await _start(**(flags or {}))
    base = f"http://127.0.0.1:{port}"
    http = None
    try:
        brief = ExecutionBrief.from_dict(pleroma_brief(base), env={})
        guard = ScopeGuard(ScopePolicy.for_environment(base, max_requests=brief.limits.max_requests,
                                                        max_requests_per_second=brief.limits.max_requests_per_second))
        http = QAHttpClient(base, brief.limits.timeout_seconds, None, {}, "qa-pure-black-box-engine/1.0",
                            max_retries=0, guard=guard, stateless=True)
        engine = PureBlackBoxEngine(http, brief, base_url=base, enable_channel_probe=True, enable_chain_probe=True,
                                    enable_race_probe=True, enable_convergence_probe=True, enable_fabric_probe=True,
                                    enable_reconciliation_probe=reconciliation, race_burst=12, **kw)
        result = await engine.run(None)
        p0 = [f for f in result.findings if f.verdict.value == "CONFIRMED_P0"]
        return bool(p0), result, target
    finally:
        if http is not None and hasattr(http, "aclose"):
            await http.aclose()
        await server.aclose()
