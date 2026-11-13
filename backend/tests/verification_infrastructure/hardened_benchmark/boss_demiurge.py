#!/usr/bin/env python3
"""BOSS 'DEMIURGE' -- the Federation Apex (see docs/DEMIURGE_BOSS_CYCLE.md).

DEMIURGE is the first boss that is a DISTRIBUTED FEDERATION rather than a single endpoint. One edge host (`gateway`)
fronts eight archon services, each a correctly-implemented perimeter (unforgeable dead-end). The archon paths are NOT
declared in the brief -- they appear only as DATA in `GET /reference`, so the engine must DISCOVER them. The single
load-bearing no-payment ENTERPRISE bypass lives in NO single archon: it is a CONFUSED DEPUTY across four trust edges
(the KENOMA), carried by an opaque packed correlation token `ct` whose MAC does not cover its basis region.

The intended no-payment chain (what the independent prober drives and an upgraded engine must rediscover):

    signup
      POST vault/correlation              -> mint ct (packed; MAC over a PREFIX only)
      <splice ct tail>                    -> inject a fabricated basis + enterprise amount (MAC still valid: coverage gap)
      POST metering/open                  -> open period P (authoritative net_due = enterprise price)
      POST disputes/credit {P, ct}        -> EDGE-1: disputes TRUSTS ct's (forged) basis -> credits the full period
      POST reconciler/close {P}           -> EDGE-2: close LOCKS the unbacked credit into P's aggregate -> net_due<=0
      POST radar/stepup -> challenge      -> a FRESH single-use step-up nonce (freshness)
      POST settlement/finalize {P, ct, ch}-> EDGE-3: settlement TRUSTS the frozen aggregate; EDGE-4: finalizes
                                             enterprise with NO real captured payment
      -> GET gateway/insights/pro         -> enterprise unlocks it for a NEVER-PAID identity (the oracle flips)

FIVE flaw flags make the bypass load-bearing (remove any one -> truth=False AND engine=False):
  ``mac_covers_basis`` (False=flaw; True closes the coverage gap -> forged tail rejected = honest boundary),
  ``disputes_trust_correlation``, ``reconcile_locks_credit``, ``settlement_trusts_aggregate``,
  ``settlement_grants_without_capture``.
Difficulty flags (hard, never the flaw): ``opaque_errors`` (uniform 422), ``token_fresh_window`` (finalize needs a
fresh single-use challenge), ``decoy_archons`` (correct grant-looking dead-ends). ``ops_declared`` (brief builder) is
used only by the clean-MISS ladder.

Everything is synthetic and in-process: a local asyncio HTTP target on 127.0.0.1, no external system, no real
payment. Driven under the same ScopeGuard RoE budget and the same ConfirmationGate as any benchmark target.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import struct
import time
import uuid
from typing import Any
from urllib.parse import parse_qs, urlparse

from app.enterprise_controls.scope import ScopeGuard, ScopePolicy
from app.testing.http_client import QAHttpClient
from app.testing.integrity.brief import ExecutionBrief
from app.testing.integrity.engine import PureBlackBoxEngine
from reference_target import _read_http_request, _TrackedServer

PFX = "/api/v1"
PRICES = {"pro": {"USD": 99.0}, "enterprise": {"USD": 999.0}}
_TIER_RANK = {None: 0, "pro": 1, "enterprise": 2}
ENT = PRICES["enterprise"]["USD"]
ENT_MINOR = int(ENT * 100)
# mesh/internal doors a customer-level session must never reach (uniform deny under opacity)
_DENY = (f"{PFX}/admin", f"{PFX}/internal", f"{PFX}/mesh", f"{PFX}/debug")

# opaque packed correlation-token layout: head = ver(B) + tenant(16s) + ts(I) [21B];  tail = basis(8s) + amount(I) [12B]
_HEAD = ">B16sI"
_TAIL = ">8sI"
_HEAD_N, _TAIL_N, _MAC_N = 21, 12, 8


def _trace() -> str:
    return uuid.uuid4().hex[:12]


class DemiurgeTarget:
    """A payment/entitlement FEDERATION: one edge (`gateway`) fronting eight archon services sharing one fabric.
    Every archon is implemented CORRECTLY; the one bypass is the cross-service confused deputy (the KENOMA)."""

    def __init__(self, *, mac_covers_basis: bool = False, disputes_trust_correlation: bool = True,
                 reconcile_locks_credit: bool = True, settlement_trusts_aggregate: bool = True,
                 settlement_grants_without_capture: bool = True,
                 opaque_errors: bool = True, token_fresh_window: bool = True, decoy_archons: bool = True) -> None:
        # -- load-bearing flaws (remove any one -> no bypass) --
        self.mac_covers_basis = mac_covers_basis                            # EDGE-1 precondition: MAC omits basis region (B54 target)
        self.disputes_trust_correlation = disputes_trust_correlation        # EDGE-1: disputes trusts ct's basis with no capture check
        self.reconcile_locks_credit = reconcile_locks_credit               # EDGE-2: close locks the unbacked credit into the aggregate
        self.settlement_trusts_aggregate = settlement_trusts_aggregate      # EDGE-3: settlement trusts the frozen aggregate
        self.settlement_grants_without_capture = settlement_grants_without_capture  # EDGE-4: finalize with no real capture
        # -- difficulty (hard, never the flaw) --
        self.opaque_errors = opaque_errors
        self.token_fresh_window = token_fresh_window
        self.decoy_archons = decoy_archons
        # -- state (the shared federation fabric) --
        self.orgs: dict[str, dict[str, Any]] = {}
        self.by_token: dict[str, dict[str, Any]] = {}
        self.intents: dict[str, dict[str, Any]] = {}
        self.bases: dict[str, dict[str, Any]] = {}       # real captured-payment bases (never forgeable)
        self.caps: dict[str, dict[str, Any]] = {}        # ABRAXAS-class capabilities (need a real basis)
        self.periods: dict[str, dict[str, Any]] = {}     # metering periods (open -> credit -> close -> finalize)
        self.challenges: dict[str, dict[str, Any]] = {}  # radar step-up nonces (fresh, single-use)
        self._ct_key = uuid.uuid4().bytes                 # vault signing key -- NEVER leaked
        self._signing_key = uuid.uuid4().hex              # crypto dead-ends' key -- NEVER leaked
        self.request_log: list[tuple[str, str]] = []
        self.calls_total = self.calls_error = self.grants_total = self.internal_hits = 0

    # -- token helpers (vault) --------------------------------------------------------------------------------------
    def _ct_mac(self, head: bytes, tail: bytes) -> bytes:
        msg = head + tail if self.mac_covers_basis else head   # FLAW: MAC covers the PREFIX only, not the basis/amount tail
        return hmac.new(self._ct_key, msg, hashlib.sha256).digest()[:_MAC_N]

    def _mint_ct(self, oid: str, basis: bytes, amount_minor: int, ts: int) -> str:
        tenant = oid.encode()[:16].ljust(16, b"\x00")
        head = struct.pack(_HEAD, 1, tenant, ts & 0xFFFFFFFF)
        tail = struct.pack(_TAIL, basis[:8].ljust(8, b"\x00"), amount_minor & 0xFFFFFFFF)
        return base64.urlsafe_b64encode(head + tail + self._ct_mac(head, tail)).decode()

    def _verify_ct(self, tok: str) -> dict[str, Any] | None:
        try:
            raw = base64.urlsafe_b64decode(tok.encode())
            head, tail, mac = raw[:_HEAD_N], raw[_HEAD_N:_HEAD_N + _TAIL_N], raw[_HEAD_N + _TAIL_N:_HEAD_N + _TAIL_N + _MAC_N]
            if len(raw) != _HEAD_N + _TAIL_N + _MAC_N or not hmac.compare_digest(mac, self._ct_mac(head, tail)):
                return None
            _ver, tenant, ts = struct.unpack(_HEAD, head)
            basis, amount = struct.unpack(_TAIL, tail)
            return {"tenant": tenant.rstrip(b"\x00").decode(errors="ignore"), "basis": basis, "amount_minor": amount, "ts": ts}
        except Exception:  # noqa: BLE001
            return None

    # -- helpers ----------------------------------------------------------------------------------------------------
    def _reject(self, *, field: str | None = None, status: int = 422, code: str = "unprocessable_entity",
                **extra: Any) -> tuple[int, dict[str, Any], dict]:
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

    def _real_captured(self, oid: str) -> float:
        return sum(b.get("amount", 0.0) for b in self.bases.values() if b["org"] == oid and b.get("paid"))

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

        # -- edge: unauthenticated public surface ------------------------------------------------------------------
        if method == "POST" and p == f"{PFX}/signup":
            oid, tok = f"o_{uuid.uuid4().hex[:8]}", f"tok_{uuid.uuid4().hex[:16]}"
            self.orgs[oid] = {"grants": [], "paid": False}
            self.by_token[tok] = {"org": oid}
            return 201, {"token": tok, "tenant_id": oid}, {}
        if method == "GET" and p == f"{PFX}/catalog":
            return 200, {"plans": [{"code": "pro", "price_id": "pr_pro", "amount": 99.0, "currency": "USD"},
                                   {"code": "enterprise", "price_id": "pr_ent", "amount": 999.0, "currency": "USD"}]}, {}
        if method == "GET" and p == f"{PFX}/reference":
            # Public API reference: documents the archon ROUTES only (no secret, no trust rule, no token layout).
            svc = {
                "vault": {"correlation": f"{PFX}/vault/correlation",
                          "note": "mints an opaque correlation token binding a settlement basis"},
                "metering": {"open": f"{PFX}/metering/open", "usage": f"{PFX}/metering/{{period}}",
                             "note": "usage is billed per accounting period; a closed period's late activity is a catch-up adjustment"},
                "disputes": {"credit": f"{PFX}/disputes/credit", "note": "issues a period credit against a correlated basis"},
                "reconciler": {"close": f"{PFX}/reconciler/close", "note": "closes a period and reconciles its net amount due"},
                "settlement": {"finalize": f"{PFX}/settlement/finalize", "atomic_pvp": f"{PFX}/settlement/atomic",
                               "consortium": f"{PFX}/settlement/consortium",
                               "note": "finalize settles a reconciled period; atomic/consortium require real captured legs"},
                "attestation": {"purchase": f"{PFX}/attestation/purchase", "note": "device-attested direct purchase"},
                "radar": {"stepup": f"{PFX}/radar/stepup", "note": "issues a short-lived single-use step-up challenge"},
                "entitlement": {"state": f"{PFX}/entitlement/state", "note": "the authoritative entitlement of record"},
            }
            return 200, {"service": "demiurge-payment-federation", "edge": f"{PFX}", "archons": svc}, {}

        # -- authentication ----------------------------------------------------------------------------------------
        auth = headers.get("authorization", "")
        ident = self.by_token.get(auth[7:]) if auth.lower().startswith("bearer ") else None
        if ident is None:
            return 401, {"error": "unauthenticated"}, {}
        oid = ident["org"]
        org = self.orgs[oid]
        if any(p.startswith(d) for d in _DENY):
            self.internal_hits += 1
            return self._reject(status=403, code="forbidden")

        if method == "GET" and p == f"{PFX}/status":
            return 200, {"tier": self._effective(org)}, {}

        # -- edge: correct happy-path purchase (mints a REAL settlement basis) -------------------------------------
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
                intent["status"], intent["captured"] = "succeeded", True
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

        # == ARCHON: vault -- mint an opaque packed correlation token ==============================================
        if method == "POST" and p == f"{PFX}/vault/correlation":
            # Honest mint: the basis + amount reflect the org's REAL captured payment (zero for a never-paid id).
            real = self._real_captured(oid)
            basis = next((k.encode() for k, b in self.bases.items() if b["org"] == oid and b.get("paid")), b"")
            ts = int(time.time())
            tok = self._mint_ct(oid, basis, int(real * 100), ts)
            return 201, {"correlation_token": tok, "ts": ts, "tenant": oid}, {}

        # == ARCHON: metering -- open / read a billing period ======================================================
        if method == "POST" and p == f"{PFX}/metering/open":
            per = f"per_{uuid.uuid4().hex[:12]}"
            self.periods[per] = {"org": oid, "state": "open", "credits": [], "frozen_net_due": None}
            return 201, {"period": per, "state": "open", "net_due": ENT}, {}
        if method == "GET" and p.startswith(f"{PFX}/metering/"):
            per = self.periods.get(p.rsplit("/", 1)[-1])
            if per is None or per["org"] != oid:
                return self._reject(field="period", code="unknown_period", status=404)
            return 200, {"period": p.rsplit("/", 1)[-1], "state": per["state"], "credits": len(per["credits"])}, {}

        # == ARCHON: disputes -- issue a period credit against a correlated basis (EDGE-1) =========================
        if method == "POST" and p == f"{PFX}/disputes/credit":
            per = self.periods.get(body.get("period", ""))
            if per is None or per["org"] != oid:
                return self._reject(field="period", code="unknown_period", status=403)
            if per["state"] != "open":
                return self._reject(field="period", code="period_not_open", status=409)
            ct = self._verify_ct(body.get("ct", ""))
            if ct is None or ct["tenant"] != oid:
                return self._reject(field="ct", code="invalid_correlation_token", status=401)
            if self.disputes_trust_correlation:
                # FLAW: trust the token's (forged) amount as a validated basis -- no capture check.
                credit = ct["amount_minor"] / 100.0
            else:
                # CORRECT: re-derive against the org's REAL captured total (a client-declared credit is not money).
                credit = min(ct["amount_minor"] / 100.0, self._real_captured(oid))
            per["credits"].append(credit)
            return 200, {"status": "credited", "period": body.get("period"), "credit": credit}, {}

        # == ARCHON: reconciler -- close a period, reconcile its aggregate (EDGE-2) ================================
        if method == "POST" and p == f"{PFX}/reconciler/close":
            per = self.periods.get(body.get("period", ""))
            if per is None or per["org"] != oid:
                return self._reject(field="period", code="unknown_period", status=403)
            if per["state"] != "open":
                return self._reject(field="period", code="period_not_open", status=409)
            per["state"] = "closed"
            if self.reconcile_locks_credit:
                # FLAW: closing LOCKS the unbacked credits into the authoritative aggregate.
                per["frozen_net_due"] = max(0.0, ENT - sum(per["credits"]))
            else:
                # CORRECT: an unbacked credit on a closing period is a CATCH-UP adjustment deferred to the next period.
                per["frozen_net_due"] = ENT
            return 200, {"status": "closed", "period": body.get("period"), "net_due": per["frozen_net_due"]}, {}

        # == ARCHON: radar -- a short-lived single-use step-up challenge (freshness) ===============================
        if method == "POST" and p == f"{PFX}/radar/stepup":
            ch = f"ch_{uuid.uuid4().hex[:12]}"
            self.challenges[ch] = {"org": oid, "ts": time.time(), "used": False}
            return 201, {"challenge": ch, "expires_in": 2}, {}

        # == ARCHON: settlement -- finalize a reconciled period (EDGE-3, EDGE-4) ===================================
        if method == "POST" and p == f"{PFX}/settlement/finalize":
            per = self.periods.get(body.get("period", ""))
            if per is None or per["org"] != oid:
                return self._reject(field="period", code="unknown_period", status=403)
            if per["state"] != "closed":
                return self._reject(field="period", code="period_not_closed", status=409)
            if self.token_fresh_window:
                ch = self.challenges.get(body.get("challenge", ""))
                if ch is None or ch["org"] != oid or ch["used"] or (time.time() - ch["ts"] > 2.0):
                    return self._reject(field="challenge", code="step_up_required", status=401)
                ch["used"] = True
            ct = self._verify_ct(body.get("ct", ""))
            if ct is None or ct["tenant"] != oid:
                return self._reject(field="ct", code="invalid_correlation_token", status=401)
            if self.settlement_trusts_aggregate:
                net = per["frozen_net_due"] if per["frozen_net_due"] is not None else ENT   # FLAW: trust the frozen cache
            else:
                net = max(0.0, ENT - self._real_captured(oid))                              # CORRECT: re-derive from real captures
            if net > 0:
                return self._reject(field="net_due", code="payment_required", status=402)
            if not self.settlement_grants_without_capture and not self._org_has_real_basis(oid):
                return self._reject(field="basis", code="no_real_settlement_basis", status=402)
            org["grants"].append({"source": "settlement", "tier": "enterprise", "state": "active"})
            return 200, {"status": "finalized", "tier": "enterprise", "net_due": net}, {}

        # == CORRECT DEAD-ENDS (decoys): always need a real captured basis -> never grant to an unbacked caller ====
        if self.decoy_archons and method == "POST" and p in (f"{PFX}/settlement/atomic", f"{PFX}/settlement/consortium"):
            basis = self.bases.get(body.get("basis", ""))
            if basis is None or basis["org"] != oid:
                return self._reject(field="basis", code="paid_basis_required", status=402)
            org["grants"].append({"source": "settlement_decoy", "tier": "enterprise", "state": "active"})
            return 200, {"status": "settled", "tier": "enterprise"}, {}
        if self.decoy_archons and method == "POST" and p == f"{PFX}/attestation/purchase":
            att = headers.get("attestation-token", "")
            good = base64.b64encode(hmac.new(self._signing_key.encode(), f"attest:{oid}".encode(), hashlib.sha256).digest()).decode()
            if not (att and hmac.compare_digest(att, good)):
                return self._reject(field="attestation", code="attestation_required", status=401)
            org["grants"].append({"source": "attested", "tier": "enterprise", "state": "active"})
            return 200, {"status": "settled", "tier": "enterprise"}, {}

        # == ARCHON: entitlement -- the authoritative entitlement of record ========================================
        if method == "GET" and p == f"{PFX}/entitlement/state":
            return 200, {"tier": self._effective(org)}, {}

        # -- protected features (the oracle surface, on the edge) --------------------------------------------------
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


# ------------------------------------------------------------------------------------------------- forge helper (B54)
def forge_ct(tok: str, basis: bytes, amount_minor: int) -> str:
    """Splice a minted token's TAIL (basis + amount) -- the region outside the MAC when ``mac_covers_basis`` is False.
    No key is needed: with a prefix-only MAC the head+mac are reused verbatim and only the tail changes. This is what
    the independent prober does directly and what the engine's B54 protocol-field inference must rediscover."""
    raw = bytearray(base64.urlsafe_b64decode(tok.encode()))
    raw[_HEAD_N:_HEAD_N + _TAIL_N] = struct.pack(_TAIL, basis[:8].ljust(8, b"\x00"), amount_minor & 0xFFFFFFFF)
    return base64.urlsafe_b64encode(bytes(raw)).decode()


# --------------------------------------------------------------------------------------------------- brief + server
def demiurge_brief(base_url: str, *, ops_declared: bool = False) -> dict[str, Any]:
    def op(method: str, path: str, via: str = "public_api_reference", **extra: Any) -> dict[str, Any]:
        return {"method": method, "path": path, "observed_via": via, **extra}
    surface = {
        "signup": op("POST", f"{PFX}/signup", "product_ui"),
        "catalog": op("GET", f"{PFX}/catalog"),
        "config_recon": op("GET", f"{PFX}/reference"),
        "status_view": op("GET", f"{PFX}/status", "product_ui"),
        "start_checkout": op("POST", f"{PFX}/checkout"),
        "sandbox_pay": op("POST", f"{PFX}/checkout/{{payment_id}}/confirm"),
        "return_flow": op("GET", f"{PFX}/checkout/return"),
        "subscription_view": op("GET", f"{PFX}/insights/pro", "product_ui"),
        "request_refund": op("POST", f"{PFX}/refund", "product_ui"),
    }
    if ops_declared:
        # clean-MISS ladder only: generously hand the current engine every archon op (it STILL misses -- structural).
        surface.update({
            "vault_correlation": op("POST", f"{PFX}/vault/correlation", response_fields={"correlation_token": "correlation_token"}),
            "metering_open": op("POST", f"{PFX}/metering/open", response_fields={"period": "period"}),
            "disputes_credit": op("POST", f"{PFX}/disputes/credit", request_fields={"period": "period", "ct": "ct"}),
            "reconciler_close": op("POST", f"{PFX}/reconciler/close", request_fields={"period": "period"}),
            "radar_stepup": op("POST", f"{PFX}/radar/stepup", response_fields={"challenge": "challenge"}),
            "settlement_finalize": op("POST", f"{PFX}/settlement/finalize",
                                      request_fields={"period": "period", "ct": "ct", "challenge": "challenge"}),
        })
    return {
        "authorization_ref": "BENCH-BOSS-DEMIURGE", "authorized_by": "qa", "environment": "benchmark",
        "target_kind": "controlled_benchmark", "attested_synthetic_data": True, "attested_sandbox_payments": True,
        "allow_signup": True, "primary_currency": "USD", "allowed_hosts": [base_url.split("//", 1)[1]],
        "surface": surface,
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


async def _start(**flags):
    target = DemiurgeTarget(**flags)
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
async def probe_demiurge_truth(**flags) -> bool:
    """Drive the intended cross-service no-payment chain as an all-knowing attacker, with ZERO reference to the
    engine's oracle or the target's flaw flags beyond driving the public API + the token layout (the reference PoC)."""
    t = DemiurgeTarget(**flags)

    async def c(method, path, token=None, body=None):
        h = {"authorization": f"Bearer {token}"} if token else {}
        s, r, _ = await t.handle(method, path, body or {}, h)
        return s, r

    _s, who = await c("POST", f"{PFX}/signup")
    tok = who["token"]
    _s, mint = await c("POST", f"{PFX}/vault/correlation", tok)
    ct = forge_ct(mint["correlation_token"], b"forged", ENT_MINOR)   # inject a fabricated basis + enterprise amount
    _s, po = await c("POST", f"{PFX}/metering/open", tok)
    per = po.get("period")
    if not per:
        return False
    await c("POST", f"{PFX}/disputes/credit", tok, {"period": per, "ct": ct})
    await c("POST", f"{PFX}/reconciler/close", tok, {"period": per})
    _s, chr_ = await c("POST", f"{PFX}/radar/stepup", tok)
    ch = chr_.get("challenge")
    _s, fin = await c("POST", f"{PFX}/settlement/finalize", tok, {"period": per, "ct": ct, "challenge": ch})
    if fin.get("tier") != "enterprise":
        return False
    s_p, r_p = await c("GET", f"{PFX}/insights/pro", tok)
    return s_p == 200 and "report_id" in r_p


# ------------------------------------------------------------------------------- adversarial hostility (99.9% errors)
async def demiurge_hostility(n: int = 3000) -> tuple[float, int, int, int]:
    """Fire ``n`` bounded adversarial probes of the kinds a brute-forcer throws across the whole federation and report
    how many CONFERRED access. A hardened, authorization-first federation answers almost everything with an opaque
    error and grants nothing. Returns (error_rate_pct, errors, grants, total)."""
    t = DemiurgeTarget()

    async def h(method, path, token=None, body=None):
        hd = {"authorization": f"Bearer {token}"} if token else {}
        s, r, _ = await t.handle(method, path, body or {}, hd)
        return s, r

    _s, who = await h("POST", f"{PFX}/signup")
    tok = who["token"]
    _s, mint = await h("POST", f"{PFX}/vault/correlation", tok)
    good_ct = mint["correlation_token"]
    await h("GET", f"{PFX}/catalog")
    await h("GET", f"{PFX}/reference", tok)
    rng = __import__("random").Random(2026)
    probes = [
        lambda: h("GET", f"{PFX}/status"),                                                   # unauth -> 401
        lambda: h("GET", f"{PFX}/insights/enterprise", tok),                                 # premature -> 402
        lambda: h("GET", f"{PFX}/insights/pro", tok),                                        # premature -> 402
        lambda: h("POST", f"{PFX}/disputes/credit", tok, {"period": f"per_{rng.random()}", "ct": good_ct}),  # forged period
        lambda: h("POST", f"{PFX}/disputes/credit", tok, {"period": f"per_{rng.random()}", "ct": "garbage"}),  # bad token
        lambda: h("POST", f"{PFX}/reconciler/close", tok, {"period": f"per_{rng.random()}"}),  # unknown period
        lambda: h("POST", f"{PFX}/settlement/finalize", tok, {"period": f"per_{rng.random()}", "ct": good_ct}),  # unknown
        lambda: h("POST", f"{PFX}/settlement/atomic", tok, {"basis": f"bas_{rng.random()}"}),  # no real basis -> 402
        lambda: h("POST", f"{PFX}/settlement/consortium", tok, {"basis": f"bas_{rng.random()}"}),
        lambda: h("POST", f"{PFX}/attestation/purchase", tok, {"n": rng.random()}),           # forged attestation -> 401
        lambda: h("POST", f"{PFX}/disputes/credit", tok, {"ct": good_ct}),                    # no period
        lambda: h("POST", f"{PFX}/settlement/finalize", tok, {"ct": good_ct}),                # no period
        lambda: h("POST", f"{PFX}/checkout", tok, {"plan": "ultra"}),                         # unknown plan
        lambda: h("GET", f"{PFX}/{uuid.uuid4().hex[:6]}", tok),                               # guessed route
        lambda: h("POST", f"{PFX}/admin", tok, {}),                                           # mesh deny
    ]
    for _ in range(max(0, n - 4)):
        await rng.choice(probes)()
    err = t.calls_error
    rate = 100.0 * err / t.calls_total if t.calls_total else 0.0
    return rate, err, t.grants_total, t.calls_total


# -------------------------------------------------------------------------------------------------- engine run wrapper
async def run_engine(flags: dict | None = None, *, ops_declared: bool = False, **kw):
    """Run the CURRENT engine (through B52) against DEMIURGE. The swarm (B53-B60) is not yet wired; phase 5 adds the
    ``enable_*`` swarm flags here. For now this proves the clean MISS."""
    target, server, port = await _start(**(flags or {}))
    base = f"http://127.0.0.1:{port}"
    http = None
    try:
        brief = ExecutionBrief.from_dict(demiurge_brief(base, ops_declared=ops_declared), env={})
        guard = ScopeGuard(ScopePolicy.for_environment(base, max_requests=brief.limits.max_requests,
                                                        max_requests_per_second=brief.limits.max_requests_per_second))
        http = QAHttpClient(base, brief.limits.timeout_seconds, None, {}, "qa-pure-black-box-engine/1.0",
                            max_retries=0, guard=guard, stateless=True)
        engine = PureBlackBoxEngine(http, brief, base_url=base, enable_channel_probe=True, enable_chain_probe=True,
                                    enable_race_probe=True, enable_convergence_probe=True, enable_fabric_probe=True,
                                    enable_reconciliation_probe=True, race_burst=12, **kw)
        result = await engine.run(None)
        p0 = [f for f in result.findings if f.verdict.value == "CONFIRMED_P0"]
        return bool(p0), result, target
    finally:
        if http is not None and hasattr(http, "aclose"):
            await http.aclose()
        await server.aclose()
