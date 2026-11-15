#!/usr/bin/env python3
"""BOSS target 'NYX' -- the apex, "from the world before the gods". The hardest and most-defended target in the
suite: it is built to put Chronos / Pangaea / Olympus / Pantheon fully in the shadow by closing EVERY flaw those
targets seeded and hardening the surface along the ``qybaihe/bla`` ("Blind LLM Agents") doctrine -- Poison, Exhaust,
Hallucinate -- translated to an HTTP payment API:

  * POISON (opaque errors).     NYX NEVER names a missing/invalid field. Every rejection is a generic
      ``422 {"error":"unprocessable_entity","trace_id": <random>}``. This defeats an analyser that learns required
      inputs from the server's own validation errors (the engine's error-driven field learning keys off
      ``res.body["field"]`` -- see engine.py). To a prober hammering the surface, NYX answers ~99.9% errors.
  * EXHAUST (many paths required).  The enterprise grant is NOT one linear chain. It requires a QUORUM of THREE
      INDEPENDENT capabilities (``ledger_cap`` + ``risk_cap`` + ``settle_cap``), each minted by its OWN multi-step
      sub-chain (ledger / risk / mandate "worlds"), that must then CONVERGE at a single settlement step.
  * HALLUCINATE (freshness-synchronised convergence).  The three capabilities must be minted inside a TIGHT
      freshness window (mint latency 0.12s >> window 0.05s), so a SEQUENTIAL assembler always busts the window and
      is rejected; only a SYNCHRONISED CONCURRENT mint lands all three in one window. A single greedy spine (even a
      fast one) mints them one-after-another and is turned away.

EVERY Stripe guard from the attached research is implemented CORRECTLY here (this is what makes NYX a clean MISS
for the current engine, not a false positive):
  * Webhook authenticity -- HMAC-SHA256 over the raw body, ``t=``/``v1=`` scheme, 300s tolerance, per-endpoint
    ``whsec_``; the secret is NEVER leaked (Pangaea's flaw) -> the webhook path is an unforgeable black-box dead-end.
  * Server-side status verification -- the success/return URL is NEVER trusted; entitlement comes only from the
    server-retrieved PaymentIntent whose status == succeeded (the classic "fake success redirect" is closed).
  * PaymentIntent lifecycle + 3DS/SCA + Radar -- requires_confirmation -> requires_action -> succeeded; only
    succeeded grants.
  * Amount / currency / line-item reconciliation -- the server RECOMPUTES the amount from the catalog price; the
    client-supplied amount / currency is ignored (numeric + currency-confusion closed) EXCEPT at the quorum (below).
  * Event re-fetch + idempotency + event-id dedup (replay closed); BOLA ownership checks (every capability is
    org-scoped); strict mandate; SSRF allowlist; atomic one-shots (no TOCTOU).

THE ONE load-bearing flaw -- a no-payment ENTERPRISE bypass -- lives at the convergence, gated behind all of the
above + the two anti-RE properties:
    the settlement quorum trusts the three capabilities' client-declared ``rate``; three ZERO-RATED caps net $0 due
    while the entitlement resolver grants MOST-GENEROUS-WINS = enterprise. No payment is ever made.

THE FINDABLE no-payment chain:
    signup -> (ledger_open -> ledger_entry[rate=0])  \\
              (risk_session -> risk_clear[rate=0])     >=  minted CONCURRENTLY (one freshness window)
              (mandate_open -> mandate_affirm[rate=0]) /
           -> settlement_finalize(ledger_cap, risk_cap, settle_cap) -> enterprise

Four flags make the bypass load-bearing (remove any one -> truth=False and engine=False): ``ledger_open``,
``risk_open``, ``mandate_open``, ``quorum_trusts_rates``. Two difficulty properties make the CURRENT engine MISS
without removing the bypass (each is independently load-bearing for DETECTION): ``opaque_errors`` and
``sync_window``. All-correct -> False/False (no false alarm).

    PYTHONPATH=tests/verification_infrastructure/shims:tests/verification_infrastructure:. \
        python3 tests/verification_infrastructure/hardened_benchmark/run_nyx.py [--controls]
"""
from __future__ import annotations

import asyncio
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
MINT_LATENCY_S = 0.12   # a real "mint" round-trip; THREE of these in series (0.36s) bust the freshness window
MINT_SPREAD_S = 0.05    # the quorum caps must be minted within this spread -> only a concurrent burst fits
_MESH = ("admin", "ledger-internal", "treasury", "ops", "audit", "kms", "fraud", "risk-internal", "disputes")
_DENY = tuple(f"{PFX}/svc/{s}" for s in _MESH) + (f"{PFX}/admin", f"{PFX}/debug", f"{PFX}/internal")


def _trace() -> str:
    return f"trc_{uuid.uuid4().hex[:16]}"


class NyxTarget:
    """A hardened, opaque, multi-branch quorum-settlement payment API. Flaw flags default True (vulnerable);
    the two difficulty flags (opaque_errors, sync_window) default to the HARD setting."""

    def __init__(self, *, ledger_open: bool = True, risk_open: bool = True, mandate_open: bool = True,
                 quorum_trusts_rates: bool = True, opaque_errors: bool = True, sync_window: bool = True) -> None:
        self.ledger_open = ledger_open                  # flaw: ledger branch mints a cap with no paid basis
        self.risk_open = risk_open                      # flaw: risk branch clears with no real card auth
        self.mandate_open = mandate_open                # flaw: mandate branch affirms with no active mandate
        self.quorum_trusts_rates = quorum_trusts_rates  # flaw: finalize nets the client-declared cap rates
        self.opaque_errors = opaque_errors              # anti-RE: never name a field (defeats error-driven learning)
        self.sync_window = sync_window                  # anti-RE: caps must be minted within one freshness window
        self.by_token: dict[str, dict[str, Any]] = {}
        self.orgs: dict[str, dict[str, Any]] = {}
        self.intents: dict[str, dict[str, Any]] = {}
        self.bases: dict[str, dict[str, Any]] = {}            # settlement bases from REAL captured payments
        self.ledger_handles: dict[str, dict[str, Any]] = {}
        self.risk_handles: dict[str, dict[str, Any]] = {}
        self.mandate_handles: dict[str, dict[str, Any]] = {}
        self.caps: dict[str, dict[str, Any]] = {}             # minted capabilities (org-scoped, freshness-stamped)
        self._webhook_secret = "whsec_" + uuid.uuid4().hex    # NEVER leaked anywhere (correct webhook crypto)
        self.used_event_ids: set[str] = set()
        self.request_log: list[tuple[str, str]] = []
        self.calls_total = 0
        self.calls_error = 0
        self.grants_total = 0   # responses that actually CONFER access/entitlement (feature proof / settle / capture)
        self.internal_hits = 0

    # -- helpers ----------------------------------------------------------------------------------------------------
    def _reject(self, *, field: str | None = None, status: int = 422, code: str = "unprocessable_entity",
                **extra: Any) -> tuple[int, dict[str, Any], dict]:
        """A business/validation rejection. HARDENED (opaque_errors): a single generic 422 with a random trace id
        and NO field name -- an analyser cannot learn which input to supply. SOFT (opaque_errors off, for the
        detection-ablation control): the named field is returned so a field-learning analyser can progress."""
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
            self.grants_total += 1   # a response that actually hands over paid access / moves entitlement
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
            # Documents ROUTES only (a real public API reference). It leaks NO secret: the webhook signing secret,
            # the cap-mint internals and the quorum's netting rule are not here. The quorum NOTE is honest product
            # documentation ("settlement requires a fresh quorum of three attestations"), not a hint at the flaw.
            return 200, {"service": "nyx-settlement-gateway", "mesh_services": list(_MESH),
                         "settlement": {"finalize": f"{PFX}/settlement/finalize",
                                        "note": "settlement requires a fresh same-window quorum of three attestations"},
                         "attestations": {"ledger": f"{PFX}/ledger/open", "risk": f"{PFX}/risk/session",
                                          "mandate": f"{PFX}/mandate/open"},
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
            return 403, {"error": "forbidden", "detail": "mesh policy"}, {}

        if method == "GET" and p == f"{PFX}/status":
            return 200, {"tier": self._effective(org)}, {}

        # -- correct happy-path purchase (PaymentIntent lifecycle) ------------------------------------------------
        if method == "POST" and p == f"{PFX}/checkout":
            plan = body.get("plan")
            if plan not in ("pro", "enterprise"):
                return self._reject(field="plan", code="unknown_plan")
            pid = f"pi_{uuid.uuid4().hex[:10]}"
            # Amount is RECOMPUTED server-side from the catalog; any client amount/currency is ignored.
            self.intents[pid] = {"org": oid, "plan": plan, "amount": PRICES[plan]["USD"], "status": "requires_confirmation"}
            return 201, {"payment_id": pid, "status": "requires_confirmation", "amount": PRICES[plan]["USD"], "currency": "USD"}, {}
        if method == "POST" and p.startswith(f"{PFX}/checkout/") and p.endswith("/confirm"):
            intent = self.intents.get(p.split("/")[-2])
            if intent is None or intent["org"] != oid:
                return 404, {"error": "unknown_payment"}, {}
            if body.get("outcome") == "success":
                intent["status"] = "succeeded"
                intent["captured"] = True
                if not any(g.get("source") == "paid" and g["tier"] == intent["plan"] and g["state"] == "active" for g in org["grants"]):
                    org["grants"].append({"source": "paid", "tier": intent["plan"], "state": "active"})
                org["paid"] = True
                # a REAL capture mints a settlement basis (the honest input the ledger branch requires when closed)
                bref = f"bas_{uuid.uuid4().hex[:10]}"
                self.bases[bref] = {"org": oid, "paid": True}
                return 200, {"status": "succeeded", "settlement_basis": bref}, {}
            intent["status"] = "requires_payment_method"
            return 402, {"error": "declined", "status": "requires_payment_method"}, {}
        if method == "GET" and p == f"{PFX}/checkout/return":
            # SERVER-SIDE verification only: the return NEVER trusts a client status/plan/tenant query.
            intent = self.intents.get(q.get("payment_id", ""))
            if intent is None or intent["org"] != oid:
                return 404, {"error": "unknown_payment"}, {}
            return 200, {"status": intent["status"]}, {}

        # -- webhook settlement: CORRECT crypto, unforgeable (secret never leaked) ---------------------------------
        if method == "POST" and p == f"{PFX}/webhooks/settlement":
            return self._verify_webhook(headers, body, org)

        # -- BRANCH L (ledger attestation) ------------------------------------------------------------------------
        if method == "POST" and p == f"{PFX}/ledger/open":
            h = f"lh_{uuid.uuid4().hex[:10]}"
            self.ledger_handles[h] = {"org": oid}
            return 201, {"ledger_handle": h}, {}
        if method == "POST" and p.startswith(f"{PFX}/ledger/") and p.endswith("/entry"):
            h = self.ledger_handles.get(p.split("/")[-2])
            if h is None or h["org"] != oid:
                return self._reject(field="ledger_handle", code="unknown_handle")
            if "rate" not in body:
                return self._reject(field="rate", code="missing_field")
            if not self.ledger_open:
                # CORRECT: a ledger entry must be backed by a real captured-payment basis the attacker cannot forge.
                basis = self.bases.get(body.get("basis", ""))
                if basis is None or basis["org"] != oid:
                    return self._reject(field="basis", code="paid_basis_required", status=402)
            return await self._mint(oid, kind="ledger", rate=body.get("rate"), out="ledger_cap")
        # -- BRANCH R (risk attestation) --------------------------------------------------------------------------
        if method == "POST" and p == f"{PFX}/risk/session":
            h = f"rh_{uuid.uuid4().hex[:10]}"
            self.risk_handles[h] = {"org": oid}
            return 201, {"risk_handle": h}, {}
        if method == "POST" and p.startswith(f"{PFX}/risk/") and p.endswith("/clear"):
            h = self.risk_handles.get(p.split("/")[-2])
            if h is None or h["org"] != oid:
                return self._reject(field="risk_handle", code="unknown_handle")
            if "rate" not in body:
                return self._reject(field="rate", code="missing_field")
            if not self.risk_open:
                # CORRECT: clearing risk requires a real 3DS/SCA card-auth assertion (bound to a succeeded intent).
                if not self._has_card_auth(oid, body.get("card_auth")):
                    return self._reject(field="card_auth", code="sca_required", status=402)
            return await self._mint(oid, kind="risk", rate=body.get("rate"), out="risk_cap")
        # -- BRANCH M (mandate attestation) -----------------------------------------------------------------------
        if method == "POST" and p == f"{PFX}/mandate/open":
            h = f"mh_{uuid.uuid4().hex[:10]}"
            self.mandate_handles[h] = {"org": oid, "status": "pending"}
            return 201, {"mandate_handle": h}, {}
        if method == "POST" and p.startswith(f"{PFX}/mandate/") and p.endswith("/affirm"):
            h = self.mandate_handles.get(p.split("/")[-2])
            if h is None or h["org"] != oid:
                return self._reject(field="mandate_handle", code="unknown_handle")
            if "rate" not in body:
                return self._reject(field="rate", code="missing_field")
            if not self.mandate_open and h["status"] != "active":
                # CORRECT: a mandate must be ACTIVE (bank-affirmed) before it can back a settlement.
                return self._reject(field="mandate_status", code="mandate_not_active", status=409)
            return await self._mint(oid, kind="mandate", rate=body.get("rate"), out="settle_cap")

        # -- CONVERGENCE: quorum settlement -----------------------------------------------------------------------
        if method == "POST" and p == f"{PFX}/settlement/finalize":
            refs = [body.get("ledger_cap"), body.get("risk_cap"), body.get("settle_cap")]
            kinds = ("ledger", "risk", "mandate")
            picked: list[dict[str, Any]] = []
            for ref, kind in zip(refs, kinds):
                cap = self.caps.get(ref) if ref else None
                if cap is None:
                    return self._reject(field=f"{kind}_cap", code="missing_field")
                if cap["org"] != oid:          # BOLA closed: a capability minted by another org is refused
                    return self._reject(field=f"{kind}_cap", code="not_capability_owner", status=403)
                if cap["kind"] != kind:
                    return self._reject(field=f"{kind}_cap", code="wrong_capability_kind")
                picked.append(cap)
            if self.sync_window:
                spread = max(c["mint_ts"] for c in picked) - min(c["mint_ts"] for c in picked)
                if spread > MINT_SPREAD_S:
                    # the quorum is STALE: the three attestations were not minted in one fresh window
                    return self._reject(field="quorum", code="stale_quorum", status=409)
            if self.quorum_trusts_rates:
                net_due = sum(float(c["rate"]) for c in picked)     # FLAW: trusts the client-declared rates
            else:
                net_due = PRICES["enterprise"]["USD"]               # CORRECT: server recomputes the real amount due
            if net_due > 0:
                return self._reject(field="net_due", code="payment_required", status=402)
            # net <= 0 -> settled free; entitlement resolves MOST-GENEROUS-WINS across the quorum -> enterprise
            org["grants"].append({"source": "quorum_settlement", "tier": "enterprise", "state": "active"})
            return 200, {"status": "settled", "tier": "enterprise", "net_due": net_due}, {}

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
        return 404, {"error": "not_found"}, {}

    async def _mint(self, oid: str, *, kind: str, rate: Any, out: str):
        """Mint a freshness-stamped capability. The latency models a real attestation round-trip; the mint_ts is
        recorded AFTER the latency, so three SEQUENTIAL mints span >= 0.24s (busting MINT_SPREAD_S) while three
        CONCURRENT mints land within a few ms of each other."""
        try:
            r = float(rate)
        except (TypeError, ValueError):
            return self._reject(field="rate", code="invalid_field")
        await asyncio.sleep(MINT_LATENCY_S)
        ref = f"cap_{kind}_{uuid.uuid4().hex[:12]}"
        self.caps[ref] = {"org": oid, "kind": kind, "rate": r, "mint_ts": time.monotonic()}
        return 201, {out: ref, "kind": kind, "mint_ts_hint": "fresh"}, {}

    def _has_card_auth(self, oid: str, token: Any) -> bool:
        return isinstance(token, str) and token.startswith("sca_") and self.intents.get(token[4:], {}).get("org") == oid

    def _verify_webhook(self, headers, body, org):
        """Standard-Webhooks v1 verification over the RAW body with a 300s tolerance and per-endpoint secret. The
        secret is never exposed, so a black-box caller cannot forge this -> the webhook settlement path is a correct
        dead-end (present only so an engine that tries to forge provider events is correctly turned away)."""
        import base64
        import hashlib
        import hmac
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


def nyx_brief(base_url: str) -> dict[str, Any]:
    def op(method: str, path: str, via: str = "authorized_browser_trace", **extra: Any) -> dict[str, Any]:
        return {"method": method, "path": path, "observed_via": via, **extra}
    return {
        "authorization_ref": "BENCH-BOSS-NYX", "authorized_by": "qa", "environment": "benchmark",
        "target_kind": "controlled_benchmark", "attested_synthetic_data": True, "attested_sandbox_payments": True,
        "allow_signup": True, "primary_currency": "USD", "allowed_hosts": [base_url.split("//", 1)[1]],
        "surface": {
            "signup": op("POST", f"{PFX}/signup", "product_ui"),
            "catalog": op("GET", f"{PFX}/catalog"),
            "config_recon": op("GET", f"{PFX}/config", "public_api_reference"),
            "status_view": op("GET", f"{PFX}/status", "product_ui"),
            "start_checkout": op("POST", f"{PFX}/checkout"),
            "sandbox_pay": op("POST", f"{PFX}/checkout/{{payment_id}}/confirm"),
            "return_flow": op("GET", f"{PFX}/checkout/return"),
            # --- the three attestation branches (each: open -> mint) ---
            "ledger_open": op("POST", f"{PFX}/ledger/open", "public_api_reference",
                              response_fields={"ledger_handle": "ledger_handle"}),
            "ledger_entry": op("POST", f"{PFX}/ledger/{{ledger_handle}}/entry", "public_api_reference",
                               request_fields={"rate": "rate"}, response_fields={"ledger_cap": "ledger_cap"}),
            "risk_session": op("POST", f"{PFX}/risk/session", "public_api_reference",
                               response_fields={"risk_handle": "risk_handle"}),
            "risk_clear": op("POST", f"{PFX}/risk/{{risk_handle}}/clear", "public_api_reference",
                             request_fields={"rate": "rate"}, response_fields={"risk_cap": "risk_cap"}),
            "mandate_open": op("POST", f"{PFX}/mandate/open", "public_api_reference",
                               response_fields={"mandate_handle": "mandate_handle"}),
            "mandate_affirm": op("POST", f"{PFX}/mandate/{{mandate_handle}}/affirm", "public_api_reference",
                                 request_fields={"rate": "rate"}, response_fields={"settle_cap": "settle_cap"}),
            # --- the convergence step: consumes all three capabilities ---
            "settlement_finalize": op("POST", f"{PFX}/settlement/finalize", "public_api_reference",
                                      request_fields={"ledger_cap": "ledger_cap", "risk_cap": "risk_cap", "settle_cap": "settle_cap"}),
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
    target = NyxTarget(**flags)
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
async def probe_nyx_truth(**flags) -> bool:
    """Drive the intended no-payment chain as an all-knowing attacker: build the three branches, mint the three
    caps CONCURRENTLY (one freshness window) at rate 0, converge at settlement_finalize, then confirm enterprise
    access via the pro feature. Returns whether a real, externally-reproducible no-payment bypass exists.
    Computed with ZERO reference to the engine's oracle code or the target's flaw flags beyond driving its API."""
    t = NyxTarget(**flags)

    async def c(method, path, token=None, body=None):
        h = {"authorization": f"Bearer {token}"} if token else {}
        s, r, _ = await t.handle(method, path, body or {}, h)
        return s, r

    _s, who = await c("POST", f"{PFX}/signup")
    tok = who["token"]
    # branch "open" steps (fast)
    _s, lo = await c("POST", f"{PFX}/ledger/open", tok)
    _s, ro = await c("POST", f"{PFX}/risk/session", tok)
    _s, mo = await c("POST", f"{PFX}/mandate/open", tok)
    if not (lo.get("ledger_handle") and ro.get("risk_handle") and mo.get("mandate_handle")):
        return False
    # the three terminal mints, CONCURRENTLY, at rate 0 -> one freshness window
    results = await asyncio.gather(
        c("POST", f"{PFX}/ledger/{lo['ledger_handle']}/entry", tok, {"rate": 0}),
        c("POST", f"{PFX}/risk/{ro['risk_handle']}/clear", tok, {"rate": 0}),
        c("POST", f"{PFX}/mandate/{mo['mandate_handle']}/affirm", tok, {"rate": 0}),
    )
    caps = {}
    for _s, r in results:
        caps.update({k: v for k, v in r.items() if k.endswith("_cap")})
    if not {"ledger_cap", "risk_cap", "settle_cap"} <= set(caps):
        return False
    _s, fin = await c("POST", f"{PFX}/settlement/finalize", tok, caps)
    if fin.get("tier") != "enterprise":
        return False
    s_p, r_p = await c("GET", f"{PFX}/insights/pro", tok)
    return s_p == 200 and "report_id" in r_p


# ------------------------------------------------------------------------------- adversarial hostility (99.9% errors)
async def nyx_hostility(n: int = 2000) -> tuple[float, int, int, int]:
    """Measure NYX's hardening the way a real system is measured under an adversarial campaign: fire ``n`` bounded
    probes -- the kinds a brute-forcer throws (unauth, guessed routes, forged webhooks, random/replayed capability
    refs, out-of-order mints, wrong-plan checkouts, premature feature access) plus a few legitimate recon calls --
    and report the error rate and how many CONFERRED access. A hardened, authorization-first target answers almost
    everything with an opaque error and grants nothing. Returns (error_rate_pct, errors, grants, total)."""
    t = NyxTarget()  # default HARD + all-flaws: even fully 'vulnerable', the bypass needs the exact fresh quorum

    async def h(method, path, token=None, body=None):
        hd = {"authorization": f"Bearer {token}"} if token else {}
        s, r, _ = await t.handle(method, path, body or {}, hd)
        return s, r

    _s, who = await h("POST", f"{PFX}/signup")   # legitimate recon (these few legitimately answer 2xx)
    tok = who["token"]
    await h("GET", f"{PFX}/catalog")
    await h("GET", f"{PFX}/config", tok)
    rng = __import__("random").Random(1337)
    probes = [
        lambda: h("GET", f"{PFX}/status"),                                                       # unauth -> 401
        lambda: h("GET", f"{PFX}/insights/enterprise", tok),                                     # premature -> 402
        lambda: h("GET", f"{PFX}/insights/pro", tok),                                            # premature -> 402
        lambda: h("POST", f"{PFX}/settlement/finalize", tok, {"ledger_cap": f"cap_x{rng.random()}", "risk_cap": "y", "settle_cap": "z"}),  # forged caps -> 422
        lambda: h("POST", f"{PFX}/ledger/lh_{rng.random()}/entry", tok, {"rate": 0}),            # out-of-order (no handle) -> 422
        lambda: h("POST", f"{PFX}/mandate/mh_{rng.random()}/affirm", tok, {"rate": 0}),          # out-of-order -> 422
        lambda: h("POST", f"{PFX}/checkout", tok, {"plan": "ultra"}),                            # unknown plan -> 422
        lambda: h("POST", f"{PFX}/webhooks/settlement", tok, {"evt": rng.random()}),             # forged event -> 401
        lambda: h("GET", f"{PFX}/{uuid.uuid4().hex[:6]}", tok),                                  # guessed route -> 404
        lambda: h("POST", f"{PFX}/admin", tok, {}),                                              # mesh deny -> 403
    ]
    for _ in range(max(0, n - 3)):
        await rng.choice(probes)()
    err = t.calls_error
    rate = 100.0 * err / t.calls_total if t.calls_total else 0.0
    return rate, err, t.grants_total, t.calls_total


# -------------------------------------------------------------------------------------------------- engine run wrapper
async def run_engine(flags: dict | None = None, *, converge: bool = False, race: bool = False, **kw):
    target, server, port = await _start(**(flags or {}))
    base = f"http://127.0.0.1:{port}"
    http = None
    try:
        brief = ExecutionBrief.from_dict(nyx_brief(base), env={})
        guard = ScopeGuard(ScopePolicy.for_environment(base, max_requests=brief.limits.max_requests,
                                                        max_requests_per_second=brief.limits.max_requests_per_second))
        http = QAHttpClient(base, brief.limits.timeout_seconds, None, {}, "qa-pure-black-box-engine/1.0",
                            max_retries=0, guard=guard, stateless=True)
        engine = PureBlackBoxEngine(http, brief, base_url=base, enable_channel_probe=True, enable_chain_probe=True,
                                    enable_race_probe=race, enable_convergence_probe=converge, race_burst=12, **kw)
        result = await engine.run(None)
        p0 = [f for f in result.findings if f.verdict.value == "CONFIRMED_P0"]
        return bool(p0), result, target
    finally:
        if http is not None and hasattr(http, "aclose"):
            await http.aclose()
        await server.aclose()
