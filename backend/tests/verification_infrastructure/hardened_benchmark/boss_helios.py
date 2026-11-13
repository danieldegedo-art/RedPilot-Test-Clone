#!/usr/bin/env python3
"""BOSS target 'Helios' -- a DEEPER, more hardened enterprise paywall than 'Aurelia'. It layers the real
defenses large payment platforms actually use (researched), so the flaw is reachable only after genuine
recon + reverse engineering + a LONG chain with several server-named inputs:

  * REVERSE-ENGINEERED ROUTE: the settlement 'commit' endpoint lives on an OPAQUE, per-deployment route
    segment that appears nowhere in the UI -- only inside GET /config (a JS/manifest-style blob). Without
    reading config you cannot even address the endpoint. (Mirrors JS-bundle/sourcemap endpoint hunting.)
  * SIGNED SETTLEMENT DEAD-END: the intended paid path is a provider webhook carrying an HMAC signature
    (TrueLayer 'Tl-Signature' style) the target holds privately -> unforgeable black-box -> honest BLOCKED.
  * ONE-TIME NONCE + TWO-REFERENCE COMMIT: the commit step requires BOTH a 'ticket' (the migration ref)
    AND a single-use 'nonce' (a seal minted by the migration-request step and consumed on use). Each is
    disclosed BY NAME only when the previous one is satisfied -> the tester must supply SEVERAL
    server-named fields in sequence (idempotency / replay-token pattern).
  * MOST-GENEROUS-WINS OVER-GRANT: the commit trusts the presence of a migration ticket instead of
    re-checking a captured payment (the classic 'confirm step trusts workflow order' business-logic flaw),
    minting an ENTERPRISE grant with NO payment.

THE FINDABLE BYPASS is a DEPTH-5 no-payment chain, each step individually harmless and heavily gated:
    enroll_trial -> mint_voucher -> apply_promo -> request_migration -> commit_migration
(preview trial)  (promo token)   (marks migratable) (mints ticket+one-time seal) (reverse-engineered route; ticket+nonce)

Honest expectation: the single-field-learning composer MISSES this (the commit needs two server-named
inputs); the iterative multi-field-learning composer FINDS it; the signed webhook path is never confirmed.

    PYTHONPATH=tests/verification_infrastructure/shims:tests/verification_infrastructure:. \
        python3 tests/verification_infrastructure/hardened_benchmark/run_helios.py
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import uuid
from typing import Any
from urllib.parse import parse_qs, urlparse

from app.enterprise_controls.scope import ScopeGuard, ScopePolicy
from app.testing.http_client import QAHttpClient
from app.testing.integrity.brief import ExecutionBrief
from app.testing.integrity.engine import PureBlackBoxEngine
from reference_target import _read_http_request, _TrackedServer

PFX = "/api"
_TIER_RANK = {None: 0, "preview": 1, "pro": 2, "enterprise": 3}


class HeliosTarget:
    def __init__(self) -> None:
        self.by_token: dict[str, dict[str, str]] = {}
        self.orgs: dict[str, dict[str, Any]] = {}
        self.intents: dict[str, dict[str, Any]] = {}
        self.vouchers: dict[str, dict[str, Any]] = {}
        self.overrides: dict[str, dict[str, Any]] = {}
        self.migrations: dict[str, dict[str, Any]] = {}
        self.seals: dict[str, dict[str, Any]] = {}
        self.gateway = f"mg-{uuid.uuid4().hex[:6]}"   # opaque per-deployment route segment, disclosed only in /config
        self._sig_key = uuid.uuid4().hex.encode()     # provider webhook HMAC key -- never leaves the process
        self.request_log: list[tuple[str, str]] = []
        self.request_headers_seen: list[dict[str, str]] = []
        self.internal_hits = 0

    def _effective(self, org: dict[str, Any]) -> str | None:
        best = None
        for g in org["grants"]:
            if g["state"] == "active" and _TIER_RANK[g["tier"]] > _TIER_RANK[best]:
                best = g["tier"]
        return best

    async def handle(self, method, raw_path, body, headers):
        p = urlparse(raw_path).path
        q = {k: v[0] for k, v in parse_qs(urlparse(raw_path).query).items()}
        body = body or {}
        self.request_log.append((method, p))
        self.request_headers_seen.append(dict(headers))

        # --- unauthenticated / public ---
        if method == "POST" and p == f"{PFX}/signup":
            oid, tok = f"o_{uuid.uuid4().hex[:8]}", f"tok_{uuid.uuid4().hex[:16]}"
            self.orgs[oid] = {"grants": []}
            self.by_token[tok] = {"org": oid}
            return 201, {"token": tok, "tenant_id": oid}, {}
        if method == "GET" and p == f"{PFX}/catalog":
            return 200, {"plans": [
                {"code": "pro", "price_id": "pr_pro", "amount": 99.0},
                {"code": "enterprise", "price_id": "pr_ent", "amount": 999.0}]}, {}
        if method == "GET" and p == f"{PFX}/config":
            # public manifest; the settlement route segment is buried here (nested) and nowhere else
            return 200, {"service": "helios", "api_versions": ["v1", "v3"],
                         "endpoints": {"settlement": {"gateway": self.gateway, "verb": "commit"}}}, {}

        # --- signed settlement webhook: the intended paid path; unforgeable black-box ---
        if method == "POST" and p == f"{PFX}/webhooks/billing":
            sig = headers.get("x-helios-signature", "")
            raw = json.dumps(body, sort_keys=True).encode()
            good = hmac.new(self._sig_key, raw, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(sig, good):
                return 401, {"error": "bad_signature"}, {}
            intent = self.intents.get(body.get("payment_id", ""))
            if intent and intent["captured"]:
                self.orgs[intent["org"]]["grants"].append(
                    {"source": "paid", "tier": intent["plan"], "state": "active", "migratable": False})
            return 200, {"status": "processed"}, {}

        # --- authenticated surface ---
        auth = headers.get("authorization", "")
        ident = self.by_token.get(auth[7:]) if auth.lower().startswith("bearer ") else None
        if ident is None:
            return 401, {"error": "unauthenticated"}, {}
        oid = ident["org"]
        org = self.orgs[oid]

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
                # test-mode: a captured sandbox payment provisions the matching paid grant (the LEGIT path)
                if not any(g["source"] == "paid" and g["tier"] == intent["plan"] and g["state"] == "active" for g in org["grants"]):
                    org["grants"].append({"source": "paid", "tier": intent["plan"], "state": "active", "migratable": False})
                return 200, {"status": "captured"}, {}
            return 402, {"error": "declined"}, {}
        if method == "GET" and p == f"{PFX}/checkout/return":
            intent = self.intents.get(q.get("payment_id", ""))
            if intent is None or intent["org"] != oid:
                return 404, {"error": "unknown_payment"}, {}
            return 200, {"status": "captured" if intent["captured"] else "pending"}, {}

        # --- aux primitives (individually harmless) ---
        if method == "POST" and p == f"{PFX}/trials":
            gref = f"g_{uuid.uuid4().hex[:8]}"
            org["grants"].append({"ref": gref, "source": "trial", "tier": "preview", "state": "active", "migratable": False})
            return 201, {"trial_ref": gref, "tier": "preview"}, {}
        if method == "POST" and p == f"{PFX}/vouchers":
            vtok = f"vc_{uuid.uuid4().hex[:12]}"
            self.vouchers[vtok] = {"org": oid, "used": False}
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
            grant["migratable"] = True       # harmless on its own (tier stays 'preview')
            oref = f"ov_{uuid.uuid4().hex[:8]}"
            self.overrides[oref] = {"org": oid, "grant": gref}
            return 201, {"override_ref": oref, "tier": "preview"}, {}
        if method == "POST" and p == f"{PFX}/migrations":
            basis = body.get("basis")
            if basis is None:
                return 422, {"error": "missing_field", "field": "basis"}, {}
            ov = self.overrides.get(basis)
            if ov is None or ov["org"] != oid:
                return 409, {"error": "no_basis"}, {}
            grant = next((g for g in org["grants"] if g.get("ref") == ov["grant"]), None)
            if grant is None or not grant.get("migratable"):
                return 409, {"error": "not_migratable"}, {}
            mref = f"mig_{uuid.uuid4().hex[:8]}"
            self.migrations[mref] = {"org": oid, "grant": ov["grant"]}
            seal = f"sl_{uuid.uuid4().hex[:12]}"
            self.seals[seal] = {"org": oid, "mig": mref, "used": False}   # single-use nonce
            return 201, {"migration_ref": mref, "seal": seal}, {}
        # commit lives on the reverse-engineered opaque route segment from /config
        if method == "POST" and p == f"{PFX}/{self.gateway}/commit":
            ticket = body.get("ticket")
            mig = self.migrations.get(ticket) if ticket else None
            if mig is None or mig["org"] != oid:
                return 422, {"error": "invalid_field" if ticket is not None else "missing_field", "field": "ticket"}, {}
            nonce = body.get("nonce")
            seal = self.seals.get(nonce) if nonce else None
            if seal is None or seal["org"] != oid or seal["mig"] != ticket or seal["used"]:
                return 422, {"error": "invalid_field" if nonce is not None else "missing_field", "field": "nonce"}, {}
            seal["used"] = True   # one-time
            # BUG: commit trusts the migration ticket instead of re-checking a captured payment ->
            # mints an ENTERPRISE grant with no payment (most-generous-wins over-grant).
            org["grants"].append({"source": "migration", "tier": "enterprise", "state": "active", "migratable": False})
            return 200, {"status": "committed", "tier": "enterprise"}, {}

        if method == "GET" and p == f"{PFX}/insights/pro":
            return (200, {"report_id": "r_x"}, {}) if _TIER_RANK[self._effective(org)] >= _TIER_RANK["pro"] else (402, {"error": "upgrade_required"}, {})
        if method == "GET" and p == f"{PFX}/insights/enterprise":
            return (200, {"dossier_id": "d_x"}, {}) if self._effective(org) == "enterprise" else (402, {"error": "upgrade_required"}, {})
        if method == "POST" and p == f"{PFX}/refund":
            for g in org["grants"]:
                g["state"] = "revoked"
            return 200, {"status": "ok"}, {}
        return 404, {"error": "not_found"}, {}


def helios_brief(base_url: str) -> dict[str, Any]:
    return {
        "authorization_ref": "BENCH-BOSS-HELIOS", "authorized_by": "qa", "environment": "benchmark",
        "target_kind": "controlled_benchmark", "attested_synthetic_data": True, "attested_sandbox_payments": True,
        "allow_signup": True, "primary_currency": "USD", "allowed_hosts": [base_url.split("//", 1)[1]],
        "surface": {
            "signup": {"method": "POST", "path": f"{PFX}/signup", "observed_via": "product_ui"},
            "catalog": {"method": "GET", "path": f"{PFX}/catalog", "observed_via": "authorized_browser_trace"},
            "config_recon": {"method": "GET", "path": f"{PFX}/config", "observed_via": "public_api_reference"},
            "start_checkout": {"method": "POST", "path": f"{PFX}/checkout", "observed_via": "authorized_browser_trace"},
            "sandbox_pay": {"method": "POST", "path": f"{PFX}/checkout/{{payment_id}}/confirm", "observed_via": "authorized_browser_trace"},
            "return_flow": {"method": "GET", "path": f"{PFX}/checkout/return", "observed_via": "authorized_browser_trace"},
            "enroll_trial": {"method": "POST", "path": f"{PFX}/trials", "observed_via": "authorized_browser_trace"},
            "mint_voucher": {"method": "POST", "path": f"{PFX}/vouchers", "observed_via": "authorized_browser_trace"},
            "apply_promo": {"method": "POST", "path": f"{PFX}/grants/{{trial_ref}}/promo", "observed_via": "authorized_browser_trace"},
            "stage_reconcile": {"method": "POST", "path": f"{PFX}/migrations", "observed_via": "public_api_reference"},
            "apply_reconcile": {"method": "POST", "path": f"{PFX}/{{gateway}}/commit", "observed_via": "public_api_reference"},
            "settle_webhook": {"method": "POST", "path": f"{PFX}/webhooks/billing", "observed_via": "public_api_reference"},
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
    target = HeliosTarget()
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
    head = f"HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {len(payload)}\r\nConnection: close\r\n\r\n"
    try:
        writer.write(head.encode("utf-8") + payload)
        await writer.drain()
    finally:
        writer.close()


async def probe_helios_truth() -> bool:
    """Drive the intended depth-5 solution in-process to confirm a real no-payment enterprise bypass exists."""
    t = HeliosTarget()

    async def c(method, path, token=None, body=None):
        h = {"authorization": f"Bearer {token}"} if token else {}
        s, r, _ = await t.handle(method, path, body or {}, h)
        return s, r

    _s, who = await c("POST", f"{PFX}/signup"); tok = who["token"]
    _s, cfg = await c("GET", f"{PFX}/config"); gw = cfg["endpoints"]["settlement"]["gateway"]
    _s, tr = await c("POST", f"{PFX}/trials", tok); gref = tr["trial_ref"]
    _s, vc = await c("POST", f"{PFX}/vouchers", tok); vtok = vc["token"]
    _s, ov = await c("POST", f"{PFX}/grants/{gref}/promo", tok, {"voucher": vtok}); oref = ov["override_ref"]
    _s, mg = await c("POST", f"{PFX}/migrations", tok, {"basis": oref}); mref, seal = mg["migration_ref"], mg["seal"]
    await c("POST", f"{PFX}/{gw}/commit", tok, {"ticket": mref, "nonce": seal})
    s_e, r_e = await c("GET", f"{PFX}/insights/enterprise", tok)
    s_p, r_p = await c("GET", f"{PFX}/insights/pro", tok)
    assert s_e == 200 and "dossier_id" in r_e, "chain should over-grant enterprise"
    return s_p == 200 and "report_id" in r_p


async def run_engine(**kw) -> tuple[bool, Any]:
    target, server, port = await _start()
    base = f"http://127.0.0.1:{port}"
    http = None
    try:
        brief = ExecutionBrief.from_dict(helios_brief(base), env={})
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
