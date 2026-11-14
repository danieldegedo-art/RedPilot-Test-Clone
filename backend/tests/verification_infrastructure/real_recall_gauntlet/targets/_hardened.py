"""Enterprise-HARDENED, GREY-BOX commerce spine shared by the hardened gauntlet tranche.

This extends the correct-by-default ``BaseCommerce`` (``_core.py`` is left byte-for-byte
unchanged) with the six enterprise defenses the mission's checklist requires, all genuinely
ENFORCED and CORRECT by default -- in BOTH ``flaw_on`` and ``patched``:

  (1) async / server-authoritative confirmation -- the grant is bound to a REAL server-side
      capture (``sandbox_pay(success)`` settles + grants server-side, modelling the PSP webhook
      firing in test-mode). The client ``return`` is a pure landing page that only *reports*
      entitlement; tampering its status grants nothing. (No trusted client return.)
  (2) idempotency / replay keys on a grant-affecting op (``confirm``): a replayed key returns the
      cached result WITHOUT re-applying the grant.
  (3) a one-time, server-issued step-up challenge before a sensitive op.
  (4) server-authoritative pricing + strict validation (amount server-set; unknown plan -> 400).
  (5) rate limiting / bounded concurrency on sensitive ops (a real lock; a bounded counter).
  (6) tenant / identity binding on every state transition (the caller must own what it names).

A flaw target flips EXACTLY ONE of the override hooks below; its patched twin flips nothing.
Weakening a defense so a heuristic binds would be faking -- the engine is adapted to the targets,
never the targets to the engine.

GREY-BOX posture: confirmation is a cross-subject / cross-state differential that uses only the
engine's OWN authenticated identities and their OWN references. Nothing here forges a signature,
guesses an id, bypasses auth, or performs a destructive probe; those stay in the honest ceiling.

Calibration guarantee: on every target a legitimate cheapest-plan success payment leaves the
payer entitled and a clean identity denied, so the engine's control establishment succeeds and
the oracle is proven discriminating -- every instance is a clean TP/FN (never an UNKNOWN that
could mask a miss), and the 0-FP property stays meaningful.
"""
from __future__ import annotations

from typing import Any, Optional
from urllib.parse import parse_qs, urlparse

from _core import CREDITS_PER_PAYMENT, BaseCommerce, _id, spine_brief
from surface import Scheme

# Anonymised (per-seed) pools for the hardened spine's own ops/fields. Meaning preserved; literal
# varies per seed via Scheme.custom/one, so no literal transfers across the DEV/TEST/HOLDOUT split.
_AUTHORIZE_ROUTES = ["authorize", "hold", "preauth", "reserve", "auth-only"]
_CHALLENGE_ROUTES = ["step-up", "challenge", "verify-human", "mfa/start", "attest"]
_CONFIRM_ROUTES = ["apply-credit", "confirm-topup", "loyalty/apply", "redeem-credit", "settle-bonus"]
_CHAL_FIELDS = ["challenge_token", "step_up", "nonce", "attestation", "human_token"]
_IDEM_FIELDS = ["idempotency_key", "request_id", "dedupe_key", "client_token", "op_id"]
_REF_FIELDS = ["payment_ref", "order_ref", "receipt", "txn_ref", "settlement_ref"]


class HardenedCommerce(BaseCommerce):
    """Correct hardened grey-box spine. One override hook = one real advisory's missing check."""

    def __init__(self, scheme: Scheme, *, flaw_on: bool, plan_names: tuple[str, ...],
                 prices: dict[str, dict[str, float]], path_log: Optional[set] = None) -> None:
        super().__init__(scheme, flaw_on=flaw_on, plan_names=plan_names, prices=prices, path_log=path_log)
        self._challenges: dict[str, dict] = {}
        self._idem: set[str] = set()
        self._rate: dict[str, int] = {}          # per-identity sensitive-op counter (defense 5)
        self._rate_cap = 64
        for t in self.tenants.values():
            t.setdefault("role", "member")

    # ---- the single-check override hooks (a flaw target overrides exactly one) ---------------
    def _entitling(self, p: dict) -> bool:
        """Correct: only a REAL capture entitles. (h_async_auth: also an unsettled 'authorized'.)"""
        return bool(p.get("captured"))

    def _record_idem(self, key: str) -> bool:
        """Correct: record the key; return True iff this key is NEW (first use).
        (h_replay_regrant: never records -> every replay is treated as new -> re-grants.)"""
        if key in self._idem:
            return False
        self._idem.add(key)
        return True

    # ---- shared helpers ---------------------------------------------------------------------
    def _settle_if_entitled(self, p: dict) -> None:
        """Server-side settle: the 'webhook' firing in test-mode. Grants iff the payment is
        entitling (defense 1), once (idempotent grant), to the PAYER's tenant (defense 6)."""
        if self._entitling(p) and not p.get("granted"):
            p["granted"] = True
            p["state"] = "settled"
            t = self.tenants[p["tenant"]]
            self._grant_plan(t, p["plan"])
            t["quota"] = t.get("quota", 0) + CREDITS_PER_PAYMENT

    def _consume_challenge(self, token: Optional[str], tid: str) -> bool:
        """Defense 3: a step-up token must exist, belong to the caller, and be unused (consumed)."""
        c = self._challenges.get(token or "")
        if c is None or c["tenant"] != tid or c["used"]:
            return False
        c["used"] = True
        return True

    def _rate_ok(self, tid: str) -> bool:
        """Defense 5: bounded sensitive-op budget per identity (never a DoS lever for the engine)."""
        self._rate[tid] = self._rate.get(tid, 0) + 1
        return self._rate[tid] <= self._rate_cap

    def _settled_payment_of(self, ref: Optional[str], tid: str) -> Optional[dict]:
        p = self.payments.get(ref or "")
        if p is not None and p["tenant"] == tid and p.get("captured"):
            return p
        return None

    # ---- the hardened grey-box spine --------------------------------------------------------
    async def handle(self, method: str, raw_path: str, body: Any, headers: dict) -> tuple:
        parsed = urlparse(raw_path)
        path = parsed.path
        q = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        body = body or {}
        headers = headers or {}
        self.calls_total += 1
        if self._path_log is not None:
            self._path_log.add(path)
        # four-rule floor, rule 1: internal/admin/hidden surface is a honeypot -- never reachable.
        if path.startswith(("/internal", "/admin", "/__", "/_debug")):
            self.internal_hits += 1
            return 404, {"error": "not_found"}

        S, F = self.s, self.s.field

        # ---- public (pre-auth) --------------------------------------------------------------
        if method == "POST" and path == S.route("signup"):
            tok, tid, _ = self._new_tenant()
            self.tenants[tid]["role"] = "member"
            return 201, {"token": tok, "tenant_id": tid}
        if method == "GET" and path == S.route("plans"):
            return 200, {"tiers": [{F("plan"): p, "price": self.prices[p]} for p in self.plans]}

        pre = await self.pre_extra(method, path, body, headers, q)
        if pre is not None:
            return pre

        ident = self._ident(headers)
        if ident is None:
            return 401, {"error": "unauthenticated"}
        tid = ident["tenant"]
        tenant = self.tenants[tid]

        # ---- account / subscription (report-only) -------------------------------------------
        if method == "GET" and path == S.route("account"):
            return 200, {"tenant_id": tid, F("plan"): tenant["plan"] or "free", "role": tenant.get("role", "member")}
        if method == "GET" and path == S.route("subscription"):
            plan = tenant["plan"] or "free"
            return 200, {F("plan"): plan, "badge": "paid" if tenant["plan"] else "free",
                         F("status"): "active" if tenant["plan"] else "inactive"}

        # ---- checkout (defense 4: server-authoritative amount; state-machine start) ---------
        if method == "POST" and path == S.route("checkout"):
            plan = body.get(F("plan")) or body.get("plan")
            currency = body.get(F("currency")) or body.get("currency") or "USD"
            if plan not in self.prices:
                return 400, {"error": "unknown_plan"}
            amount = self.resolve_billed_amount(plan, currency, body)
            pid = _id("pay")
            self.payments[pid] = {"tenant": tid, "plan": plan, "amount": amount, "currency": currency,
                                  "state": "created", "captured": False, "granted": False}
            return 201, {F("payment_id"): pid, F("amount"): amount, F("currency"): currency, F("status"): "created"}

        # ---- authorize: a HOLD, not a capture (defense 1 state machine) ---------------------
        auth_route = S.custom(_AUTHORIZE_ROUTES, "h_authorize")
        if method == "POST" and path.startswith(auth_route + "/"):
            pid = path[len(auth_route) + 1:]
            p = self.payments.get(pid)
            if p is None or p["tenant"] != tid:
                return 404, {"error": "unknown_payment"}
            if p["state"] == "created":
                p["state"] = "authorized"
            self._settle_if_entitled(p)  # correct: 'authorized' is NOT entitling -> no grant
            return 200, {F("status"): p["state"]}

        # ---- sandbox pay: capture on success -> server-side settle+grant --------------------
        if method == "POST" and path.startswith(S.route("pay") + "/"):
            pid = path[len(S.route("pay")) + 1:]
            p = self.payments.get(pid)
            if p is None or p["tenant"] != tid:
                return 404, {"error": "unknown_payment"}
            outcome = body.get("outcome") or body.get(F("status"))
            if outcome == "success":
                p["captured"] = True
                p["state"] = "captured"
                self._settle_if_entitled(p)
                return 200, {F("status"): "captured"}
            return 402, {"error": "declined"}

        # ---- return: landing page, REPORTS only, never grants (defense 1) -------------------
        if method == "GET" and path == S.route("return"):
            pid = q.get(F("payment_id")) or q.get("payment_id")
            p = self.payments.get(pid or "")
            if p is None:
                return 404, {"error": "unknown_payment"}
            return 200, {F("status"): "ok" if p.get("granted") else "pending"}

        # ---- refund (immediate revocation) --------------------------------------------------
        if method == "POST" and path == S.route("refund"):
            pid = body.get(F("payment_id")) or body.get("payment_id")
            p = self.payments.get(pid or "")
            if p is None or p["tenant"] != tid:
                return 404, {"error": "unknown_payment"}
            tenant["plan"] = None
            tenant["quota"] = 0
            p["granted"] = False
            p["state"] = "refunded"
            return 200, {F("status"): "refunded"}

        # ---- step-up challenge issue (defense 3) --------------------------------------------
        chal_route = S.custom(_CHALLENGE_ROUTES, "h_challenge")
        if method == "POST" and path == chal_route:
            if not self._rate_ok(tid):
                return 429, {"error": "rate_limited"}
            token = _id("chal")
            self._challenges[token] = {"tenant": tid, "used": False}
            return 200, {self.s.one(_CHAL_FIELDS, "h_chal_field"): token}

        # ---- idempotent credit/top-up confirm (defense 2 + 6) -------------------------------
        confirm_route = S.custom(_CONFIRM_ROUTES, "h_confirm")
        if method == "POST" and path == confirm_route:
            if not self._rate_ok(tid):
                return 429, {"error": "rate_limited"}
            key = headers.get("idempotency-key") or body.get(self.s.one(_IDEM_FIELDS, "h_idem"))
            ref = body.get(self.s.one(_REF_FIELDS, "h_ref"))
            p = self._settled_payment_of(ref, tid)   # defense 6: must be the caller's settled payment
            if p is None:
                return 402, {"error": "no_settled_payment"}
            if not key:
                return 400, {"error": "idempotency_key_required"}
            if not self._record_idem(key):            # defense 2: replay returns cached, no re-grant
                return 200, {"status": "already_applied", "remaining": tenant.get("quota", 0)}
            tenant["quota"] = tenant.get("quota", 0) + CREDITS_PER_PAYMENT
            return 200, {"status": "applied", "remaining": tenant["quota"]}

        # ---- protected features (the oracle surface) ----------------------------------------
        if method == "POST" and path == S.route("feature_basic"):
            if self.rank.get(tenant["plan"], 0) >= self.rank[self.basic]:
                return 200, {"export_id": _id("exp")}
            return 402, {"error": "payment_required"}
        if method == "GET" and path == S.route("feature_tier"):
            if tenant["plan"] == self.top:
                return 200, {"report_id": _id("rep")}
            return 403, {"error": "upgrade_required"}
        if method == "POST" and path == S.route("feature_quota"):
            if self.rank.get(tenant["plan"], 0) >= self.rank[self.basic] and tenant.get("quota", 0) > 0:
                tenant["quota"] -= 1
                return 200, {"credit_used": True, "remaining": tenant["quota"]}
            return 402, {"error": "quota_exhausted"}

        extra = await self.extra(method, path, body, ident, q)
        if extra is not None:
            return extra
        return 404, {"error": "not_found"}


# ----------------------------------------------------------------------------------------------
# Published-spec brief for the hardened spine. The core happy-path ops are declared exactly as the
# simple spine declares them (same routes), so the engine calibrates identically. ``extra_ops`` is
# the mechanism's published-spec surface (grey-box recon: documented endpoints + their documented
# fields; the privileged/abusable field or shadow route is declared only where a real published
# spec would show it). Attack-only properties are NOT declared -- the engine must discover them.
def hardened_brief(base_url: str, scheme: Scheme, *, plan_names: tuple[str, ...],
                   prices: dict[str, dict[str, float]], extra_ops: Optional[dict] = None) -> dict[str, Any]:
    base = spine_brief(base_url, scheme, plan_names=plan_names, prices=prices)
    S, F = scheme, scheme.field
    # Always-documented hardened ops (a real published API spec shows auth-and-capture, the step-up,
    # and the idempotent credit apply). These are the grey-box discovery surface.
    base["surface"].update({
        "authorize_hold": {"method": "POST", "path": S.custom(_AUTHORIZE_ROUTES, "h_authorize") + "/{payment_id}",
                           "observed_via": "public_api_reference"},
        "step_up_challenge": {"method": "POST", "path": S.custom(_CHALLENGE_ROUTES, "h_challenge"),
                              "observed_via": "public_api_reference",
                              "response_fields": {"challenge": S.one(_CHAL_FIELDS, "h_chal_field")}},
        "apply_credit": {"method": "POST", "path": S.custom(_CONFIRM_ROUTES, "h_confirm"),
                         "observed_via": "public_api_reference",
                         "request_fields": {"idempotency_key": S.one(_IDEM_FIELDS, "h_idem"),
                                            "payment_ref": S.one(_REF_FIELDS, "h_ref")}},
    })
    if extra_ops:
        base["surface"].update(extra_ops)
    base["target_kind"] = "controlled_benchmark"
    return base
