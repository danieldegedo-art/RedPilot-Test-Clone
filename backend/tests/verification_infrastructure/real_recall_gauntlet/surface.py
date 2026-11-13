"""Deterministic, identity-stripped surface generator (AnonVul-style anonymisation).

Goal: neither the engine nor the engine's *author* (me, in Phase 2) can memorise a literal
route or field name. For a given (family, seed) this yields concrete, plausible, brand-free
strings that PRESERVE the real semantic shape (the action verb, the field's meaning) while
stripping product/version/advisory identity -- exactly what AnonVul strips to defeat an
LLM's memorised provider knowledge.

Per-seed the strings VARY across a synonym pool, so a sealed-TEST instance of a class uses
different surface strings than a DEV instance of the same class. A Phase-2 change that
secretly keyed on a DEV literal therefore would NOT transfer to TEST -- the split stays
honest by construction.

It is NOT tuned toward or away from the engine's keyword sets: synonyms are chosen without
reference to engine internals. That is the iron law -- the engine is on trial, not the names.
"""
from __future__ import annotations

import random
from typing import Any

# Semantic role -> synonym pool. Every synonym means the same thing; none is "the" engine word.
_PREFIX = ["acme", "northwind", "globex", "initech", "umbrella", "hooli", "vandelay", "wonka"]
_VERBS: dict[str, list[str]] = {
    "signup": ["register", "signup", "onboard", "join", "enroll"],
    "plans": ["catalog", "plans", "pricing", "tiers", "offerings"],
    "account": ["account", "me", "profile", "whoami", "identity"],
    "checkout": ["checkout", "order", "purchase", "cart/submit", "charge/new"],
    "pay": ["settle", "confirm-pay", "sandbox-pay", "capture", "process"],
    "return": ["return", "callback", "complete", "done", "finish"],
    "subscription": ["subscription", "membership", "entitlement", "plan-status", "my-plan"],
    "refund": ["refund", "cancel", "reverse", "void", "downgrade"],
    "feature_basic": ["export", "download", "report", "sync", "query"],
    "feature_quota": ["credits/use", "tokens/spend", "units/consume", "api/call", "jobs/run"],
    "feature_tier": ["bulk-export", "enterprise-report", "advanced-analytics", "full-dump", "priority-run"],
}
# Field-name synonyms (wire names). Meaning preserved; literal varies per seed.
_FIELDS: dict[str, list[str]] = {
    "amount": ["amount", "charge_total", "grand_total", "price_paid", "pay_amount"],
    "currency": ["currency", "ccy", "money_code", "iso_currency"],
    "plan": ["plan", "tier", "sku", "product", "offering"],
    "payment_id": ["payment_id", "order_ref", "charge_id", "txn_ref", "pay_token"],
    "status": ["status", "state", "result", "outcome_flag", "phase"],
    "tenant": ["tenant", "org", "workspace", "account_ref", "team_id"],
    "coupon": ["coupon", "promo", "voucher", "discount_code", "promo_code"],
    "credit": ["credit", "balance", "wallet", "store_credit", "funds"],
}


class Scheme:
    """Resolved surface for one (family, seed). ``route(role)`` and ``field(name)`` are stable."""

    def __init__(self, family: str, seed: int) -> None:
        self._r = random.Random(f"{family}:{seed}")
        self.family = family
        self.seed = seed
        self.prefix = f"/{self._r.choice(_PREFIX)}{self._r.randint(1, 9)}/v{self._r.randint(1, 3)}"
        self._routes: dict[str, str] = {}
        self._fields: dict[str, str] = {}

    def route(self, role: str, *, extra: str = "") -> str:
        if role not in self._routes:
            verb = self._r.choice(_VERBS[role]) if role in _VERBS else role
            self._routes[role] = f"{self.prefix}/{verb}"
        return self._routes[role] + extra

    def field(self, name: str) -> str:
        if name not in self._fields:
            self._fields[name] = self._r.choice(_FIELDS[name]) if name in _FIELDS else name
        return self._fields[name]

    def custom(self, pool: list[str], tag: str) -> str:
        """A glue-code-specific route segment (no canonical role), chosen deterministically."""
        key = f"custom:{tag}"
        if key not in self._routes:
            self._routes[key] = f"{self.prefix}/{self._r.choice(pool)}"
        return self._routes[key]

    def one(self, pool: list[str], tag: str) -> str:
        key = f"one:{tag}"
        if key not in self._fields:
            self._fields[key] = self._r.choice(pool)
        return self._fields[key]
