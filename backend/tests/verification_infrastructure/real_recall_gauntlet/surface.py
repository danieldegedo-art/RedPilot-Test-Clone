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
    """Resolved surface for one (family, seed). ``route(role)`` and ``field(name)`` are stable.

    Each string is drawn from a key-DERIVED RNG (``random.Random(f"{family}:{seed}:{key}")``),
    so generation is ORDER-INDEPENDENT: any Scheme instance for the same (family, seed) yields
    the same string for a given key no matter the call order, and the brief, the target and
    the truth prober agree even when built from separate instances. Truly deterministic
    anonymisation per (family, seed) -- the property the sealed DEV/TEST split relies on.
    """

    def __init__(self, family: str, seed: int) -> None:
        self.family = family
        self.seed = seed
        self._base = f"{family}:{seed}"
        self.prefix = self._prefix()

    def _rng(self, key: str) -> random.Random:
        return random.Random(f"{self._base}:{key}")

    def _prefix(self) -> str:
        r = self._rng("__prefix__")
        return f"/{r.choice(_PREFIX)}{r.randint(1, 9)}/v{r.randint(1, 3)}"

    def route(self, role: str, *, extra: str = "") -> str:
        verb = self._rng(f"route:{role}").choice(_VERBS[role]) if role in _VERBS else role
        return f"{self.prefix}/{verb}" + extra

    def field(self, name: str) -> str:
        return self._rng(f"field:{name}").choice(_FIELDS[name]) if name in _FIELDS else name

    def custom(self, pool: list[str], tag: str) -> str:
        """A glue-code-specific route segment (no canonical role), chosen deterministically."""
        return f"{self.prefix}/{self._rng(f'custom:{tag}').choice(pool)}"

    def one(self, pool: list[str], tag: str) -> str:
        return self._rng(f"one:{tag}").choice(pool)
