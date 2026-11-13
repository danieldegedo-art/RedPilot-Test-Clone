"""ZR-008 / B23: Commercial-Context modeling on evidence nodes.

Audit Point 10: the engine set a commercial-context dimension only as free text
(`plan=basic`, `cheapest_plan=X, top_plan=Y`, `alternative_currency=EUR,
public_price=9.99`, `quota_cap=5`, `declared_sla_s=3600`). ZR-008 makes it a
first-class, structured field so every finding/evidence node carries an EXPLICIT,
typed commercial context -- what plan/price/currency/quota/SLA the test exercised
-- which impact assessment and billing-side readers can consume without parsing
prose.

This models the dimension that is already produced; it does NOT rewrite the
engine. `parse_commercial_context` turns the existing free text into the typed
`CommercialContext` (backward-compatible), and unknown `key=value` pairs are kept
verbatim in `dimensions` rather than dropped. Bounded to payment/commercial
fields; stdlib only; pure.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.testing.integrity.findings import EngineResult

_PLAN_KEYS = {"plan", "cheapest_plan"}
_TOP_PLAN_KEYS = {"top_plan", "priciest_plan"}
_CURRENCY_KEYS = {"currency", "alternative_currency"}
_PRICE_KEYS = {"public_price", "price"}


def _as_int(v: str) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _as_float(v: str) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


@dataclass(frozen=True)
class CommercialContext:
    plan: str | None = None
    top_plan: str | None = None
    currency: str | None = None
    public_price: str | None = None
    quota_cap: int | None = None
    declared_sla_s: float | None = None
    dimensions: dict[str, str] = field(default_factory=dict)  # any extra key=value the engine set that has no typed slot

    def is_empty(self) -> bool:
        return (self.plan is None and self.top_plan is None and self.currency is None and self.public_price is None
                and self.quota_cap is None and self.declared_sla_s is None and not self.dimensions)

    def to_dict(self) -> dict[str, Any]:
        return {"plan": self.plan, "top_plan": self.top_plan, "currency": self.currency, "public_price": self.public_price,
                "quota_cap": self.quota_cap, "declared_sla_s": self.declared_sla_s, "dimensions": dict(sorted(self.dimensions.items()))}


def parse_commercial_context(text: str | None) -> CommercialContext:
    """Structure the engine's free-text commercial-context string. A bad value for
    a typed key is kept verbatim in `dimensions` rather than silently coerced to a
    wrong number."""
    if not text:
        return CommercialContext()
    plan = top = currency = price = None
    quota: int | None = None
    sla: float | None = None
    dims: dict[str, str] = {}
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            dims.setdefault("_note", part)
            continue
        k, v = (s.strip() for s in part.split("=", 1))
        if k in _PLAN_KEYS:
            plan = v
        elif k in _TOP_PLAN_KEYS:
            top = v
        elif k in _CURRENCY_KEYS:
            currency = v
        elif k in _PRICE_KEYS:
            price = v
        elif k == "quota_cap":
            quota = _as_int(v)
            if quota is None:
                dims[k] = v  # unparseable -> keep raw, do not invent a number
        elif k == "declared_sla_s":
            sla = _as_float(v)
            if sla is None:
                dims[k] = v
        else:
            dims[k] = v
    return CommercialContext(plan, top, currency, price, quota, sla, dims)


def commercial_context_by_hypothesis(result: EngineResult) -> dict[str, CommercialContext]:
    """ZR-008 acceptance: an explicit, structured commercial-context field for
    every finding/evidence node in the run."""
    return {f.hypothesis_id: parse_commercial_context(getattr(f, "commercial_context", None)) for f in result.findings}


def commercial_context_payload(result: EngineResult) -> dict[str, Any]:
    return {"commercial_context": {h: cc.to_dict() for h, cc in commercial_context_by_hypothesis(result).items()},
            "note": "Structured commercial context per finding (ZR-008); typed from the engine's own per-experiment dimension, nothing inferred."}
