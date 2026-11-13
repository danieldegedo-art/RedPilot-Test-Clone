"""A21-A24: payment-domain recon specialists -- one bounded module.

Each specialist is a recon FOCUS over the pre-registered oracle set: it names which of
the ten classes its sub-domain exercises and which PUBLIC signals it watches. It emits
a focus (a lead for the planner), never a finding and never a new capability, and every
class it references must be pre-registered (ZR-036). Where a sub-domain's classic
attack is out of scope, the specialist says so and focuses on the observable surface:

  * A21 Payment-Provider Specialist -- which provider/stack is in use (feeds B40/B36).
  * A22 Webhook-Fraud Specialist -- provider-event FORGERY is BLOCKED (it needs the
    target's signing secret, a grey-box dependency the engine rejects), so this
    specialist focuses on the customer-observable return-flow trust (PBB-U), not forgery.
  * A23 Coupon/Promo-Abuse Specialist -- plan/price and currency binding (PBB-F/PBB-H).
  * A24 Subscription-Lifecycle Specialist -- retention-after-refund and duplicate value
    over the lifecycle (PBB-R/PBB-C).

Stdlib only; pure.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.testing.integrity.findings import EXPERIMENT_CLASSES

MODULE_VERSION = "specialists/1.0"


@dataclass(frozen=True)
class Specialist:
    agent_id: str
    name: str
    sub_domain: str
    oracle_classes: tuple[str, ...]   # pre-registered classes this sub-domain exercises
    signals: tuple[str, ...]          # PUBLIC signal tokens the specialist watches
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"agent_id": self.agent_id, "name": self.name, "sub_domain": self.sub_domain,
                "oracle_classes": list(self.oracle_classes), "signals": list(self.signals), "note": self.note}


SPECIALISTS: tuple[Specialist, ...] = (
    Specialist("A21", "Payment-Provider Specialist", "payment_provider",
               ("unconfirmed_payment_grants_access",),
               ("header:stripe-version", "domain:adyen.com", "domain:braintreegateway.com"),
               "identifies the provider/stack (hands off to B40 fingerprinting + B36)"),
    Specialist("A22", "Webhook-Fraud Specialist", "webhook",
               ("unconfirmed_payment_grants_access",),
               ("path:/return", "field:status", "field:payment_id"),
               "provider-event FORGERY is BLOCKED (needs the target signing secret, grey-box, rejected); "
               "focuses on the customer-observable return-flow trust (PBB-U)"),
    Specialist("A23", "Coupon/Promo-Abuse Specialist", "coupon_promo",
               ("plan_or_price_binding", "currency_binding"),
               ("field:coupon", "field:promo_code", "field:discount"),
               "watches plan/price and currency binding (PBB-F/PBB-H)"),
    Specialist("A24", "Subscription-Lifecycle Specialist", "subscription",
               ("retention_after_refund", "duplicate_value_via_return_flow_repetition"),
               ("field:renewal", "field:refund", "path:/subscription"),
               "watches retention-after-refund and duplicate value over the lifecycle (PBB-R/PBB-C)"),
)

for _s in SPECIALISTS:
    assert set(_s.oracle_classes) <= set(EXPERIMENT_CLASSES.values()), f"{_s.agent_id}: off-catalog oracle class"
_BY_ID = {s.agent_id: s for s in SPECIALISTS}
assert len(_BY_ID) == len(SPECIALISTS), "duplicate specialist id"


def get(agent_id: str) -> Specialist | None:
    return _BY_ID.get(agent_id)


def by_sub_domain(sub_domain: str) -> Specialist | None:
    return next((s for s in SPECIALISTS if s.sub_domain == sub_domain), None)


def focus(agent_id: str) -> dict[str, Any]:
    """The specialist's recon focus: its pre-registered oracle classes + watched signals.
    A lead for the planner, never a finding."""
    s = _BY_ID.get(agent_id)
    if s is None:
        raise KeyError(f"unknown specialist {agent_id!r}")
    return {"agent_id": s.agent_id, "oracle_classes": list(s.oracle_classes), "signals": list(s.signals),
            "note": "recon focus only; a lead for the planner, never a finding (ZR-017 still confirms)"}


def roster_payload() -> dict[str, Any]:
    return {"module_version": MODULE_VERSION, "specialists": [s.to_dict() for s in SPECIALISTS],
            "note": "Payment-domain recon specialists; each focuses on pre-registered oracle classes only "
                    "(ZR-036) and emits a lead, never a finding or a new capability."}
