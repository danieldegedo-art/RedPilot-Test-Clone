"""Domain-pack FOCUS (A31-A36): the NARROWED, entitlement-verification-only scope.

A "domain pack" is a specialist for a non-payment domain (Active Directory, cloud,
smart contracts, binaries, mobile, OSINT). The owner's decision (turn 1) kept ONLY the
entitlement-verification slice of each: in domain X, which of the ten PRE-REGISTERED
payment-integrity oracle classes the domain's own surface lets us confirm, and which
PUBLIC signals to read. Every domain's classic OFFENSIVE capability -- AD attack paths,
cloud IAM escalation, contract exploitation, C2/implant tooling, DRM/app exploitation,
broad people-OSINT -- is EXCLUDED here and named explicitly in `excluded`. This module
has no surface for any of it; it emits a recon FOCUS (a lead for the planner), never a
finding, never an attack, and never a new capability.

Two packs are owner-DECLINED outright (A31 AD Operator, A32 Cloud Hunter): their entry
documents the would-be narrowed focus for transparency, but the roster marks them
out-of-scope so their agent refuses at the scope gate and this focus is never emitted.
A36 (OSINT) is NARROWED to authorization/scope confirmation and exercises no oracle
class at all. Every referenced class is validated against the pre-registered set
(ZR-036) at import. Stdlib only; pure.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.testing.integrity.findings import EXPERIMENT_CLASSES

MODULE_VERSION = "domain-focus/1.0"
_REGISTERED = frozenset(EXPERIMENT_CLASSES.values())


@dataclass(frozen=True)
class DomainPack:
    agent_id: str
    name: str
    domain: str
    oracle_classes: tuple[str, ...]   # PRE-REGISTERED entitlement-verification classes only
    signals: tuple[str, ...]          # PUBLIC signal tokens the pack reads
    excluded: tuple[str, ...]         # the domain's OFFENSIVE capability, explicitly OUT
    scope: str                        # "in_scope" | "narrowed" | "out_of_scope" (mirrors the roster)

    def to_dict(self) -> dict[str, Any]:
        return {"agent_id": self.agent_id, "name": self.name, "domain": self.domain,
                "oracle_classes": list(self.oracle_classes), "signals": list(self.signals),
                "excluded": list(self.excluded), "scope": self.scope}


DOMAIN_PACKS: dict[str, DomainPack] = {
    "A31": DomainPack("A31", "AD Operator", "active_directory",
                      ("cross_identity_binding", "cross_tenant_binding"),
                      ("attr:memberOf", "claim:entitlement_group", "token:group_sid"),
                      ("Kerberoasting", "DCSync", "AD attack-path / privilege-escalation enumeration"),
                      "out_of_scope"),
    "A32": DomainPack("A32", "Cloud Hunter", "cloud",
                      ("cross_tenant_binding",),
                      ("header:x-tenant-id", "claim:aud", "path:/orgs/"),
                      ("IAM privilege escalation", "RBAC escape", "cloud resource attacks"),
                      "out_of_scope"),
    "A33": DomainPack("A33", "Contract Auditor", "smart_contract",
                      ("unconfirmed_payment_grants_access", "plan_or_price_binding", "currency_binding"),
                      ("abi:priceOf", "event:PaymentConfirmed", "fn:grantEntitlement"),
                      ("contract deployment", "reentrancy/overflow exploitation", "on-chain fund movement"),
                      "in_scope"),
    "A34": DomainPack("A34", "Reverser", "binary_re",
                      ("ui_vs_server_divergence", "paid_feature_open_to_unpaid"),
                      ("symbol:checkEntitlement", "string:isPremium", "const:feature_flags"),
                      ("Sliver C2 / implant tooling", "BloodHound collection", "binary patching / exploitation"),
                      "in_scope"),
    "A35": DomainPack("A35", "Mobile Operator", "mobile",
                      ("ui_vs_server_divergence", "paid_feature_open_to_unpaid"),
                      ("api:/entitlements", "flag:pro_unlocked_local", "plist:receipt"),
                      ("DRM bypass", "app repackaging / exploitation", "SSL-pinning defeat for attack"),
                      "in_scope"),
    "A36": DomainPack("A36", "OSINT Operator", "scope_confirmation",
                      (),   # exercises NO oracle class -- pure authorization/scope confirmation
                      ("whois:registrant", "dns:authorized_domain", "cert:SAN"),
                      ("employee / personal profiling", "breach-data collection", "broad infrastructure enumeration"),
                      "narrowed"),
}

# Every referenced class is pre-registered; no off-catalog target is ever introduced.
for _p in DOMAIN_PACKS.values():
    assert set(_p.oracle_classes) <= _REGISTERED, f"{_p.agent_id}: off-catalog oracle class"
assert len(DOMAIN_PACKS) == 6, "there are exactly six domain packs (A31-A36)"


def get(agent_id: str) -> DomainPack | None:
    return DOMAIN_PACKS.get(agent_id)


def focus(agent_id: str) -> dict[str, Any]:
    """The domain pack's NARROWED entitlement-verification focus: which pre-registered
    oracle classes its domain surface confirms, the public signals it reads, and the
    offensive capability it explicitly excludes. A lead for the planner, never a finding."""
    p = DOMAIN_PACKS.get(agent_id)
    if p is None:
        raise KeyError(f"unknown domain pack {agent_id!r}")
    return {"agent_id": p.agent_id, "domain": p.domain, "oracle_classes": list(p.oracle_classes),
            "signals": list(p.signals), "excluded": list(p.excluded),
            "note": "NARROWED to entitlement verification over pre-registered oracles only (ZR-036); the domain's "
                    "offensive capability is excluded and has no surface here; a recon lead, never a finding (ZR-017 confirms)"}


def roster_payload() -> dict[str, Any]:
    return {"module_version": MODULE_VERSION, "domain_packs": [p.to_dict() for p in DOMAIN_PACKS.values()],
            "note": "Six domain packs, each narrowed to entitlement verification over the pre-registered oracle set; "
                    "offensive domain capability is excluded (named per pack). A31/A32 are owner-declined (out of scope)."}
