"""ZR-031: the minimum required test-scenario set.

A declared, fixed checklist of the scenarios an engagement MUST exercise before it can
be called complete. A scenario is one pre-registered oracle class (ZR-036) tested at a
declared test scope. The minimum is:

  * every one of the ten pre-registered classes exercised at the SERVER_ENFORCED scope
    (the only authoritative surface -- see differencer.py); plus
  * the identity/tenant-binding classes (cross_identity, cross_tenant, entitlement_leak)
    ALSO at the CROSS_SUBJECT scope -- binding can only be confirmed by testing access
    as a *different* subject, not just one's own; plus
  * ui_vs_server_divergence ALSO at the ACCOUNT_VIEW scope -- a divergence needs both a
    non-authoritative surface and the server surface to compare.

This is the *required* set (what must be covered); ZR-006's coverage matrix tracks what
*was* covered, and the ZR-033 quality gate checks the one against the other. The set is
bounded to the pre-registered classes and never grows at runtime. Stdlib only; pure.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable

from app.testing.integrity.findings import EXPERIMENT_CLASSES

MODULE_VERSION = "scenario-registry/1.0"
_CLASSES = tuple(sorted(EXPERIMENT_CLASSES.values()))


class Scope(str, Enum):
    SERVER_ENFORCED = "server_enforced"   # using the paid feature -- the only authority
    CROSS_SUBJECT = "cross_subject"       # access attempted as a different identity/tenant
    ACCOUNT_VIEW = "account_view"         # a non-authoritative claim surface (for divergence)


@dataclass(frozen=True)
class Scenario:
    oracle_class: str
    scope: str

    def to_dict(self) -> dict[str, Any]:
        return {"oracle_class": self.oracle_class, "scope": self.scope}


# classes that require MORE than the single authoritative-scope scenario, with why.
_EXTRA_SCOPES: dict[str, tuple[Scope, ...]] = {
    "cross_identity_binding": (Scope.CROSS_SUBJECT,),
    "cross_tenant_binding": (Scope.CROSS_SUBJECT,),
    "entitlement_leak_to_unrelated_identity": (Scope.CROSS_SUBJECT,),
    "ui_vs_server_divergence": (Scope.ACCOUNT_VIEW,),
}

REQUIRED: tuple[Scenario, ...] = tuple(
    Scenario(c, s.value)
    for c in _CLASSES
    for s in (Scope.SERVER_ENFORCED,) + _EXTRA_SCOPES.get(c, ())
)

# Every required scenario targets a pre-registered class (ZR-036); nothing off-catalog.
assert {s.oracle_class for s in REQUIRED} == set(_CLASSES), "required set must cover exactly the registered classes"


def _normalize(observed: Iterable[Any]) -> set[Scenario]:
    out: set[Scenario] = set()
    for o in observed:
        if isinstance(o, Scenario):
            out.add(o)
        else:  # accept (oracle_class, scope) pairs for convenience
            cls, scope = o
            out.add(Scenario(cls, scope if isinstance(scope, str) else scope.value))
    return out


def required() -> tuple[Scenario, ...]:
    return REQUIRED


def unmet(observed: Iterable[Any]) -> tuple[Scenario, ...]:
    """Required scenarios not present in `observed`. Deterministic ordering."""
    have = _normalize(observed)
    return tuple(sorted((s for s in REQUIRED if s not in have), key=lambda s: (s.oracle_class, s.scope)))


def is_complete(observed: Iterable[Any]) -> bool:
    return not unmet(observed)


def coverage_report(observed: Iterable[Any]) -> dict[str, Any]:
    missing = unmet(observed)
    return {"module_version": MODULE_VERSION, "required": len(REQUIRED), "unmet": [s.to_dict() for s in missing],
            "complete": not missing,
            "note": "Minimum required scenario set (ZR-031): the fixed checklist an engagement must exercise. "
                    "Bounded to the pre-registered oracle classes; the ZR-033 quality gate consumes `unmet`."}
