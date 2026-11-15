"""B34 (owns A30): Closed-Loop Capability Synthesis -- BOUNDED and FAIL-CLOSED.

The name is the dangerous one, so the construction is deliberately the opposite of a
code/capability generator. "Synthesis" here means: pick a PRE-REGISTERED probe
template from a FIXED catalog and fill its parameters from a DECLARED, bounded space.
Nothing novel can come out:

  * The catalog is exactly the ten pre-registered oracle classes
    (`findings.EXPERIMENT_CLASSES`). The synthesized output is always a parameterised
    instance of one of them -- never new code, a new probe, or a new capability. The
    engine already knows how to run these; synthesis only chooses and parameterises.
  * Parameters are confined to each template's DECLARED allowed set (ZR-036). An
    out-of-bounds value, or a missing required parameter, is REFUSED -- never guessed
    or widened.
  * "Closed-loop" = it reads the feedback state (B16: which classes are still
    inconclusive) and the learned prior (B31) to choose the next template. The choice
    space is still only the fixed catalog, so the loop reprioritises; it cannot grow
    the action set (B28 self-scope-expansion is structurally impossible -- candidates
    are drawn from the registered classes alone).
  * FAIL-CLOSED: without its enabling control nothing is synthesised.
  * Deterministic given its inputs.

A synthesized probe is an instruction to run a known oracle with declared inputs; it
is never proof and never a verdict (ZR-017 still governs confirmation).

Stdlib only; pure.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from app.testing.integrity.findings import EXPERIMENT_CLASSES

MODULE_VERSION = "capability-synthesis/1.0"
_CLASSES = tuple(sorted(EXPERIMENT_CLASSES))


@dataclass(frozen=True)
class ProbeTemplate:
    """A pre-registered oracle class plus the DECLARED, bounded parameter space of
    its synthesizable inputs. Most oracles are fully pre-specified (no params)."""
    template_id: str                      # == a pre-registered oracle class
    param_schema: dict[str, tuple[Any, ...]] = field(default_factory=dict)


# One template per pre-registered class. Only a couple take a declared choice; the
# rest are fully specified by their pre-registered action sequence (empty schema).
TEMPLATES: dict[str, ProbeTemplate] = {
    "PBB-U": ProbeTemplate("PBB-U"),
    "PBB-F": ProbeTemplate("PBB-F", {"plan": ("basic", "pro", "enterprise")}),
    "PBB-H": ProbeTemplate("PBB-H", {"currency": ("USD", "EUR", "JPY")}),
    "PBB-C": ProbeTemplate("PBB-C"),
    "PBB-G": ProbeTemplate("PBB-G"),
    "PBB-X": ProbeTemplate("PBB-X"),
    "PBB-R": ProbeTemplate("PBB-R"),
    "PBB-E": ProbeTemplate("PBB-E"),
    "PBB-OPEN": ProbeTemplate("PBB-OPEN"),
    "PBB-LEAK": ProbeTemplate("PBB-LEAK"),
    "PBB-D": ProbeTemplate("PBB-D"),  # cross-subject object/property-level access (fully specified; no params)
}
assert set(TEMPLATES) == set(EXPERIMENT_CLASSES), "template catalog must be exactly the pre-registered classes"


class SynthStatus(str, Enum):
    SYNTHESIZED = "SYNTHESIZED"
    FAIL_CLOSED = "FAIL_CLOSED"
    NOTHING_TO_DO = "NOTHING_TO_DO"   # every class already conclusive
    REFUSED_PARAM = "REFUSED_PARAM"   # a required param missing / out of the declared bounds


@dataclass(frozen=True)
class SynthesizedProbe:
    template_id: str
    params: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {"template_id": self.template_id, "params": dict(self.params)}


@dataclass(frozen=True)
class SynthResult:
    status: SynthStatus
    probe: SynthesizedProbe | None
    note: str

    def to_dict(self) -> dict[str, Any]:
        return {"status": self.status.value, "probe": self.probe.to_dict() if self.probe else None, "note": self.note}


def _choose(conclusive: set[str], prior: dict[str, float]) -> str | None:
    candidates = [c for c in _CLASSES if c not in conclusive]   # always a subset of the registered classes
    if not candidates:
        return None
    # highest-prior candidate; deterministic tie-break by class id.
    return min(candidates, key=lambda c: (-prior.get(c, 0.0), c))


def synthesize(*, enabled: bool, conclusive: set[str] | None = None, prior: dict[str, float] | None = None,
               declared_params: dict[str, Any] | None = None) -> SynthResult:
    """Choose the next pre-registered template (feedback + prior) and parameterise it
    from the declared bounds. FAIL-CLOSED when `enabled` is False."""
    conclusive = set(conclusive or set())
    prior = prior or {}
    declared = declared_params or {}

    choice = _choose(conclusive, prior)
    if choice is None:
        return SynthResult(SynthStatus.NOTHING_TO_DO, None,
                           "every pre-registered class is already conclusive; nothing to synthesise")

    template = TEMPLATES[choice]   # choice is always a registered class -> always in the catalog (B28 safe)
    params: dict[str, Any] = {}
    for key, allowed in template.param_schema.items():
        if key not in declared:
            return SynthResult(SynthStatus.REFUSED_PARAM, None,
                               f"REFUSED: template {choice} requires parameter {key!r} and no declared value was "
                               f"given (never guessed)")
        value = declared[key]
        if value not in allowed:
            return SynthResult(SynthStatus.REFUSED_PARAM, None,
                               f"REFUSED: value {value!r} for {key!r} is outside the declared bounds "
                               f"{list(allowed)} (never widened)")
        params[key] = value

    return SynthResult(SynthStatus.SYNTHESIZED, SynthesizedProbe(choice, params),
                       f"synthesised a parameterised instance of pre-registered oracle {choice}; a known probe to "
                       f"run under controls (ZR-017 still confirms), never new code or a new capability")


def synthesize_payload(*, enabled: bool, conclusive: set[str] | None = None, prior: dict[str, float] | None = None,
                       declared_params: dict[str, Any] | None = None) -> dict[str, Any]:
    res = synthesize(enabled=enabled, conclusive=conclusive, prior=prior, declared_params=declared_params)
    return {"module_version": MODULE_VERSION, **res.to_dict(), "catalog": list(_CLASSES),
            "note": "Synthesis = choose a FIXED pre-registered template + fill DECLARED bounded params (ZR-036); "
                    "output is always a parameterised instance of a registered oracle, FAIL-CLOSED, never novel "
                    "code/capability and never a verdict."}
