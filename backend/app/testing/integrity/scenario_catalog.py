"""ZR-031 / ZR-036: declarative scenario catalog -- the fixed oracle-class set as
a versioned, machine-readable template for CI.

The Nuclei pattern contributes exactly one thing here: a declarative, versioned
definition format with clean machine-readable output -- NOT a drop-in template
corpus that can add attacks. RedPilot's action set is fixed and MUST NOT grow at
runtime (ZR-036), so this module is strictly a read-only serialization of the ten
pre-registered oracle classes already defined in `findings.SPECS` /
`EXPERIMENT_CLASSES` and the required-scope checklist in `scenario_registry`. It
introduces no new scenario, parameter or capability; it renders the existing
bounded set as a stable JSON catalog a CI pipeline can diff, pin, and gate on.

Stdlib only; pure and deterministic.
"""
from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any

from app.testing.integrity import scenario_registry
from app.testing.integrity.findings import ENGINE_VERSION, EXPERIMENT_CLASSES, SPECS

SCENARIO_CATALOG_VERSION = "scenario-catalog/1.0"


def _scopes_for_class(oracle_class: str) -> list[str]:
    return sorted({s.scope for s in scenario_registry.required() if s.oracle_class == oracle_class})


def scenario_template(hypothesis_id: str) -> dict[str, Any]:
    """The declarative template for ONE pre-registered oracle class: its id, p0
    class, required test scopes, and the full fixed OracleSpec (invariant, baseline,
    action sequence, expected outcome, p0 / rule-out / stop conditions, evidence).
    Raises KeyError for an unknown id -- the catalog cannot describe a class that
    was not pre-registered (the bounded-set guarantee, surfaced as an error)."""
    spec = SPECS[hypothesis_id]
    oracle_class = EXPERIMENT_CLASSES[hypothesis_id]
    return {
        "hypothesis_id": hypothesis_id,
        "p0_class": oracle_class,
        "required_scopes": _scopes_for_class(oracle_class),
        "spec": asdict(spec),
        "spec_completeness": round(spec.completeness(), 4),
    }


def build_scenario_catalog() -> dict[str, Any]:
    """The whole fixed catalog, deterministic (ids sorted). Read-only: generated
    from the pre-registered set, never a runtime-mutable registry."""
    ids = sorted(EXPERIMENT_CLASSES)
    classes = [scenario_template(h) for h in ids]
    return {
        "version": SCENARIO_CATALOG_VERSION,
        "engine_version": ENGINE_VERSION,
        "bounded": True,
        "note": ("Declarative, read-only serialization of the FIXED pre-registered oracle-class set (ZR-036). "
                 "It adds no scenario, parameter or capability at runtime; it renders the existing bounded set "
                 "as a stable catalog for CI to diff, pin and gate on."),
        "oracle_classes": classes,
        "required_scenarios": [s.to_dict() for s in scenario_registry.required()],
        "counts": {"oracle_classes": len(classes), "required_scenarios": len(scenario_registry.required())},
    }


def scenario_catalog_json(*, indent: int | None = 2) -> str:
    """The catalog as deterministic JSON (sorted keys) for CI pipelines to pin/diff."""
    return json.dumps(build_scenario_catalog(), indent=indent, sort_keys=True)
