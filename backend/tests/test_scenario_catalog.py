"""Declarative scenario catalog (app/testing/integrity/scenario_catalog.py).

Imports only findings + scenario_registry (no engine/httpx), so it runs in the
stdlib sandbox directly.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.testing.integrity.findings import EXPERIMENT_CLASSES  # noqa: E402
from app.testing.integrity.scenario_catalog import (  # noqa: E402
    SCENARIO_CATALOG_VERSION, build_scenario_catalog, scenario_catalog_json, scenario_template,
)


def test_catalog_covers_exactly_the_registered_classes_and_nothing_else():
    cat = build_scenario_catalog()
    ids = {c["hypothesis_id"] for c in cat["oracle_classes"]}
    assert ids == set(EXPERIMENT_CLASSES)
    assert cat["counts"]["oracle_classes"] == len(EXPERIMENT_CLASSES)
    assert cat["version"] == SCENARIO_CATALOG_VERSION and cat["bounded"] is True


def test_catalog_is_deterministic_and_does_not_mutate_the_registered_set():
    before = len(EXPERIMENT_CLASSES)
    a = build_scenario_catalog()
    b = build_scenario_catalog()
    assert a == b                      # deterministic
    assert len(EXPERIMENT_CLASSES) == before  # read-only: building the catalog adds nothing


def test_each_entry_carries_the_full_oracle_spec_and_server_scope():
    spec_fields = {"invariant", "baseline_state", "identity_and_tenant", "controlled_variable",
                   "action_sequence", "expected_outcome", "p0_condition", "rule_out_condition",
                   "stop_condition", "evidence_requirements"}
    for c in build_scenario_catalog()["oracle_classes"]:
        assert set(c["spec"]) == spec_fields
        assert 0.0 < c["spec_completeness"] <= 1.0
        assert "server_enforced" in c["required_scopes"]  # every class is tested at the authoritative scope


def test_identity_binding_and_divergence_classes_require_their_extra_scopes():
    by_class = {c["p0_class"]: c["required_scopes"] for c in build_scenario_catalog()["oracle_classes"]}
    for cls in ("cross_identity_binding", "cross_tenant_binding", "entitlement_leak_to_unrelated_identity"):
        assert "cross_subject" in by_class[cls], cls
    assert "account_view" in by_class["ui_vs_server_divergence"]


def test_scenario_template_rejects_an_unregistered_id():
    try:
        scenario_template("PBB-NOPE")
        raise AssertionError("expected KeyError for an unregistered class")
    except KeyError:
        pass


def test_catalog_json_is_deterministic_and_parses():
    j1 = scenario_catalog_json()
    j2 = scenario_catalog_json()
    assert j1 == j2
    parsed = json.loads(j1)
    assert parsed["counts"]["oracle_classes"] == len(EXPERIMENT_CLASSES)


if __name__ == "__main__":
    import traceback
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = failed = 0
    for t in tests:
        try:
            t()
            print(f"PASS {t.__name__}")
            passed += 1
        except Exception:
            print(f"FAIL {t.__name__}")
            traceback.print_exc()
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
