"""ZR-031: tests for app/testing/integrity/scenario_registry.py. Stdlib only."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.testing.integrity.scenario_registry import (  # noqa: E402
    REQUIRED, Scenario, Scope, coverage_report, is_complete, required, unmet,
)
from app.testing.integrity.findings import EXPERIMENT_CLASSES  # noqa: E402


def test_required_covers_exactly_the_ten_registered_classes():
    assert {s.oracle_class for s in required()} == set(EXPERIMENT_CLASSES.values())


def test_binding_and_divergence_classes_require_a_second_scope():
    def scopes(cls):
        return {s.scope for s in REQUIRED if s.oracle_class == cls}
    assert scopes("cross_identity_binding") == {"server_enforced", "cross_subject"}
    assert scopes("cross_tenant_binding") == {"server_enforced", "cross_subject"}
    assert scopes("entitlement_leak_to_unrelated_identity") == {"server_enforced", "cross_subject"}
    assert scopes("ui_vs_server_divergence") == {"server_enforced", "account_view"}
    # a plain class needs only the authoritative scope
    assert scopes("retention_after_refund") == {"server_enforced"}


def test_total_required_is_eleven_plus_four_extras():
    assert len(REQUIRED) == 15  # 11 pre-registered classes at server_enforced + 4 second-scope extras


def test_empty_observed_leaves_everything_unmet():
    assert len(unmet([])) == 15 and not is_complete([])


def test_full_observed_is_complete():
    assert is_complete(required()) and unmet(required()) == ()


def test_unmet_accepts_class_scope_pairs_and_reports_the_gap():
    observed = [(s.oracle_class, s.scope) for s in REQUIRED if s.scope == "server_enforced"]
    missing = unmet(observed)
    # exactly the four second-scope requirements remain
    assert {(s.oracle_class, s.scope) for s in missing} == {
        ("cross_identity_binding", "cross_subject"), ("cross_tenant_binding", "cross_subject"),
        ("entitlement_leak_to_unrelated_identity", "cross_subject"), ("ui_vs_server_divergence", "account_view")}


def test_coverage_report_json_safe():
    rep = coverage_report([Scenario("retention_after_refund", Scope.SERVER_ENFORCED.value)])
    assert rep["complete"] is False and rep["required"] == 15
    assert json.loads(json.dumps(rep)) == rep
