"""ZR-033: tests for app/testing/integrity/quality_gate.py. Stdlib only."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.testing.integrity.quality_gate import FindingView, evaluate, evaluate_payload  # noqa: E402
from app.testing.integrity.scenario_registry import required  # noqa: E402

ALL_SCENARIOS = required()


def _good_p0(fid="f1"):
    return FindingView(fid, "CONFIRMED_P0", schema_completeness=1.0, server_confirmed=True,
                       has_reproduction=True, has_regression_reference=True)


def test_complete_engagement_passes_all_five():
    r = evaluate(observed_scenarios=ALL_SCENARIOS, findings=[_good_p0()])
    assert r.passed is True and r.failing() == ()


def test_qg1_fails_when_a_required_scenario_is_unmet():
    observed = [s for s in ALL_SCENARIOS if s.scope != "cross_subject"]
    r = evaluate(observed_scenarios=observed, findings=[_good_p0()])
    assert r.failing() == ("QG-1",)
    qg1 = next(c for c in r.conditions if c.condition_id == "QG-1")
    assert qg1.offenders   # names the unmet scenarios


def test_qg2_fails_on_incomplete_schema():
    bad = FindingView("f2", "CONFIRMED_P0", schema_completeness=0.9, server_confirmed=True,
                      has_reproduction=True, has_regression_reference=True)
    r = evaluate(observed_scenarios=ALL_SCENARIOS, findings=[bad])
    assert "QG-2" in r.failing()
    assert next(c for c in r.conditions if c.condition_id == "QG-2").offenders == ("f2",)


def test_qg3_fails_when_confirmation_rests_on_client_signal_alone():
    bad = FindingView("f3", "CONFIRMED_P0", schema_completeness=1.0, server_confirmed=False,
                      has_reproduction=True, has_regression_reference=True)
    r = evaluate(observed_scenarios=ALL_SCENARIOS, findings=[bad])
    assert "QG-3" in r.failing()


def test_qg4_and_qg5_fail_without_reproduction_or_regression():
    bad = FindingView("f4", "CONFIRMED_P0", schema_completeness=1.0, server_confirmed=True,
                      has_reproduction=False, has_regression_reference=False)
    r = evaluate(observed_scenarios=ALL_SCENARIOS, findings=[bad])
    assert "QG-4" in r.failing() and "QG-5" in r.failing()


def test_fail_closed_on_missing_inputs():
    r = evaluate(observed_scenarios=None, findings=None)
    assert r.passed is False
    assert set(r.failing()) == {"QG-1", "QG-2", "QG-3", "QG-4", "QG-5"}


def test_clean_engagement_with_no_confirmed_findings_passes_vacuously():
    # a RULED_OUT finding is not held to the P0 schema; with full scenario coverage the gate passes
    ruled = FindingView("f5", "RULED_OUT", schema_completeness=0.4)
    r = evaluate(observed_scenarios=ALL_SCENARIOS, findings=[ruled])
    assert r.passed is True


def test_payload_json_safe_and_lists_failing():
    payload = evaluate_payload(observed_scenarios=None, findings=[_good_p0()])
    assert payload["passed"] is False and payload["failing"] == ["QG-1"]
    assert json.loads(json.dumps(payload)) == payload
