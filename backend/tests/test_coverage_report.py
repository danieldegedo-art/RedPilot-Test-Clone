"""ZR-022: tests for gaps.coverage_report (capability-gap register + ZR-006 matrix). Stdlib only."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.testing.integrity.gaps import coverage_report  # noqa: E402
from app.testing.purity.taxonomy import Verdict  # noqa: E402


class _F:
    def __init__(self, hid, verdict, p0_class, affected_flow, summary="s"):
        self.hypothesis_id = hid
        self.verdict = verdict
        self.p0_class = p0_class
        self.affected_flow = affected_flow
        self.summary = summary
        self.divergences = []


class _Result:
    def __init__(self, findings):
        self._f = findings

    @property
    def findings(self):
        return self._f

    def by_id(self):
        return {f.hypothesis_id: f for f in self._f}


def test_no_brief_no_result_reports_the_register_but_no_matrix():
    rep = coverage_report(None, None)
    assert rep["capability_gaps"]  # the register is always emitted (BLOCKED / not-supported rows)
    assert rep["coverage_matrix"] is None
    assert rep["summary"]["p0_classes_total"] > 0 and rep["summary"]["p0_classes_covered"] == 0
    assert rep["summary"]["verdict_tally"] == {}


def test_with_a_result_the_matrix_and_tally_are_included():
    r = _Result([
        _F("PBB-U", Verdict.RULED_OUT, "unconfirmed_payment_grants_access", "checkout"),
        _F("PBB-F", Verdict.RULED_OUT, "plan_or_price_binding", "subscription"),
    ])
    rep = coverage_report(object(), r)  # any non-None brief object
    assert rep["coverage_matrix"] is not None
    assert rep["coverage_matrix"]["verdict_tally"] == {"RULED_OUT": 2}
    assert rep["summary"]["verdict_tally"] == {"RULED_OUT": 2}
    # PBB-U has no residual limitation -> COVERED in the register; PBB-F carries a
    # documented residual channel so the register (correctly) keeps it PARTIAL,
    # even though the verdict-based matrix counts both RULED_OUT.
    assert rep["summary"]["p0_classes_covered"] >= 1


def test_report_is_fully_json_safe():
    assert json.loads(json.dumps(coverage_report(None, None))) == coverage_report(None, None)
