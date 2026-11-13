"""ZR-034 (Section 15.1): tests for the Standard Engagement Completion Report. Stdlib only."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.testing.integrity.completion_report import (  # noqa: E402
    SECTIONS, build_completion_report, completion_report_markdown,
)
from app.testing.integrity.findings import EXPERIMENT_CLASSES  # noqa: E402
from app.testing.purity.taxonomy import Verdict  # noqa: E402


class _F:
    def __init__(self, hid, verdict, p0_class, flow, reproduction_steps=None):
        self.hypothesis_id = hid
        self.verdict = verdict
        self.p0_class = p0_class
        self.title = f"title {hid}"
        self.confidence = "high"
        self.priority = "P0"
        self.affected_flow = flow
        self.reproduction_status = "externally_reproduced" if verdict == Verdict.CONFIRMED_P0 else "n/a"
        self.reproduction_steps = reproduction_steps
        self.regression_test_reference = f"k:{hid}@bf"
        self.summary = f"summary {hid}"
        self.reasons = []
        self.divergences = []

    def schema_completeness(self):
        return 0.9


class _Result:
    engine_version = "pbb/1.0"
    brief_fingerprint = "bf-xyz"
    started_at = "t0"
    finished_at = "t1"

    def __init__(self, findings):
        self._f = findings
        self.stats = {"experiment_order": [f.hypothesis_id for f in findings], "synthetic_identities_used": ["S", "K"]}
        self.controls = {"oracle_discriminating": True}
        self.ledger_summary = {"accepted": 10, "rejected": 0}
        self.replay_bundles = {f.hypothesis_id: {"authorization_ref": "AUTH-9", "artifacts": []} for f in findings}

    @property
    def findings(self):
        return self._f

    def by_id(self):
        return {f.hypothesis_id: f for f in self._f}


def _confirmed_run():
    return _Result([
        _F("PBB-U", Verdict.CONFIRMED_P0, "unconfirmed_payment_grants_access", "checkout", reproduction_steps="step 1\nstep 2"),
        _F("PBB-F", Verdict.RULED_OUT, "plan_or_price_binding", "subscription"),
        _F("PBB-H", Verdict.UNKNOWN, "currency_binding", "payment"),
    ])


def test_all_seven_sections_are_present():
    rep = build_completion_report(_confirmed_run(), brief=None)
    for section in SECTIONS:
        assert section in rep, section
    assert rep["report_type"] == "engagement_completion_report"


def test_status_is_p0_confirmed_when_a_confirmed_finding_exists():
    assert build_completion_report(_confirmed_run())["summary"]["status"] == "P0_CONFIRMED"


def test_status_is_clean_only_when_all_ruled_out_without_divergence():
    r = _Result([_F("PBB-U", Verdict.RULED_OUT, "unconfirmed_payment_grants_access", "checkout"),
                 _F("PBB-F", Verdict.RULED_OUT, "plan_or_price_binding", "subscription")])
    assert build_completion_report(r)["summary"]["status"] == "CLEAN"


def test_status_is_incomplete_when_an_experiment_is_unknown():
    r = _Result([_F("PBB-U", Verdict.RULED_OUT, "unconfirmed_payment_grants_access", "checkout"),
                 _F("PBB-H", Verdict.UNKNOWN, "currency_binding", "payment")])
    assert build_completion_report(r)["summary"]["status"] == "INCOMPLETE"


def test_requirements_matrix_has_a_row_per_target_class_marking_not_run():
    rep = build_completion_report(_confirmed_run())
    rows = {r["experiment"]: r for r in rep["requirements_matrix"]}
    assert set(rows) == set(EXPERIMENT_CLASSES)  # every targeted class is represented
    assert rows["PBB-U"]["tested"] and rows["PBB-U"]["verdict"] == "CONFIRMED_P0"
    assert rows["PBB-G"]["tested"] is False and rows["PBB-G"]["verdict"] == "NOT_RUN"  # not in this run


def test_not_implemented_lists_unknown_and_blocked_never_hidden():
    rep = build_completion_report(_confirmed_run())
    classes = {n["p0_class"] for n in rep["not_implemented"]}
    assert "currency_binding" in classes  # the UNKNOWN experiment surfaces here, not silently dropped


def test_authorization_ref_falls_back_to_a_replay_bundle_when_no_brief():
    assert build_completion_report(_confirmed_run(), brief=None)["summary"]["authorization_ref"] == "AUTH-9"


def test_report_is_json_safe_and_markdown_renders():
    rep = build_completion_report(_confirmed_run())
    assert json.loads(json.dumps(rep)) == rep
    md = completion_report_markdown(rep)
    assert md.startswith("# Engagement Completion Report")
    for header in ("## Summary", "## Requirements Matrix", "## Implemented Changes", "## Coverage", "## Findings", "## Verification", "## Not-Implemented"):
        assert header in md, header
