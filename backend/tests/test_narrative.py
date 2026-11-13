"""B15: tests for app/testing/integrity/narrative.py. Stdlib only."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.testing.integrity.narrative import narrate_chain, narrate_finding, report  # noqa: E402

CONFIRMED = {"hypothesis_id": "PBB-U", "title": "Unconfirmed-payment access", "verdict": "CONFIRMED_P0",
             "confidence": "high", "summary": "feature usable after a declined payment", "impact": "revenue loss"}
RULED = {"hypothesis_id": "PBB-F", "title": "Plan/price binding", "verdict": "RULED_OUT",
         "confidence": "high", "summary": "tier denied in every variant", "impact": "should be ignored"}


def test_confirmed_p0_uses_confirmed_language_and_includes_impact():
    s = narrate_finding(CONFIRMED)
    assert "confirmed (P0)" in s and "Unconfirmed-payment access" in s
    assert "feature usable after a declined payment" in s and "Impact: revenue loss" in s


def test_ruled_out_never_says_confirmed_or_p0():
    s = narrate_finding(RULED)
    assert "ruled out" in s
    assert "confirmed" not in s.lower() and "P0" not in s


def test_missing_fields_are_omitted_not_invented():
    s = narrate_finding({"hypothesis_id": "PBB-C", "verdict": "UNKNOWN"})
    assert s == "[PBB-C] unknown"
    assert ":" not in s and "confidence" not in s and "Impact" not in s


def test_impact_is_shown_only_for_confirmed_p0():
    # RULED has an impact field, but it must not appear for a non-P0 verdict
    assert "Impact" not in narrate_finding(RULED)


def test_narrate_chain_renders_steps_and_establishes():
    s = narrate_chain({"steps": ["PBB-U", "PBB-X", "PBB-G"], "establishes": ["access_without_payment"]})
    assert s == "Chain reaching PBB-G: PBB-U -> PBB-X -> PBB-G (establishes: access_without_payment)"
    assert narrate_chain({"steps": []}) == "(empty chain)"


def test_report_counts_headline_and_ordering():
    rep = report([CONFIRMED, RULED])
    assert rep["verdict_counts"] == {"CONFIRMED_P0": 1, "RULED_OUT": 1}
    assert "PBB-U" in rep["headline"] and rep["headline"].startswith("1 confirmed")
    # ordered by hypothesis id: PBB-F before PBB-U
    assert rep["finding_narratives"][0].startswith("[PBB-F]")


def test_report_json_safe():
    rep = report([CONFIRMED, RULED], chains=[{"steps": ["PBB-U"], "establishes": []}])
    assert json.loads(json.dumps(rep)) == rep
