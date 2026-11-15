"""ZR-023 / B26: tests for regression_reference + attach_regression_references, and a
characterization guard that the shared-helper refactor left build_regression_spec's
output unchanged. Stdlib only."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.testing.integrity.regression import (  # noqa: E402
    attach_regression_references, build_regression_spec, regression_reference,
)
from app.testing.purity.taxonomy import Verdict  # noqa: E402


class _F:
    def __init__(self, hid, verdict, p0_class="demo_class"):
        self.hypothesis_id = hid
        self.verdict = verdict
        self.p0_class = p0_class
        self.regression_test_reference = None


class _Result:
    def __init__(self, findings):
        self.findings = findings


class _Brief:
    def __init__(self, fp):
        self._fp = fp

    def fingerprint(self):
        return self._fp


def test_regression_reference_maps_each_verdict_class():
    assert regression_reference("PBB-U", Verdict.CONFIRMED_P0, "bf") == "regression_for_confirmed_p0:PBB-U@bf"
    assert regression_reference("PBB-F", Verdict.RULED_OUT, "bf") == "false_positive_control:PBB-F@bf"
    assert regression_reference("PBB-C", Verdict.UNKNOWN, "bf") == "open_not_a_pass:PBB-C@bf"
    assert regression_reference("PBB-C", Verdict.BLOCKED, "bf") == "open_not_a_pass:PBB-C@bf"


def test_pbb_open_has_no_regression_reference():
    # PBB-OPEN is excluded from regression entirely (no pass/fail expectation possible)
    assert regression_reference("PBB-OPEN", Verdict.RULED_OUT, "bf") is None


def test_the_reference_encodes_the_brief_fingerprint_so_a_stale_spec_is_detectable():
    assert regression_reference("PBB-U", Verdict.CONFIRMED_P0, "fp-A").endswith("@fp-A")
    assert regression_reference("PBB-U", Verdict.CONFIRMED_P0, "fp-B").endswith("@fp-B")


def test_attach_sets_references_in_place_and_skips_pbb_open():
    findings = [_F("PBB-U", Verdict.CONFIRMED_P0), _F("PBB-F", Verdict.RULED_OUT), _F("PBB-OPEN", Verdict.RULED_OUT)]
    attach_regression_references(findings, "bf")
    assert findings[0].regression_test_reference == "regression_for_confirmed_p0:PBB-U@bf"
    assert findings[1].regression_test_reference == "false_positive_control:PBB-F@bf"
    assert findings[2].regression_test_reference is None  # PBB-OPEN stays unset, not fabricated


def test_build_regression_spec_kinds_unchanged_by_the_refactor_and_share_the_reference_vocabulary():
    result = _Result([
        _F("PBB-U", Verdict.CONFIRMED_P0), _F("PBB-F", Verdict.RULED_OUT),
        _F("PBB-C", Verdict.UNKNOWN), _F("PBB-OPEN", Verdict.RULED_OUT),
    ])
    spec = build_regression_spec(result, _Brief("bf"))
    kinds = {c["hypothesis_id"]: c["kind"] for c in spec["checks"]}
    assert kinds == {"PBB-U": "regression_for_confirmed_p0", "PBB-F": "false_positive_control", "PBB-C": "open_not_a_pass"}  # PBB-OPEN excluded
    expects = {c["hypothesis_id"]: c["expect_after_fix"] for c in spec["checks"]}
    assert expects == {"PBB-U": "RULED_OUT", "PBB-F": "RULED_OUT", "PBB-C": None}
    # the per-finding reference uses exactly the spec's own kind (no drift between the two code paths)
    for f in result.findings:
        if f.hypothesis_id == "PBB-OPEN":
            continue
        assert regression_reference(f.hypothesis_id, f.verdict, "bf").startswith(kinds[f.hypothesis_id] + ":")
