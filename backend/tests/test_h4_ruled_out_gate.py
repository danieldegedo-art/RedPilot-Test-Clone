"""ZR-004 / H4: the central RULED_OUT calibration guard in
PureBlackBoxEngine._finding.

The guard is behaviour-preserving on every live path (the control phase +
_precondition already refuse to reach a RULED_OUT unless the primary oracle
discriminated), so these tests exercise the guard directly: _finding only reads
`self._run_calibration`, so a tiny stub carrying that one attribute is enough to
drive it without standing up a full engine run.

Stdlib only.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
# http_client -> httpx: use the repo's import-sufficient httpx shim, exactly as the
# other engine-touching tests do (test_agents_proof.py, test_planning.py, ...).
sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))

from app.testing.integrity.engine import PureBlackBoxEngine  # noqa: E402
from app.testing.integrity.oracle_calibration import OracleTier, calibration_from_outcomes  # noqa: E402
from app.testing.purity.taxonomy import Verdict  # noqa: E402

CALIBRATED = calibration_from_outcomes(OracleTier.DURABLE_STATE_CHANGE, "allowed", "denied")
UNCALIBRATED = calibration_from_outcomes(OracleTier.DURABLE_STATE_CHANGE, "denied", "denied")  # cannot tell paid from clean


class _Stub:
    """Carries only what _finding reads."""

    def __init__(self, calibration):
        self._run_calibration = calibration


def _finding(calibration, verdict, summary="under the tested conditions the feature was not unlocked"):
    return PureBlackBoxEngine._finding(_Stub(calibration), "PBB-F", verdict, "high", summary)


def test_ruled_out_passes_through_unchanged_when_the_oracle_is_calibrated():
    f = _finding(CALIBRATED, Verdict.RULED_OUT)
    assert f.verdict is Verdict.RULED_OUT
    assert "ruled_out_withheld_uncalibrated_oracle" not in f.reasons


def test_ruled_out_is_downgraded_to_unknown_when_the_oracle_is_uncalibrated():
    f = _finding(UNCALIBRATED, Verdict.RULED_OUT)
    assert f.verdict is Verdict.UNKNOWN
    assert "ruled_out_withheld_uncalibrated_oracle" in f.reasons
    assert any("H4 guard" in lim for lim in f.limitations)


def test_ruled_out_is_downgraded_when_calibration_was_never_established():
    f = _finding(None, Verdict.RULED_OUT)
    assert f.verdict is Verdict.UNKNOWN
    assert "ruled_out_withheld_uncalibrated_oracle" in f.reasons


def test_non_ruled_out_verdicts_are_never_touched_by_the_guard():
    # Even with no calibration at all, UNKNOWN / BLOCKED / PARTIALLY_VALIDATED are unaffected:
    # the guard is scoped strictly to the RULED_OUT "cleared" claim. (CONFIRMED_P0 is excluded
    # here because the finding schema independently forbids building one without a
    # ConfirmationToken -- a stronger invariant than this guard, enforced in findings.py.)
    for v in (Verdict.UNKNOWN, Verdict.BLOCKED,
              Verdict.PARTIALLY_VALIDATED_PAYMENT_INTEGRITY_ISSUE):
        assert _finding(None, v).verdict is v


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
