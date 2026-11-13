"""ZR-024 (second half): the four-label uncertainty vocabulary for a
ConfirmationCandidate that ConfirmationGate.evaluate() did NOT confirm --
BLOCKED BY MISSING SERVER-SIDE ORACLE / NOT SUFFICIENTLY PROVABLE /
PARTIALLY VERIFIED / UNCONFIRMED (contract.py's UncertaintyStatus).

Two things matter here: (1) each individual reason prefix maps to the label
a human reviewer would actually expect, and (2) EVERY reason prefix
evaluate() can produce is handled -- not just the ones someone thought to
test. (2) is the one that actually catches drift: if a future change adds a
new `reasons.append(...)` to evaluate() without updating
_classify_uncertainty, this file's exhaustiveness test fails instead of the
new reason silently falling through to the defensive UNCONFIRMED fallback.

Stdlib only, same as oracle_gate.py itself -- no shims needed.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.core.control_port.contract import UncertaintyStatus  # noqa: E402
from app.enterprise_controls import oracle_gate  # noqa: E402
from app.enterprise_controls.oracle_gate import _classify_uncertainty  # noqa: E402

EXPECTED = {
    "feature_not_registered": UncertaintyStatus.UNCONFIRMED,
    "control_missing": UncertaintyStatus.BLOCKED_BY_MISSING_ORACLE,
    "clean_reproduction_missing": UncertaintyStatus.NOT_SUFFICIENTLY_PROVABLE,
    "clean_reproduction_not_independent": UncertaintyStatus.NOT_SUFFICIENTLY_PROVABLE,
    "scenario_not_proven": UncertaintyStatus.PARTIALLY_VERIFIED,
    "no_evidence_artifacts": UncertaintyStatus.PARTIALLY_VERIFIED,
    "artifact_not_admitted": UncertaintyStatus.PARTIALLY_VERIFIED,
    "evidence_class_not_external": UncertaintyStatus.PARTIALLY_VERIFIED,
    "oracle_requirement_not_met": UncertaintyStatus.UNCONFIRMED,
    "non_authoritative_signals_only": UncertaintyStatus.UNCONFIRMED,
}


def test_each_reason_in_isolation_maps_to_the_expected_label():
    for prefix, expected in EXPECTED.items():
        got = _classify_uncertainty((f"{prefix}: some detail",))
        assert got == expected, f"{prefix!r} -> expected {expected}, got {got}"


def test_qualifying_payment_present_is_not_an_unproven_suspicion():
    """The one reason that's deliberately NOT one of the four -- it means the
    access was legitimate, which is a conclusively-determined non-finding,
    not an open question."""
    assert _classify_uncertainty(("qualifying_payment_present: the access may be correct behaviour",)) is None


def test_priority_order_reports_the_most_fundamental_blocker_first():
    """Missing oracle AND missing reproduction together -> report the oracle.
    Fix that first; the reproduction question can't even be meaningfully
    asked until there's a control-denied observation to reproduce against."""
    reasons = ("control_missing: x", "clean_reproduction_missing: y")
    assert _classify_uncertainty(reasons) == UncertaintyStatus.BLOCKED_BY_MISSING_ORACLE


def test_exhaustiveness_every_reason_evaluate_can_actually_emit_is_classified():
    """Extracts every literal reasons.append(f"...") / reasons.append("...")
    prefix straight from oracle_gate.py's own source via a regex over the
    evaluate() method's text, instead of hand-maintaining a parallel list
    here that could silently drift out of sync with the real code."""
    import inspect
    source = inspect.getsource(oracle_gate.ConfirmationGate.evaluate)
    prefixes = set(re.findall(r'reasons\.append\(\s*(?:f?["\'])([a-z_]+)', source))

    assert prefixes, "regex found nothing -- it no longer matches evaluate()'s source, fix the regex before trusting this test"
    assert prefixes == set(EXPECTED) | {"qualifying_payment_present"}, (
        f"evaluate() produces {prefixes} but this test's EXPECTED mapping covers "
        f"{set(EXPECTED) | {'qualifying_payment_present'}} -- a reason was added or "
        f"renamed in oracle_gate.py without updating _classify_uncertainty/this test"
    )
    for prefix in prefixes - {"qualifying_payment_present"}:
        assert _classify_uncertainty((f"{prefix}: x",)) is not None, f"{prefix!r} falls through to no classification"


def test_empty_reasons_tuple_does_not_crash():
    # Not a real-world case (evaluate() only calls this inside `if reasons:`),
    # but _classify_uncertainty should not blow up if ever called directly.
    assert _classify_uncertainty(()) == UncertaintyStatus.UNCONFIRMED


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
