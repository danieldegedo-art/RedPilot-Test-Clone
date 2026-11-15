"""ZR-017: "demonstrable link between an invalid/insufficient payment-or-
entitlement state and nonetheless-successful feature use; every CONFIRMED_P0
shows both halves of the linkage explicitly."

Checked by direct reading first, not assumed: every _confirmed_or_partial(...)
call across all 7 PBB experiments in integrity/engine.py (PBB-U, F, H, R and
three more) states both halves in its summary text explicitly --
e.g. PBB-U: "...USED the paid feature after a non-qualifying
(declined/cancelled) payment...". No code change was needed for the
narrative half of this requirement; it was already there.

What this file adds is the structural backbone that narrative depends on
being true, not just descriptive: Finding.__post_init__ (findings.py) already
refuses to let a CONFIRMED_P0 Finding even be CONSTRUCTED without a
ConfirmationToken that covers that exact hypothesis_id, and
ConfirmationToken itself (oracle_gate.py) cannot be constructed by anything
other than ConfirmationGate.evaluate(). Verifying both of those hold for
real, not just trusting the __slots__/private-key comments, is what's new
here -- this is the enforcement that makes "every CONFIRMED_P0 shows both
halves" a guarantee instead of a convention a future experiment method could
quietly skip.

Stdlib only.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.core.control_port.contract import ConfirmationRefused  # noqa: E402
from app.enterprise_controls.oracle_gate import ConfirmationToken  # noqa: E402
from app.testing.integrity.findings import Finding, OracleSpec  # noqa: E402
from app.testing.purity.taxonomy import Verdict  # noqa: E402


def _spec() -> OracleSpec:
    return OracleSpec(
        invariant="x", baseline_state="x", identity_and_tenant="x", controlled_variable="x",
        action_sequence="x", expected_outcome="x", p0_condition="x", rule_out_condition="x",
        stop_condition="x", evidence_requirements="x",
    )


def test_confirmed_p0_without_a_token_cannot_even_be_constructed():
    try:
        Finding(hypothesis_id="PBB-U", p0_class="x", title="x", verdict=Verdict.CONFIRMED_P0,
                confidence="high", summary="x", spec=_spec(), token=None)
        raise AssertionError("expected ConfirmationRefused, Finding was constructed")
    except ConfirmationRefused:
        pass


def test_confirmed_p0_with_a_token_for_a_different_hypothesis_is_refused():
    """A token that's real but covers the wrong hypothesis_id must be
    rejected just as hard as no token at all -- otherwise a copy-paste bug
    (reusing yesterday's token) would silently pass."""
    real_token = ConfirmationGate_evaluate_a_token_for("PBB-F")
    try:
        Finding(hypothesis_id="PBB-U", p0_class="x", title="x", verdict=Verdict.CONFIRMED_P0,
                confidence="high", summary="x", spec=_spec(), token=real_token)
        raise AssertionError("expected ConfirmationRefused, Finding was constructed with a mismatched token")
    except ConfirmationRefused:
        pass


def test_a_token_cannot_be_forged_directly():
    try:
        ConfirmationToken("PBB-U", ("fake-artifact",))
        raise AssertionError("expected ConfirmationRefused, a bare ConfirmationToken(...) call succeeded")
    except ConfirmationRefused:
        pass


def test_a_genuinely_issued_token_does_let_a_confirmed_p0_finding_exist():
    """The positive control -- this file isn't just proving things are
    blocked, it's proving the legitimate path still works."""
    token = ConfirmationGate_evaluate_a_token_for("PBB-U")
    f = Finding(hypothesis_id="PBB-U", p0_class="x", title="x", verdict=Verdict.CONFIRMED_P0,
                confidence="high", summary="A synthetic identity USED the paid feature after a non-qualifying payment.",
                spec=_spec(), token=token)
    assert f.verdict == Verdict.CONFIRMED_P0


def ConfirmationGate_evaluate_a_token_for(hypothesis_id: str):
    """Helper: mints a real token the only legitimate way -- through
    ConfirmationGate.evaluate() with a well-evidenced candidate -- rather
    than reaching into oracle_gate's private _MINT sentinel, which would
    defeat the point of this file."""
    from app.core.control_port.contract import KIND_FEATURE_USE, ConfirmationCandidate, OracleObservation
    from app.enterprise_controls.oracle_gate import ConfirmationGate

    class _FakeLedger:
        def is_admitted(self, artifact_id):
            return True

    cand = ConfirmationCandidate(
        hypothesis_id=hypothesis_id,
        control_denied=OracleObservation("o1", "feat-x", "clean-id", None, "denied", KIND_FEATURE_USE, True, "s1", ("a1",), discriminating=True),
        scenario_allowed=OracleObservation("o2", "feat-x", "victim-id", None, "allowed", KIND_FEATURE_USE, True, "s2", ("a1",)),
        clean_reproduction=OracleObservation("o3", "feat-x", "victim-id", None, "allowed", KIND_FEATURE_USE, True, "s3", ("a1",)),
        qualifying_payment_present=False,
    )
    decision = ConfirmationGate(ledger=_FakeLedger()).evaluate(cand)
    assert decision.confirmed and decision.token is not None, "test setup broken, not the thing under test"
    return decision.token


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
