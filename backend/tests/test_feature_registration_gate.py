"""ZR-002 x ZR-025 condition 1: a ConfirmationGate must not confirm a
candidate about a feature that was never registered as paid/protected --
once a registry is actually wired in. Three things to prove, not two:
(1) perfect evidence for an unregistered feature is blocked when a registry
IS configured, (2) perfect evidence for a registered feature still confirms
(the check isn't overbroad), and (3) with NO registry configured at all
(today's only production wiring -- control_adapter/adapter.py's
new_confirmation_gate doesn't pass one yet), behaviour is unchanged from
before this feature existed. (3) is the regression this file guards against:
an earlier version of this check made (3) a hard block too, which broke
test_control_adapter.py::test_ledger_and_gate_through_the_adapter_confirm_with_a_real_token
-- confirmation would have become impossible everywhere until PESM is
actually populated by agents that don't exist yet (A3/A5-A7).

Stdlib only.
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.core.control_port.contract import ConfirmationCandidate, KIND_FEATURE_USE, OracleObservation, UncertaintyStatus  # noqa: E402
from app.enterprise_controls.oracle_gate import ConfirmationGate  # noqa: E402


class _FakeLedger:
    """evaluate() only ever calls ledger.is_admitted(artifact_id) -- isolates
    this file's tests from EvidenceLedger's own admission logic, which is
    tested elsewhere (provenance/EvidenceArtifact requirements aren't what's
    under test here)."""

    def __init__(self, admitted):
        self._admitted = set(admitted)

    def is_admitted(self, artifact_id):
        return artifact_id in self._admitted


def _well_evidenced_candidate(feature_id: str) -> ConfirmationCandidate:
    """Every OTHER condition satisfied -- isolates the feature-registration
    check specifically; if this ever fails to confirm with a registry that
    DOES contain feature_id, the bug is in this check, not elsewhere."""
    return ConfirmationCandidate(
        hypothesis_id="h-reg-test",
        control_denied=OracleObservation("o1", feature_id, "clean-id", None, "denied", KIND_FEATURE_USE, True, "s1", ("a1",), discriminating=True),
        scenario_allowed=OracleObservation("o2", feature_id, "victim-id", None, "allowed", KIND_FEATURE_USE, True, "s2", ("a1",)),
        clean_reproduction=OracleObservation("o3", feature_id, "victim-id", None, "allowed", KIND_FEATURE_USE, True, "s3", ("a1",)),
        qualifying_payment_present=False,
    )


def _ledger_admitting(*artifact_ids: str) -> _FakeLedger:
    return _FakeLedger(admitted=artifact_ids)


def test_unregistered_feature_is_blocked_when_a_registry_is_configured():
    cand = _well_evidenced_candidate("feat-unregistered")
    gate = ConfirmationGate(ledger=_ledger_admitting("a1"), registered_feature_ids=frozenset({"some-other-feature"}))
    decision = gate.evaluate(cand)

    assert decision.confirmed is False
    assert any(r.startswith("feature_not_registered") for r in decision.reasons)
    assert decision.uncertainty_status == UncertaintyStatus.UNCONFIRMED


def test_registered_feature_still_confirms_the_check_is_not_overbroad():
    cand = _well_evidenced_candidate("feat-registered")
    gate = ConfirmationGate(ledger=_ledger_admitting("a1"), registered_feature_ids=frozenset({"feat-registered"}))
    decision = gate.evaluate(cand)

    assert decision.confirmed is True
    assert decision.token is not None
    assert decision.uncertainty_status is None


def test_no_registry_configured_is_unchanged_from_before_this_check_existed():
    """The regression case: control_adapter/adapter.py's real production call
    site doesn't supply registered_feature_ids yet. This must keep working
    exactly as it did before ZR-002/condition-1 was added."""
    cand = _well_evidenced_candidate("feat-anything")
    gate = ConfirmationGate(ledger=_ledger_admitting("a1"))  # no registered_feature_ids -- today's only real wiring
    decision = gate.evaluate(cand)

    assert decision.confirmed is True
    assert decision.token is not None
    assert not any(r.startswith("feature_not_registered") for r in decision.reasons)


def test_observations_disagreeing_on_feature_id_is_blocked_even_with_no_registry():
    """Internal inconsistency on the candidate itself, not a PESM question --
    this part of the check is NOT fail-open, unlike the registry lookup."""
    cand = ConfirmationCandidate(
        hypothesis_id="h-mismatch",
        control_denied=OracleObservation("o1", "feat-a", "clean-id", None, "denied", KIND_FEATURE_USE, True, "s1", ("a1",), discriminating=True),
        scenario_allowed=OracleObservation("o2", "feat-b", "victim-id", None, "allowed", KIND_FEATURE_USE, True, "s2", ("a1",)),
        clean_reproduction=OracleObservation("o3", "feat-b", "victim-id", None, "allowed", KIND_FEATURE_USE, True, "s3", ("a1",)),
        qualifying_payment_present=False,
    )
    gate = ConfirmationGate(ledger=_ledger_admitting("a1"))  # still no registry
    decision = gate.evaluate(cand)

    assert decision.confirmed is False
    assert any("disagree on feature_id" in r for r in decision.reasons)


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
