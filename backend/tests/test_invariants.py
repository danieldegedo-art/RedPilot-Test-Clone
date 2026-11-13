"""Tests for app.testing.invariants. See test_state_exploration.py's module
docstring for why these are plain-assert functions runnable both under
pytest and directly via `python3 tests/test_invariants.py`.
"""
from __future__ import annotations

from app.testing.invariants import (
    AttemptRecord,
    check_idempotent_replay,
    check_ledger_consistency,
    check_no_illegal_transition_succeeded,
    check_refund_sum_within_capture,
)


def test_idempotent_replay_passes_when_all_attempts_agree_on_resource_id():
    attempts = [
        AttemptRecord(operation="create_payment", idempotency_key="k1", succeeded=True, resulting_resource_id="pay_1"),
        AttemptRecord(operation="create_payment", idempotency_key="k1", succeeded=True, resulting_resource_id="pay_1"),
        AttemptRecord(operation="create_payment", idempotency_key="k1", succeeded=True, resulting_resource_id="pay_1"),
    ]
    assert check_idempotent_replay(attempts) == []


def test_idempotent_replay_flags_a_double_debit():
    attempts = [
        AttemptRecord(operation="create_payment", idempotency_key="k2", succeeded=True, resulting_resource_id="pay_10"),
        AttemptRecord(operation="create_payment", idempotency_key="k2", succeeded=True, resulting_resource_id="pay_11"),
    ]
    violations = check_idempotent_replay(attempts)
    assert len(violations) == 1
    assert violations[0].invariant_id == "idempotent_replay"


def test_idempotent_replay_ignores_attempts_without_a_key():
    attempts = [AttemptRecord(operation="create_payment", succeeded=True, resulting_resource_id=f"pay_{i}") for i in range(5)]
    assert check_idempotent_replay(attempts) == []


def test_refund_sum_within_capture_passes_at_exact_boundary():
    violations = check_refund_sum_within_capture(100.00, [
        AttemptRecord(operation="refund", succeeded=True, request_amount=60.00),
        AttemptRecord(operation="refund", succeeded=True, request_amount=40.00),
    ])
    assert violations == []


def test_refund_sum_within_capture_flags_over_refund():
    violations = check_refund_sum_within_capture(100.00, [
        AttemptRecord(operation="refund", succeeded=True, request_amount=60.00),
        AttemptRecord(operation="refund", succeeded=True, request_amount=50.00),
    ])
    assert len(violations) == 1
    assert "110.00" in violations[0].message and "100.00" in violations[0].message


def test_refund_sum_ignores_failed_attempts():
    violations = check_refund_sum_within_capture(100.00, [
        AttemptRecord(operation="refund", succeeded=True, request_amount=60.00),
        AttemptRecord(operation="refund", succeeded=False, request_amount=50.00),  # rejected by the SUT
    ])
    assert violations == []


def test_refund_sum_does_not_false_positive_on_float_rounding():
    """The canonical float trap: 0.1 + 0.2 != 0.3 as raw floats. A naive
    implementation of this invariant using float equality would wrongly
    flag a perfectly correct system here."""
    assert 0.1 + 0.2 != 0.30  # sanity: confirms the trap this test guards against is real
    violations = check_refund_sum_within_capture(0.30, [
        AttemptRecord(operation="refund", succeeded=True, request_amount=0.10),
        AttemptRecord(operation="refund", succeeded=True, request_amount=0.20),
    ])
    assert violations == []


def test_no_illegal_transition_succeeded_catches_refunded_to_captured():
    """This is the same case modules/state_transition_consistency.py's
    STATE-002 already tests by hand -- proof this generic invariant
    subsumes that specific case rather than being an unrelated new check."""
    violations = check_no_illegal_transition_succeeded([
        AttemptRecord(operation="capture", resource_type="payment", from_state="refunded", to_state="captured", succeeded=True),
    ])
    assert len(violations) == 1


def test_no_illegal_transition_succeeded_allows_legal_transitions():
    violations = check_no_illegal_transition_succeeded([
        AttemptRecord(operation="capture", resource_type="payment", from_state="authorized", to_state="captured", succeeded=True),
    ])
    assert violations == []


def test_no_illegal_transition_ignores_failed_attempts():
    """An illegal transition that the SUT correctly REJECTED (succeeded=False)
    is the system working -- not a violation."""
    violations = check_no_illegal_transition_succeeded([
        AttemptRecord(operation="capture", resource_type="payment", from_state="refunded", to_state="captured", succeeded=False),
    ])
    assert violations == []


def test_ledger_consistency_passes_when_totals_match():
    assert check_ledger_consistency(150.00, [100.00, 50.00]) == []


def test_ledger_consistency_flags_a_discrepancy():
    violations = check_ledger_consistency(150.00, [100.00, 49.99])
    assert len(violations) == 1
    assert "0.01" in violations[0].message


def _run(fn):
    try:
        fn()
        print(f"[PASS] {fn.__name__}")
    except AssertionError as exc:
        print(f"[FAIL] {fn.__name__}: {exc}")
        raise


if __name__ == "__main__":
    for _name, _fn in list(globals().items()):
        if _name.startswith("test_") and callable(_fn):
            _run(_fn)
    print("Alle invariants-Tests bestanden.")
