"""B7 / A7: tests for app/testing/integrity/contract_inference.py. Stdlib only."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.testing.integrity.contract_inference import (  # noqa: E402
    AccessObservation, ClauseStatus, Outcome, infer, infer_payload,
)


def _o(antecedent, outcome, aid=None):
    return AccessObservation(antecedent=antecedent, outcome=outcome, artifact_id=aid)


def test_unanimous_group_becomes_an_inferred_clause():
    obs = [_o((("qualifying_payment", False),), Outcome.DENIED, "a1"),
           _o((("qualifying_payment", False),), Outcome.DENIED, "a2")]
    clauses = infer(obs)
    assert len(clauses) == 1
    c = clauses[0]
    assert c.status == ClauseStatus.INFERRED and c.inferred_outcome == Outcome.DENIED and c.support == 2
    assert set(c.evidence_ids) == {"a1", "a2"}


def test_single_observation_is_insufficient_never_inferred():
    clauses = infer([_o((("qualifying_payment", True),), Outcome.ALLOWED)])
    assert clauses[0].status == ClauseStatus.INSUFFICIENT
    assert clauses[0].inferred_outcome is None


def test_conflicting_outcomes_are_conflicted_not_collapsed_to_a_majority():
    ant = (("tier_claimed", "top"), ("amount_paid_tier", "cheapest"))
    obs = [_o(ant, Outcome.DENIED), _o(ant, Outcome.DENIED), _o(ant, Outcome.DENIED), _o(ant, Outcome.ALLOWED)]
    c = infer(obs)[0]
    assert c.status == ClauseStatus.CONFLICTED
    assert c.inferred_outcome is None            # the 3:1 majority DENIED is NOT asserted
    assert c.support == 4


def test_antecedent_atom_order_does_not_matter():
    a = (("qualifying_payment", True), ("is_payer_identity", True))
    b = (("is_payer_identity", True), ("qualifying_payment", True))   # same atoms, reversed
    clauses = infer([_o(a, Outcome.ALLOWED), _o(b, Outcome.ALLOWED)])
    assert len(clauses) == 1 and clauses[0].support == 2 and clauses[0].status == ClauseStatus.INFERRED


def test_min_support_below_two_is_rejected():
    try:
        infer([_o((("x", True),), Outcome.ALLOWED)], min_support=1)
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_non_scalar_antecedent_value_is_rejected():
    try:
        infer([_o((("bad", [1, 2]),), Outcome.DENIED)])
        assert False, "expected TypeError"
    except TypeError:
        pass


def test_deterministic_ordering_buckets_and_json_safe():
    obs = [
        _o((("qualifying_payment", False),), Outcome.DENIED), _o((("qualifying_payment", False),), Outcome.DENIED),
        _o((("qualifying_payment", True),), Outcome.ALLOWED),                                  # insufficient (1)
        _o((("tier", "top"),), Outcome.ALLOWED), _o((("tier", "top"),), Outcome.DENIED),       # conflicted
    ]
    payload = infer_payload(obs)
    assert [c["antecedent"] for c in payload["clauses"]] == sorted(c["antecedent"] for c in payload["clauses"])
    assert len(payload["inferred"]) == 1 and len(payload["conflicts"]) == 1
    assert json.loads(json.dumps(payload)) == payload
