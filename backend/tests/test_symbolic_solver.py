"""B41: tests for app/testing/integrity/symbolic_solver.py. Stdlib only."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.testing.integrity.symbolic_solver import (  # noqa: E402
    Implication, SolveStatus, Variable, solve_for_violation, solve_payload,
)

QP = Variable("qualifying_payment", (True, False))
ENT = Variable("entitled", (True, False))
LEAK = (("entitled", True), ("qualifying_payment", False))   # entitled without paying


def test_finds_a_counterexample_when_the_contract_underspecifies():
    # contract only says "paying -> entitled"; it does NOT forbid entitlement without paying.
    imps = [Implication((("qualifying_payment", True),), ("entitled", True))]
    res = solve_for_violation([QP, ENT], imps, violation=LEAK)
    assert res.status == SolveStatus.SOLVED
    assert {"entitled": True, "qualifying_payment": False} in [dict(c) for c in res.counterexamples]
    assert res.space == 4


def test_no_counterexample_when_the_contract_forbids_the_violation():
    imps = [Implication((("qualifying_payment", True),), ("entitled", True)),
            Implication((("entitled", True),), ("qualifying_payment", True))]   # entitled -> must have paid
    res = solve_for_violation([QP, ENT], imps, violation=LEAK)
    assert res.status == SolveStatus.NO_COUNTEREXAMPLE and res.counterexamples == ()


def test_bounded_exceeded_refuses_to_enumerate():
    res = solve_for_violation([QP, ENT], [], violation=(("entitled", True),), max_space=3)  # space 4 > 3
    assert res.status == SolveStatus.BOUNDED_EXCEEDED and res.counterexamples == () and res.space == 4


def test_violation_pattern_is_required():
    try:
        solve_for_violation([QP, ENT], [], violation=())
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_malformed_model_is_rejected():
    try:
        solve_for_violation([Variable("x", ())], [], violation=(("x", True),))  # empty domain
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_max_results_caps_output():
    x, y, z = Variable("x", (True, False)), Variable("y", (True, False)), Variable("z", (True, False))
    res = solve_for_violation([x, y, z], [], violation=(("x", True),), max_results=2)
    assert res.status == SolveStatus.SOLVED and len(res.counterexamples) == 2 and res.space == 8


def test_deterministic_and_json_safe():
    imps = [Implication((("qualifying_payment", True),), ("entitled", True))]
    a = solve_for_violation([QP, ENT], imps, violation=LEAK)
    b = solve_for_violation([QP, ENT], imps, violation=LEAK)
    assert a == b
    payload = solve_payload([QP, ENT], imps, violation=LEAK)
    assert json.loads(json.dumps(payload)) == payload
