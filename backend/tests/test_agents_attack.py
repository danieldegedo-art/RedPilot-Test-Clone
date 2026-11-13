"""Attack agents: tests for app/testing/agents/attack.py. Stdlib only."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.testing.agents.attack import (  # noqa: E402
    AGENTS, BusinessLogicHypothesisAgent, DifferentialTestingAgent, RaceStateTransitionAgent, SymbolicSolverAgent,
)
from app.testing.integrity.contract_inference import AccessObservation, Outcome  # noqa: E402
from app.testing.integrity.differencer import Surface, SurfaceClaim, SubjectSurfaces  # noqa: E402
from app.testing.integrity.race_window import Operation  # noqa: E402
from app.testing.integrity.symbolic_solver import Implication, Variable  # noqa: E402


def test_differential_agent_flags_cross_surface_trust_defect():
    subj = SubjectSurfaces("s1", "paid_feature_open_to_unpaid", (
        SurfaceClaim(Surface.SERVER_ENFORCED, False), SurfaceClaim(Surface.ACCOUNT_VIEW, True)))
    r = DifferentialTestingAgent().run(subjects=[subj])
    assert r.status == "ok" and r.data["trust_defects"] == ["s1"]
    assert r.summary == "1 trust defect(s), 0 inconclusive"
    assert r.leads == ["trust-defect lead on s1 (cross-surface divergence)"]


def test_differential_agent_inconclusive_without_authoritative_surface():
    subj = SubjectSurfaces("s2", "paid_feature_open_to_unpaid", (SurfaceClaim(Surface.ACCOUNT_VIEW, True),))
    r = DifferentialTestingAgent().run(subjects=[subj])
    assert r.data["inconclusive"] == ["s2"] and r.data["trust_defects"] == []


def test_business_logic_agent_infers_unanimous_clause():
    obs = [AccessObservation((("plan", "pro"),), Outcome.ALLOWED),
           AccessObservation((("plan", "pro"),), Outcome.ALLOWED)]
    r = BusinessLogicHypothesisAgent().run(observations=obs)
    assert r.summary == "1 inferred, 0 conflicted, 0 insufficient"
    assert "hypothesis: {'plan': 'pro'} -> ALLOWED" in r.leads


def test_business_logic_agent_surfaces_conflict_never_a_majority():
    obs = [AccessObservation((("coupon", "X"),), Outcome.ALLOWED),
           AccessObservation((("coupon", "X"),), Outcome.DENIED)]
    r = BusinessLogicHypothesisAgent().run(observations=obs)
    assert r.summary == "0 inferred, 1 conflicted, 0 insufficient"
    assert any("non-determinism lead" in x for x in r.leads)


def test_race_agent_finds_window_and_illegal_transition():
    ops = [Operation("o1", 0.0, 2.0), Operation("o2", 1.0, 3.0)]
    r = RaceStateTransitionAgent().run(
        operations=ops, quota=1,
        observed_transitions=[("refunded", "active"), ("active", "canceled")],
        allowed_transitions=[("active", "canceled")])
    assert r.data["race"]["status"] == "WINDOW_FOUND"
    assert r.data["illegal_transitions"] == ["refunded->active"]
    assert r.summary == "race WINDOW_FOUND; 1 illegal transition(s)"
    assert any("race-window lead" in x for x in r.leads)


def test_race_agent_no_window_and_all_transitions_legal():
    ops = [Operation("o1", 0.0, 1.0), Operation("o2", 2.0, 3.0)]  # disjoint
    r = RaceStateTransitionAgent().run(
        operations=ops, quota=1,
        observed_transitions=[("active", "canceled")], allowed_transitions=[("active", "canceled")])
    assert r.data["race"]["status"] == "NO_WINDOW" and r.data["illegal_transitions"] == []
    assert r.leads == []


def test_symbolic_agent_solves_bounded_counterexample():
    variables = [Variable("paid", (True, False)), Variable("access", (True, False))]
    r = SymbolicSolverAgent().run(variables=variables, implications=[],
                                  violation=(("paid", False), ("access", True)))
    assert r.data["status"] == "SOLVED" and len(r.data["counterexamples"]) == 1
    assert r.leads == ["probe condition: {'access': True, 'paid': False}"]


def test_symbolic_agent_no_counterexample_under_contract():
    variables = [Variable("paid", (True, False)), Variable("access", (True, False))]
    imp = [Implication(antecedent=(("paid", False),), consequent=("access", False))]
    r = SymbolicSolverAgent().run(variables=variables, implications=imp,
                                  violation=(("paid", False), ("access", True)))
    assert r.data["status"] == "NO_COUNTEREXAMPLE" and r.leads == []


def test_all_attack_agents_registered_scope_preserved_and_json_safe():
    ids = {a.agent_id for a in AGENTS}
    assert ids == {"A8", "A9", "A11", "A38"}
    assert all(a.activatable and a.role == "attack" for a in AGENTS)
    rep = SymbolicSolverAgent().run(variables=[Variable("x", (True, False))], implications=[],
                                    violation=(("x", True),)).to_dict()
    assert json.loads(json.dumps(rep))["agent_id"] == "A38"
