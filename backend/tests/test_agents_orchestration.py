"""Learning/planning/orchestration agents: tests for app/testing/agents/orchestration.py."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.testing.agents.orchestration import (  # noqa: E402
    AGENTS, CapabilitySynthesisAgent, FeedbackLearningAgent, GraphAnalystAgent, OrchestratorAgent,
)
from app.testing.integrity.capability_synthesis import TEMPLATES  # noqa: E402
from app.testing.integrity.feedback_loop import FeedbackEvent, Signal  # noqa: E402
from app.testing.purity.taxonomy import Verdict  # noqa: E402

FLOWS = {"PBB-U": "checkout", "PBB-E": "entitlement", "PBB-F": "subscription", "PBB-H": "payment",
         "PBB-G": "entitlement", "PBB-X": "payment", "PBB-LEAK": "entitlement", "PBB-C": "checkout",
         "PBB-R": "refund", "PBB-OPEN": "entitlement"}


class _F:
    def __init__(self, hid, verdict):
        self.hypothesis_id, self.verdict, self.affected_flow = hid, verdict, FLOWS[hid]


class _Result:
    def __init__(self, verdicts):
        self._f = [_F(h, v) for h, v in verdicts.items()]

    def by_id(self):
        return {f.hypothesis_id: f for f in self._f}


# --- A19 Feedback-Learning -------------------------------------------------
def test_feedback_agent_folds_events_dedups_and_demotes():
    events = [FeedbackEvent("e1", "PBB-U", Signal.ALLOWED),
              FeedbackEvent("e1", "PBB-U", Signal.ALLOWED),   # duplicate event_id -> skipped
              FeedbackEvent("e2", "PBB-R", Signal.RULED_OUT)]
    r = FeedbackLearningAgent().run(events=events, registered={"PBB-U", "PBB-R"})
    assert r.status == "ok" and r.summary == "2 event(s) folded, 1 duplicate(s) skipped"
    assert r.data["states"]["PBB-R"]["ruled_out"] is True
    assert "ruled out (demoted, never skipped): PBB-R" in r.leads


def test_feedback_agent_refuses_unregistered_target_via_error_containment():
    # feedback never invents a target (B28); the delegate raises, the agent contains it
    r = FeedbackLearningAgent().run(events=[FeedbackEvent("e1", "PBB-U", Signal.ALLOWED)], registered=set())
    assert r.status == "error" and r.scope_ok is True


# --- A30 Capability-Synthesis (FAIL-CLOSED) --------------------------------
def test_synthesis_agent_parameterises_a_pre_registered_template():
    conclusive = set(TEMPLATES) - {"PBB-U"}   # only PBB-U left to synthesise; it has no params
    r = CapabilitySynthesisAgent().run(enabled=True, conclusive=conclusive)
    assert r.data["status"] == "SYNTHESIZED" and r.data["probe"]["template_id"] == "PBB-U"
    assert any("run pre-registered probe PBB-U" in x for x in r.leads)


def test_synthesis_agent_is_fail_closed_when_disabled():
    r = CapabilitySynthesisAgent().run(enabled=False)
    assert r.data["status"] == "FAIL_CLOSED" and r.data["probe"] is None and r.leads == []


def test_synthesis_agent_refuses_param_outside_declared_bounds():
    conclusive = set(TEMPLATES) - {"PBB-F"}   # PBB-F requires a declared 'plan'
    r = CapabilitySynthesisAgent().run(enabled=True, conclusive=conclusive)  # no declared_params
    assert r.data["status"] == "REFUSED_PARAM" and r.leads == []


# --- A39 Graph-Analyst -----------------------------------------------------
def test_graph_analyst_ranks_proven_flawed_chokepoint_first():
    verdicts = {h: Verdict.RULED_OUT for h in FLOWS}
    verdicts["PBB-U"] = Verdict.CONFIRMED_P0
    r = GraphAnalystAgent().run(result=_Result(verdicts))
    assert r.summary == "highest-leverage fix: payment_event_verification"
    assert "highest-leverage remediation: fix payment_event_verification (proven flawed)" in r.leads


# --- A20 Orchestrator (prioritization + fleet + roster) --------------------
def test_orchestrator_prioritises_then_schedules_dependency_waves():
    r = OrchestratorAgent().run(hypotheses=["PBB-U", "PBB-C", "PBB-G"], weights={"PBB-C": 200.0}, max_workers=4)
    assert r.status == "ok"
    assert r.data["priority_order"][0] == "PBB-C"              # weight boosted it above PBB-U
    flat = {h for wave in r.data["plan"]["waves"] for h in wave}
    assert flat == {"PBB-U", "PBB-C", "PBB-G"}                 # every hypothesis scheduled, none dropped
    assert r.data["plan"]["status"] == "SCHEDULED"


def test_orchestrator_reports_fleet_composition_with_declined_agents():
    r = OrchestratorAgent().run(hypotheses=["PBB-U"])
    fleet = r.data["fleet"]
    assert fleet["out_of_scope"] == ["A31", "A32"]             # owner-declined domain packs
    assert fleet["activatable"] == fleet["in_roster"] - 2
    assert fleet["declared_fleet_size"] == 37


def test_orchestrator_is_fail_closed_when_disabled():
    r = OrchestratorAgent().run(hypotheses=["PBB-U", "PBB-C"], enabled=False)
    assert r.data["plan"]["status"] == "FAIL_CLOSED" and r.data["plan"]["waves"] == []


def test_all_orchestration_agents_registered_and_json_safe():
    assert {a.agent_id for a in AGENTS} == {"A19", "A30", "A39", "A20"}
    assert all(a.activatable for a in AGENTS)
    rep = OrchestratorAgent().run(hypotheses=["PBB-U"]).to_dict()
    assert json.loads(json.dumps(rep))["agent_id"] == "A20"
