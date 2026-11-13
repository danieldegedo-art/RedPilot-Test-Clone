"""Agent framework: tests for app/testing/agents/base.py. Stdlib only."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.testing.agents.base import Agent, AgentReport  # noqa: E402


class _OkAgent(Agent):
    agent_id, name, role = "A13", "Severity and Impact-Assessment", "proof"   # in_scope in the roster

    def _run(self, **inputs):
        return "assessed", {"n": inputs.get("n", 0)}, ["lead-1"]


class _DeclinedAgent(Agent):
    agent_id, name, role = "A31", "AD Operator", "recon"   # out_of_scope in the roster

    def _run(self, **inputs):
        return "should never run", {}, []


class _FaultyAgent(Agent):
    agent_id, name, role = "A13", "Faulty", "proof"

    def _run(self, **inputs):
        raise RuntimeError("boom")


def test_in_scope_agent_runs_and_reports():
    r = _OkAgent().run(n=3)
    assert r.status == "ok" and r.scope_ok and r.summary == "assessed"
    assert r.data == {"n": 3} and r.leads == ["lead-1"]


def test_out_of_scope_agent_refuses_without_delegating():
    r = _DeclinedAgent().run()
    assert r.status == "refused_scope" and r.scope_ok is False
    assert "out of scope" in r.summary and r.data == {}      # delegate never called


def test_delegate_fault_is_contained_not_crashing():
    r = _FaultyAgent().run()
    assert r.status == "error" and r.scope_ok is True and "boom" in r.summary


def test_scope_status_is_read_from_the_roster():
    assert _OkAgent().scope_status == "in_scope"
    assert _DeclinedAgent().scope_status == "out_of_scope" and _DeclinedAgent().activatable is False


def test_report_is_json_safe():
    assert json.loads(json.dumps(_OkAgent().run(n=1).to_dict()))["status"] == "ok"
