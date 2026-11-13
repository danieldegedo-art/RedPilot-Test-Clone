"""Proof agents: tests for app/testing/agents/proof.py. Stdlib only."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.testing.agents.proof import (  # noqa: E402
    AGENTS, ChainTraceAgent, ImpactQuantifierAgent, NoveltyAgent, ReportAgent, SeverityImpactAgent,
)

FINDINGS = [
    {"hypothesis_id": "PBB-OPEN", "p0_class": "paid_feature_open_to_unpaid", "verdict": "CONFIRMED_P0",
     "title": "open", "summary": "usable with no payment"},
    {"hypothesis_id": "PBB-H", "p0_class": "currency_binding", "verdict": "RULED_OUT", "title": "cur", "summary": "ok"},
]


def test_severity_agent_delegates_to_impact_assessment():
    r = SeverityImpactAgent().run(findings=FINDINGS)
    assert r.status == "ok" and r.data["severity_counts"] == {"critical": 1, "none": 1}


def test_impact_quantifier_counts_critical_and_high():
    r = ImpactQuantifierAgent().run(findings=FINDINGS)
    assert r.summary == "1 critical, 0 high"


def test_novelty_agent_flags_duplicate_of_own_history():
    fs = [{"id": "f1", "issue_class": "x", "flow": "checkout", "target": "t"},
          {"id": "f2", "issue_class": "x", "flow": "checkout", "target": "t"}]
    r = NoveltyAgent().run(findings=fs)
    assert r.data["novel"] == ["f1"] and r.data["duplicate"] == ["f2"]


def test_report_agent_headline():
    r = ReportAgent().run(findings=[{"hypothesis_id": "PBB-U", "verdict": "CONFIRMED_P0", "title": "t", "summary": "s"}])
    assert r.summary.startswith("1 confirmed")


def test_chain_trace_agent_renders():
    r = ChainTraceAgent().run(chains=[{"steps": ["PBB-U", "PBB-X"], "establishes": ["a"]}])
    assert len(r.data["traces"]) == 1 and "PBB-U -> PBB-X" in r.data["traces"][0]


def test_all_proof_agents_registered_and_json_safe():
    ids = {a.agent_id for a in AGENTS}
    assert ids == {"A13", "A14", "A15", "A28", "A29"}
    rep = SeverityImpactAgent().run(findings=FINDINGS).to_dict()
    assert json.loads(json.dumps(rep))["agent_id"] == "A13"
