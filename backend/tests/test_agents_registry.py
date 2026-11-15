"""Agent registry: tests for app/testing/agents/registry.py. Stdlib only."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.testing.agents import registry  # noqa: E402
from app.testing.integrity import kill_chain_roster as roster  # noqa: E402


def test_whole_roster_is_accounted_for():
    cov = registry.coverage()
    assert cov["unaccounted"] == [] and cov["fully_accounted"] is True
    # wrapped + capability-satisfied == the full roster
    assert set(cov["wrapped"]) | set(cov["capability_satisfied"]) == {a.agent_id for a in roster.roster()}


def test_twenty_six_wrappers_and_nine_capability_satisfied():
    cov = registry.coverage()
    assert len(cov["wrapped"]) == 26 and len(cov["capability_satisfied"]) == 9
    assert cov["roster_size"] == 35


def test_wrapped_and_capability_satisfied_are_disjoint():
    cov = registry.coverage()
    assert not (set(cov["wrapped"]) & set(cov["capability_satisfied"]))


def test_declined_agents_are_the_only_out_of_scope_wrappers():
    assert registry.coverage()["out_of_scope"] == ["A31", "A32"]
    assert {a.agent_id for a in registry.activatable()} == registry.wrapped_ids() - {"A31", "A32"}


def test_known_gaps_are_recorded_not_wrapped():
    cov = registry.coverage()
    assert cov["known_gaps"] == ["A1", "A17"]
    assert not (set(cov["known_gaps"]) & set(cov["wrapped"]))


def test_get_returns_the_right_agent_and_coverage_is_json_safe():
    assert registry.get("A20").name == "Orchestrator/Fleet Coordinator"
    assert registry.get("A99") is None
    cov = registry.coverage()
    assert json.loads(json.dumps(cov)) == cov
