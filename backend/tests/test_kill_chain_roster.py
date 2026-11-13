"""B37: tests for app/testing/integrity/kill_chain_roster.py. Stdlib only."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.testing.integrity.kill_chain_roster import (  # noqa: E402
    FLEET_SIZE, KNOWN_GAPS, ROSTER, AgentRole, ScopeStatus, by_role, domain_packs,
    get, is_activatable, out_of_scope, owner_of, roster_payload,
)


def test_fleet_size_is_37_and_gaps_are_recorded_not_invented():
    assert FLEET_SIZE == 37
    assert len(ROSTER) == 35 and KNOWN_GAPS == ("A1", "A17")


def test_owner_declined_agents_are_never_activatable():
    assert is_activatable("A31") is False and is_activatable("A32") is False
    assert {a.agent_id for a in out_of_scope()} == {"A31", "A32"}
    assert all(a.scope_status is ScopeStatus.OUT_OF_SCOPE and "out of scope" in a.scope_note for a in out_of_scope())


def test_narrowed_agent_is_activatable_but_carries_its_boundary():
    a36 = get("A36")
    assert a36.scope_status is ScopeStatus.NARROWED and a36.activatable is True
    assert "NOT broad" in a36.scope_note


def test_unknown_agent_is_not_activatable():
    assert is_activatable("A999") is False and get("A999") is None


def test_capability_ownership_lookup():
    assert owner_of("B32").agent_id == "A25"
    assert owner_of("B41").agent_id == "A38" and owner_of("B33").agent_id == "A20"
    assert owner_of("B-nonexistent") is None


def test_roles_and_domain_packs():
    attackers = by_role(AgentRole.ATTACK)
    assert attackers and all(a.role is AgentRole.ATTACK for a in attackers)
    assert {a.agent_id for a in domain_packs()} == {"A31", "A32", "A33", "A34", "A35", "A36"}
    assert all(a.domain_pack for a in domain_packs())


def test_roster_payload_json_safe_and_ids_unique():
    ids = [a.agent_id for a in ROSTER]
    assert len(ids) == len(set(ids))
    payload = roster_payload()
    assert payload["fleet_size"] == 37 and payload["out_of_scope"] == ["A31", "A32"]
    assert json.loads(json.dumps(payload)) == payload
