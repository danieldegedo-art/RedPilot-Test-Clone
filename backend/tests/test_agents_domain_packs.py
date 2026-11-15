"""Domain-pack agents: tests for app/testing/agents/domain_packs.py. Stdlib only."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.testing.agents.domain_packs import (  # noqa: E402
    AGENTS, ADOperatorAgent, CloudHunterAgent, ContractAuditorAgent, MobileOperatorAgent,
    OSINTOperatorAgent, ReverserAgent,
)


def test_declined_packs_refuse_at_the_scope_gate_without_emitting_focus():
    for cls in (ADOperatorAgent, CloudHunterAgent):
        r = cls().run()
        assert r.status == "refused_scope" and r.scope_ok is False
        assert r.data == {}   # the capability is never touched for an out-of-scope pack


def test_contract_auditor_emits_entitlement_focus_and_names_exclusions():
    r = ContractAuditorAgent().run()
    assert r.status == "ok" and "unconfirmed_payment_grants_access" in r.data["oracle_classes"]
    assert any("exploitation" in x for x in r.data["excluded"])
    assert "excludes" in r.summary


def test_reverser_focus_is_client_trust_and_excludes_offensive_tooling():
    r = ReverserAgent().run()
    assert set(r.data["oracle_classes"]) == {"ui_vs_server_divergence", "paid_feature_open_to_unpaid"}
    assert any("BloodHound" in x for x in r.data["excluded"])


def test_mobile_operator_in_scope_and_excludes_drm_bypass():
    r = MobileOperatorAgent().run()
    assert r.status == "ok" and any("DRM bypass" in x for x in r.data["excluded"])


def test_osint_operator_narrowed_to_scope_confirmation_no_oracle():
    r = OSINTOperatorAgent().run()
    assert r.status == "ok" and r.data["oracle_classes"] == []
    assert "authorization/scope confirmation only" in r.summary


def test_all_six_packs_registered_scope_preserved_and_json_safe():
    assert {a.agent_id for a in AGENTS} == {"A31", "A32", "A33", "A34", "A35", "A36"}
    # the two declined packs are not activatable; the other four are
    not_activatable = {a.agent_id for a in AGENTS if not a.activatable}
    assert not_activatable == {"A31", "A32"}
    rep = ContractAuditorAgent().run().to_dict()
    assert json.loads(json.dumps(rep))["agent_id"] == "A33"
