"""Recon agents: tests for app/testing/agents/recon.py. Stdlib only."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.testing.agents.recon import (  # noqa: E402
    AGENTS, AuthWorkflowMapperAgent, CouponPromoSpecialistAgent, PaymentProviderSpecialistAgent,
    SubscriptionLifecycleSpecialistAgent, SurfaceDiscoveryAgent, ThreatIntelAgent,
    WebhookFraudSpecialistAgent,
)


def test_surface_discovery_delegates_to_fingerprint():
    r = SurfaceDiscoveryAgent().run(observed_signals={"header:stripe-version", "field:client_secret"})
    assert r.status == "ok" and r.scope_ok and r.data["best"] == "stripe"
    assert r.leads == ["payment stack looks like stripe"]


def test_surface_discovery_unknown_signals_no_lead():
    r = SurfaceDiscoveryAgent().run(observed_signals={"field:nothing_known"})
    assert r.status == "ok" and r.data["best"] is None and r.leads == []


def test_auth_workflow_mapper_partitions_flows():
    flows = [{"name": "checkout", "authenticated": True}, {"name": "pricing", "authenticated": False},
             {"name": "account", "authenticated": True}]
    r = AuthWorkflowMapperAgent().run(flows=flows)
    assert r.data["authenticated"] == ["account", "checkout"] and r.data["anonymous"] == ["pricing"]
    assert r.summary == "2 authenticated / 1 anonymous workflow(s)"


def test_specialists_delegate_to_focus():
    for cls, aid, klass in (
        (PaymentProviderSpecialistAgent, "A21", "unconfirmed_payment_grants_access"),
        (CouponPromoSpecialistAgent, "A23", "plan_or_price_binding"),
        (SubscriptionLifecycleSpecialistAgent, "A24", "retention_after_refund"),
    ):
        r = cls().run()
        assert r.status == "ok" and r.agent_id == aid
        assert klass in r.data["oracle_classes"]


def test_webhook_specialist_focus_is_return_flow_not_forgery():
    r = WebhookFraudSpecialistAgent().run()
    # forgery is blocked; the focus stays on the customer-observable return flow (PBB-U)
    assert r.data["oracle_classes"] == ["unconfirmed_payment_grants_access"]
    assert "never a finding" in r.data["note"]


def test_threat_intel_agent_delegates_to_ingest():
    r = ThreatIntelAgent().run(advisories=["coupon_abuse", "totally_unknown"])
    assert r.status == "ok" and r.data["ingested"] == 1 and r.data["unmapped"] == ["totally_unknown"]
    assert r.data["prior"]["plan_or_price_binding"] > r.data["prior"]["currency_binding"]


def test_all_recon_agents_registered_and_json_safe():
    ids = {a.agent_id for a in AGENTS}
    assert ids == {"A3", "A4", "A21", "A22", "A23", "A24", "A37"}
    assert all(a.activatable and a.role == "recon" for a in AGENTS)  # all in-scope recon agents
    rep = SurfaceDiscoveryAgent().run(observed_signals={"domain:adyen.com"}).to_dict()
    assert json.loads(json.dumps(rep))["agent_id"] == "A3" and rep["role"] == "recon"
