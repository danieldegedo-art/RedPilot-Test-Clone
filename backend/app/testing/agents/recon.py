"""Recon-layer agents (A3, A4, A21-A24, A37) over the existing recon capabilities.

  A3  Application-Surface Discovery -> payment_fingerprint.fingerprint (public-signal
                                       stack/provider discovery)
  A4  Authenticated Workflow Mapper -> bounded partition of declared flows into
                                       authenticated vs anonymous
  A21-A24 payment specialists       -> specialists.focus (recon focus per sub-domain)
  A37 Threat-Intel Ingestion        -> threat_intel.ingest (advisory -> oracle prior)

All are recon leads for the planner, never findings. Stdlib only; pure.
"""
from __future__ import annotations

from typing import Any

from app.testing.agents.base import Agent
from app.testing.integrity import payment_fingerprint, specialists, threat_intel


class SurfaceDiscoveryAgent(Agent):
    agent_id, name, role = "A3", "Application-Surface Discovery", "recon"

    def _run(self, *, observed_signals: set[str]) -> tuple[str, dict[str, Any], list[str]]:
        res = payment_fingerprint.fingerprint(set(observed_signals))
        lead = [] if res.best is None else [f"payment stack looks like {res.best}"]
        return f"surface fingerprint: {res.best or 'unknown'}", res.to_dict(), lead


class AuthWorkflowMapperAgent(Agent):
    agent_id, name, role = "A4", "Authenticated Workflow Mapper", "recon"

    def _run(self, *, flows: list[dict[str, Any]]) -> tuple[str, dict[str, Any], list[str]]:
        authenticated = sorted(f["name"] for f in flows if f.get("authenticated"))
        anonymous = sorted(f["name"] for f in flows if not f.get("authenticated"))
        return f"{len(authenticated)} authenticated / {len(anonymous)} anonymous workflow(s)", \
            {"authenticated": authenticated, "anonymous": anonymous}, []


class _SpecialistAgent(Agent):
    role = "recon"

    def _run(self, **inputs: Any) -> tuple[str, dict[str, Any], list[str]]:
        focus = specialists.focus(self.agent_id)
        return f"{self.name}: focus {focus['oracle_classes']}", focus, []


class PaymentProviderSpecialistAgent(_SpecialistAgent):
    agent_id, name = "A21", "Payment-Provider Specialist"


class WebhookFraudSpecialistAgent(_SpecialistAgent):
    agent_id, name = "A22", "Webhook-Fraud Specialist"


class CouponPromoSpecialistAgent(_SpecialistAgent):
    agent_id, name = "A23", "Coupon/Promo-Abuse Specialist"


class SubscriptionLifecycleSpecialistAgent(_SpecialistAgent):
    agent_id, name = "A24", "Subscription-Lifecycle Specialist"


class ThreatIntelAgent(Agent):
    agent_id, name, role = "A37", "Threat-Intel Ingestion Agent", "recon"

    def _run(self, *, advisories: list[str]) -> tuple[str, dict[str, Any], list[str]]:
        res = threat_intel.ingest(advisories)
        return f"ingested {res.ingested} advisory credit(s), {len(res.unmapped)} unmapped", res.to_dict(), []


AGENTS: tuple[Agent, ...] = (
    SurfaceDiscoveryAgent(), AuthWorkflowMapperAgent(),
    PaymentProviderSpecialistAgent(), WebhookFraudSpecialistAgent(),
    CouponPromoSpecialistAgent(), SubscriptionLifecycleSpecialistAgent(),
    ThreatIntelAgent(),
)
