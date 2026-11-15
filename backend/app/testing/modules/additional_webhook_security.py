"""Additional Webhook Security Module.

Runs the same unsigned/invalid-signature webhook rejection pattern
STRIPE-002/003 runs for Stripe (see checkout_provider_testing.py) against
every provider declared under Settings -> additional_webhook_providers.
This is the concrete "add a new payment method without writing a new test
module" proof: a target that also integrates a second processor (common
in real systems -- e.g. Stripe for cards plus a regional or backup
processor) gets the same two security-critical checks by declaring three
things (path, method, signature header name), not by copying
stripe_flow.py and adapting 250 lines of it.

Recon has no fingerprint for a provider it doesn't know about, so unlike
Stripe (auto-detected) these are always manual -- there is deliberately no
attempt here to guess a second provider's JS/cookie signature. If nothing
is declared, this emits one INFO result and returns, same as
stripe_flow.py's own skip case.

Only the webhook-signature pair is generalized here, not
checkout-session-creation or the redirect-channel checks (STRIPE-001,
004-006): those need provider-specific response-shape knowledge (what a
REAL session response/redirect looks like) this project has no verified
reference for beyond Stripe's own documented shapes. Generalizing them
from a guess would risk plausible-looking but wrong pass/fail verdicts --
worse than not covering them at all for a tool whose output feeds
compliance evidence. See the hardening report for this scope boundary.
"""
from __future__ import annotations

from datetime import datetime, timezone

from app.testing.base import BaseTestModule
from app.testing.checkout_provider_testing import run_invalid_signature_case, run_unsigned_webhook_case
from app.testing.enums import ResultStatus, TestCategory
from app.testing.models import TestResult
from app.core.control_port import get_control_adapter


class AdditionalWebhookSecurityModule(BaseTestModule):
    module_id = "additional_webhook_security"
    display_name = "Additional Webhook Security Module"
    category = TestCategory.STRIPE_FLOW  # same functional family as STRIPE-002/003 -- webhook-channel signature security

    async def run(self) -> None:
        providers = self.context.settings.additional_webhook_providers
        if not providers:
            await self._emit_skipped()
            return

        for provider in providers:
            config = provider.to_provider_config()
            prefix = provider.provider_id.upper()
            if not get_control_adapter().is_allowed_observed_via(getattr(provider, "observed_via", None)):
                await self._emit_blocked(provider)  # Pure Black-Box: a route without external provenance is a private endpoint list
                continue
            await run_unsigned_webhook_case(
                self, provider=config, method=provider.method, path=provider.path, test_case_id=f"WEBHOOK-{prefix}-001"
            )
            await run_invalid_signature_case(
                self, provider=config, method=provider.method, path=provider.path, test_case_id=f"WEBHOOK-{prefix}-002"
            )

    async def _emit_blocked(self, provider) -> None:  # type: ignore[no-untyped-def]
        now = datetime.now(timezone.utc)
        await self.emit(
            TestResult(
                test_case_id=f"WEBHOOK-{provider.provider_id.upper()}-BLOCKED",
                category=self.category,
                name=f"Webhook security tests BLOCKED for provider {provider.display_name}",
                description="A provider-facing webhook route declared by the operator has no external provenance attestation.",
                input_parameters={"provider_id": provider.provider_id, "reason": "provider_route_no_external_provenance"},
                expected="Provider-facing routes are only probed when an authorised external tester could learn them (browser trace, customer API trace, public documentation).",
                actual="BLOCKED: no request was sent. An operator-declared webhook path is a private endpoint list (grey-box) and is not used in pure black-box mode.",
                status=ResultStatus.WARNING,
                recommendation=(
                    "Set observed_via on the provider to one of: authorized_browser_trace, authorized_customer_api_trace, public_documentation, "
                    "product_ui, public_api_reference -- ONLY if the route is genuinely discoverable that way. Otherwise this class stays UNKNOWN (not safe)."
                ),
                started_at=now,
                finished_at=now,
                duration_ms=0.0,
            )
        )

    async def _emit_skipped(self) -> None:
        now = datetime.now(timezone.utc)
        await self.emit(
            TestResult(
                test_case_id="WEBHOOK-ADDITIONAL-000",
                category=self.category,
                name="Additional webhook security tests skipped",
                description="No additional (non-Stripe) webhook providers are declared for this Test Environment.",
                input_parameters={},
                expected="N/A - informational.",
                actual="Skipped: Settings -> additional_webhook_providers is empty.",
                status=ResultStatus.INFO,
                recommendation=(
                    "If this target integrates a second payment processor's webhooks, declare it under Settings -- "
                    "provider id, display name, HTTP method, path, and signature header name -- to get the same "
                    "unsigned/invalid-signature rejection checks STRIPE-002/003 already run for Stripe."
                ),
                started_at=now,
                finished_at=now,
                duration_ms=0.0,
            )
        )
