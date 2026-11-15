"""Pydantic schema for the dashboard's Settings screen."""
from __future__ import annotations

from app.testing.module_defaults import DEFAULT_ENABLED_MODULES

from pydantic import BaseModel, Field

_DEFAULT_ENABLED_MODULES = list(DEFAULT_ENABLED_MODULES)


class EndpointOverrideSchema(BaseModel):
    method: str
    path: str


class ManualWebhookProviderSchema(BaseModel):
    """One additional (non-Stripe) webhook provider to run the
    unsigned/invalid-signature rejection pattern against -- see
    modules/additional_webhook_security.py."""

    provider_id: str
    display_name: str
    method: str = "POST"
    path: str
    signature_header: str
    # Pure Black-Box provenance of the route: how an authorised EXTERNAL tester learned it
    # (authorized_browser_trace | authorized_customer_api_trace | public_documentation | product_ui | public_api_reference).
    # Without it the route is a private endpoint list (grey-box) and the provider is reported BLOCKED, not tested.
    observed_via: str | None = None


class SettingsSchema(BaseModel):
    timeout_seconds: float = 30.0
    proxy_url: str | None = None
    custom_headers: dict[str, str] = Field(default_factory=dict)
    user_agent: str = "PaymentQA-Suite/1.0"
    enabled_modules: list[str] = Field(default_factory=lambda: list(_DEFAULT_ENABLED_MODULES))
    discovery_layer_enabled: bool = True
    # See RunSettings' matching field (context.py) for what this does.
    prioritize_experiments: bool = True
    endpoint_overrides: dict[str, EndpointOverrideSchema] = Field(default_factory=dict)
    session_cookies: dict[str, str] = Field(default_factory=dict)
    # Unlike endpoint_overrides above (which only overrides the ~15 named payment
    # OPERATIONS used by Functional/Stripe Flow/Integration), these are
    # arbitrary routes merged directly into Recon's FunctionMap -- the
    # thing ROLE-002/ROLE-003/Discovery actually iterate over. This is how
    # a DISCOVERY-CORRELATION-* finding's "add this route" recommendation
    # actually takes effect: paste the method/path here, save, re-run.
    manual_routes: list[EndpointOverrideSchema] = Field(default_factory=list)
    # Resilience + concurrency knobs (fault-isolation and efficiency passes
    # -- see http_client.py/resilience.py and registry.py's
    # PARALLEL_SAFE_MODULES). Defaults match RunSettings' own defaults, so
    # leaving the Settings screen untouched reproduces exactly what a fresh
    # install already does without it.
    http_max_retries: int = 2
    http_retry_base_delay_seconds: float = 0.5
    http_circuit_breaker_threshold: int = 5
    http_circuit_breaker_cooldown_seconds: float = 20.0
    module_concurrency: int = 4
    # New payment providers this project has no Recon fingerprint for --
    # see ManualWebhookProviderSchema / modules/additional_webhook_security.py.
    additional_webhook_providers: list[ManualWebhookProviderSchema] = Field(default_factory=list)
