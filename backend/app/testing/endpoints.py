"""Maps logical payment operations to concrete REST routes on the system
under test.

Every payment platform names its routes differently. Rather than hardcoding
one company's API shape, test modules ask the EndpointMap for a *logical*
operation ("create_payment", "create_refund", ...) and get back the
method/path to call. Override any entry to match your API:

    endpoints = EndpointMap(overrides={
        "create_payment": EndpointSpec("POST", "/v2/charges"),
    })

Path templates may contain `{placeholder}` segments (e.g. "{payment_id}"),
filled in via `str.format(...)` at call time by the test module.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from app.core.control_port import get_control_adapter


@dataclass(frozen=True)
class EndpointSpec:
    method: str
    path: str


def _default_endpoints() -> dict[str, EndpointSpec]:
    return {
        "list_products": EndpointSpec("GET", "/api/v1/products"),
        "get_product": EndpointSpec("GET", "/api/v1/products/{product_id}"),
        "create_cart": EndpointSpec("POST", "/api/v1/cart"),
        "create_checkout_session": EndpointSpec("POST", "/api/v1/checkout"),
        "create_payment": EndpointSpec("POST", "/api/v1/payments"),
        "get_payment": EndpointSpec("GET", "/api/v1/payments/{payment_id}"),
        "create_subscription": EndpointSpec("POST", "/api/v1/subscriptions"),
        "get_subscription": EndpointSpec("GET", "/api/v1/subscriptions/{subscription_id}"),
        "cancel_subscription": EndpointSpec("POST", "/api/v1/subscriptions/{subscription_id}/cancel"),
        "create_refund": EndpointSpec("POST", "/api/v1/refunds"),
        "get_refund": EndpointSpec("GET", "/api/v1/refunds/{refund_id}"),
        "webhook_test": EndpointSpec("POST", "/api/v1/webhooks/test"),
        "stripe_webhook": EndpointSpec("POST", "/api/v1/webhooks/stripe"),
        "stripe_success_redirect": EndpointSpec("GET", "/subscription/success"),
        "health": EndpointSpec("GET", "/health"),
    }


# Provider-facing (server-to-server) operations. A customer-level tester has no normal-product-use way to learn such a route, so an
# operator-DECLARED path is a private endpoint list (grey-box) and is NEVER applied. Only the built-in conventional placeholder is used
# (an external guess that carries no target information); a 404 there simply means "not testable here". The rule (which operations are
# provider-facing) is an Enterprise Control (enterprise_controls/allowlists.py) asked through the Control Adapter.


@dataclass
class EndpointMap:
    overrides: dict[str, EndpointSpec] = field(default_factory=dict)
    _defaults: dict[str, EndpointSpec] = field(default_factory=_default_endpoints, repr=False)

    def get(self, operation: str) -> EndpointSpec:
        if get_control_adapter().is_provider_facing_operation(operation):
            return self._defaults[operation]  # pure black-box: operator-declared provider-facing routes are ignored
        return self.overrides.get(operation) or self._defaults[operation]

    @property
    def ignored_provider_overrides(self) -> list[str]:
        """Operator-declared provider-facing overrides that were NOT applied (reported, never silently dropped)."""
        return sorted(op for op in self.overrides if get_control_adapter().is_provider_facing_operation(op))

    @staticmethod
    def known_operations() -> list[str]:
        return sorted(_default_endpoints().keys())

    @property
    def list_products(self) -> EndpointSpec:
        return self.get("list_products")

    @property
    def get_product(self) -> EndpointSpec:
        return self.get("get_product")

    @property
    def create_cart(self) -> EndpointSpec:
        return self.get("create_cart")

    @property
    def create_checkout_session(self) -> EndpointSpec:
        return self.get("create_checkout_session")

    @property
    def create_payment(self) -> EndpointSpec:
        return self.get("create_payment")

    @property
    def get_payment(self) -> EndpointSpec:
        return self.get("get_payment")

    @property
    def create_subscription(self) -> EndpointSpec:
        return self.get("create_subscription")

    @property
    def get_subscription(self) -> EndpointSpec:
        return self.get("get_subscription")

    @property
    def cancel_subscription(self) -> EndpointSpec:
        return self.get("cancel_subscription")

    @property
    def create_refund(self) -> EndpointSpec:
        return self.get("create_refund")

    @property
    def get_refund(self) -> EndpointSpec:
        return self.get("get_refund")

    @property
    def webhook_test(self) -> EndpointSpec:
        return self.get("webhook_test")

    @property
    def stripe_webhook(self) -> EndpointSpec:
        """The server-to-server route Stripe calls directly. Recon cannot
        discover this: it's never called from the browser, so it never
        appears in client-side JS or observed network traffic. PURE BLACK-BOX:
        only the conventional placeholder below is ever probed; an operator-
        declared path would be a private endpoint list (grey-box) and is
        ignored (see PROVIDER_FACING_OPERATIONS)."""
        return self.get("stripe_webhook")

    @property
    def stripe_success_redirect(self) -> EndpointSpec:
        """The page Stripe redirects the browser back to after checkout
        (?session_id=cs_...). Unlike stripe_webhook, this one CAN
        sometimes be discovered -- Recon looks for it in client-side JS and
        rendered HTML links -- but StripeFlowTestModule also falls back to
        probing a list of standard path patterns if nothing was found. This
        placeholder is the last-resort default if none of that works."""
        return self.get("stripe_success_redirect")

    @property
    def health(self) -> EndpointSpec:
        return self.get("health")
