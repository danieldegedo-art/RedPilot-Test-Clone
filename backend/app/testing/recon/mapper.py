"""Best-effort heuristic mapping of discovered (method, path) calls onto the
QA suite's logical operations (create_payment, create_subscription, ...).

Only maps calls with a reasonably unambiguous keyword signal in the path;
anything else is reported by ReconModule but left for the QA engineer to
map manually. Every applied mapping is emitted as its own auditable
TestResult (see modules/recon.py) -- this is not a silent black box.
"""
from __future__ import annotations

import re
from datetime import datetime

from app.testing.endpoints import EndpointSpec
from app.testing.pesm import Feature, PESMStore
from app.testing.recon.browser_crawler import DiscoveredCall

# (logical_operation, http_method, path_pattern)
_RULES: list[tuple[str, str, re.Pattern[str]]] = [
    ("create_payment", "POST", re.compile(r"/(payments?|charges?)/?$", re.IGNORECASE)),
    ("get_payment", "GET", re.compile(r"/(payments?|charges?)/[^/]+/?$", re.IGNORECASE)),
    ("create_subscription", "POST", re.compile(r"/subscriptions?/?$", re.IGNORECASE)),
    ("get_subscription", "GET", re.compile(r"/subscriptions?/[^/]+/?$", re.IGNORECASE)),
    ("cancel_subscription", "POST", re.compile(r"/subscriptions?/[^/]+/cancel/?$", re.IGNORECASE)),
    ("create_refund", "POST", re.compile(r"/refunds?/?$", re.IGNORECASE)),
    ("get_refund", "GET", re.compile(r"/refunds?/[^/]+/?$", re.IGNORECASE)),
    ("create_cart", "POST", re.compile(r"/cart/?$", re.IGNORECASE)),
    ("create_checkout_session", "POST", re.compile(r"/checkout/?$", re.IGNORECASE)),
    ("list_products", "GET", re.compile(r"/products?/?$", re.IGNORECASE)),
    ("get_product", "GET", re.compile(r"/products?/[^/]+/?$", re.IGNORECASE)),
    ("webhook_test", "POST", re.compile(r"/webhooks?/", re.IGNORECASE)),
]


def map_to_endpoint_overrides(calls: list[DiscoveredCall]) -> dict[str, tuple[EndpointSpec, DiscoveredCall]]:
    """Returns {logical_operation: (EndpointSpec, source_call)} for every
    call that matched a rule unambiguously. Network-observed calls are
    preferred over static-JS-only findings when both match the same
    operation, since live traffic is the more trustworthy signal."""
    matches: dict[str, tuple[EndpointSpec, DiscoveredCall]] = {}
    ordered_calls = sorted(calls, key=lambda c: 0 if c.source == "network" else 1)

    for call in ordered_calls:
        for operation, method, pattern in _RULES:
            if operation in matches:
                continue
            if call.method != method:
                continue
            if pattern.search(call.path):
                matches[operation] = (EndpointSpec(call.method, call.path), call)
                break

    return matches


async def register_discovered_features(
    mapped: dict[str, tuple[EndpointSpec, DiscoveredCall]],
    registry: PESMStore,
    *,
    discovered_at: datetime,
) -> None:
    """ZR-002: every operation map_to_endpoint_overrides successfully mapped
    becomes a registered PESM Feature -- the concrete link between Section
    3.2 (surface discovery) and ZR-025 condition 1 ("target is a defined
    paid/protected feature"). Idempotent: re-running recon against the same
    target re-confirms the same features (register_feature upserts by
    feature_id, see pesm.InMemoryPESMStore), it doesn't duplicate them.

    feature_id is the operation string itself (``create_payment``,
    ``cancel_subscription``, ...) -- the exact vocabulary
    map_to_endpoint_overrides already returns and every caller of this
    module's EndpointMap overrides already keys on; introducing a second,
    translated id here would just be something else that can drift out of
    sync with it.
    """
    for operation, (spec, source_call) in mapped.items():
        await registry.register_feature(
            Feature(
                feature_id=operation,
                name=operation.replace("_", " ").title(),
                discovered_via=f"A3 recon ({source_call.source}): {spec.method} {spec.path}",
                registered_at=discovered_at,
            )
        )
