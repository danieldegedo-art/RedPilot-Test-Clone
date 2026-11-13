"""Categorizes every route Recon finds (network-observed, static-JS, or
actively path-probed) into one of three functional buckets, for AICPA SOC2
CC6.1's "Completeness of Service Coverage" requirement: the evidence that
ALL of an application's functions were considered for access-control review,
not only the obviously payment-shaped ones.

    ACCOUNT_MANAGEMENT    - profile, settings, subscription, billing: routes
                            that read or write the caller's OWN account state.
    SERVICE_FUNCTION      - the application's main functions (payments,
                            checkout, cart, products, refunds, webhooks, ...).
                            This is the default bucket: anything that doesn't
                            match a more specific pattern below.
    SYSTEM_ADMINISTRATION - admin/config/role/permission surfaces: routes
                            that configure the system itself rather than one
                            user's own data.

This is intentionally a second, broader classification than
recon/mapper.py's `_RULES` -- that module maps a handful of routes onto
specific, canonical payment OPERATIONS (create_payment, cancel_subscription,
...) so the Functional/Negative/etc. modules know which exact route to call.
This module instead labels EVERY discovered route for coverage/audit
purposes, whether or not it matches any canonical operation. The two run
independently and don't need to agree route-for-route.

Ordering matters: SYSTEM_PATTERNS are checked before ACCOUNT_PATTERNS, so a
path like "/api/account/role" (administering ANOTHER account's role) is
classified as system administration, not account management, even though it
contains "account". Matching is substring/regex-based on the path only, the
same best-effort spirit as recon/mapper.py -- treat a category as a strong
hint to route the right test at a route, not a certified classification.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum


class FunctionCategory(str, Enum):
    ACCOUNT_MANAGEMENT = "account_management"
    SERVICE_FUNCTION = "service_function"
    SYSTEM_ADMINISTRATION = "system_administration"


# (keyword, pattern) -- keyword is kept alongside the pattern purely so a
# match can cite *which* signal fired, for the audit trail (see MappedRoute
# .matched_keyword below and RECON-004's evidence).
_SYSTEM_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("account/role", re.compile(r"/account/roles?(?:/|$)", re.IGNORECASE)),
    ("admin", re.compile(r"/admin(?:istrator)?s?(?:/|$)", re.IGNORECASE)),
    ("role", re.compile(r"/roles?(?:/|$)", re.IGNORECASE)),
    ("permission", re.compile(r"/permissions?(?:/|$)", re.IGNORECASE)),
    ("system", re.compile(r"/system(?:/|$)", re.IGNORECASE)),
    ("config", re.compile(r"/config(?:uration)?s?(?:/|$)", re.IGNORECASE)),
    ("user/manage", re.compile(r"/users?/manage(?:/|$)", re.IGNORECASE)),
    ("manage", re.compile(r"/manage(?:ment)?(?:/|$)", re.IGNORECASE)),
    ("internal", re.compile(r"/internal(?:/|$)", re.IGNORECASE)),
    ("superuser", re.compile(r"/super-?users?(?:/|$)", re.IGNORECASE)),
    ("moderator", re.compile(r"/moderat(?:e|ors?)(?:/|$)", re.IGNORECASE)),
    ("audit-log", re.compile(r"/audit(?:[-_]?logs?)?(?:/|$)", re.IGNORECASE)),
    ("feature-flag", re.compile(r"/feature[-_]?flags?(?:/|$)", re.IGNORECASE)),
    ("backoffice", re.compile(r"/back[-_]?office(?:/|$)", re.IGNORECASE)),
]

_ACCOUNT_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("profile", re.compile(r"/profile(?:/|$)", re.IGNORECASE)),
    ("account", re.compile(r"/account(?:/|$)", re.IGNORECASE)),
    ("settings", re.compile(r"/settings?(?:/|$)", re.IGNORECASE)),
    ("subscription", re.compile(r"/subscriptions?(?:/|$)", re.IGNORECASE)),
    ("billing", re.compile(r"/billing(?:/|$)", re.IGNORECASE)),
    ("preferences", re.compile(r"/preferences?(?:/|$)", re.IGNORECASE)),
    ("membership", re.compile(r"/membership(?:/|$)", re.IGNORECASE)),
    ("me", re.compile(r"/me(?:/|$)", re.IGNORECASE)),
    ("my-", re.compile(r"/my[-_]", re.IGNORECASE)),
]


def categorize_route(path: str) -> tuple[FunctionCategory, str | None]:
    """Returns (category, matched_keyword). matched_keyword is None for the
    SERVICE_FUNCTION default bucket, since nothing specific fired."""
    for keyword, pattern in _SYSTEM_PATTERNS:
        if pattern.search(path):
            return FunctionCategory.SYSTEM_ADMINISTRATION, keyword
    for keyword, pattern in _ACCOUNT_PATTERNS:
        if pattern.search(path):
            return FunctionCategory.ACCOUNT_MANAGEMENT, keyword
    return FunctionCategory.SERVICE_FUNCTION, None


@dataclass
class MappedRoute:
    method: str
    path: str
    category: FunctionCategory
    source: str  # "network" | "static-js" | "path-probed"
    confidence: str  # "high" | "medium" | "low"
    matched_keyword: str | None = None
    param_names: frozenset[str] = field(default_factory=frozenset)
    status_code_at_discovery: int | None = None

    @property
    def key(self) -> tuple[str, str]:
        return (self.method, self.path)


@dataclass
class FunctionMap:
    """The CC6.1 "Completeness of Service Coverage" audit artifact: every
    route Recon found this pass, categorized. Stored in
    `context.shared_state["function_map"]` so RoleBasedAccessModule (and any
    future module) can consume it without re-running discovery."""

    routes: list[MappedRoute] = field(default_factory=list)

    def add(self, route: MappedRoute) -> None:
        # A (method, path) pair may be observed from more than one source
        # (e.g. both live network traffic and static JS) -- keep the
        # higher-confidence entry rather than listing duplicates.
        existing = next((r for r in self.routes if r.key == route.key), None)
        if existing is None:
            self.routes.append(route)
            return
        if _confidence_rank(route.confidence) > _confidence_rank(existing.confidence):
            self.routes.remove(existing)
            self.routes.append(route)

    def by_category(self, category: FunctionCategory) -> list[MappedRoute]:
        return [r for r in self.routes if r.category == category]

    def counts_by_category(self) -> dict[str, int]:
        counts: dict[str, int] = {c.value: 0 for c in FunctionCategory}
        for route in self.routes:
            counts[route.category.value] += 1
        return counts


def _confidence_rank(confidence: str) -> int:
    return {"high": 3, "medium": 2, "low": 1}.get(confidence, 0)


def build_function_map(
    *,
    network_and_js_calls: list[tuple[str, str, str, frozenset[str]]],
    probed_hits: list[tuple[str, str, int | None, str]],
) -> FunctionMap:
    """Builds a FunctionMap from Recon's two discovery channels.

    `network_and_js_calls`: (method, path, source, param_names) tuples from
    the existing passive crawl (browser_crawler.py / js_endpoint_parser.py).
    `probed_hits`: (method, path, status_code, confidence) tuples from the
    new active system-path probe (path_prober.py).
    """
    function_map = FunctionMap()
    for method, path, source, param_names in network_and_js_calls:
        category, keyword = categorize_route(path)
        # Passive, organic discovery is inherently trustworthy about the
        # route's existence (the page itself called it) -- "medium" reflects
        # that the *category* is a keyword guess, not that the route itself
        # is in doubt.
        function_map.add(
            MappedRoute(
                method=method,
                path=path,
                category=category,
                source=source,
                confidence="medium",
                matched_keyword=keyword,
                param_names=param_names,
            )
        )
    for method, path, status_code, probe_confidence in probed_hits:
        category, keyword = categorize_route(path)
        function_map.add(
            MappedRoute(
                method=method,
                path=path,
                category=category,
                source="path-probed",
                confidence=probe_confidence,
                matched_keyword=keyword,
                status_code_at_discovery=status_code,
            )
        )
    return function_map
