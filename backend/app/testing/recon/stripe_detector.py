"""Best-effort detection of Stripe Checkout integration from a crawled page.

Looks at signals a passive page load already exposes: the __stripe_mid/
__stripe_sid cookies Stripe.js sets client-side, <script> tags loaded from
js.stripe.com, a network request to checkout.stripe.com (only observable
if a redirect happens without user interaction -- see caveat below), the
page's Stripe *publishable* key, and any client-visible success/cancel
redirect URLs or checkout-session endpoint path.

Success-URL detection tries three signals, in descending confidence order:
1. A `success_url`/`successUrl` literal in client-side JS (most reliable --
   this is very likely the actual value passed to Stripe).
2. A rendered `<a href="...">` link containing "success"/"complete" in the
   page's HTML (plausible, but could be an unrelated link).
3. Nothing found here -- StripeFlowTestModule falls back further, to a
   manual EndpointMap override or a standard-path probe; see
   modules/stripe_flow.py.

The publishable key (pk_test_.../pk_live_...) is designed by Stripe to be
public -- every Stripe.js integration ships it in client-side code, and
Stripe's own docs confirm it is safe to expose (see
https://stripe.com/docs/keys). This module never looks for, and has no way
to find, the Stripe *secret* key or webhook signing secret -- those never
reach the browser.

Caveat: this crawler only observes a passive page load; it does not click
any "Checkout"/"Subscribe" button. Stripe's redirect to checkout.stripe.com
is usually only triggered by such a click, so `checkout_redirect_observed`
will often be False even on a fully Stripe-integrated page -- treat it as
a bonus signal, not a reliable negative.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

_PUBLISHABLE_KEY_RE = re.compile(r"pk_(?:test|live)_[A-Za-z0-9]{16,}")
_SUCCESS_URL_JS_PATTERNS = [
    re.compile(r"""success_url['"]?\s*[:=]\s*['"`]([^'"`]+)['"`]""", re.IGNORECASE),
    re.compile(r"""successUrl['"]?\s*[:=]\s*['"`]([^'"`]+)['"`]""", re.IGNORECASE),
]
_CANCEL_URL_RE = re.compile(r"""cancel_url['"]?\s*[:=]\s*['"`]([^'"`]+)['"`]""", re.IGNORECASE)
_CHECKOUT_SESSION_PATH_RE = re.compile(r"/[\w/-]*checkout[\w/-]*session[\w/-]*", re.IGNORECASE)
_HREF_SUCCESS_RE = re.compile(r"""href\s*=\s*['"]([^'"]*(?:success|order-complete|checkout-complete)[^'"]*)['"]""", re.IGNORECASE)


@dataclass
class StripeDetection:
    detected: bool = False
    publishable_key: str | None = None
    is_test_mode: bool | None = None
    stripe_js_loaded: bool = False
    checkout_redirect_observed: bool = False
    checkout_session_endpoint: str | None = None
    success_url: str | None = None
    success_url_source: str | None = None  # "js" | "html_link" | None
    cancel_url: str | None = None
    evidence: list[str] = field(default_factory=list)


def _find_success_url(js_sources: list[str], html_content: str) -> tuple[str | None, str | None]:
    for source in js_sources:
        for pattern in _SUCCESS_URL_JS_PATTERNS:
            match = pattern.search(source)
            if match:
                return match.group(1), "js"

    href_match = _HREF_SUCCESS_RE.search(html_content)
    if href_match:
        return href_match.group(1), "html_link"

    return None, None


def detect_stripe(
    *,
    cookie_names: set[str],
    script_urls: list[str],
    network_hosts: set[str],
    js_sources: list[str],
    html_content: str = "",
) -> StripeDetection:
    result = StripeDetection()

    if any(name.startswith("__stripe_") for name in cookie_names):
        result.detected = True
        result.evidence.append("Stripe fraud-detection cookie (__stripe_mid/__stripe_sid) present.")

    if any("js.stripe.com" in url for url in script_urls) or any("js.stripe.com" in host for host in network_hosts):
        result.detected = True
        result.stripe_js_loaded = True
        result.evidence.append("Stripe.js loaded from js.stripe.com.")

    if any("checkout.stripe.com" in host for host in network_hosts):
        result.detected = True
        result.checkout_redirect_observed = True
        result.evidence.append("Redirect/request observed to checkout.stripe.com.")

    for source in js_sources:
        key_match = _PUBLISHABLE_KEY_RE.search(source)
        if key_match and not result.publishable_key:
            result.publishable_key = key_match.group(0)
            result.is_test_mode = result.publishable_key.startswith("pk_test_")
            result.detected = True
            result.evidence.append("Publishable key found in client-side JS (safe to expose by Stripe's own design).")

        cancel_match = _CANCEL_URL_RE.search(source)
        if cancel_match and not result.cancel_url:
            result.cancel_url = cancel_match.group(1)

        session_match = _CHECKOUT_SESSION_PATH_RE.search(source)
        if session_match and not result.checkout_session_endpoint:
            result.checkout_session_endpoint = session_match.group(0)
            result.evidence.append(f"Checkout-session creation endpoint referenced in JS: {session_match.group(0)}")

    success_url, success_source = _find_success_url(js_sources, html_content)
    if success_url:
        result.success_url = success_url
        result.success_url_source = success_source
        source_label = "client-side JS literal" if success_source == "js" else "a rendered HTML link"
        result.evidence.append(f"success_url found via {source_label}: {success_url}")

    return result
