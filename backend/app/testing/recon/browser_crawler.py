"""Headless-browser crawler that observes real network traffic made by the
target page to discover API endpoints and third-party payment-provider
integrations (currently: Stripe -- see stripe_detector.py).

Loads the given URL in headless Chromium and records every same-origin
XHR/fetch request the page makes while loading (and briefly after, to catch
lazy/deferred calls). Same-origin <script> URLs are also collected so the
caller can statically scan them for additional fetch()/axios() call
patterns (see js_endpoint_parser.py) that didn't fire during a plain load.
Every distinct request HOST contacted (same-origin or third-party) and
every cookie name set during the visit are also recorded -- this is what
lets stripe_detector.py notice "this page talks to js.stripe.com and has a
__stripe_mid cookie" without needing any special-cased Stripe logic here.

Only observes traffic the page already generates for any visitor and reads
same-origin JavaScript the target already serves publicly -- no brute
forcing, fuzzing, or attempts to reach anything not already exposed to the
page. This module does NOT click buttons or otherwise interact with the
page, so a redirect that only happens after a user-initiated "Checkout"
click (the common case for Stripe) will typically not be observed here --
see stripe_detector.py's docstring for what that means for its findings.

Requires the `playwright` package with Chromium installed:
`playwright install chromium` (already run in backend/Dockerfile).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote, urlparse


@dataclass
class DiscoveredCall:
    """`param_values` holds a REAL example value the target itself sent for
    (a subset of) `param_names` -- only populated for network-observed
    calls, since static JS analysis has no runtime value to read (see
    js_endpoint_parser.py). Consumed by DiscoveredValues
    (dynamic_values.py) so test modules can send realistic values instead
    of this suite's own generic defaults."""

    method: str
    path: str  # path only, query string stripped
    param_names: set[str] = field(default_factory=set)
    source: str = "network"  # "network" or "static-js"
    param_values: dict[str, Any] = field(default_factory=dict)


@dataclass
class CrawlResult:
    discovered: list[DiscoveredCall]
    script_urls: list[str]
    pages_visited: list[str]
    errors: list[str]
    cookie_names: set[str] = field(default_factory=set)
    network_hosts: set[str] = field(default_factory=set)
    html_content: str = ""


def _origin_of(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _path_of(url: str) -> str:
    parsed = urlparse(url)
    return parsed.path or "/"


def _host_of(url: str) -> str:
    return urlparse(url).netloc


def _param_names_from_request(request: Any) -> set[str]:
    names: set[str] = set()
    try:
        post_data = request.post_data_json
        if isinstance(post_data, dict):
            names |= set(post_data.keys())
    except Exception:
        pass
    parsed = urlparse(request.url)
    if parsed.query:
        names |= {pair.split("=")[0] for pair in parsed.query.split("&") if pair}
    return names


def _param_values_from_request(request: Any) -> dict[str, Any]:
    """Best-effort extraction of REAL values the page's own request sent --
    only scalar (str/int/float/bool) top-level body fields and query-string
    values are captured; nested objects/arrays are skipped since a nested
    value can't be safely spliced into another endpoint's differently-shaped
    payload by name alone (see dynamic_values.py's own shallow-by-name
    matching). Never captures anything from cookies/auth headers."""
    values: dict[str, Any] = {}
    try:
        post_data = request.post_data_json
        if isinstance(post_data, dict):
            for key, value in post_data.items():
                if isinstance(value, (str, int, float, bool)) and value != "":
                    values[key] = value
    except Exception:
        pass
    parsed = urlparse(request.url)
    if parsed.query:
        for pair in parsed.query.split("&"):
            if not pair or "=" not in pair:
                continue
            key, _, raw_value = pair.partition("=")
            if key and raw_value and key not in values:
                values[key] = unquote(raw_value)
    return values


async def crawl(base_url: str, *, timeout_seconds: float = 20.0, extra_headers: dict[str, str] | None = None) -> CrawlResult:
    # Playwright is a heavy, optional dependency -- imported lazily here so the
    # rest of the backend still starts even if the recon module's dependency
    # isn't fully set up; a broken/missing import surfaces as a clean per-run
    # ERROR result instead of crashing the whole application at startup.
    from playwright.async_api import TimeoutError as PlaywrightTimeoutError
    from playwright.async_api import async_playwright

    origin = _origin_of(base_url)
    discovered: dict[tuple[str, str], DiscoveredCall] = {}
    script_urls: list[str] = []
    network_hosts: set[str] = set()
    errors: list[str] = []

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        try:
            context = await browser.new_context(extra_http_headers=extra_headers or {})
            page = await context.new_page()

            def on_request(request: Any) -> None:
                host = _host_of(request.url)
                if host:
                    network_hosts.add(host)

                if request.resource_type == "script" and _origin_of(request.url) == origin:
                    if request.url not in script_urls:
                        script_urls.append(request.url)
                if request.resource_type not in ("xhr", "fetch"):
                    return
                if _origin_of(request.url) != origin:
                    return
                method = request.method.upper()
                path = _path_of(request.url)
                key = (method, path)
                entry = discovered.setdefault(key, DiscoveredCall(method=method, path=path, source="network"))
                entry.param_names |= _param_names_from_request(request)
                for param_name, value in _param_values_from_request(request).items():
                    entry.param_values.setdefault(param_name, value)  # first-seen, non-empty value wins

            page.on("request", on_request)

            try:
                await page.goto(base_url, timeout=timeout_seconds * 1000, wait_until="networkidle")
            except PlaywrightTimeoutError:
                errors.append(f"Page did not reach network-idle within {timeout_seconds}s; results may be incomplete.")

            # Give SPA route-based lazy requests a brief extra window.
            await page.wait_for_timeout(1500)

            cookies = await context.cookies()
            cookie_names = {c["name"] for c in cookies if "name" in c}
            html_content = await page.content()
        finally:
            await browser.close()

    return CrawlResult(
        discovered=list(discovered.values()),
        script_urls=script_urls,
        pages_visited=[base_url],
        errors=errors,
        cookie_names=cookie_names,
        network_hosts=network_hosts,
        html_content=html_content,
    )
