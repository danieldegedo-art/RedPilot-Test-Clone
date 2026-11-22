"""Per-run configuration and execution context passed to every test module."""
from __future__ import annotations

from app.testing.module_defaults import DEFAULT_ENABLED_MODULES

from dataclasses import dataclass, field
from typing import Any

from app.core.control_port import RunGuard
from app.testing.endpoints import EndpointMap
from app.testing.enums import TestScope
from app.testing.http_client import QAHttpClient
from app.testing.pesm import PESMStore


@dataclass
class RunSettings:
    """Maps 1:1 to the dashboard's Settings screen."""

    timeout_seconds: float = 30.0
    proxy_url: str | None = None
    custom_headers: dict[str, str] = field(default_factory=dict)
    user_agent: str = "PaymentQA-Suite/1.0"
    # Resilience knobs for QAHttpClient's calls to the target under test
    # (see http_client.py / resilience.py). Per-run/per-target, like
    # timeout_seconds above, rather than a global env-var setting --
    # different targets warrant different tolerance (a known-flaky
    # staging environment vs. a solid one). GET/HEAD/OPTIONS retry
    # automatically up to http_max_retries times; a mutating call only
    # retries when the module explicitly marks that specific call
    # idempotent=True (see http_client.py's module docstring for why).
    http_max_retries: int = 2
    http_retry_base_delay_seconds: float = 0.5
    http_circuit_breaker_threshold: int = 5
    http_circuit_breaker_cooldown_seconds: float = 20.0
    # How many PARALLEL_SAFE_MODULES (registry.py) may run concurrently
    # within one run (see runner.py's batched execution). Bounds load on
    # the target, not correctness -- every module in that set is already
    # verified independent of every other member (no shared_state
    # dependency, no shared mutable target-side resource), so this only
    # trades wall-clock time for how much simultaneous traffic hits the
    # target. Default keeps every current batch (currently 7 modules) from
    # firing all at once while still giving real concurrency.
    module_concurrency: int = 4
    # See ManualWebhookProvider / modules/additional_webhook_security.py.
    additional_webhook_providers: list = field(default_factory=list)
    enabled_modules: set[str] = field(default_factory=lambda: set(DEFAULT_ENABLED_MODULES))
    # Not a module (it doesn't test the target itself -- it re-reads the
    # TestResults the modules above already produced), so it isn't part of
    # enabled_modules/SCOPE_MODULES. Runs after a normal (non-cancelled,
    # non-crashed) module pass regardless of scope, since it's pure
    # analysis with no additional requests to the target -- see
    # discovery/engine.py and TestRunner.execute().
    discovery_layer_enabled: bool = True
    # ZR-003/ZR-012/ZR-007: order the integrity engine's experiments by payment
    # risk, prior-run evidence and FSM coverage (app/testing/prioritization.py)
    # instead of the static EXPERIMENT_ORDER. Off by default -- the static order
    # is the one this platform's regression history is built on; see
    # modules/payment_integrity.py for where this is actually read.
    prioritize_experiments: bool = True
    # (method, path) pairs a human has explicitly registered via Settings ->
    # Manual Routes. ReconModule merges these into the FunctionMap it builds
    # (as high-confidence "manual-override" entries) BEFORE role_based_access
    # and input_format_consistency run, so a route Recon's crawler/JS-parser/
    # path-prober didn't find on its own still gets the full, already-audited
    # ROLE-002/003 + format-consistency treatment. This is the mechanism a
    # DISCOVERY-CORRELATION-* finding's recommendation points at.
    manual_routes: list[tuple[str, str]] = field(default_factory=list)
    # Customer-level payment-integrity Execution Brief (testing/integrity/brief.py),
    # loaded from core/integrity_store.py at run start. Never persisted in the
    # settings table -- no DB migration needed. It contains no secrets by construction
    # (identity tokens are referenced by environment-variable NAME only).
    integrity_brief: dict[str, Any] | None = None
    electron_recon: dict[str, Any] | None = None


@dataclass
class TestContext:
    """Everything a BaseTestModule needs to run: where to send requests, how,
    and at what scope.

    `base_url` is always a clean origin (scheme://host[:port]) -- every
    EndpointMap-based module builds absolute API paths and sends them here.
    `entry_url` is the exact URL the user typed into the dashboard
    (may include a path/query, e.g. a specific /payment?productId=... page)
    -- only ReconModule uses this, to know which page to actually load in
    the browser.

    `shared_state` is a generic, deliberately untyped scratch space modules
    running earlier in the pass can use to hand discoveries to modules
    running later (e.g. Recon stashes its StripeDetection under the key
    "stripe_detection" for the Stripe flow module to read) -- keeps the
    core context free of any specific integration's types.
    """

    run_id: str
    base_url: str
    entry_url: str
    scope: TestScope
    settings: RunSettings
    endpoints: EndpointMap
    http: QAHttpClient
    shared_state: dict[str, Any] = field(default_factory=dict)
    # Shared scope guard of this run (None only in unit tests that build a bare context).
    guard: RunGuard | None = None
    # ZR-002: PESM feature registry, cross-run (unlike shared_state). None
    # until a real caller wires one in (api/v1/runs.py doesn't yet -- same
    # explicitly-deferred state as ZR-009's persist_result before it was
    # wired into the one production TestRunner construction site).
    feature_registry: PESMStore | None = None
    twin_url: str | None = None
    session_cookies: str | None = None
