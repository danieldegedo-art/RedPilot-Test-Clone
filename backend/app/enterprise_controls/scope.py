"""Scope enforcement, request budgeting and kill switch for every request the
suite sends to a target.

WHY THIS EXISTS (Phase-0/1 finding G3): before this module the only input that
bounded a run's reach was one URL string. ``QAHttpClient.request`` accepted
absolute URLs to ANY host (``path.startswith("http")``) and followed redirects
blindly; there was no request budget or rate control; and
``TestRunner.cancel()`` only took effect between module batches. For a tool
whose whole safety story is "authorised, bounded, reversible", the bound has to
live at the single choke point every module already passes through, not in each
module's good behaviour.

WHAT IT ENFORCES (all in ``ScopeGuard.acquire``, called before EVERY wire-level
attempt -- retries and redirect hops included):
  1. host allowlist (``host``, ``host:port`` or ``*.suffix``) + scheme allowlist
  2. total request budget per run
  3. request rate (token bucket shared by all concurrently running modules)
  4. optional wall-clock deadline
  5. kill switch (``kill()``) that takes effect INSIDE a running module
  6. PURE BLACK-BOX purity gate (always on while this component is available -- not configurable; if the component is unavailable the
     Control Port degrades fail-open, see app/core/control_port): only customer-facing surfaces may be addressed -- no
     internal/admin/debug/hidden-test paths, provider dashboards, cloud consoles, DB/log/trace ports (enterprise_controls/access_gate.py).
     The one exception is a request explicitly tagged ``probe_class="negative_access_control"`` (a test that EXPECTS an
     admin-looking route to reject a customer-level session); those are counted and still obey host/scheme/port rules.

A denied request is never raised into module code: QAHttpClient turns it into
``ResponseEvidence.error = "scope_violation[<code>]: ..."`` (same shape as a
transport failure), so one denial cannot crash a module and is visible in the
results.

Stdlib-only on purpose: unit-testable anywhere, reusable by non-HTTP drivers.
"""
from __future__ import annotations

import asyncio
import math
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Iterable
from urllib.parse import urlparse

from app.core.control_port.contract import NEGATIVE_ACCESS_CONTROL, SCOPE_ERROR_PREFIX, ScopeViolation  # noqa: F401  (K1/K2 live in the contract)
from app.enterprise_controls.access_gate import AccessGate
from app.testing.rate_limiter import TokenBucket

_DEFAULT_PORTS = {"http": 80, "https": 443}


def _parse_entry(entry: str) -> tuple[str, str, int | None]:
    """Parse one allowlist entry into (kind, host, port); kind is 'exact'|'suffix'."""
    raw = (entry or "").strip().lower()
    if not raw:
        raise ValueError("allowed_hosts contains an empty entry")
    kind = "exact"
    if raw.startswith("*."):
        kind, raw = "suffix", raw[2:]
    if not raw or "://" in raw or any(ch in raw for ch in ("/", "@", " ", "?", "#")):
        raise ValueError(f"allowed_hosts entry must be a bare host[:port] or *.suffix, got {entry!r}")
    port: int | None = None
    if raw.startswith("["):
        end = raw.find("]")
        if end == -1:
            raise ValueError(f"malformed IPv6 allowed_hosts entry {entry!r}")
        host, rest = raw[1:end], raw[end + 1:]
        if rest:
            if not (rest.startswith(":") and rest[1:].isdigit()):
                raise ValueError(f"malformed allowed_hosts entry {entry!r}")
            port = int(rest[1:])
    elif raw.count(":") == 1:
        host, _, port_text = raw.partition(":")
        if not port_text.isdigit():
            raise ValueError(f"malformed port in allowed_hosts entry {entry!r}")
        port = int(port_text)
    else:
        host = raw  # bare hostname, or a bare (unbracketed) IPv6 literal
    if not host:
        raise ValueError(f"allowed_hosts entry has no host: {entry!r}")
    if port is not None and not (0 < port < 65536):
        raise ValueError(f"port out of range in allowed_hosts entry {entry!r}")
    return kind, host, port


def _url_parts(url: str) -> tuple[str, int | None, str, str]:
    """Return (host, effective_port, scheme, netloc). Raises ScopeViolation(invalid_url)."""
    try:
        parsed = urlparse(url)
        port = parsed.port
    except ValueError as exc:
        raise ScopeViolation("invalid_url", f"unparseable URL {url!r}") from exc
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").lower()
    if port is None and scheme in _DEFAULT_PORTS:
        port = _DEFAULT_PORTS[scheme]
    return host, port, scheme, parsed.netloc


@dataclass(frozen=True)
class ScopePolicy:
    """The authorised reach of one run. Immutable; snapshot it into the run summary."""

    allowed_hosts: tuple[str, ...]
    allowed_schemes: tuple[str, ...] = ("http", "https")
    max_requests: int = 10_000
    max_requests_per_second: float = 25.0
    burst: int = 0  # 0 => derived: max(10, ceil(max_requests_per_second))
    deadline_seconds: float | None = None
    max_redirects: int = 5
    _parsed: tuple = field(init=False, repr=False, compare=False, default=())

    def __post_init__(self) -> None:
        hosts = tuple(self.allowed_hosts)
        if not hosts:
            raise ValueError("ScopePolicy.allowed_hosts must not be empty")
        parsed = tuple(_parse_entry(h) for h in hosts)
        if self.max_requests < 1:
            raise ValueError("max_requests must be >= 1")
        if not (self.max_requests_per_second > 0):
            raise ValueError("max_requests_per_second must be > 0")
        if self.burst < 0:
            raise ValueError("burst must be >= 0")
        if self.deadline_seconds is not None and not (self.deadline_seconds > 0):
            raise ValueError("deadline_seconds must be > 0 when set")
        if self.max_redirects < 0:
            raise ValueError("max_redirects must be >= 0")
        object.__setattr__(self, "allowed_hosts", hosts)
        object.__setattr__(self, "allowed_schemes", tuple(s.lower() for s in self.allowed_schemes))
        object.__setattr__(self, "_parsed", parsed)

    @classmethod
    def for_environment(cls, environment_url: str, extra_hosts: Iterable[str] = (), **overrides: Any) -> "ScopePolicy":
        """Secure default: only the host the user typed (any port) plus explicit extras."""
        host = (urlparse(environment_url).hostname or "").lower()
        if not host:
            raise ValueError(f"cannot derive a host from environment URL {environment_url!r}")
        hosts = {host} | {h.strip().lower() for h in extra_hosts if h and h.strip()}
        return cls(allowed_hosts=tuple(sorted(hosts)), **overrides)

    def match(self, host: str, port: int | None) -> bool:
        for kind, entry_host, entry_port in self._parsed:
            if kind == "exact" and host != entry_host:
                continue
            if kind == "suffix" and not host.endswith("." + entry_host):
                continue
            if entry_port is not None and port != entry_port:
                continue
            return True
        return False

    def host_allowed(self, url: str) -> bool:
        try:
            host, port, scheme, netloc = _url_parts(url)
        except ScopeViolation:
            return False
        if "@" in netloc or not host or scheme not in self.allowed_schemes:
            return False
        return self.match(host, port)

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed_hosts": list(self.allowed_hosts),
            "allowed_schemes": list(self.allowed_schemes),
            "max_requests": self.max_requests,
            "max_requests_per_second": self.max_requests_per_second,
            "burst": self.burst,
            "deadline_seconds": self.deadline_seconds,
            "max_redirects": self.max_redirects,
        }


class ScopeGuard:
    """Runtime enforcement of a ScopePolicy. One instance per run, shared by every module."""

    def __init__(
        self,
        policy: ScopePolicy,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[Any]] = asyncio.sleep,
    ) -> None:
        self.policy = policy
        self._clock = clock
        self._sleep = sleep
        self._bucket = TokenBucket(
            rate=policy.max_requests_per_second,
            capacity=float(policy.burst or max(10, math.ceil(policy.max_requests_per_second))),
            clock=clock, sleep=sleep,
        )
        self._used = 0
        self._denied: dict[str, int] = {}
        self._killed = False
        self._kill_reason = ""
        self._t0: float | None = None
        self.access_gate = AccessGate()

    # -- control ---------------------------------------------------------------
    def start(self) -> None:
        """Start the deadline clock (idempotent). Also started lazily on first request."""
        if self._t0 is None:
            self._t0 = self._clock()

    def kill(self, reason: str = "kill switch engaged") -> None:
        self._killed = True
        self._kill_reason = reason

    @property
    def killed(self) -> bool:
        return self._killed

    @property
    def kill_reason(self) -> str:
        return self._kill_reason

    @property
    def requests_used(self) -> int:
        return self._used

    @property
    def remaining_budget(self) -> int:
        return max(0, self.policy.max_requests - self._used)

    def stop_reason(self) -> str | None:
        """Non-raising probe for cooperative loops (e.g. the oracle engine)."""
        if self._killed:
            return f"killed: {self._kill_reason}"
        if self._deadline_exceeded():
            return "deadline_exceeded"
        if self._used >= self.policy.max_requests:
            return "budget_exhausted"
        return None

    # -- checks ----------------------------------------------------------------
    def _deny(self, code: str, message: str) -> None:
        self._denied[code] = self._denied.get(code, 0) + 1
        raise ScopeViolation(code, message)

    def _deadline_exceeded(self) -> bool:
        limit = self.policy.deadline_seconds
        return limit is not None and self._t0 is not None and (self._clock() - self._t0) > limit

    def _raise_if_stopped(self) -> None:
        if self._killed:
            self._deny("killed", self._kill_reason)
        if self._deadline_exceeded():
            self._deny("deadline_exceeded", f"run deadline of {self.policy.deadline_seconds}s exceeded")

    def check_url(self, url: str, probe_class: str | None = None) -> None:
        """Non-counting URL check (redirect targets, pre-flight)."""
        try:
            host, port, scheme, netloc = _url_parts(url)
        except ScopeViolation as violation:
            self._deny(violation.code, violation.message)
            return
        if "@" in netloc:
            self._deny("invalid_url", "userinfo in URL is not permitted")
        if scheme not in self.policy.allowed_schemes:
            self._deny("scheme_not_allowed", f"scheme {scheme!r} is not in {list(self.policy.allowed_schemes)}")
        if not host or not self.policy.match(host, port):
            self._deny("host_not_allowed", f"host {host or '?'!r} (port {port}) is outside the authorised scope")
        decision = self.access_gate.check(url, probe_class=probe_class)  # Pure Black-Box: customer-facing surfaces only
        if not decision.allowed:
            self._deny(decision.code or "purity_denied", decision.message or "request is not addressed to a customer-facing surface")

    def preflight(self, url: str, probe_class: str | None = None) -> None:
        """Sync, non-counting: every denial that can be known before touching the network."""
        self.start()
        self._raise_if_stopped()
        self.check_url(url, probe_class)
        if self._used >= self.policy.max_requests:
            self._deny("budget_exhausted", f"request budget of {self.policy.max_requests} exhausted")

    def _raise_if_killed(self) -> None:
        if self._killed:
            self._deny("killed", self._kill_reason)

    async def _throttle(self) -> None:
        # Rate drossel = technical stability function, shared with the fail-open guard (testing/rate_limiter.py).
        await self._bucket.take(before_each=self._raise_if_killed)

    async def acquire(self, url: str, method: str = "GET", probe_class: str | None = None) -> None:
        """Authorise ONE wire-level attempt or raise ScopeViolation. Counts against the budget."""
        self.preflight(url, probe_class)
        await self._throttle()
        self._raise_if_stopped()
        if self._used >= self.policy.max_requests:  # re-check: concurrent callers may have raced past preflight
            self._deny("budget_exhausted", f"request budget of {self.policy.max_requests} exhausted")
        self._used += 1
        if probe_class == NEGATIVE_ACCESS_CONTROL:
            self.access_gate.note_negative_probe()

    def stats(self) -> dict[str, Any]:
        elapsed = None if self._t0 is None else round(self._clock() - self._t0, 3)
        return {
            "requests_used": self._used,
            "requests_denied": sum(self._denied.values()),
            "denied_by_code": dict(self._denied),
            "killed": self._killed,
            "kill_reason": self._kill_reason or None,
            "purity_gate": self.access_gate.stats(),
            "rate_wait_seconds": round(self._bucket.waited, 3),
            "elapsed_seconds": elapsed,
            "policy": self.policy.to_dict(),
        }
