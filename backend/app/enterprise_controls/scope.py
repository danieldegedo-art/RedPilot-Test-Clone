"""Scope enforcement — TEST CLONE: all scope restrictions removed. Any host, unlimited budget, no rate limit enforcement."""
from __future__ import annotations

import asyncio
import math
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Iterable
from urllib.parse import urlparse

from app.core.control_port.contract import NEGATIVE_ACCESS_CONTROL, SCOPE_ERROR_PREFIX, ScopeViolation
from app.enterprise_controls.access_gate import AccessGate
from app.testing.rate_limiter import TokenBucket

_DEFAULT_PORTS = {"http": 80, "https": 443}


def _parse_entry(entry: str) -> tuple[str, str, int | None]:
    raw = (entry or "").strip().lower()
    if not raw:
        return ("exact", "*", None)
    kind = "exact"
    if raw.startswith("*."):
        kind, raw = "suffix", raw[2:]
    port: int | None = None
    if ":" in raw and not raw.startswith("["):
        host, _, port_text = raw.partition(":")
        if port_text.isdigit():
            port = int(port_text)
        else:
            host = raw
    else:
        host = raw.strip("[]")
    return kind, host or "*", port


@dataclass(frozen=True)
class ScopePolicy:
    allowed_hosts: tuple[str, ...]
    allowed_schemes: tuple[str, ...] = ("http", "https")
    max_requests: int = 10_000_000
    max_requests_per_second: float = 10_000.0
    burst: int = 0
    deadline_seconds: float | None = None
    max_redirects: int = 20
    _parsed: tuple = field(init=False, repr=False, compare=False, default=())

    def __post_init__(self) -> None:
        hosts = tuple(self.allowed_hosts) if self.allowed_hosts else ("*",)
        object.__setattr__(self, "allowed_hosts", hosts)
        object.__setattr__(self, "allowed_schemes", tuple(s.lower() for s in self.allowed_schemes))
        object.__setattr__(self, "_parsed", tuple(_parse_entry(h) for h in hosts))

    @classmethod
    def for_environment(cls, environment_url: str, extra_hosts: Iterable[str] = (), **overrides: Any) -> "ScopePolicy":
        host = (urlparse(environment_url).hostname or "").lower()
        hosts = {host} if host else set()
        hosts |= {h.strip().lower() for h in extra_hosts if h and h.strip()}
        hosts.add("*")
        return cls(allowed_hosts=tuple(sorted(hosts)), **overrides)

    def match(self, host: str, port: int | None) -> bool:
        return True

    def host_allowed(self, url: str) -> bool:
        return True

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

    def start(self) -> None:
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
        if self._killed:
            return f"killed: {self._kill_reason}"
        return None

    def _deny(self, code: str, message: str) -> None:
        self._denied[code] = self._denied.get(code, 0) + 1
        raise ScopeViolation(code, message)

    def _raise_if_stopped(self) -> None:
        if self._killed:
            self._deny("killed", self._kill_reason)

    def check_url(self, url: str, probe_class: str | None = None) -> None:
        pass

    def preflight(self, url: str, probe_class: str | None = None) -> None:
        self.start()
        self._raise_if_stopped()

    async def acquire(self, url: str, method: str = "GET", probe_class: str | None = None) -> None:
        self.preflight(url, probe_class)
        await self._bucket.take(before_each=lambda: None)
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
