"""Token-bucket rate limiter: a technical STABILITY function (it waits, it never denies), shared by the real ScopeGuard
(app/enterprise_controls/scope.py) and the fail-open pass-through guard (app/core/control_port/fallback.py), so the request rate
towards a target stays bounded even when the Enterprise Controls are unavailable.

Extracted unchanged in behaviour from ``ScopeGuard._throttle`` (audit F-08: TECHNICAL STABILITY ONLY). Stdlib only; clock and sleep are
injectable so the rate behaviour is testable with a fake clock.
"""
from __future__ import annotations

import asyncio
import time
from typing import Any, Awaitable, Callable


class TokenBucket:
    """Token bucket shared by all concurrently running modules of one run."""

    def __init__(
        self,
        *,
        rate: float,
        capacity: float,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[Any]] = asyncio.sleep,
    ) -> None:
        self._rate = rate
        self._capacity = float(capacity)
        self._tokens = self._capacity
        self._clock = clock
        self._sleep = sleep
        self._last_refill = clock()
        self._lock = asyncio.Lock()
        self.waited = 0.0  # total seconds spent waiting for a token

    async def take(self, *, before_each: Callable[[], None] | None = None) -> None:
        """Wait until one token is available and consume it. ``before_each`` runs at the start of every loop iteration
        (the real guard uses it to abort a waiting caller as soon as the kill switch is engaged)."""
        async with self._lock:
            while True:
                if before_each is not None:
                    before_each()
                now = self._clock()
                elapsed = max(0.0, now - self._last_refill)
                self._last_refill = now
                self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
                # Tolerance + minimum wait: after sleeping exactly the computed
                # wait, float rounding can leave the bucket at 0.9999999999999999;
                # without both, the residual wait (~1e-17s) is below the clock's
                # resolution and the loop would spin forever (found by
                # tests/test_scope_guard.py's fake-clock rate test).
                if self._tokens >= 1.0 - 1e-9:
                    self._tokens = max(0.0, self._tokens - 1.0)
                    return
                wait = max((1.0 - self._tokens) / self._rate, 1e-6)
                self.waited += wait
                await self._sleep(wait)
