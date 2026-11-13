"""Shared resilience primitives.

One canonical circuit breaker and one canonical bounded-retry helper for
every place this project makes a call it doesn't fully control the
reliability of -- currently that is only the target payment API under
test (http_client.py). Same principle as pattern_library.py for
secret/card-number patterns: one implementation, not two that quietly
drift apart.

`CircuitBreaker` below is the exact circuit breaker
backend/benchmark/llm_escalation.py shipped first (see
CHANGELOG_COGNITIVE_UPGRADE.md, "Real-model escalation"), lifted out
unchanged so http_client.py could share it. llm_escalation.py (and its
own use of this class) was removed in a later pass -- see
backend/benchmark/ambiguous_case_resolution.py's module docstring --
once its escalation path no longer made a network call and had nothing
left to protect against with a breaker. http_client.py's use of a real,
external target it doesn't control is the reason this primitive still
earns its place here.
"""
from __future__ import annotations

import asyncio
import logging
import random
import time
from typing import Any, Awaitable, Callable, TypeVar

logger = logging.getLogger("qa.resilience")

T = TypeVar("T")


class CircuitBreaker:
    """Single-event-loop circuit breaker (no lock needed: every method here
    runs to completion between `await` points -- every user of this class
    in this project lives on one asyncio event loop, not across threads,
    the same reasoning PersistentMemoryStore's SQLite connection does NOT
    get to rely on, since that one really is touched from multiple
    threads via asyncio.to_thread). Opens after `failure_threshold`
    consecutive failures; after `cooldown_seconds`, lets exactly one probe
    call through (half-open) before deciding whether to close or re-open.
    """

    def __init__(self, failure_threshold: int, cooldown_seconds: float) -> None:
        self._failure_threshold = max(1, failure_threshold)
        self._cooldown_seconds = max(0.0, cooldown_seconds)
        self._consecutive_failures = 0
        self._opened_at: float | None = None
        self._half_open_probe_in_flight = False
        self._trip_count = 0

    @property
    def is_open(self) -> bool:
        if self._opened_at is None:
            return False
        if time.monotonic() - self._opened_at < self._cooldown_seconds:
            return True
        return self._half_open_probe_in_flight

    def try_acquire(self) -> bool:
        """Returns True if a call may proceed right now. If this returns
        True while the breaker was open, that call IS the half-open probe
        -- exactly one is ever in flight at a time. Call this at most once
        per logical operation (one QAHttpClient.request() call, including
        any retries inside it -- not once per retry attempt): the
        half-open slot represents one *operation* getting a chance to
        prove the target recovered, not one wire-level attempt."""
        if self._opened_at is None:
            return True
        if time.monotonic() - self._opened_at < self._cooldown_seconds:
            return False
        if self._half_open_probe_in_flight:
            return False
        self._half_open_probe_in_flight = True
        return True

    def record_success(self) -> None:
        self._consecutive_failures = 0
        self._opened_at = None
        self._half_open_probe_in_flight = False

    def record_failure(self) -> None:
        was_probing = self._half_open_probe_in_flight
        self._half_open_probe_in_flight = False
        self._consecutive_failures += 1
        if was_probing:
            # BUGFIX (this pass -- see the fault-isolation/hardening report):
            # the half-open probe that just ran is what proved the target is
            # STILL down. The original condition below
            # (`and self._opened_at is None`) only ever (re-)opens the
            # breaker from a fully-closed state; once tripped once,
            # `_opened_at` stays non-None until a SUCCESS clears it, so a
            # failed half-open probe fell through this method doing nothing
            # to `_opened_at` -- leaving the *original* trip time in place.
            # Since that original cooldown had, by definition, already
            # elapsed (that's the only way a probe was admitted at all),
            # every following try_acquire() call saw an elapsed-cooldown
            # check that was already satisfied and a just-cleared probe
            # flag -- i.e. it treated EVERY subsequent call as a fresh
            # half-open probe with NO cooldown enforced between them at
            # all. A target that's down for an extended period with
            # periodic failed recovery attempts would get hit on literally
            # every call after the first trip, not once per cooldown window
            # -- silently defeating the breaker's actual purpose after the
            # first failed recovery. Re-opening with a fresh timestamp here
            # (regardless of the running consecutive-failure count) is what
            # makes "recovery attempt failed -> wait another full cooldown"
            # true again. See test_resilience.py's
            # test_half_open_failure_reopens_with_fresh_cooldown, which
            # failed against the pre-fix code and is what surfaced this.
            self._opened_at = time.monotonic()
            self._trip_count += 1
            return
        if self._consecutive_failures >= self._failure_threshold and self._opened_at is None:
            self._opened_at = time.monotonic()
            self._trip_count += 1

    def release_probe_without_result(self) -> None:
        """Releases a half-open probe slot without counting it as either a
        success or a failure. Used when something short-circuits a call
        that happened to consume the probe slot (e.g. a cache hit) before
        it actually reached the provider, so the *next* call still gets
        to test recovery instead of the breaker staying artificially
        stuck in half-open."""
        self._half_open_probe_in_flight = False

    def get_statistics(self) -> dict[str, Any]:
        if self._opened_at is None:
            state = "closed"
        elif self.is_open:
            state = "open"
        else:
            state = "half_open"
        return {
            "state": state,
            "consecutive_failures": self._consecutive_failures,
            "trip_count": self._trip_count,
        }


async def retry_on(
    call: Callable[[], Awaitable[T]],
    *,
    should_retry: Callable[[T], bool],
    max_retries: int,
    base_delay_seconds: float,
    max_delay_seconds: float = 10.0,
) -> T:
    """Calls `call` up to `max_retries + 1` times total, stopping at the
    first result `should_retry` says to keep. Delays between attempts use
    full-jitter exponential backoff (`random.uniform(0, cap)`, not a fixed
    or deterministic wait) so many parallel callers retrying against the
    same struggling target don't all hammer it again at the exact same
    moment.

    Deliberately knows nothing about circuit breakers: this is useful
    anywhere bounded retry alone is needed, and composing it with a
    CircuitBreaker is the caller's job (see http_client.py's `request`,
    which calls `breaker.try_acquire()` once before the retry sequence and
    records exactly one success/failure after it -- the breaker tracks
    operations, this tracks attempts within one operation).

    `call` must never raise for an ordinary, expected failure -- the same
    discipline QAHttpClient.request already follows for the target under
    test (a timeout becomes a populated ResponseEvidence.error, never an
    exception, so one unreachable environment can't crash the run).
    `should_retry` is what decides retryable-vs-not from the *returned
    value*. If `call` raises anyway, that's treated as an unexpected,
    non-retryable error and propagates immediately -- retrying something
    that broke that contract risks repeating whatever caused it to raise.
    """
    attempt = 0
    result = await call()
    while should_retry(result) and attempt < max_retries:
        delay = min(max_delay_seconds, base_delay_seconds * (2**attempt))
        wait_for = random.uniform(0, delay)
        logger.info("retry_on: attempt %d failed, retrying in %.2fs", attempt + 1, wait_for)
        await asyncio.sleep(wait_for)
        attempt += 1
        result = await call()
    return result
