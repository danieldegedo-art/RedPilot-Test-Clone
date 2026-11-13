"""Tests for app/testing/resilience.py -- the CircuitBreaker and retry_on
primitives used by http_client.py (calls to the target under test).
Originally shared with benchmark/llm_escalation.py's real-model
escalation endpoint too; that module was later removed in favor of a
fully local resolver with no network call left to protect with a breaker
(see benchmark/ambiguous_case_resolution.py's module docstring) --
http_client.py is this primitive's one remaining consumer.

Unlike most of this project's own network-adjacent code, this module has
zero external dependencies (stdlib only), so -- unlike
test_http_client_resilience.py and test_run_fault_isolation.py, which need
httpx/pydantic/fastapi to even import -- every test in this file runs
directly in a bare Python 3 interpreter with nothing installed. It was
runtime-verified this way during this pass, the same "prove it, don't just
assert it" discipline CHANGELOG_COGNITIVE_UPGRADE.md documents everywhere
else in this project.
"""
from __future__ import annotations

import asyncio

import pytest

from app.testing.resilience import CircuitBreaker, retry_on


class TestCircuitBreaker:
    def test_starts_closed(self):
        cb = CircuitBreaker(failure_threshold=3, cooldown_seconds=10)
        assert cb.get_statistics() == {"state": "closed", "consecutive_failures": 0, "trip_count": 0}
        assert cb.is_open is False
        assert cb.try_acquire() is True

    def test_does_not_open_before_threshold(self):
        cb = CircuitBreaker(failure_threshold=3, cooldown_seconds=10)
        cb.record_failure()
        cb.record_failure()
        assert cb.get_statistics()["state"] == "closed"
        assert cb.try_acquire() is True

    def test_opens_at_threshold(self):
        cb = CircuitBreaker(failure_threshold=3, cooldown_seconds=10)
        cb.record_failure()
        cb.record_failure()
        cb.record_failure()
        stats = cb.get_statistics()
        assert stats["state"] == "open"
        assert stats["trip_count"] == 1
        assert cb.try_acquire() is False, "no calls admitted while open and within cooldown"

    def test_success_resets_failure_count(self):
        cb = CircuitBreaker(failure_threshold=3, cooldown_seconds=10)
        cb.record_failure()
        cb.record_failure()
        cb.record_success()
        assert cb.get_statistics()["consecutive_failures"] == 0
        cb.record_failure()
        cb.record_failure()
        assert cb.get_statistics()["state"] == "closed", "two more failures after a reset must not trip a threshold-3 breaker"

    @pytest.mark.asyncio
    async def test_half_open_probe_allows_exactly_one_call(self):
        cb = CircuitBreaker(failure_threshold=1, cooldown_seconds=0.05)
        cb.record_failure()
        assert cb.get_statistics()["state"] == "open"
        await asyncio.sleep(0.06)
        assert cb.try_acquire() is True, "first call after cooldown is the half-open probe"
        assert cb.try_acquire() is False, "a second concurrent call must not also be treated as the probe"

    @pytest.mark.asyncio
    async def test_half_open_success_closes_breaker(self):
        cb = CircuitBreaker(failure_threshold=1, cooldown_seconds=0.05)
        cb.record_failure()
        await asyncio.sleep(0.06)
        assert cb.try_acquire() is True
        cb.record_success()
        stats = cb.get_statistics()
        assert stats["state"] == "closed"
        assert stats["trip_count"] == 1, "closing doesn't erase the historical trip count"
        assert cb.try_acquire() is True

    @pytest.mark.asyncio
    async def test_half_open_failure_reopens_with_fresh_cooldown(self):
        """Regression test for a real bug found by this test during this
        pass (see resilience.py's record_failure docstring/comment): a
        half-open probe that FAILS must restart the cooldown from now, not
        leave the original trip timestamp in place. Before the fix, this
        assertion failed -- try_acquire() returned True immediately after
        the failing probe instead of False, because the original
        `_opened_at` (already older than cooldown_seconds, or the probe
        could never have been admitted at all) was never refreshed."""
        cb = CircuitBreaker(failure_threshold=1, cooldown_seconds=0.05)
        cb.record_failure()
        await asyncio.sleep(0.06)
        assert cb.try_acquire() is True
        cb.record_failure()
        stats = cb.get_statistics()
        assert stats["state"] == "open"
        assert stats["trip_count"] == 2
        assert cb.try_acquire() is False, "re-opened immediately, must not admit another call yet"
        await asyncio.sleep(0.06)
        assert cb.try_acquire() is True, "but a FRESH cooldown after the failed probe must still elapse normally"

    def test_release_probe_without_result_does_not_count_either_way(self):
        cb = CircuitBreaker(failure_threshold=1, cooldown_seconds=0)
        cb.record_failure()  # opens (cooldown_seconds=0, so next acquire is immediately a probe)
        assert cb.try_acquire() is True
        cb.release_probe_without_result()
        stats = cb.get_statistics()
        assert stats["trip_count"] == 1, "release must not itself count as a new trip"
        # The probe slot is free again -- another call can immediately probe.
        assert cb.try_acquire() is True

    def test_failure_threshold_and_cooldown_are_clamped_to_sane_minimums(self):
        cb = CircuitBreaker(failure_threshold=0, cooldown_seconds=-5)
        cb.record_failure()
        assert cb.get_statistics()["trip_count"] == 1, "a single failure still registers as a trip (threshold clamped up to 1)"
        # cooldown_seconds is clamped to 0.0 -- an elapsed-time check against
        # a 0-second window is satisfied instantly, so the very next call is
        # already a valid (half-open) probe rather than blocked forever.
        assert cb.try_acquire() is True


class TestRetryOn:
    @pytest.mark.asyncio
    async def test_no_retry_when_first_attempt_is_not_retryable(self):
        calls = {"n": 0}

        async def call():
            calls["n"] += 1
            return "ok"

        result = await retry_on(call, should_retry=lambda r: r == "fail", max_retries=5, base_delay_seconds=0.01)
        assert result == "ok"
        assert calls["n"] == 1

    @pytest.mark.asyncio
    async def test_retries_until_success_within_budget(self):
        calls = {"n": 0}

        async def call():
            calls["n"] += 1
            return "fail" if calls["n"] < 3 else "ok"

        result = await retry_on(call, should_retry=lambda r: r == "fail", max_retries=5, base_delay_seconds=0.01)
        assert result == "ok"
        assert calls["n"] == 3

    @pytest.mark.asyncio
    async def test_stops_at_max_retries_and_returns_last_failure(self):
        calls = {"n": 0}

        async def call():
            calls["n"] += 1
            return "fail"

        result = await retry_on(call, should_retry=lambda r: r == "fail", max_retries=2, base_delay_seconds=0.01)
        assert result == "fail"
        assert calls["n"] == 3, "1 initial attempt + 2 retries, never more"

    @pytest.mark.asyncio
    async def test_zero_max_retries_means_exactly_one_attempt(self):
        calls = {"n": 0}

        async def call():
            calls["n"] += 1
            return "fail"

        result = await retry_on(call, should_retry=lambda r: r == "fail", max_retries=0, base_delay_seconds=0.01)
        assert result == "fail"
        assert calls["n"] == 1

    @pytest.mark.asyncio
    async def test_delay_is_bounded_by_max_delay_seconds(self):
        """A large base_delay_seconds with a small max_delay_seconds cap must
        never sleep longer than the cap, even before jitter is applied --
        regression guard for the min(max_delay_seconds, ...) call in
        resilience.py."""
        calls = {"n": 0}
        sleeps: list[float] = []

        async def call():
            calls["n"] += 1
            return "fail" if calls["n"] < 2 else "ok"

        orig_sleep = asyncio.sleep

        async def spy_sleep(seconds):
            sleeps.append(seconds)
            await orig_sleep(0)  # don't actually wait in the test

        asyncio.sleep = spy_sleep
        try:
            await retry_on(call, should_retry=lambda r: r == "fail", max_retries=3, base_delay_seconds=100.0, max_delay_seconds=0.2)
        finally:
            asyncio.sleep = orig_sleep

        assert sleeps and all(s <= 0.2 for s in sleeps), sleeps
