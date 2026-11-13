"""In-memory store for webhook events pushed to this backend during a run.

A staging environment's webhook URL can be pointed at
POST /api/v1/webhook-sink/{run_id} (see api/v1/webhook_sink.py) so
FunctionalTestModule can verify delivery automatically, the same pattern
`stripe listen` / ngrok-based webhook testing uses.
"""
from __future__ import annotations

import time
from collections import defaultdict
from typing import Any


def _contains_correlation_id(payload: Any, correlation_id: str) -> bool:
    if isinstance(payload, dict):
        return any(_contains_correlation_id(v, correlation_id) for v in payload.values())
    if isinstance(payload, list):
        return any(_contains_correlation_id(item, correlation_id) for item in payload)
    return payload == correlation_id


class WebhookSink:
    def __init__(self, ttl_seconds: float = 3600.0) -> None:
        self._events: dict[str, list[tuple[float, dict[str, Any]]]] = defaultdict(list)
        self._ttl_seconds = ttl_seconds

    def record(self, run_id: str, payload: dict[str, Any]) -> None:
        self._events[run_id].append((time.time(), payload))
        self._evict_expired(run_id)

    def has_event(self, run_id: str, correlation_id: str) -> bool:
        self._evict_expired(run_id)
        return any(_contains_correlation_id(payload, correlation_id) for _, payload in self._events.get(run_id, []))

    def events_for_run(self, run_id: str) -> list[dict[str, Any]]:
        self._evict_expired(run_id)
        return [payload for _, payload in self._events.get(run_id, [])]

    def _evict_expired(self, run_id: str) -> None:
        cutoff = time.time() - self._ttl_seconds
        self._events[run_id] = [(ts, p) for ts, p in self._events.get(run_id, []) if ts >= cutoff]


webhook_sink = WebhookSink()
