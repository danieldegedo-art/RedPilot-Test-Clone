"""In-process pub/sub used to stream live run progress to WebSocket clients.

Each run_id gets its own set of subscriber queues. The TestRunner publishes
`status` / `phase` / `result` messages as a run progresses; the WebSocket
endpoint subscribes and forwards every message to the connected dashboard.
"""
from __future__ import annotations

import asyncio
from collections import defaultdict
from typing import Any


class EventBus:
    def __init__(self) -> None:
        self._subscribers: dict[str, set[asyncio.Queue]] = defaultdict(set)
        self._lock = asyncio.Lock()

    async def subscribe(self, run_id: str) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=1000)
        async with self._lock:
            self._subscribers[run_id].add(queue)
        return queue

    async def unsubscribe(self, run_id: str, queue: asyncio.Queue) -> None:
        async with self._lock:
            self._subscribers[run_id].discard(queue)
            if not self._subscribers[run_id]:
                self._subscribers.pop(run_id, None)

    async def publish(self, run_id: str, message: dict[str, Any]) -> None:
        async with self._lock:
            queues = list(self._subscribers.get(run_id, ()))
        for queue in queues:
            if queue.full():
                # Drop the oldest message rather than block the test runner
                # on a slow/disconnected consumer.
                try:
                    queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            await queue.put(message)


event_bus = EventBus()
