"""Shared helper for polling the in-memory webhook sink (see
core/webhook_sink.py) for a correlation id. Used by any test module that
triggers a payment event and needs to verify a webhook was delivered
afterwards (FunctionalTestModule's payment webhook check,
IntegrationTestModule's refund notification step, ...).
"""
from __future__ import annotations

import asyncio


async def poll_webhook_sink(run_id: str, correlation_id: str, timeout_seconds: float) -> bool:
    from app.core.webhook_sink import webhook_sink  # local import avoids a circular import at module load

    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout_seconds
    while loop.time() < deadline:
        if webhook_sink.has_event(run_id, correlation_id):
            return True
        await asyncio.sleep(0.5)
    return False
