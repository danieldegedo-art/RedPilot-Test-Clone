"""Receives webhook calls from the system under test during a run.

Point your staging environment's webhook URL at
POST http://<this-machine>:8420/api/v1/webhook-sink/{run_id} and
FunctionalTestModule's webhook-notification test will pick it up.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request

from app.core.webhook_sink import webhook_sink

router = APIRouter(tags=["webhook-sink"])


@router.post("/webhook-sink/{run_id}")
async def receive_webhook(run_id: str, request: Request) -> dict[str, str]:
    try:
        payload: Any = await request.json()
    except ValueError:
        payload = {"raw_body": (await request.body()).decode("utf-8", errors="replace")}
    webhook_sink.record(run_id, payload if isinstance(payload, dict) else {"payload": payload})
    return {"status": "received"}
