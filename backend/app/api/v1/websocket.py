"""WebSocket endpoint powering the dashboard's live status/progress/results
stream while a run is in flight. One connection per run_id; every event the
TestRunner publishes (status/phase/result) is forwarded verbatim as JSON."""
from __future__ import annotations

import json
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.testing.event_bus import event_bus

logger = logging.getLogger("qa.ws")
router = APIRouter()


@router.websocket("/ws/runs/{run_id}")
async def run_updates(websocket: WebSocket, run_id: str) -> None:
    await websocket.accept()
    queue = await event_bus.subscribe(run_id)
    try:
        while True:
            message = await queue.get()
            await websocket.send_text(json.dumps(message, default=str))
    except WebSocketDisconnect:
        logger.info("WebSocket disconnected for run %s", run_id)
    finally:
        await event_bus.unsubscribe(run_id, queue)
