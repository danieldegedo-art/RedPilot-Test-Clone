"""Aggregates every /api/v1 sub-router into one includable router."""
from __future__ import annotations

from fastapi import APIRouter

from app.api.v1 import modules, runs, settings, webhook_sink, websocket

api_router = APIRouter()
api_router.include_router(runs.router)
api_router.include_router(modules.router)
api_router.include_router(settings.router)
api_router.include_router(websocket.router)
api_router.include_router(webhook_sink.router)
