"""GET/PUT for the dashboard's Settings screen (timeout, proxy, custom
headers, User-Agent, enabled test modules, EndpointMap overrides), plus a
read-only endpoint listing every known operation with its current
effective value (override or built-in default) for the Settings UI's
API-contract table."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.settings_store import load_settings, save_settings
from app.db.session import get_session
from app.schemas.settings import SettingsSchema
from app.testing.endpoints import EndpointMap

router = APIRouter(prefix="/settings", tags=["settings"])


@router.get("", response_model=SettingsSchema)
async def get_settings(session: AsyncSession = Depends(get_session)) -> SettingsSchema:
    return await load_settings(session)


@router.put("", response_model=SettingsSchema)
async def update_settings(payload: SettingsSchema, session: AsyncSession = Depends(get_session)) -> SettingsSchema:
    return await save_settings(session, payload)


@router.get("/endpoints")
async def list_endpoint_operations(session: AsyncSession = Depends(get_session)) -> list[dict]:
    settings = await load_settings(session)
    defaults = EndpointMap()
    result = []
    for operation in EndpointMap.known_operations():
        override = settings.endpoint_overrides.get(operation)
        default_spec = defaults.get(operation)
        result.append(
            {
                "operation": operation,
                "method": override.method if override else default_spec.method,
                "path": override.path if override else default_spec.path,
                "is_override": override is not None,
                "default_method": default_spec.method,
                "default_path": default_spec.path,
            }
        )
    return result
