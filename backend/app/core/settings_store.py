"""Persists and loads the dashboard's Settings (timeout, proxy, custom
headers, User-Agent, enabled modules, EndpointMap overrides, session
cookies) as a single row in Postgres, and converts them into the
dataclasses the test framework consumes (RunSettings, EndpointMap).

Session cookies live in a dedicated `session_cookies` column rather than
piggybacking on `custom_headers` -- the Settings UI's Cookie Manager needs
per-cookie rows (parse a pasted `Cookie:` string, mask values, remove one
at a time), which a flat header-key-value list doesn't support cleanly.
`to_run_settings` merges them into a single Cookie header at read time, so
everything downstream of Settings (QAHttpClient, every test module) still
just sees one flat `custom_headers` dict and doesn't need to know the
Cookie Manager exists.
"""
from __future__ import annotations

from app.testing.module_defaults import DEFAULT_ENABLED_MODULES

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings as app_settings
from app.db import models as db_models
from app.schemas.settings import EndpointOverrideSchema, ManualWebhookProviderSchema, SettingsSchema
from app.testing.checkout_provider_testing import ManualWebhookProvider
from app.testing.context import RunSettings
from app.testing.endpoints import EndpointMap, EndpointSpec

_SETTINGS_ID = "default"

_DEFAULT_ENABLED_MODULES = list(DEFAULT_ENABLED_MODULES)


async def _get_or_create(session: AsyncSession) -> db_models.SettingsRecord:
    record = await session.get(db_models.SettingsRecord, _SETTINGS_ID)
    if record is None:
        record = db_models.SettingsRecord(
            id=_SETTINGS_ID,
            user_agent=app_settings.default_user_agent,
            timeout_seconds=app_settings.default_timeout_seconds,
            enabled_modules=_DEFAULT_ENABLED_MODULES,
        )
        session.add(record)
        await session.commit()
        await session.refresh(record)
    return record


async def load_settings(session: AsyncSession) -> SettingsSchema:
    record = await _get_or_create(session)
    return SettingsSchema(
        timeout_seconds=record.timeout_seconds,
        proxy_url=record.proxy_url,
        custom_headers=record.custom_headers,
        user_agent=record.user_agent,
        enabled_modules=record.enabled_modules,
        discovery_layer_enabled=record.discovery_layer_enabled,
        prioritize_experiments=record.prioritize_experiments,
        endpoint_overrides={op: EndpointOverrideSchema(**spec) for op, spec in (record.endpoint_overrides or {}).items()},
        session_cookies=record.session_cookies or {},
        manual_routes=[EndpointOverrideSchema(**spec) for spec in (record.manual_routes or [])],
        http_max_retries=record.http_max_retries,
        http_retry_base_delay_seconds=record.http_retry_base_delay_seconds,
        http_circuit_breaker_threshold=record.http_circuit_breaker_threshold,
        http_circuit_breaker_cooldown_seconds=record.http_circuit_breaker_cooldown_seconds,
        module_concurrency=record.module_concurrency,
        additional_webhook_providers=[
            ManualWebhookProviderSchema(**spec) for spec in (record.additional_webhook_providers or [])
        ],
    )


async def save_settings(session: AsyncSession, payload: SettingsSchema) -> SettingsSchema:
    record = await _get_or_create(session)
    record.timeout_seconds = payload.timeout_seconds
    record.proxy_url = payload.proxy_url
    record.custom_headers = payload.custom_headers
    record.user_agent = payload.user_agent
    record.enabled_modules = payload.enabled_modules
    record.discovery_layer_enabled = payload.discovery_layer_enabled
    record.prioritize_experiments = payload.prioritize_experiments
    record.endpoint_overrides = {op: spec.model_dump() for op, spec in payload.endpoint_overrides.items()}
    record.session_cookies = payload.session_cookies
    record.manual_routes = [spec.model_dump() for spec in payload.manual_routes]
    record.http_max_retries = payload.http_max_retries
    record.http_retry_base_delay_seconds = payload.http_retry_base_delay_seconds
    record.http_circuit_breaker_threshold = payload.http_circuit_breaker_threshold
    record.http_circuit_breaker_cooldown_seconds = payload.http_circuit_breaker_cooldown_seconds
    record.module_concurrency = payload.module_concurrency
    record.additional_webhook_providers = [spec.model_dump() for spec in payload.additional_webhook_providers]
    await session.commit()
    return payload


def _merge_cookie_header(custom_headers: dict[str, str], session_cookies: dict[str, str]) -> dict[str, str]:
    """Combines the Cookie Manager's cookies with any `Cookie` entry that
    might already exist in the generic custom_headers table, so using
    either UI (or both) produces one correct, de-duplicated Cookie header.
    Cookie Manager values win on a name conflict."""
    if not session_cookies:
        return dict(custom_headers)

    merged = dict(custom_headers)
    existing_cookie_header = next((v for k, v in merged.items() if k.lower() == "cookie"), "")
    pairs: dict[str, str] = {}
    for part in existing_cookie_header.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        name, _, value = part.partition("=")
        pairs[name.strip()] = value.strip()
    pairs.update(session_cookies)

    # Remove any casing of an existing "Cookie" key before re-adding the merged one.
    merged = {k: v for k, v in merged.items() if k.lower() != "cookie"}
    merged["Cookie"] = "; ".join(f"{name}={value}" for name, value in pairs.items())
    return merged


def to_run_settings(loaded: SettingsSchema) -> RunSettings:
    """Pure conversion, no DB access -- lets callers load settings once and
    derive both RunSettings and EndpointMap from the same snapshot."""
    return RunSettings(
        timeout_seconds=loaded.timeout_seconds,
        proxy_url=loaded.proxy_url,
        custom_headers=_merge_cookie_header(loaded.custom_headers, loaded.session_cookies),
        user_agent=loaded.user_agent,
        enabled_modules=set(loaded.enabled_modules),
        discovery_layer_enabled=loaded.discovery_layer_enabled,
        prioritize_experiments=loaded.prioritize_experiments,
        manual_routes=[(spec.method, spec.path) for spec in loaded.manual_routes],
        http_max_retries=loaded.http_max_retries,
        http_retry_base_delay_seconds=loaded.http_retry_base_delay_seconds,
        http_circuit_breaker_threshold=loaded.http_circuit_breaker_threshold,
        http_circuit_breaker_cooldown_seconds=loaded.http_circuit_breaker_cooldown_seconds,
        module_concurrency=loaded.module_concurrency,
        additional_webhook_providers=[
            ManualWebhookProvider(
                provider_id=spec.provider_id,
                display_name=spec.display_name,
                method=spec.method,
                path=spec.path,
                signature_header=spec.signature_header,
                observed_via=spec.observed_via,
            )
            for spec in loaded.additional_webhook_providers
        ],
    )


def to_endpoint_map(loaded: SettingsSchema) -> EndpointMap:
    """Pure conversion, no DB access -- see to_run_settings."""
    overrides = {op: EndpointSpec(spec.method, spec.path) for op, spec in loaded.endpoint_overrides.items()}
    return EndpointMap(overrides=overrides)


async def get_run_settings(session: AsyncSession) -> RunSettings:
    return to_run_settings(await load_settings(session))


async def get_endpoint_map(session: AsyncSession) -> EndpointMap:
    return to_endpoint_map(await load_settings(session))
