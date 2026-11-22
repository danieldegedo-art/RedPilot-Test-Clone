"""REST endpoints for starting, listing, inspecting, cancelling and
exporting QA runs. This is the core of the dashboard's Start Screen,
QA Dashboard and Test History views."""
from __future__ import annotations

import asyncio
import logging
import uuid
from typing import Any
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.control_port import PurityViolation, ScopePolicyView, get_control_adapter
from app.core.config import settings as app_settings
from app.core.run_registry import active_runners
from app.core.settings_store import load_settings, to_endpoint_map, to_run_settings
from app.db import models as db_models
from app.db.session import SessionLocal, get_session
from app.schemas.run import (
    RequestEvidenceSchema,
    ResponseEvidenceSchema,
    RunCreateRequest,
    RunDetailSchema,
    RunSummarySchema,
    ScanRequest,
    TestResultSchema,
)
from app.testing.collector import ResultCollector
from app.testing.enums import RunStatus, TestScope
from app.testing.event_bus import event_bus
from app.testing.models import RequestEvidence, ResponseEvidence, TestResult
from app.testing.redaction import normalize_result_for_persistence
from app.testing.reporter import Reporter
from app.testing.runner import TestRunner

logger = logging.getLogger("qa.api.runs")

router = APIRouter(prefix="/runs", tags=["runs"])

# Bounds how many runs execute at once. Each run can launch a headless
# Chromium instance (Recon) and do real embedding/ML work per failed test
# result (the cognitive layer's AutonomousImprovementLoop) on top of the
# HTTP traffic against the target -- nothing previously stopped an
# unbounded number of POST /runs calls (a double-clicked "Run QA Suite", a
# CI pipeline firing several environments in parallel, a scripted caller)
# from all executing simultaneously with no backpressure at any layer. A
# run over the limit is still accepted and recorded immediately (status
# stays "queued", matching current behavior and the API contract) -- it
# just doesn't acquire the execution semaphore below until a slot frees,
# so it visibly waits in the dashboard's existing "Queued" state instead
# of silently competing for the same host resources as everything already
# running. See CHANGELOG_COGNITIVE_UPGRADE.md for the fault-isolation pass
# this was added alongside.
_run_semaphore = asyncio.Semaphore(app_settings.max_concurrent_runs)


def _purity_check_or_400(run_settings: Any, endpoints: Any, payload: RunCreateRequest) -> None:
    """Pure Black-Box: refuse non-customer-level credentials / non-customer-facing surfaces up front, with the exact (value-free) reasons."""
    try:
        get_control_adapter().validate_run_inputs(
            custom_headers=run_settings.custom_headers,
            endpoint_overrides=getattr(endpoints, "overrides", None),
            extra_allowed_hosts=payload.extra_allowed_hosts,
            integrity_brief=run_settings.integrity_brief,
        )
    except PurityViolation as violation:
        raise HTTPException(status_code=400, detail={"error": "pure_black_box_violation", "code": violation.code, "message": violation.message}) from violation


def _scope_policy_for(payload: RunCreateRequest) -> ScopePolicyView:
    """Every run's authorised reach: the target host plus whatever extra hosts the
    caller explicitly listed (see RunCreateRequest.extra_allowed_hosts) -- never wider.
    Rate/budget/deadline come from Settings (core/config.py), env-overridable like
    every other QA_-prefixed setting; a run cannot loosen them itself."""
    return get_control_adapter().build_scope_policy(
        str(payload.environment_url),
        extra_hosts=payload.extra_allowed_hosts,
        max_requests=app_settings.max_requests_per_run,
        max_requests_per_second=app_settings.max_requests_per_second,
        deadline_seconds=app_settings.run_deadline_seconds,
    )


def _record_to_result_schema(record: db_models.TestResultRecord) -> TestResultSchema:
    return TestResultSchema(
        id=record.id,
        test_case_id=record.test_case_id,
        category=record.category,
        name=record.name,
        description=record.description,
        input_parameters=record.input_parameters,
        expected=record.expected,
        actual=record.actual,
        status=record.status,
        request=RequestEvidenceSchema(**record.request_json) if record.request_json else None,
        response=ResponseEvidenceSchema(**record.response_json) if record.response_json else None,
        recommendation=record.recommendation,
        started_at=record.started_at,
        finished_at=record.finished_at,
        duration_ms=record.duration_ms,
    )


async def _persist_result_db(run_id: str, result: TestResult) -> None:
    """Write one TestResult through to TestResultRecord immediately (ZR-009).
    Raises on failure -- TestRunner._persist_one_result is what catches,
    logs, and records it in persist_failures; this function's only job is
    the write itself, using its own short-lived session (per-unit-of-work,
    same as get_session() -- never a session reused across an await
    boundary it didn't open, and never the request-scoped session from
    start_run(), which must not outlive the request)."""
    fields = normalize_result_for_persistence({
        "test_case_id": result.test_case_id,
        "name": result.name,
        "input_parameters": result.input_parameters,
        "actual": result.actual,
        "expected": result.expected,
        "recommendation": result.recommendation,
        "description": result.description,
        "request_json": result.request.model_dump(mode="json") if result.request else None,
        "response_json": result.response.model_dump(mode="json") if result.response else None,
    })
    async with SessionLocal() as session:
        session.add(
            db_models.TestResultRecord(
                id=str(result.id),
                run_id=run_id,
                test_case_id=fields["test_case_id"],
                category=result.category if isinstance(result.category, str) else result.category.value,
                name=fields["name"],
                description=fields["description"],
                input_parameters=fields["input_parameters"],
                expected=fields["expected"],
                actual=fields["actual"],
                status=result.status if isinstance(result.status, str) else result.status.value,
                request_json=fields["request_json"],
                response_json=fields["response_json"],
                recommendation=fields["recommendation"],
                started_at=result.started_at,
                finished_at=result.finished_at,
                duration_ms=result.duration_ms,
            )
        )
        await session.commit()


async def _persist_run(runner: TestRunner, collector: ResultCollector, error_message: str | None) -> None:
    async with SessionLocal() as session:
        record = await session.get(db_models.RunRecord, runner.run_id)
        if record is None:
            logger.warning("Run record %s not found when persisting results", runner.run_id)
            return
        record.status = runner.status.value
        record.finished_at = datetime.now(timezone.utc)
        summary = collector.summary()
        # Scope-guard stats (requests used/denied, kill/deadline state) and any
        # modules the scope/enabled-modules intersection silently dropped
        # (Phase-0 finding G6 -- also emitted as a WARNING result, this is the
        # structured counterpart for programmatic consumers of the summary).
        summary["scope_guard"] = runner.guard_stats
        summary["skipped_modules"] = runner.skipped_modules
        # ZR-009: each result is now written through to TestResultRecord by
        # TestRunner._emit_result as it's produced (see runner.py), not
        # batched here -- re-inserting collector.results in a loop at this
        # point would collide on result.id for everything that already
        # persisted cleanly. What belongs here is visibility into whatever
        # DIDN'T make it through at emit time (transient DB error mid-run);
        # those results still exist in collector.results/the live stream,
        # they're just not durable, which is exactly the gap this fixes for
        # everything else. Non-empty is a real signal worth seeing, not
        # expected steady-state.
        summary["persistence_failures"] = runner.persist_failures
        record.summary_json = summary
        record.cognitive_snapshot_json = runner.cognitive_snapshot
        record.error_message = error_message
        await session.commit()


async def _execute_and_persist(runner: TestRunner) -> None:
    async with _run_semaphore:
        error_message: str | None = None
        try:
            collector = await runner.execute()
        except Exception as exc:
            # Before this fix, an exception escaping runner.execute() --
            # e.g. from the discovery layer prior to its own fix in this
            # same pass, or anywhere else not already wrapped in a
            # try/except inside execute() -- meant this function jumped
            # straight past ALL persistence code below with nothing
            # committed: no status update (the row stayed at whatever it
            # was last set to, typically "queued" forever), no summary, no
            # results, and http_client.aclose() never ran either. The
            # failure was only ever visible in backend container logs,
            # invisible from the dashboard/Test History and from any
            # export -- exactly the wrong failure mode for a tool whose
            # purpose is producing audit evidence. Now: still persist
            # everything the run DID collect before it broke (runner.collector
            # holds it regardless of where execute() raised -- it's a plain
            # attribute updated as results come in, not something scoped to
            # the try block) under a real, visible RunStatus.FAILED with
            # `error_message` set, rather than discarding it.
            logger.exception("TestRunner.execute() raised for run %s -- persisting partial results as FAILED", runner.run_id)
            runner.status = RunStatus.FAILED
            error_message = f"{type(exc).__name__}: {exc}"
            collector = runner.collector

        try:
            await _persist_run(runner, collector, error_message)
        except Exception:
            logger.exception("Failed to execute/persist run %s", runner.run_id)
        finally:
            active_runners.pop(runner.run_id, None)


@router.post("", response_model=RunSummarySchema, status_code=202)
async def start_run(payload: RunCreateRequest, session: AsyncSession = Depends(get_session), twin_url: str | None = None, session_cookies: str | None = None, electron_recon: dict | None = None, user_agent: str | None = None) -> RunSummarySchema:
    loaded_settings = await load_settings(session)
    run_settings = to_run_settings(loaded_settings)
    if session_cookies:
        run_settings.custom_headers["Cookie"] = session_cookies
    if user_agent:
        run_settings.user_agent = user_agent
    if electron_recon:
        run_settings.electron_recon = electron_recon
    # Customer-declared integrity contract: a plain 0600 file, never a DB column (no migration). None => the
    # payment_integrity module sends no traffic and only reports the capability gaps.
    run_settings.integrity_brief = get_control_adapter().load_brief(app_settings.integrity_brief_path)
    endpoints = to_endpoint_map(loaded_settings)
    _purity_check_or_400(run_settings, endpoints, payload)
    run_id = str(uuid.uuid4())
    started_at = datetime.now(timezone.utc)

    # ZR-002/ZR-007: construct the durable PESM store ONCE for this run at the real
    # entry point and inject it into the runner (which threads it into the module
    # TestContext). build_feature_registry prefers the SQLAlchemy-backed store and
    # fail-safe-falls-back to the in-memory store, so this never blocks a run.
    from app.testing.modules.payment_integrity import build_feature_registry
    feature_registry = await build_feature_registry()

    runner = TestRunner(
        run_id=run_id,
        base_url=str(payload.environment_url),
        scope=payload.scope,
        settings=run_settings,
        endpoints=endpoints,
        event_bus=event_bus,
        scope_policy=_scope_policy_for(payload),
        persist_result=_persist_result_db,
        feature_registry=feature_registry,
        twin_url=twin_url,
    )
    active_runners[run_id] = runner

    session.add(
        db_models.RunRecord(
            id=run_id,
            environment_url=str(payload.environment_url),
            scope=payload.scope.value,
            status=RunStatus.QUEUED.value,
            started_at=started_at,
        )
    )
    await session.commit()

    # Fire-and-forget: execution runs in the background and persists via its
    # own DB session once complete (request-scoped sessions must not be
    # reused across the request/response boundary). Actual execution start
    # is additionally gated by _run_semaphore inside _execute_and_persist --
    # the task is always created immediately (so cancellation and listing
    # work right away), but it may sit waiting to acquire a slot, during
    # which the run stays visibly "queued".
    asyncio.create_task(_execute_and_persist(runner))

    return RunSummarySchema(
        run_id=run_id,
        status=RunStatus.QUEUED,
        environment_url=str(payload.environment_url),
        scope=payload.scope,
        started_at=started_at,
        summary=None,
    )


@router.post("/scan", response_model=RunSummarySchema, status_code=202)
async def scan_cold_domain(payload: ScanRequest, session: AsyncSession = Depends(get_session)) -> RunSummarySchema:
    """Paste a cold domain URL, press run. Everything fires at full power automatically.

    No brief file, no scope selection, no extra config. The system auto-generates
    an execution brief from the domain, runs ALL 20 modules + cognitive analysis +
    discovery layer + payment integrity engine with all 13 probes enabled.
    """
    run_request = RunCreateRequest(
        environment_url=payload.url,
        scope=TestScope.FULL_REGRESSION,
        extra_allowed_hosts=[],
    )
    electron_recon = None
    if payload.recon_html or payload.recon_network_calls:
        electron_recon = {
            "html": payload.recon_html or "",
            "network_calls": [c.model_dump() for c in (payload.recon_network_calls or [])],
            "cookie_names": payload.recon_cookie_names or [],
        }
    return await start_run(
        run_request, session,
        twin_url=str(payload.twin_url) if payload.twin_url else None,
        session_cookies=payload.session_cookies,
        electron_recon=electron_recon,
        user_agent=payload.user_agent,
    )


@router.get("", response_model=list[RunSummarySchema])
async def list_runs(limit: int = Query(50, le=200), session: AsyncSession = Depends(get_session)) -> list[RunSummarySchema]:
    stmt = select(db_models.RunRecord).order_by(db_models.RunRecord.started_at.desc()).limit(limit)
    rows = (await session.execute(stmt)).scalars().all()
    return [
        RunSummarySchema(
            run_id=row.id,
            status=RunStatus(row.status),
            environment_url=row.environment_url,
            scope=TestScope(row.scope),
            started_at=row.started_at,
            finished_at=row.finished_at,
            summary=row.summary_json,
            error_message=row.error_message,
        )
        for row in rows
    ]


@router.get("/{run_id}", response_model=RunDetailSchema)
async def get_run(
    run_id: str,
    status: str | None = Query(None, description="Filter by PASS/FAIL/WARNING/INFO/ERROR"),
    category: str | None = Query(None, description="Filter by functional/negative/edge_case/error_handling/integration"),
    session: AsyncSession = Depends(get_session),
) -> RunDetailSchema:
    record = await session.get(db_models.RunRecord, run_id, options=[selectinload(db_models.RunRecord.results)])
    if record is None:
        raise HTTPException(status_code=404, detail=f"Run {run_id} not found")

    results = record.results
    if status:
        results = [r for r in results if r.status == status.upper()]
    if category:
        results = [r for r in results if r.category == category.lower()]

    return RunDetailSchema(
        run_id=record.id,
        status=RunStatus(record.status),
        environment_url=record.environment_url,
        scope=TestScope(record.scope),
        started_at=record.started_at,
        finished_at=record.finished_at,
        summary=record.summary_json,
        cognitive_snapshot=record.cognitive_snapshot_json,
        results=[_record_to_result_schema(r) for r in results],
        error_message=record.error_message,
    )


@router.delete("/{run_id}", status_code=204)
async def cancel_run(run_id: str) -> None:
    runner = active_runners.get(run_id)
    if runner is None:
        raise HTTPException(status_code=404, detail=f"Run {run_id} is not currently active")
    runner.cancel()


@router.get("/{run_id}/export")
async def export_run(
    run_id: str,
    export_format: str = Query("json", pattern="^(json|csv|pdf)$", alias="format"),
    session: AsyncSession = Depends(get_session),
) -> Response:
    record = await session.get(db_models.RunRecord, run_id, options=[selectinload(db_models.RunRecord.results)])
    if record is None:
        raise HTTPException(status_code=404, detail=f"Run {run_id} not found")

    collector = ResultCollector(run_id=run_id)
    for r in record.results:
        # NOTE (fault-isolation pass): ResultCollector.add is `async def` --
        # this loop previously called it without `await`, which does not
        # run the coroutine body at all (no error, no warning; the
        # coroutine object is simply created and discarded). Every export
        # (JSON, CSV, and PDF alike, since all three read from the same
        # `collector` populated here) silently reflected zero results
        # regardless of how many the run actually had. Fixed by awaiting
        # it, as every other call site in this codebase already does.
        await collector.add(
            TestResult(
                test_case_id=r.test_case_id,
                category=r.category,
                name=r.name,
                description=r.description,
                input_parameters=r.input_parameters,
                expected=r.expected,
                actual=r.actual,
                status=r.status,
                request=RequestEvidence(**r.request_json) if r.request_json else None,
                response=ResponseEvidence(**r.response_json) if r.response_json else None,
                recommendation=r.recommendation,
                started_at=r.started_at,
                finished_at=r.finished_at,
                duration_ms=r.duration_ms,
            )
        )

    reporter = Reporter(collector, environment_url=record.environment_url, scope=record.scope)

    if export_format == "json":
        return Response(
            content=reporter.to_json(),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="qa-report-{run_id}.json"'},
        )
    if export_format == "csv":
        return Response(
            content=reporter.to_csv(),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="qa-report-{run_id}.csv"'},
        )
    return Response(
        content=reporter.to_pdf(),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="qa-report-{run_id}.pdf"'},
    )
