"""TestRunner: orchestrates async execution of test modules for one run.

Resolves which modules apply to the requested scope (intersected with the
user's enabled-modules setting), runs them in order, streams status/phase/
result events to the EventBus as it goes, and returns the populated
ResultCollector when done.

This version integrates the Cognitive Architecture:
- After all standard modules complete, the CognitiveEngine analyzes
  every collected result through the full cognitive cycle
- The engine forms hypotheses, identifies patterns, and generates
  intelligent findings beyond what static test cases check for
- Results from the cognitive analysis are emitted as their own
  category (INTELLIGENT_DISCOVERY) alongside the standard results
- The engine's recommendations are included in the run summary

The cognitive layer runs AFTER all other modules finish (same as the
original discovery layer) because it needs the complete evidence base
to reason over.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from collections.abc import Awaitable, Callable

from app.core.control_port import ScopePolicyView, get_control_adapter
from app.testing.collector import ResultCollector
from app.testing.context import RunSettings, TestContext
from app.testing.discovery.engine import DiscoveryEngine
from app.testing.endpoints import EndpointMap
from app.testing.enums import ResultStatus, RunStatus, TestCategory, TestScope
from app.testing.event_bus import EventBus
from app.testing.http_client import QAHttpClient
from app.testing.models import TestResult
from app.testing.recon.function_mapper import FunctionMap
from app.testing.registry import MODULE_REGISTRY, SCOPE_MODULES, batch_execution_order
from app.testing.url_utils import origin_of, target_identity_key

logger = logging.getLogger("qa.runner")

# ZR-009: how TestRunner writes each result through to durable storage the
# moment it's produced, instead of only in a single batch after the whole run
# finishes. Injected (same pattern as `event_bus: EventBus` below) rather than
# imported directly, on purpose: runner.py stays DB-free and importable/
# testable without sqlalchemy, exactly as it was before this fix, and the
# sequencing/crash-survival/error-handling behaviour can be verified with a
# fake implementation (see tests/test_write_through_persistence.py) instead of
# requiring a real Postgres to even exercise. api/v1/runs.py supplies the real
# SQLAlchemy-backed implementation at the one place TestRunner is constructed
# for an actual run.
PersistResultFn = Callable[[str, TestResult], Awaitable[None]]


async def _noop_persist_result(run_id: str, result: TestResult) -> None:
    """Default when no persist_result is supplied: do nothing, same as this
    codebase's behaviour before ZR-009. Keeps every existing TestRunner(...)
    call site (tests included) working unchanged -- only api/v1/runs.py's
    production call site opts into real persistence, explicitly."""
    return None


class TestRunner:
    def __init__(
        self,
        run_id: str,
        base_url: str,
        scope: TestScope,
        settings: RunSettings,
        endpoints: EndpointMap,
        event_bus: EventBus,
        scope_policy: ScopePolicyView | None = None,
        persist_result: PersistResultFn | None = None,
        feature_registry: Any = None,
    ) -> None:
        # Pure Black-Box: only customer-level synthetic credentials and customer-facing surfaces may ever reach a target. Refused HERE,
        # before any request exists (defence in depth: start_run answers 400 earlier with the same reasons).
        get_control_adapter().validate_run_inputs(
            custom_headers=settings.custom_headers,
            endpoint_overrides=getattr(endpoints, "overrides", None),
            extra_allowed_hosts=[h for h in (scope_policy.allowed_hosts if scope_policy else ())],
            integrity_brief=settings.integrity_brief,
        )
        self.run_id = run_id
        self.entry_url = base_url  # exactly what the user typed -- Recon loads this page
        self.base_url = origin_of(base_url)  # clean origin -- every API-calling module sends requests here
        self.scope = scope
        self.settings = settings
        self.endpoints = endpoints
        self.event_bus = event_bus
        self._persist_result: PersistResultFn = persist_result or _noop_persist_result
        # ZR-002/ZR-007: the durable PESM store, constructed once at the API boundary
        # (api/v1/runs.py::start_run) and injected here, then threaded into the module
        # TestContext below. None => the PaymentIntegrityModule falls back to building
        # one itself (build_feature_registry), so the durable store is used either way.
        self._feature_registry: Any = feature_registry
        self.collector = ResultCollector(run_id=run_id)
        self.status = RunStatus.QUEUED
        self._cancel_requested = False
        # ZR-009: result ids that were produced (in collector.results / already
        # live-streamed) but could NOT be written through to TestResultRecord
        # at the time they were emitted. Surfaced in the run summary (see
        # api/v1/runs.py::_persist_run) instead of silently dropping them --
        # the in-memory/live copy still exists, only the durable copy is missing.
        self.persist_failures: list[str] = []
        self.cognitive_snapshot: dict[str, Any] | None = None
        # Secure default: only the host the user typed (any port) and the entry
        # page's host are in scope; budget/rate come from ScopePolicy defaults or
        # the caller's explicit policy (api/v1/runs.py builds it from config).
        controls = get_control_adapter()
        self.guard = controls.create_run_guard(
            scope_policy
            or controls.build_scope_policy(self.base_url, extra_hosts=[urlparse(self.entry_url).hostname or ""])
        )
        self.skipped_modules: list[str] = []
        self.guard_stats: dict[str, Any] | None = None

    def cancel(self) -> None:
        self._cancel_requested = True
        # Effective INSIDE a running module, not only between batches: every
        # further request any module attempts is denied immediately.
        self.guard.kill("run cancelled by user")

    async def execute(self) -> ResultCollector:
        self.status = RunStatus.INITIALIZING
        await self.event_bus.publish(self.run_id, {"type": "status", "status": self.status.value})

        http_client = QAHttpClient(
            base_url=self.base_url,
            timeout_seconds=self.settings.timeout_seconds,
            proxy_url=self.settings.proxy_url,
            headers=self.settings.custom_headers,
            user_agent=self.settings.user_agent,
            max_retries=self.settings.http_max_retries,
            retry_base_delay_seconds=self.settings.http_retry_base_delay_seconds,
            circuit_breaker_threshold=self.settings.http_circuit_breaker_threshold,
            circuit_breaker_cooldown_seconds=self.settings.http_circuit_breaker_cooldown_seconds,
            guard=self.guard,
        )
        context = TestContext(
            run_id=self.run_id,
            base_url=self.base_url,
            entry_url=self.entry_url,
            scope=self.scope,
            settings=self.settings,
            endpoints=self.endpoints,
            http=http_client,
            guard=self.guard,
            feature_registry=self._feature_registry,
        )

        # A module planned for this scope but absent from the enabled-modules
        # setting used to vanish silently (Phase-0 finding G6). It is now an
        # explicit, visible coverage result.
        planned_modules = SCOPE_MODULES[self.scope]
        effective_modules = planned_modules & self.settings.enabled_modules
        self.skipped_modules = sorted(planned_modules - effective_modules)
        self.guard.start()
        batches = batch_execution_order(effective_modules)

        self.status = RunStatus.RUNNING
        await self.event_bus.publish(self.run_id, {"type": "status", "status": self.status.value})
        if self.skipped_modules:
            await self._emit_result(self._scope_coverage_result())

        module_concurrency = max(1, self.settings.module_concurrency)
        batch_semaphore = asyncio.Semaphore(module_concurrency)

        for batch in batches:
            if self._cancel_requested:
                self.status = RunStatus.CANCELLED
                await self.event_bus.publish(self.run_id, {"type": "status", "status": self.status.value})
                break

            if len(batch) == 1:
                # Exactly today's behavior for every module outside the
                # verified-independent cluster: one at a time, own phase
                # announcement.
                await self._run_one_module(context, batch[0], announce=True)
                continue

            # A batch here is a run of PARALLEL_SAFE_MODULES (see
            # registry.py for the evidence gating membership: no
            # shared_state dependency AND no shared/mutable target-side
            # resource between any two of them). Bounded by
            # module_concurrency so a big batch doesn't throw every request
            # at the target in the same instant -- each module still makes
            # its own requests through the same QAHttpClient (and the same
            # CircuitBreaker/retry policy) it always has; this only changes
            # which modules may be in flight at once, not how any single
            # module talks to the target.
            display_names = ", ".join(
                (MODULE_REGISTRY[m].display_name if m in MODULE_REGISTRY else m) for m in batch
            )
            await self.event_bus.publish(self.run_id, {
                "type": "phase",
                "phase": f"Running {len(batch)} independent modules in parallel (max {module_concurrency} at once): {display_names}",
            })

            async def _bounded(module_id: str) -> None:
                async with batch_semaphore:
                    await self._run_one_module(context, module_id, announce=False)

            await asyncio.gather(*(_bounded(module_id) for module_id in batch))

        # -- Cognitive Analysis Layer ---------------------------------------
        # Runs after all modules complete, analyzing the full evidence base
        # through the cognitive architecture (hypothesis formation, pattern
        # recognition, multi-perspective reasoning, etc.)
        if (
            not self._cancel_requested
            and self.status == RunStatus.RUNNING
            and self.settings.discovery_layer_enabled
            and self.collector.results
        ):
            await self.event_bus.publish(self.run_id, {
                "type": "phase",
                "phase": "Running cognitive analysis layer",
            })

            try:
                cognitive_results = await self._run_cognitive_analysis(context, http_client)
                for result in cognitive_results:
                    await self._emit_result(result)
            except Exception as exc:
                logger.exception("Cognitive analysis layer crashed")
                error_result = TestResult(
                    test_case_id="COGNITIVE-ERROR",
                    category=TestCategory.INTELLIGENT_DISCOVERY,
                    name="Cognitive analysis layer error",
                    description="The cognitive analysis layer encountered an unhandled exception.",
                    input_parameters={},
                    expected="Cognitive analysis completes without crashing.",
                    actual=f"{type(exc).__name__}: {exc}",
                    status=ResultStatus.ERROR,
                    started_at=datetime.now(timezone.utc),
                    finished_at=datetime.now(timezone.utc),
                    duration_ms=0.0,
                )
                await self._emit_result(error_result)

        # -- Intelligent Discovery Layer (retrospective) ---------------------
        # Original discovery layer — runs after cognitive analysis
        if (
            not self._cancel_requested
            and self.status == RunStatus.RUNNING
            and self.settings.discovery_layer_enabled
            and self.collector.results
        ):
            await self.event_bus.publish(self.run_id, {
                "type": "phase",
                "phase": "Running intelligent discovery layer",
            })

            try:
                function_map = context.shared_state.get("function_map")
                discovery_engine = DiscoveryEngine(
                    self.collector.results, function_map if isinstance(function_map, FunctionMap) else None
                )
                await discovery_engine.run(self._emit_result)
            except Exception as exc:
                # Mirrors the Cognitive Analysis Layer's try/except directly
                # above -- until this fix, this was the one late-run stage
                # without it: an exception here (after all modules AND the
                # cognitive layer already succeeded) propagated out of
                # execute() entirely, which api/v1/runs.py's
                # _execute_and_persist never reached its own persistence
                # code for either (see that file's fix in the same pass) --
                # silently losing every result this run collected, with the
                # DB row stuck at its last-persisted status forever. Discovery
                # analyzers are additionally isolated from EACH OTHER inside
                # discovery/engine.py's own _run_analyzers -- this outer
                # try/except is the backstop for anything outside a single
                # analyzer (e.g. DiscoveryEngine construction itself).
                logger.exception("Discovery layer crashed")
                error_result = TestResult(
                    test_case_id="DISCOVERY-ERROR",
                    category=TestCategory.INTELLIGENT_DISCOVERY,
                    name="Discovery layer error",
                    description=(
                        "The intelligent discovery layer encountered an unhandled exception outside any "
                        "single analyzer (see discovery/engine.py's own per-analyzer isolation for "
                        "exceptions raised inside one of the nine analyzers, which do not reach here)."
                    ),
                    input_parameters={},
                    expected="Discovery analysis completes without crashing.",
                    actual=f"{type(exc).__name__}: {exc}",
                    status=ResultStatus.ERROR,
                    started_at=datetime.now(timezone.utc),
                    finished_at=datetime.now(timezone.utc),
                    duration_ms=0.0,
                )
                await self._emit_result(error_result)

        # -- Finalize ----------------------------------------------------------
        self.guard_stats = self.guard.stats()
        if self._cancel_requested and self.status == RunStatus.RUNNING:
            self.status = RunStatus.CANCELLED
        if self.status == RunStatus.RUNNING:
            self.status = RunStatus.COMPLETED

        await self.event_bus.publish(self.run_id, {
            "type": "status",
            "status": self.status.value,
            "summary": self.collector.summary(),
        })

        await http_client.aclose()
        return self.collector

    def _scope_coverage_result(self) -> TestResult:
        now = datetime.now(timezone.utc)
        return TestResult(
            test_case_id="SCOPE-COVERAGE",
            category=TestCategory.PAYMENT_INTEGRITY,
            name="Planned modules were not executed (disabled in Settings)",
            description=(
                "Modules planned for the requested scope are intersected with the enabled-modules "
                "setting. Modules dropped by that intersection did not run, so the vulnerability "
                "classes they cover are UNKNOWN for this run -- not safe."
            ),
            input_parameters={"scope": self.scope.value, "skipped_modules": self.skipped_modules},
            expected="Every module planned for the requested scope executes, or its omission is explicit.",
            actual=(
                f"{len(self.skipped_modules)} planned module(s) skipped because they are not in the "
                f"enabled-modules setting: {', '.join(self.skipped_modules)}."
            ),
            status=ResultStatus.WARNING,
            recommendation="Enable the listed modules in Settings (or accept the documented coverage gap for this run).",
            started_at=now,
            finished_at=now,
            duration_ms=0.0,
        )

    async def _emit_result(self, result: TestResult) -> None:
        await self.collector.add(result)
        await self.event_bus.publish(self.run_id, {"type": "result", "result": result.model_dump(mode="json")})
        await self._persist_one_result(result)

    async def _persist_one_result(self, result: TestResult) -> None:
        """ZR-009 (evidence must not vanish after engine.run()): write ``result``
        through to durable storage immediately via the injected
        ``self._persist_result``, instead of only at the end of the run.

        Before this fix, every result lived ONLY in ``self.collector.results``
        (a plain in-memory list -- see collector.py) and the live event-bus
        stream until the ENTIRE run finished, at which point a single loop in
        ``api/v1/runs.py::_persist_run`` inserted every row at once. A clean
        run already persisted everything correctly on completion; the actual
        gap was anything in between -- a crash, container restart, or OOM
        kill between the run starting and that final commit lost every result
        collected so far, and the DB/REST API could show nothing for an
        in-progress run (only an actively-connected websocket client saw
        anything). Each result is now durable the moment it's produced (when
        persist_result is the real, DB-backed implementation -- see
        api/v1/runs.py), so a mid-run crash only loses what was never even
        reported.

        A failure here is logged loudly and recorded in self.persist_failures;
        it must NEVER raise outward -- the in-memory/live-stream copy this ran
        after is the fallback of record, and one write hiccup must not abort a
        live run any more than one module crashing does (see _run_one_module).
        """
        try:
            await self._persist_result(self.run_id, result)
        except Exception:
            logger.exception("Failed to write-through result %s (run %s) -- kept in memory/live stream only", result.id, self.run_id)
            self.persist_failures.append(str(result.id))

    async def _run_one_module(self, context: TestContext, module_id: str, *, announce: bool) -> None:
        """Runs exactly one module to completion: SKIP-result if it isn't
        registered, crashes caught and turned into an ERROR result (never
        propagated -- one module's bug must not take down its batch, exactly
        as it must not take down the sequential loop this replaces). Used
        for both single-module batches (today's exact sequential behavior)
        and as the per-module unit of work `execute()`'s parallel batches
        gather -- each concurrent call gets its own local `module_cls`/
        `module`/`exc` bindings (ordinary Python locals inside a coroutine
        call), so concurrent invocations don't share or race on any of
        this method's own state. `self.collector.add` and
        `self.event_bus.publish` are safe to call from multiple concurrently
        running coroutines on the same event loop (see collector.py /
        CircuitBreaker's own single-event-loop reasoning) -- there is
        nothing here a lock would need to protect."""
        module_cls = MODULE_REGISTRY.get(module_id)
        if module_cls is None:
            result = TestResult(
                test_case_id=f"SKIP-{module_id}",
                category=TestCategory.RUN_META,
                name=f"Module not implemented: {module_id}",
                description=f"The module '{module_id}' is scoped for this run but not yet implemented.",
                input_parameters={},
                expected="N/A",
                actual="Skipped: module not in MODULE_REGISTRY.",
                status=ResultStatus.INFO,
                started_at=datetime.now(timezone.utc),
                finished_at=datetime.now(timezone.utc),
                duration_ms=0.0,
            )
            await self._emit_result(result)
            return

        if announce:
            await self.event_bus.publish(self.run_id, {
                "type": "phase",
                "phase": f"Running module: {module_cls.display_name}",
            })

        try:
            module = module_cls(context, self._emit_result)
            await module.run()
        except Exception as exc:
            logger.exception("Module %s crashed", module_id)
            error_result = TestResult(
                test_case_id=f"ERROR-{module_id}",
                category=TestCategory.ERROR_HANDLING,
                name=f"Module crashed: {module_id}",
                description=f"Module {module_id} raised an unhandled exception during execution.",
                input_parameters={},
                expected="Module completes without crashing.",
                actual=f"{type(exc).__name__}: {exc}",
                status=ResultStatus.ERROR,
                started_at=datetime.now(timezone.utc),
                finished_at=datetime.now(timezone.utc),
                duration_ms=0.0,
            )
            await self._emit_result(error_result)

    async def _run_cognitive_analysis(
        self, context: TestContext, http_client: QAHttpClient
    ) -> list[TestResult]:
        """Runs the cognitive analysis layer over all collected results.

        This is where the 'thinking' happens: the CognitiveEngine receives
        every test result from the standard modules and applies hypothesis
        formation, pattern recognition, multi-perspective analysis, and
        self-reflection to generate intelligent findings that no static
        test case would produce.
        """
        from app.testing.cognition.engine import CognitiveEngine
        from app.testing.cognition.blackboard import AttentionPriority
        from app.core.config import settings as app_settings
        from benchmark.ambiguous_case_resolution import build_ambiguous_resolution_config_from_settings

        results: list[TestResult] = []

        # Initialize the cognitive engine. Storage is keyed by the TARGET
        # (origin_of(base_url), hashed -- see target_identity_key), not by
        # run_id: the whole point of the persistent-memory / coverage-mapper
        # layers is that they accumulate across runs against the same
        # system under test. A run_id-scoped path would hand every single
        # run a fresh, empty database and silently defeat that.
        target_key = target_identity_key(self.base_url)
        resolution_config = build_ambiguous_resolution_config_from_settings(app_settings)
        engine = CognitiveEngine(
            storage_path=f"qa_cognition/{target_key}",
            coverage_db_path=f"qa_cognition/{target_key}/coverage.db",
            enable_persistence=self.settings.discovery_layer_enabled,
            enable_experimental_cognition_modules=app_settings.enable_experimental_cognition_modules,
            ambiguous_resolution_config=resolution_config if resolution_config.enabled else None,
            episodic_retention_seconds=app_settings.episodic_retention_seconds,
        )

        system_context = {
            "run_id": self.run_id,
            "base_url": self.base_url,
            "scope": self.scope.value,
            "entry_url": self.entry_url,
            "total_results_so_far": len(self.collector.results),
        }

        engine.initialize(system_context)

        # Process every result through the cognitive cycle
        cognitive_findings_count = 0
        now = datetime.now(timezone.utc)

        for test_result in self.collector.results:
            # Convert TestResult to observation dict for the engine
            observation = {
                "test_case_id": test_result.test_case_id,
                "category": test_result.category if isinstance(test_result.category, str) else test_result.category.value,
                "status": test_result.status if isinstance(test_result.status, str) else test_result.status.value,
                "endpoint": test_result.request.url if test_result.request else "",
                "method": test_result.request.method if test_result.request else "",
                "status_code": test_result.response.status_code if test_result.response else None,
                "elapsed_ms": test_result.response.elapsed_ms if test_result.response else None,
                "body": test_result.response.body if test_result.response else None,
                "headers": test_result.response.headers if test_result.response else {},
                "duration_ms": test_result.duration_ms,
                "name": test_result.name,
                "actual": test_result.actual[:200] if test_result.actual else "",
                "recommendation": test_result.recommendation[:200] if test_result.recommendation else "",
            }

            # Process through cognitive engine
            decision = await engine.process_observation(observation)

            # If the engine decided something significant, record it
            if decision.get("action") not in ("continue_current_approach", "not_initialized"):
                cognitive_findings_count += 1

            # Record outcome for learning
            await engine.record_outcome(
                {
                    "test_case_id": test_result.test_case_id,
                    "status": observation["status"],
                    "actual": observation["actual"],
                    "request": {
                        "url": observation["endpoint"],
                        "method": observation["method"],
                    },
                }
            )

            # Learn from execution
            await engine.learn_from_execution({
                "test_case_id": test_result.test_case_id,
                "status": observation["status"],
                "category": observation["category"],
                "duration_ms": test_result.duration_ms,
                "actual": observation["actual"],
                "recommendation": observation["recommendation"],
            })

        # Run self-reflection
        reflection = engine.reflect()

        # Get intelligent recommendations
        recommendations = engine.get_intelligent_recommendations()

        # End session and get final report
        session_report = engine.end_session({
            "total_results": len(self.collector.results),
            "total_findings": sum(1 for r in self.collector.results if r.status == ResultStatus.FAIL),
        })

        # Structured snapshot (hypotheses, coverage, memory-store stats,
        # LLM-Ersatz-Layer findings) for the Cognitive Insights API/
        # dashboard view -- captured here while the engine is still alive
        # since belief_system/self_reflection state doesn't persist to
        # disk the way memory_store/coverage_mapper do.
        try:
            self.cognitive_snapshot = engine.get_snapshot()
        except Exception:
            logger.exception("Failed to capture cognitive snapshot for run %s", self.run_id)
            self.cognitive_snapshot = None

        # Generate cognitive analysis result
        cognitive_result = TestResult(
            test_case_id="COGNITIVE-ANALYSIS",
            category=TestCategory.INTELLIGENT_DISCOVERY,
            name="Cognitive analysis layer summary",
            description=(
                "Applies the full cognitive architecture (hypothesis formation, "
                "belief revision, multi-perspective reasoning, self-reflection, "
                "and persistent memory) to every result collected by the standard "
                "modules. Generates intelligent findings that no static test case "
                "would produce."
            ),
            input_parameters={
                "observations_processed": session_report.get("observations_processed", 0),
                "hypotheses_formed": session_report.get("hypotheses_formed", 0),
                "discoveries_recorded": session_report.get("discoveries_recorded", 0),
                "decisions_made": session_report.get("decisions_made", 0),
            },
            expected="N/A - informational summary of cognitive processing.",
            actual=self._format_cognitive_summary(session_report, recommendations, reflection),
            status=ResultStatus.INFO,
            started_at=now,
            finished_at=datetime.now(timezone.utc),
            duration_ms=0.0,
        )
        results.append(cognitive_result)

        # Generate hypothesis summary
        belief_stats = engine.belief_system.get_statistics()
        if belief_stats.get("total_hypotheses", 0) > 0:
            hypothesis_result = TestResult(
                test_case_id="COGNITIVE-HYPOTHESES",
                category=TestCategory.INTELLIGENT_DISCOVERY,
                name="Hypotheses formed during cognitive analysis",
                description=(
                    "Lists all hypotheses the cognitive engine formed about the "
                    "system under test during this run, along with their current "
                    "confidence levels and status. These represent the engine's "
                    "'beliefs' about what inconsistencies may exist."
                ),
                input_parameters={
                    "total_hypotheses": belief_stats.get("total_hypotheses", 0),
                    "confirmed": belief_stats.get("confirmed_hypotheses", 0),
                    "refuted": belief_stats.get("refuted_hypotheses", 0),
                    "active": belief_stats.get("active_hypotheses", 0),
                },
                expected="N/A - informational.",
                actual=self._format_hypothesis_summary(belief_stats),
                status=ResultStatus.INFO,
                started_at=now,
                finished_at=datetime.now(timezone.utc),
                duration_ms=0.0,
            )
            results.append(hypothesis_result)

        # Generate self-reflection result
        reflection_quality = reflection.get("reasoning_quality", {})
        if reflection_quality.get("quality") in ("low", "moderate"):
            reflection_result = TestResult(
                test_case_id="COGNITIVE-REFLECTION",
                category=TestCategory.INTELLIGENT_DISCOVERY,
                name="Self-reflection findings",
                description=(
                    "The cognitive engine's self-assessment of its own reasoning "
                    "quality during this run. Identifies biases, blind spots, and "
                    "strategy corrections for future runs."
                ),
                input_parameters={
                    "quality_score": reflection_quality.get("score", 0.0),
                    "calibration_status": reflection.get("calibration", {}).get("calibration_status", "unknown"),
                    "biases_detected": len(reflection.get("biases", {}).get("by_type", {})),
                    "blind_spots": len(reflection.get("blind_spots", [])),
                },
                expected="N/A - informational self-assessment.",
                actual=self._format_reflection_summary(reflection),
                status=ResultStatus.INFO,
                started_at=now,
                finished_at=datetime.now(timezone.utc),
                duration_ms=0.0,
            )
            results.append(reflection_result)

        # Generate recommendations result if there are meaningful ones
        if recommendations.get("suggested_next_test"):
            rec_result = TestResult(
                test_case_id="COGNITIVE-RECOMMENDATIONS",
                category=TestCategory.INTELLIGENT_DISCOVERY,
                name="Cognitive recommendations for next steps",
                description=(
                    "The cognitive engine's intelligent recommendations for what "
                    "to test next, based on active hypotheses, expected information "
                    "gain, and accumulated knowledge from this and prior sessions."
                ),
                input_parameters={
                    "top_hypotheses": len(recommendations.get("top_hypotheses", [])),
                    "best_strategies": len(recommendations.get("best_strategies", [])),
                },
                expected="N/A - informational recommendations.",
                actual=self._format_recommendations(recommendations),
                status=ResultStatus.INFO,
                started_at=now,
                finished_at=datetime.now(timezone.utc),
                duration_ms=0.0,
            )
            results.append(rec_result)

        return results

    def _format_cognitive_summary(
        self,
        session_report: dict,
        recommendations: dict,
        reflection: dict,
    ) -> str:
        """Formats the cognitive analysis summary for display."""
        lines = []

        lines.append(f"Observations processed: {session_report.get('observations_processed', 0)}")
        lines.append(f"Hypotheses formed: {session_report.get('hypotheses_formed', 0)}")
        lines.append(f"Discoveries recorded: {session_report.get('discoveries_recorded', 0)}")
        lines.append(f"Decisions made: {session_report.get('decisions_made', 0)}")

        knowledge = session_report.get("knowledge_accumulated", {})
        if knowledge:
            lines.append("")
            lines.append("Knowledge accumulated:")
            lines.append(f"  Confirmed hypotheses: {knowledge.get('confirmed_hypotheses', 0)}")
            lines.append(f"  Refuted hypotheses: {knowledge.get('refuted_hypotheses', 0)}")
            lines.append(f"  Active hypotheses: {knowledge.get('active_hypotheses', 0)}")

        quality = reflection.get("reasoning_quality", {})
        if quality:
            lines.append("")
            lines.append(f"Reasoning quality: {quality.get('quality', 'unknown')} (score: {quality.get('score', 0.0):.2f})")

        calibration = reflection.get("calibration", {})
        if calibration:
            lines.append(f"Calibration: {calibration.get('calibration_status', 'unknown')} (score: {calibration.get('calibration_score', 0.0):.2f})")

        next_session = session_report.get("recommendations_for_next_session", [])
        if next_session:
            lines.append("")
            lines.append("Recommendations for next session:")
            for rec in next_session[:5]:
                lines.append(f"  - {rec}")

        return "\n".join(lines)

    def _format_hypothesis_summary(self, belief_stats: dict) -> str:
        """Formats the hypothesis summary for display."""
        lines = []

        top = belief_stats.get("top_hypotheses", [])
        if top:
            lines.append("Top hypotheses by confidence:")
            for i, hyp in enumerate(top, start=1):
                lines.append(
                    f"  {i}. [{hyp.get('status', 'unknown').upper()}] "
                    f"{hyp.get('description', '')[:80]} "
                    f"(confidence: {hyp.get('confidence', 0.0):.0%})"
                )

        by_type = belief_stats.get("hypotheses_by_type", {})
        if by_type:
            lines.append("")
            lines.append("Hypotheses by type:")
            for hyp_type, count in sorted(by_type.items(), key=lambda pair: pair[1], reverse=True):
                lines.append(f"  {hyp_type}: {count}")

        return "\n".join(lines)

    def _format_reflection_summary(self, reflection: dict) -> str:
        """Formats the self-reflection summary for display."""
        lines = []

        biases = reflection.get("biases", {})
        bias_types = biases.get("by_type", {})
        if bias_types:
            lines.append("Detected reasoning biases:")
            for bias_type, info in bias_types.items():
                lines.append(f"  {bias_type}: {info.get('count', 0)} occurrence(s), severity: {info.get('max_severity', 'low')}")

        blind_spots = reflection.get("blind_spots", [])
        if blind_spots:
            lines.append("")
            lines.append("Identified blind spots:")
            for bs in blind_spots[:5]:
                if isinstance(bs, dict):
                    lines.append(f"  [{bs.get('severity', 'medium').upper()}] {bs.get('description', '')[:80]}")

        corrections = reflection.get("strategy_corrections", [])
        if corrections:
            lines.append("")
            lines.append("Strategy corrections recommended:")
            for sc in corrections[:3]:
                if isinstance(sc, dict):
                    lines.append(f"  [{sc.get('priority', 'medium').upper()}] {sc.get('recommended_behavior', '')[:80]}")

        recommendations = reflection.get("recommendations", [])
        if recommendations:
            lines.append("")
            lines.append("Overall recommendations:")
            for rec in recommendations[:5]:
                lines.append(f"  - {rec}")

        if not lines:
            lines.append("No significant reasoning issues detected — reasoning quality appears adequate.")

        return "\n".join(lines)

    def _format_recommendations(self, recommendations: dict) -> str:
        """Formats the cognitive recommendations for display."""
        lines = []

        suggested = recommendations.get("suggested_next_test")
        if suggested:
            lines.append("Suggested next test:")
            lines.append(f"  Hypothesis: {suggested.get('description', '')[:80]}")
            lines.append(f"  Confidence: {suggested.get('confidence', 0.0):.0%}")
            lines.append(f"  Information gain: {suggested.get('information_gain', 0.0):.2f}")

        top_hypotheses = recommendations.get("top_hypotheses", [])
        if top_hypotheses:
            lines.append("")
            lines.append("Top active hypotheses:")
            for i, hyp in enumerate(top_hypotheses[:3], start=1):
                lines.append(f"  {i}. {hyp.get('description', '')[:70]} ({hyp.get('confidence', 0.0):.0%})")

        stopping = recommendations.get("optimal_stopping", {})
        if stopping:
            lines.append("")
            lines.append(f"Optimal stopping: {stopping.get('recommendation', 'unknown')}")
            lines.append(f"  Reason: {stopping.get('reason', 'N/A')[:80]}")

        best_strategies = recommendations.get("best_strategies", [])
        if best_strategies:
            lines.append("")
            lines.append("Best verification strategies:")
            for i, strategy in enumerate(best_strategies[:3], start=1):
                lines.append(f"  {i}. {strategy.get('name', '')[:50]} (fitness: {strategy.get('fitness', 0.0):.2f})")

        return "\n".join(lines)
