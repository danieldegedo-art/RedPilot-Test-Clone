"""Cognitive Architecture Engine — Master Orchestrator.

This is the main entry point for the cognitive architecture that
sits above and coordinates all test modules. It integrates all
cognitive components into a unified "thinking" system:

CORE (original 9) — always active, verified to be reachable from
process_observation()/record_outcome() below, not merely instantiated:
1. BlackboardWorkspace — Shared consciousness / coordination
2. BeliefRevisionSystem — Dynamic hypothesis evolution
3. PersistentKnowledgeStore — Cross-session memory
4. ActiveExperimentSelector — Optimal test selection
5. MultiPerspectiveReasoner — Multi-viewpoint analysis
6. EmergentStrategyGenerator — Novel strategy creation
7. SelfReflectionEngine — Metacognition and blind spot detection
8. MultiTimescalePlanner — Hierarchical planning

EVOLUTION (6) — split by whether anything actually calls their core
method, not just their constructor:
9. HypothesisManager — always active (add_hypothesis() is called from
   process_observation()/learn_from_execution())
10. MemoryCompressor — always active (add_observation()/consolidate())
11. AsyncPipeline — OFF by default (see
    enable_experimental_cognition_modules below): verified, repo-wide,
    that nothing calls process_batch()/start_continuous() outside that
    file's own docstring example
12. HyperparameterOptimizer — always active, but NOT via a top-level
    attribute on this class (there isn't one -- see __init__'s comment
    on Evolution components for why): AutonomousImprovementLoop below
    owns its own instance and calls optimize() from
    process_test_results(), reachable from every failed test result via
    _trigger_improvement_loop(). get_statistics()['hyperparameter_optimizer']
    reports that real instance.
13. MultiAgentEnsemble — OFF by default: verified, repo-wide, that
    nothing calls analyze() outside that file's own docstring example
14. NovelDiscoveryEngine — always active, same situation as
    HyperparameterOptimizer above: owned by AutonomousImprovementLoop,
    called from process_test_results() via _discover_novel()

INFRASTRUCTURE (4) — always active when their own enable_* flag is set:
15. EventBus — Real-time event coordination
16. SubSecondCognition — <10ms decisions via cache
17. AutonomousImprovementLoop — Self-improvement after each run; owns
    its own HyperparameterOptimizer/NovelDiscoveryEngine instances (12,
    14 above), target-scoped alongside this engine's other persisted
    state, bounded by self._improvement_loop_semaphore so a burst of
    failures can't pile up unbounded concurrent background work
18. CoverageMapper — Graph-based test coverage analysis

LLM (benchmark/):
19. LLMReplacementLayer — always active when importable: zero-shot +
    structural + contextual heuristics, no network, no real model call
20. AmbiguousAnomalyResolver — OFF unless an enabled
    AmbiguousResolutionConfig is passed in: local (no network call, ever)
    second opinion for the specific findings the heuristic layer is least
    certain about, using this run's own novelty/occurrence pattern and
    past-run history instead of a model call. Formerly an optional
    real-model call, since removed -- see
    benchmark/ambiguous_case_resolution.py's module docstring for the
    full removal rationale.

11 and 13 (AsyncPipeline, MultiAgentEnsemble) are not broken -- they
simply are not wired to anything yet. Turning
enable_experimental_cognition_modules on instantiates them (so they no
longer silently no-op) but does not, by itself, connect their core
methods to process_observation(); that is separate follow-up work for
whoever picks each one up. This is narrower than an earlier version of
this docstring claimed: 12 and 14 were listed here as also OFF by
default, which was wrong -- they run today, unconditionally, via 17,
not via this flag; the mistake was checking only whether *this class*
called their methods directly and missing that a different class does.

The engine operates as follows:
1. Receives observations from test module execution
2. Checks CognitiveCache for instant (<5ms) response
3. Routes through LLM-Ersatz-Layer for anomaly detection, optionally
   followed by a real-model escalation for the least certain findings
4. Publishes findings to EventBus for real-time coordination
5. Coordinates all components through the blackboard
6. Produces intelligent decisions about what to test next
7. Learns from every execution to improve future testing
8. After each run: triggers improvement loop

This is what makes the system COGNITIVE rather than merely automated:
it thinks about what it's testing, forms hypotheses, revises beliefs,
and gets smarter over time.
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Dict, List, Optional

from app.testing.cognition.blackboard import (
    AttentionPriority,
    BlackboardWorkspace,
    CognitiveCycle,
    Coalition,
    WorkspaceEntry,
)
from app.testing.cognition.belief_revision import (
    BeliefRevisionSystem,
    Evidence,
    Hypothesis,
    HypothesisStatus,
)
from app.testing.cognition.persistent_memory import (
    EpisodicMemory,
    PersistentMemoryStore,
    ProceduralMemory,
    SemanticMemory,
)
from app.testing.cognition.experiment_selector import (
    ActiveExperimentSelector,
    Experiment,
    ExperimentType,
    ExperimentOutcome,
)
from app.testing.cognition.multi_perspective import (
    Argument,
    MultiPerspectiveReasoner,
    PerspectiveType,
    SynthesizedAnalysis,
)
from app.testing.cognition.emergent_strategy import (
    EmergentStrategyGenerator,
    VerificationStrategy,
    StrategyComponent,
)
from app.testing.cognition.self_reflection import (
    BiasType,
    CalibrationStatus,
    SelfReflectionEngine,
)
from app.testing.cognition.multi_timescale_planner import (
    Goal,
    GoalType,
    MultiTimescalePlanner,
    Plan,
    PlanStep,
    Timescale,
)

# Evolution components
from app.testing.cognition.hypothesis_manager import (
    HypothesisManager,
    HypothesisTier,
)
from app.testing.cognition.memory_compressor import MemoryCompressor
from app.testing.cognition.async_pipeline import AsyncPipeline
from app.testing.cognition.multi_agent_ensemble import MultiAgentEnsemble
# HyperparameterOptimizer/NovelDiscoveryEngine deliberately NOT imported
# here anymore: this class no longer constructs its own top-level
# instance of either (see the Evolution-components comment in __init__
# below) -- AutonomousImprovementLoop imports and owns both itself.

# Infrastructure components
from app.testing.cognition.event_bus import (
    EventBus,
    Event,
    EventPriority,
    EventTypes,
)
from app.testing.cognition.sub_second_cognition import SubSecondCognition
from app.testing.cognition.improvement_loop import AutonomousImprovementLoop
from app.testing.cognition.coverage_mapper import CoverageMapper
from app.testing.url_utils import path_of

logger = logging.getLogger("qa.cognition.engine")


class CognitiveEngine:
    """Master orchestrator for the cognitive architecture.

    This engine coordinates all cognitive components and provides
    the interface between the test framework (modules, runner) and
    the thinking layer.

    Usage:
        engine = CognitiveEngine()
        engine.initialize(system_context)

        # During test execution:
        decision = engine.process_observation(observation)
        # decision tells the framework what to do next

        # After test execution:
        engine.record_outcome(test_result)
        engine.learn_from_execution(test_result)

        # Periodically:
        reflection = engine.reflect()
        engine.consolidate_memory()
    """

    def __init__(
        self,
        storage_path: str = "qa_cognition",
        coverage_db_path: str | None = None,
        enable_persistence: bool = True,
        enable_event_bus: bool = True,
        enable_sub_second: bool = True,
        enable_experimental_cognition_modules: bool = False,
        ambiguous_resolution_config: "AmbiguousResolutionConfig | None" = None,
        episodic_retention_seconds: float | None = None,
    ):
        # --- Core components (original) ---
        self.workspace = BlackboardWorkspace()
        self.cognitive_cycle = CognitiveCycle(self.workspace)
        self.belief_system = BeliefRevisionSystem()
        self.self_reflection = SelfReflectionEngine()

        # Persistent memory (optional)
        self._enable_persistence = enable_persistence
        self.memory_store: PersistentMemoryStore | None = None
        if enable_persistence:
            self.memory_store = PersistentMemoryStore(storage_path=storage_path)

        # Coverage mapper -- graph-based CC6.1 "completeness of service
        # coverage" tracking (see also RECON-004). Persisted on the same
        # target-scoped root as memory_store when a path is given, so
        # coverage accumulates across runs against the same target instead
        # of resetting every time; falls back to in-memory-only (no
        # cross-run persistence) if no path is given.
        self.coverage_mapper = CoverageMapper(db_path=coverage_db_path)

        # Intelligent components (original)
        self.experiment_selector = ActiveExperimentSelector(self.belief_system)
        self.multi_perspective = MultiPerspectiveReasoner()
        self.strategy_generator = EmergentStrategyGenerator()
        self.timescale_planner = MultiTimescalePlanner()

        # --- Evolution components (new) ---
        # hypothesis_manager and memory_compressor ARE exercised on the
        # real per-observation/per-outcome path (process_observation,
        # record_outcome below) -- always constructed.
        self.hypothesis_manager = HypothesisManager()
        self.memory_compressor = MemoryCompressor()

        # async_pipeline and multi_agent_ensemble are NOT: verified with a
        # repo-wide search of every call site (not just this file) that
        # their actual entry points (process_batch/start_continuous,
        # analyze) are never invoked anywhere -- the only matches outside
        # their own file are inside that file's own docstring "Usage:"
        # example, not executable code.
        #
        # hyperparameter_optimizer and novel_discovery are DELIBERATELY
        # NOT listed here, unlike an earlier version of this comment
        # claimed: they are not dead. AutonomousImprovementLoop below
        # constructs its own separate instances of both and genuinely
        # calls their core methods (optimize()/discover_novel()) from
        # process_test_results(), triggered on every failed test result
        # via _trigger_improvement_loop() further down. A top-level
        # engine.hyperparameter_optimizer / engine.novel_discovery
        # attribute existed alongside that real, working path and was
        # never read by anything except this engine's own
        # get_statistics() -- i.e. it was a second, disconnected,
        # genuinely-inert instance sitting next to the one that actually
        # runs. Removed rather than flag-gated: there was no meaningful
        # "on" for it in the first place. See get_statistics() below,
        # which now reports the real instance's statistics instead.
        self._enable_experimental_cognition_modules = enable_experimental_cognition_modules
        if enable_experimental_cognition_modules:
            self.async_pipeline = AsyncPipeline()
            self.multi_agent_ensemble = MultiAgentEnsemble(num_agents=15)
        else:
            self.async_pipeline = None
            self.multi_agent_ensemble = None

        # --- Infrastructure components (new) ---
        self._enable_event_bus = enable_event_bus
        self.event_bus = EventBus() if enable_event_bus else None

        self._enable_sub_second = enable_sub_second
        self.sub_second = SubSecondCognition() if enable_sub_second else None

        # Target-scoped, matching PersistentMemoryStore/CoverageMapper
        # above -- BUGFIX (2026-09-20): previously constructed bare
        # (AutonomousImprovementLoop() with every path left at its
        # class-default), so its state was shared/conflated across every
        # different target ever tested from this same process, unlike
        # every other piece of persisted cognition state in this engine.
        self.improvement_loop = AutonomousImprovementLoop(
            db_path=f"{storage_path}/improvement_loop.db",
            patterns_db_path=f"{storage_path}/patterns.db",
            novel_db_path=f"{storage_path}/novel_findings.db",
            hyperparameters_db_path=f"{storage_path}/hyperparameters.db",
        )
        # Bounds the fire-and-forget background work _trigger_improvement_loop
        # queues per failed test result (pattern extraction/validation, a
        # 5-trial Optuna study, a NovelDiscoveryEngine pass) -- see that
        # method below for why an unbounded number of these piling up
        # during a run with many failures was a real, previously-unbounded
        # resource-exhaustion risk, not just a hypothetical one.
        self._improvement_loop_semaphore = asyncio.Semaphore(2)

        # --- LLM-Ersatz (from benchmark/) ---
        self.llm_replacement = None
        self._try_init_llm_replacement()

        # --- Local ambiguous-case resolution on top of the LLM-Ersatz-Layer
        # (from benchmark/ambiguous_case_resolution.py; formerly an
        # optional real-model escalation path, since removed) -- off
        # unless the caller explicitly passes an enabled config; see that
        # module's docstring for the full rationale.
        self.ambiguous_resolver = None
        if ambiguous_resolution_config is not None:
            self._try_init_ambiguous_resolver(ambiguous_resolution_config)

        # Retention: off unless an operator explicitly sets a window (see
        # PersistentMemoryStore.prune_episodic_older_than /
        # CoverageMapper.prune_test_history_older_than for why this
        # project doesn't pick a default value on anyone's behalf).
        # Applied once per end_session() call, not on a timer -- a QA
        # suite's own natural cadence (one prune per completed run) is
        # already the right cadence for this, without adding a scheduler.
        self._episodic_retention_seconds = episodic_retention_seconds

        # State
        self._initialized = False
        self._session_start_time: float | None = None
        self._observations_processed = 0
        self._decisions_made = 0
        self._hypotheses_formed = 0
        self._discoveries_recorded = 0

        # Register default hypothesis generators
        self._register_default_generators()

        # Register default experiment generators
        self._register_default_experiment_generators()

        logger.info(
            "CognitiveEngine initialized "
            "(persistence=%s, event_bus=%s, sub_second=%s, experimental_cognition_modules=%s, ambiguous_resolver=%s)",
            enable_persistence, enable_event_bus, enable_sub_second,
            enable_experimental_cognition_modules, self.ambiguous_resolver is not None,
        )

    def _try_init_llm_replacement(self) -> None:
        """Versucht den LLM-Ersatz-Layer zu initialisieren."""
        try:
            from benchmark.llm_replacement_layer import LLMReplacementLayer
            self.llm_replacement = LLMReplacementLayer()
        except ImportError:
            # benchmark/ Paket nicht verfügbar — LLM-Ersatz ist optional
            self.llm_replacement = None

    def _try_init_ambiguous_resolver(self, config: "AmbiguousResolutionConfig") -> None:
        """Constructs the optional local ambiguous-case resolver. Import
        is local (not at module top) for the same reason
        _try_init_llm_replacement's is: benchmark/ staying importable
        elsewhere even if this specific optional piece isn't available
        must never take the whole engine down with it -- config.enabled/
        resolver.active already degrade gracefully on their own, but a
        broken import shouldn't either."""
        try:
            from benchmark.ambiguous_case_resolution import AmbiguousAnomalyResolver
            self.ambiguous_resolver = AmbiguousAnomalyResolver(config)
        except ImportError:
            logger.warning("benchmark.ambiguous_case_resolution could not be imported; resolution stays disabled.")
            self.ambiguous_resolver = None

    # ------------------------------------------------------------------
    # Default generators (from original engine.py — unchanged)
    # ------------------------------------------------------------------

    def _register_default_generators(self) -> None:
        """Registers default hypothesis generators based on common patterns."""

        def timing_anomaly_generator(observation: dict[str, Any]) -> list[Hypothesis]:
            """Generates hypotheses from timing anomalies."""
            hypotheses = []

            if observation.get("elapsed_ms", 0) > 3000:
                hypotheses.append(Hypothesis(
                    description="This endpoint may have a timing side-channel — response time varies significantly based on internal state",
                    hypothesis_type="timing_side_channel",
                    prior_probability=0.4,
                    test_suggestions=["Compare response times for different resource states", "Check if timing correlates with data existence"],
                ))

            if observation.get("timing_variance", 0) > 0.5:
                hypotheses.append(Hypothesis(
                    description="Response time variance suggests non-deterministic processing — possible race condition or cache behavior",
                    hypothesis_type="nondeterministic_processing",
                    prior_probability=0.3,
                ))

            return hypotheses

        def consistency_anomaly_generator(observation: dict[str, Any]) -> list[Hypothesis]:
            """Generates hypotheses from consistency anomalies."""
            hypotheses = []

            if observation.get("inconsistent_with_prior", False):
                hypotheses.append(Hypothesis(
                    description="This endpoint's response is inconsistent with prior responses — possible state synchronization issue",
                    hypothesis_type="state_synchronization",
                    prior_probability=0.5,
                    test_suggestions=["Compare state across multiple endpoints", "Check if the inconsistency is reproducible"],
                ))

            if observation.get("cross_version_inconsistent", False):
                hypotheses.append(Hypothesis(
                    description="Different API versions return different results for the same resource — validation rules may differ",
                    hypothesis_type="version_inconsistency",
                    prior_probability=0.6,
                ))

            return hypotheses

        def structure_anomaly_generator(observation: dict[str, Any]) -> list[Hypothesis]:
            """Generates hypotheses from structural anomalies."""
            hypotheses = []

            if observation.get("unexpected_fields", False):
                hypotheses.append(Hypothesis(
                    description="Response contains unexpected fields — possible data exposure or debug mode enabled",
                    hypothesis_type="data_exposure",
                    prior_probability=0.5,
                ))

            if observation.get("body_type") == "unexpected":
                hypotheses.append(Hypothesis(
                    description="Response body type doesn't match expected format — possible error in content negotiation or serialization",
                    hypothesis_type="format_inconsistency",
                    prior_probability=0.3,
                ))

            return hypotheses

        def status_anomaly_generator(observation: dict[str, Any]) -> list[Hypothesis]:
            """Generates hypotheses from status code anomalies."""
            hypotheses = []

            status_code = observation.get("status_code", 200)

            if status_code >= 500:
                hypotheses.append(Hypothesis(
                    description=f"Server error (HTTP {status_code}) — possible unhandled edge case or crash",
                    hypothesis_type="server_error",
                    prior_probability=0.7,
                ))

            if status_code == 200 and observation.get("should_have_failed", False):
                hypotheses.append(Hypothesis(
                    description="Request succeeded when it should have been rejected — possible validation gap",
                    hypothesis_type="validation_gap",
                    prior_probability=0.6,
                ))

            return hypotheses

        # Register all generators
        self.belief_system.register_hypothesis_generator(timing_anomaly_generator)
        self.belief_system.register_hypothesis_generator(consistency_anomaly_generator)
        self.belief_system.register_hypothesis_generator(structure_anomaly_generator)
        self.belief_system.register_hypothesis_generator(status_anomaly_generator)

    def _register_default_experiment_generators(self) -> None:
        """Registers default experiment generators."""

        def consistency_experiment_generator(context: dict[str, Any]) -> list[Experiment]:
            """Generates experiments for consistency verification."""
            experiments = []

            endpoint = context.get("endpoint", "")
            if endpoint:
                experiments.append(Experiment(
                    experiment_type=ExperimentType.STATE_TRANSITION_CHECK,
                    description=f"Verify state consistency for {endpoint}",
                    target_endpoint=endpoint,
                    method="GET",
                    related_hypothesis_ids=[],
                    estimated_duration_ms=500.0,
                    estimated_request_count=1,
                    risk_level="low",
                ))

                experiments.append(Experiment(
                    experiment_type=ExperimentType.RACE_CONDITION_CHECK,
                    description=f"Test concurrent access to {endpoint}",
                    target_endpoint=endpoint,
                    method="POST",
                    related_hypothesis_ids=[],
                    estimated_duration_ms=2000.0,
                    estimated_request_count=2,
                    risk_level="medium",
                ))

            return experiments

        def format_experiment_generator(context: dict[str, Any]) -> list[Experiment]:
            """Generates experiments for format consistency."""
            experiments = []

            endpoint = context.get("endpoint", "")
            if endpoint:
                for variant in ["form_urlencoded", "text_plain", "charset_variant", "array_wrap"]:
                    experiments.append(Experiment(
                        experiment_type=ExperimentType.FORMAT_VARIANT_CHECK,
                        description=f"Test {endpoint} with {variant} format",
                        target_endpoint=endpoint,
                        method="POST",
                        parameters={"format": variant},
                        estimated_duration_ms=300.0,
                        estimated_request_count=1,
                        risk_level="low",
                    ))

            return experiments

        # Register generators
        self.experiment_selector.register_experiment_generator(consistency_experiment_generator)
        self.experiment_selector.register_experiment_generator(format_experiment_generator)

    # ------------------------------------------------------------------
    # Initialization
    # ------------------------------------------------------------------

    def initialize(self, system_context: dict[str, Any]) -> None:
        """Initializes the cognitive engine for a new testing session."""
        self._initialized = True
        self._session_start_time = time.time()

        # Start memory session
        if self.memory_store:
            self.memory_store.start_session(system_context)

        # Start event bus
        if self.event_bus:
            asyncio.create_task(self.event_bus.start())

        # Plan the session strategically
        session_goals = self.timescale_planner.plan_session(system_context)

        # Post initial context to workspace
        asyncio.create_task(self.workspace.post(
            entry_type="session_context",
            content=system_context,
            source="engine",
            priority=AttentionPriority.HIGH,
        ))

        # Publish initialization event
        if self.event_bus:
            asyncio.create_task(self.event_bus.publish(
                EventTypes.SYSTEM_HEALTH,
                source="cognitive_engine",
                data={"status": "initialized", "goals": len(session_goals)},
                priority=EventPriority.LOW,
            ))

        logger.info(
            "CognitiveEngine initialized with %d session goals",
            len(session_goals),
        )

    # ------------------------------------------------------------------
    # Main: Process observation
    # ------------------------------------------------------------------

    async def process_observation(self, observation: dict[str, Any]) -> dict[str, Any]:
        """Processes a single observation through the full cognitive cycle.

        NEW: Checks SubSecondCognition cache first for <10ms response.
        NEW: Routes through LLM-Ersatz-Layer for anomaly detection.
        NEW: Publishes findings to EventBus for real-time coordination.
        """
        if not self._initialized:
            return {"action": "not_initialized", "priority": "none"}

        self._observations_processed += 1

        # --- NEW: Sub-second cache check ---
        cache_result = None
        if self.sub_second:
            cache_result = await self.sub_second.make_decision(observation)
            if cache_result.get("cache_hit"):
                self._decisions_made += 1
                return cache_result["decision"]

        start_time = time.perf_counter()

        # --- Step 1: PERCEPTION — Post to workspace ---
        await self.workspace.post(
            entry_type="observation",
            content=observation,
            source="test_module",
            priority=self._determine_priority(observation),
        )

        # --- Step 2: REFLEX — Check for immediate reactions ---
        reflex_response = self.timescale_planner.process_observation(observation)

        # --- Step 3: NEW — LLM-Ersatz-Layer ---
        llm_insights = None
        if self.llm_replacement is not None:
            llm_observation = {
                "request_data": {
                    "url": observation.get("endpoint", ""),
                    "method": observation.get("method", "GET"),
                },
                "response_data": {
                    "status_code": observation.get("status_code", 0),
                    "body": observation.get("body"),
                    "headers": observation.get("headers", {}),
                    "elapsed_ms": observation.get("elapsed_ms", 0),
                },
            }
            llm_insights = self.llm_replacement.analyze_observation(llm_observation)

            # Local ambiguous-case resolution for the findings the
            # heuristic layer above is least certain about (see
            # benchmark/ambiguous_case_resolution.py). No-ops back to
            # `llm_insights` unchanged whenever resolution isn't
            # configured/warranted -- this call is always safe to make.
            if self.ambiguous_resolver is not None:
                llm_insights = await self.ambiguous_resolver.resolve_ambiguous_case(
                    llm_observation["request_data"],
                    llm_observation["response_data"],
                    llm_insights,
                    memory_store=self.memory_store,
                )

            # Publish anomalies to EventBus (reflects the resolved
            # verdict above when resolution ran and changed anything)
            if self.event_bus and llm_insights.suspicious_fields:
                asyncio.create_task(self.event_bus.publish(
                    EventTypes.ANOMALY_DETECTED,
                    source="llm_replacement",
                    data={
                        "endpoint": observation.get("endpoint", ""),
                        "suspicious_count": len(llm_insights.suspicious_fields),
                        "severity": llm_insights.overall_severity,
                    },
                    priority=EventPriority.HIGH if llm_insights.overall_severity in ("high", "critical") else EventPriority.MEDIUM,
                ))

        # --- Step 4: HYPOTHESIS — Generate hypotheses ---
        hypotheses = self.belief_system.generate_hypotheses(observation)
        self._hypotheses_formed += len(hypotheses)

        # NEW: Also add to HypothesisManager (sharded, 10k+)
        for hyp in hypotheses:
            await self.hypothesis_manager.add_hypothesis(
                description=hyp.description,
                hypothesis_type=hyp.hypothesis_type,
                priority=hyp.prior_probability,
            )

        for hypothesis in hypotheses:
            await self.workspace.post(
                entry_type="hypothesis",
                content={
                    "id": hypothesis.id,
                    "description": hypothesis.description,
                    "type": hypothesis.hypothesis_type,
                    "confidence": hypothesis.posterior_probability,
                },
                source="belief_system",
                priority=AttentionPriority.MEDIUM,
                confidence=hypothesis.posterior_probability,
            )

        # --- Step 5: ATTENTION — Run cognitive cycle ---
        cycle_result = await self.cognitive_cycle.run_cycle()

        # --- Step 6: DECISION — Select next experiment ---
        next_experiment = None
        if self.belief_system.get_active_hypotheses():
            next_experiment = self.experiment_selector.select_next_experiment(observation)

        # --- Step 7: MULTI-PERSPECTIVE — If significant ---
        multi_perspective_result = None
        if self._is_significant(observation):
            multi_perspective_result = self.multi_perspective.analyze_situation(
                situation=observation,
                perspectives_to_use=[
                    PerspectiveType.ATTACKER,
                    PerspectiveType.DEFENDER,
                    PerspectiveType.DEVELOPER,
                ],
            )

        # Compile decision
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        self._decisions_made += 1

        decision = {
            "action": self._determine_action(reflex_response, next_experiment, cycle_result),
            "priority": reflex_response.get("priority", "normal"),
            "hypotheses_formed": len(hypotheses),
            "active_hypotheses": len(self.belief_system.get_active_hypotheses()),
            "next_experiment": {
                "description": next_experiment.description,
                "type": next_experiment.experiment_type.value,
                "information_gain": next_experiment.expected_information_gain,
            } if next_experiment else None,
            "cycle_result": {
                "winning_coalition": cycle_result.get("winning_coalition"),
            } if cycle_result else None,
            "llm_insights": {
                "suspicious_fields": len(llm_insights.suspicious_fields) if llm_insights else 0,
                "severity": llm_insights.overall_severity if llm_insights else "none",
                "suspicion_score": llm_insights.overall_suspicion_score if llm_insights else 0.0,
                "assessment_source": llm_insights.assessment_source if llm_insights else "heuristic",
            } if llm_insights else None,
            "multi_perspective": {
                "perspectives": multi_perspective_result.perspectives_covered,
                "blind_spots": len(multi_perspective_result.blind_spots_identified),
            } if multi_perspective_result else None,
            "processing_time_ms": round(elapsed_ms, 2),
        }

        # --- NEW: Cache the decision ---
        if self.sub_second:
            self.sub_second.cache.put(
                observation, decision,
                severity=observation.get("severity", "none"),
            )

        return decision

    # ------------------------------------------------------------------
    # Record outcome
    # ------------------------------------------------------------------

    async def record_outcome(
        self,
        test_result: dict[str, Any],
        hypothesis_id: str | None = None,
        experiment_id: str | None = None,
    ) -> None:
        """Records the outcome of a test execution.

        NEW: Publishes to EventBus.
        NEW: Triggers improvement loop.
        NEW: Offloads its persistent-memory write via asyncio.to_thread so a
        synchronous SQLite commit never blocks the event loop -- this runs
        once per test result (potentially hundreds of times per run), so
        unlike the one-per-run initialize()/end_session() calls, leaving it
        synchronous would visibly stall concurrent work (e.g. WebSocket
        result streaming) for the duration of every commit.
        NEW: Records route coverage in CoverageMapper (CC6.1 completeness
        of service coverage -- was previously wired nowhere).
        """
        outcome = test_result.get("status", "info")
        test_case_id = test_result.get("test_case_id", "unknown")
        request_info = test_result.get("request") or {}
        endpoint = request_info.get("url", "")
        method = request_info.get("method", "")

        # Record in episodic memory (off the event loop: sqlite3 is a
        # blocking C extension, not an async driver)
        if self.memory_store:
            await asyncio.to_thread(
                self.memory_store.store_episodic,
                memory_type="test_result",
                content=test_result,
                context={"endpoint": endpoint, "method": method},
                outcome=outcome,
                tags=[test_case_id, outcome],
            )

        # NEW: Record in memory compressor
        self.memory_compressor.add_observation(
            text=f"Test {test_case_id} on {endpoint or 'unknown'}: {outcome}",
            source=test_case_id,
        )

        # NEW: Record coverage -- every observed (method, path) counts
        # toward CC6.1 completeness of service coverage, regardless of
        # outcome; `detected` reflects whether this check found an
        # inconsistency (FAIL), matching CoverageMapper.record_test's
        # contract.
        if method and endpoint:
            path = path_of(endpoint)
            await asyncio.to_thread(
                self.coverage_mapper.add_endpoint, path, method,
            )
            await asyncio.to_thread(
                self.coverage_mapper.record_test,
                path=path,
                method=method,
                check_type=test_result.get("category", test_case_id.split("-")[0].lower()),
                detected=outcome == "fail",
            )

        # Update hypotheses with evidence
        if hypothesis_id:
            supports = outcome in ("pass", "warning")
            evidence = Evidence(
                evidence_type="test_result",
                content={
                    "test_case_id": test_case_id,
                    "status": outcome,
                    "actual": test_result.get("actual", ""),
                },
                supports=supports,
                strength=0.7 if outcome == "pass" else 0.5,
                source=test_case_id,
            )
            self.belief_system.register_evidence(hypothesis_id, evidence)

        # Update experiment selector
        if experiment_id:
            experiment_outcome = ExperimentOutcome(
                experiment_id=experiment_id,
                informative=outcome in ("fail", "warning"),
                evidence_type="test_result",
                evidence_content=test_result,
                discoveries=[test_result.get("actual", "")] if outcome == "fail" else [],
            )
            self.experiment_selector.record_outcome(experiment_outcome)

        # Record for self-reflection
        self.self_reflection.record_reasoning(
            context=f"Test {test_case_id} on {endpoint or 'unknown'}",
            hypothesis_formed="",
            evidence_considered=[f"Result: {outcome}"],
            conclusion=f"Test {test_case_id} resulted in {outcome}",
            confidence=0.8 if outcome in ("pass", "fail") else 0.5,
        )

        # NEW: Publish to EventBus
        if self.event_bus:
            event_type = EventTypes.FINDING_DETECTED if outcome == "fail" else EventTypes.TEST_COMPLETED
            priority = EventPriority.HIGH if outcome == "fail" else EventPriority.MEDIUM

            asyncio.create_task(self.event_bus.publish(
                event_type,
                source="cognitive_engine",
                data={
                    "test_case_id": test_case_id,
                    "status": outcome,
                    "endpoint": endpoint,
                },
                priority=priority,
            ))

    # ------------------------------------------------------------------
    # Learn from execution
    # ------------------------------------------------------------------

    async def learn_from_execution(self, test_result: dict[str, Any]) -> None:
        """Learns from a test execution.

        NEW: Triggers improvement loop asynchronously.
        """
        # Store in persistent memory
        if self.memory_store:
            await asyncio.to_thread(
                self.memory_store.store_episodic,
                memory_type="execution_learning",
                content={
                    "test_case_id": test_result.get("test_case_id"),
                    "outcome": test_result.get("status"),
                    "duration_ms": test_result.get("duration_ms", 0),
                    "lessons": self._extract_lessons(test_result),
                },
                context={
                    "category": test_result.get("category", ""),
                    "module": test_result.get("test_case_id", "").split("-")[0],
                },
                outcome=test_result.get("status", "info"),
            )

        # If this was a discovery, record it
        if test_result.get("status") == "fail":
            self._discoveries_recorded += 1

            # NEW: Record in HypothesisManager
            await self.hypothesis_manager.add_hypothesis(
                description=f"Finding: {test_result.get('actual', '')[:80]}",
                hypothesis_type="confirmed_finding",
                priority=0.95,
            )

        # NEW: Trigger improvement loop (non-blocking)
        asyncio.create_task(
            self._trigger_improvement_loop(test_result)
        )

    async def _trigger_improvement_loop(self, test_result: dict[str, Any]) -> None:
        """Triggers the improvement loop after significant findings.

        Bounded by self._improvement_loop_semaphore (see __init__): each
        call does real work (pattern extraction/validation, a 5-trial
        Optuna study, a NovelDiscoveryEngine pass), and this is fired via
        asyncio.create_task -- untracked and, before this fix, unbounded
        -- for every single failed test result. A run against a
        genuinely broken environment producing many failures in a burst
        could otherwise pile up an unbounded number of these
        concurrently; the semaphore caps how many actually run at once,
        and later ones simply wait their turn instead of piling on.
        """
        if test_result.get("status") == "fail":
            try:
                async with self._improvement_loop_semaphore:
                    await self.improvement_loop.process_test_results(
                        test_results=[test_result],
                        app_seed=0,
                    )
            except Exception as exc:
                logger.debug("Improvement loop error: %s", exc)

    # ------------------------------------------------------------------
    # NEW: Coverage and Progress
    # ------------------------------------------------------------------

    def record_test_coverage(
        self,
        path: str,
        method: str,
        check_type: str,
        detected: bool = False,
    ) -> None:
        """Records test coverage for an endpoint. record_outcome() already
        does this automatically for every test result processed through the
        standard pipeline; this remains as a direct entry point for
        anything recording coverage outside that pipeline (e.g. a manual
        or future integration)."""
        self.coverage_mapper.add_endpoint(path, method)
        self.coverage_mapper.record_test(path=path, method=method, check_type=check_type, detected=detected)

    def get_coverage_report(self) -> dict[str, Any]:
        """Returns the current CC6.1 completeness-of-service-coverage
        report as a plain dict (see CoverageMapper.calculate_coverage)."""
        report = self.coverage_mapper.calculate_coverage()
        return asdict(report)

    def get_learning_progress(self) -> dict[str, Any]:
        """Returns the learning progress from the improvement loop."""
        return self.improvement_loop.get_learning_progress()

    def get_improvement_statistics(self) -> dict[str, Any]:
        """Returns improvement loop statistics."""
        return self.improvement_loop.get_statistics()

    def get_snapshot(self) -> dict[str, Any]:
        """Returns the cognitive architecture's full current state as
        plain, JSON-serializable data: top hypotheses, belief-system
        statistics, self-reflection/calibration status, accumulated
        knowledge-store statistics, and the CC6.1 coverage report.

        This is what backs the Cognitive Insights API/dashboard view --
        previously the only way to see any of this was to read prose
        crammed into a handful of INFO-status TestResult.actual strings
        (COGNITIVE-ANALYSIS, COGNITIVE-HYPOTHESES), which is fine as run
        evidence but unusable as a live, structured "what does the brain
        currently know" view.
        """

        def hypothesis_dict(h: Hypothesis) -> dict[str, Any]:
            d = asdict(h)
            d["status"] = h.status.value
            d["confidence"] = h.confidence
            d["evidence_count"] = h.evidence_count
            d["support_ratio"] = h.support_ratio
            return d

        top_hypotheses = [hypothesis_dict(h) for h in self.belief_system.get_top_hypotheses(10)]

        memory_stats: dict[str, Any] = {}
        if self.memory_store:
            memory_stats = self.memory_store.get_statistics()

        return {
            "belief_system": self.belief_system.get_statistics(),
            "top_hypotheses": top_hypotheses,
            "self_reflection": self.self_reflection.get_self_verification(),
            "memory_store": memory_stats,
            "coverage": self.get_coverage_report(),
            "llm_replacement_active": self.llm_replacement is not None,
            "llm_replacement": self.llm_replacement.get_statistics() if self.llm_replacement else None,
            "ambiguous_resolver_active": self.ambiguous_resolver is not None and self.ambiguous_resolver.active,
            "ambiguous_resolver": self.ambiguous_resolver.get_statistics() if self.ambiguous_resolver else None,
            "event_bus_active": self.event_bus is not None,
            "experimental_cognition_modules_enabled": self._enable_experimental_cognition_modules,
        }

    # ------------------------------------------------------------------
    # Reflection and consolidation (from original — with additions)
    # ------------------------------------------------------------------

    def reflect(self) -> dict[str, Any]:
        """Performs a self-reflection cycle."""
        reflection = self.self_reflection.reflect()

        reflection["cognitive_metrics"] = {
            "observations_processed": self._observations_processed,
            "decisions_made": self._decisions_made,
            "hypotheses_formed": self._hypotheses_formed,
            "discoveries_recorded": self._discoveries_recorded,
            "active_hypotheses": len(self.belief_system.get_active_hypotheses()),
            "confirmed_hypotheses": len(self.belief_system.get_confirmed_hypotheses()),
        }

        # NEW: Add sub-second stats
        if self.sub_second:
            reflection["sub_second_stats"] = self.sub_second.get_stats()

        # NEW: Add event bus stats
        if self.event_bus:
            reflection["event_bus_stats"] = self.event_bus.get_statistics()

        # NEW: Add hypothesis manager stats
        reflection["hypothesis_manager_stats"] = {
            "total": self.hypothesis_manager.shards[0].size if self.hypothesis_manager.shards else 0,
        }

        return reflection

    def consolidate_memory(self) -> dict[str, Any]:
        """Triggers memory consolidation."""
        if not self.memory_store:
            return {"consolidated": False, "reason": "Persistence disabled"}

        result = self.memory_store.consolidate()

        # Also evolve strategies
        new_strategies = self.strategy_generator.evolve_generation()
        result["new_strategies_generated"] = len(new_strategies)

        # NEW: Also consolidate memory compressor
        compression_result = self.memory_compressor.consolidate()
        result["memory_compression"] = compression_result

        return result

    # ------------------------------------------------------------------
    # Recommendations and reports
    # ------------------------------------------------------------------

    def get_intelligent_recommendations(self) -> dict[str, Any]:
        """Returns intelligent recommendations from all components."""
        recommendations: dict[str, Any] = {}

        # From belief system
        top_hypotheses = self.belief_system.get_top_hypotheses(5)
        recommendations["top_hypotheses"] = [
            {
                "description": h.description[:100],
                "confidence": h.posterior_probability,
                "status": h.status.value,
            }
            for h in top_hypotheses
        ]

        # From experiment selector
        suggested_test = self.belief_system.suggest_next_test()
        recommendations["suggested_next_test"] = suggested_test
        recommendations["optimal_stopping"] = self.experiment_selector.get_optimal_stopping_recommendation()

        # From strategy generator
        best_strategies = self.strategy_generator.get_best_strategies({}, 3)
        recommendations["best_strategies"] = [
            {"name": s.name[:60], "fitness": s.fitness_score}
            for s in best_strategies
        ]

        # NEW: From hypothesis manager
        recommendations["hypothesis_capacity"] = "10,000+ (sharded)"

        # NEW: From memory compressor
        recommendations["memory_compression"] = self.memory_compressor.get_statistics()

        # NEW: From multi-agent ensemble (None when
        # enable_experimental_cognition_modules is off -- see engine
        # module docstring for why that's the default)
        recommendations["ensemble_stats"] = (
            self.multi_agent_ensemble.get_statistics() if self.multi_agent_ensemble else None
        )

        # NEW: Learning progress
        recommendations["learning_progress"] = self.get_learning_progress()

        return recommendations

    # ------------------------------------------------------------------
    # End session
    # ------------------------------------------------------------------

    def end_session(self, session_summary: dict[str, Any]) -> dict[str, Any]:
        """Ends the cognitive session."""
        if not self._initialized:
            return {"ended": False, "reason": "Not initialized"}

        final_reflection = self.reflect()
        consolidation_result = self.consolidate_memory()

        if self.memory_store:
            self.memory_store.end_session(session_summary)

        # NEW: Retention (opt-in only -- see __init__'s
        # episodic_retention_seconds comment). Best-effort: a pruning
        # failure must not fail session teardown.
        retention_result: dict[str, int] | None = None
        if self._episodic_retention_seconds is not None:
            retention_result = {}
            try:
                if self.memory_store:
                    retention_result["episodic_memories_pruned"] = self.memory_store.prune_episodic_older_than(
                        self._episodic_retention_seconds
                    )
                retention_result["test_history_pruned"] = self.coverage_mapper.prune_test_history_older_than(
                    self._episodic_retention_seconds
                )
            except Exception:
                logger.warning("Retention pruning failed during end_session; continuing.", exc_info=True)

        # NEW: Stop event bus
        if self.event_bus:
            asyncio.create_task(self.event_bus.stop())

        session_duration = time.time() - (self._session_start_time or time.time())

        report = {
            "session_duration_seconds": session_duration,
            "observations_processed": self._observations_processed,
            "decisions_made": self._decisions_made,
            "hypotheses_formed": self._hypotheses_formed,
            "discoveries_recorded": self._discoveries_recorded,
            "final_reflection": final_reflection,
            "consolidation_result": consolidation_result,
            "retention_result": retention_result,
            "knowledge_accumulated": {
                "total_hypotheses": len(self.belief_system._hypotheses),
                "confirmed_hypotheses": len(self.belief_system.get_confirmed_hypotheses()),
                "active_hypotheses": len(self.belief_system.get_active_hypotheses()),
            },
            "recommendations_for_next_session": self.timescale_planner._meta_strategist.get_recommended_focus({}),
        }

        self._initialized = False

        return report

    # ------------------------------------------------------------------
    # Statistics and export
    # ------------------------------------------------------------------

    def get_statistics(self) -> dict[str, Any]:
        """Returns comprehensive statistics."""
        stats = {
            "initialized": self._initialized,
            "session_duration": time.time() - (self._session_start_time or time.time()),
            "observations_processed": self._observations_processed,
            "decisions_made": self._decisions_made,
            "hypotheses_formed": self._hypotheses_formed,
            "discoveries_recorded": self._discoveries_recorded,
        }

        # Component statistics
        stats["workspace"] = self.workspace.get_statistics()
        stats["belief_system"] = self.belief_system.get_statistics()
        stats["experiment_selector"] = self.experiment_selector.get_statistics()
        stats["self_reflection"] = self.self_reflection.get_statistics()
        stats["timescale_planner"] = self.timescale_planner.get_statistics()

        # NEW: Evolution components. multi_agent_ensemble is None unless
        # enable_experimental_cognition_modules=True (genuinely dead
        # otherwise -- see engine module docstring). hyperparameter_optimizer
        # is NOT gated by that flag: it always reflects
        # improvement_loop.optimizer's real, running statistics (see this
        # class's __init__ comment on why there is no separate top-level
        # instance to gate here).
        stats["hypothesis_manager"] = "10,000+ capacity (sharded)"
        stats["memory_compressor"] = self.memory_compressor.get_statistics()
        stats["multi_agent_ensemble"] = self.multi_agent_ensemble.get_statistics() if self.multi_agent_ensemble else None
        stats["hyperparameter_optimizer"] = self.improvement_loop.optimizer.get_statistics()

        # NEW: Infrastructure
        if self.event_bus:
            stats["event_bus"] = self.event_bus.get_statistics()
        if self.sub_second:
            stats["sub_second_cognition"] = self.sub_second.get_stats()
        stats["improvement_loop"] = self.improvement_loop.get_statistics()

        if self.memory_store:
            stats["memory_store"] = self.memory_store.get_statistics()

        if self.ambiguous_resolver:
            stats["ambiguous_resolver"] = self.ambiguous_resolver.get_statistics()

        return stats

    def export_state(self) -> dict[str, Any]:
        """Exports the complete cognitive state."""
        return {
            "belief_system": self.belief_system.export_state(),
            "strategies": self.strategy_generator.export_strategies(),
            "statistics": self.get_statistics(),
            "session_info": {
                "initialized": self._initialized,
                "observations_processed": self._observations_processed,
                "decisions_made": self._decisions_made,
            },
        }

    # ------------------------------------------------------------------
    # Helpers (from original — unchanged)
    # ------------------------------------------------------------------

    def _determine_priority(self, observation: dict[str, Any]) -> AttentionPriority:
        if observation.get("status_code", 200) >= 500:
            return AttentionPriority.CRITICAL
        if observation.get("status") == "fail":
            return AttentionPriority.HIGH
        if observation.get("unexpected", False):
            return AttentionPriority.MEDIUM
        return AttentionPriority.LOW

    def _is_significant(self, observation: dict[str, Any]) -> bool:
        if observation.get("status") == "fail":
            return True
        if observation.get("unexpected", False):
            return True
        if observation.get("status_code", 200) >= 500:
            return True
        if observation.get("timing_anomaly", False):
            return True

        endpoint = observation.get("endpoint", "")
        if endpoint:
            for hypothesis in self.belief_system.get_active_hypotheses():
                if endpoint in hypothesis.description:
                    return True

        return False

    def _determine_action(
        self,
        reflex_response: dict[str, Any],
        next_experiment: Experiment | None,
        cycle_result: dict[str, Any] | None,
    ) -> str:
        if reflex_response.get("action") == "handle_critical_reflex":
            return "investigate_anomaly"

        if next_experiment:
            return f"execute_experiment:{next_experiment.experiment_type.value}"

        if cycle_result and cycle_result.get("winning_coalition"):
            return "investigate_coalition"

        return "continue_current_approach"

    def _extract_lessons(self, test_result: dict[str, Any]) -> list[str]:
        lessons = []
        status = test_result.get("status", "")
        test_case_id = test_result.get("test_case_id", "")

        if status == "fail":
            lessons.append(f"Test {test_case_id} revealed an issue — {test_result.get('actual', '')[:80]}")
        elif status == "pass":
            lessons.append(f"Verification approach for {test_case_id.split('-')[0]} worked correctly")
        elif status == "warning":
            lessons.append(f"Test {test_case_id} produced ambiguous results")

        duration = test_result.get("duration_ms", 0)
        if duration > 5000:
            lessons.append(f"Test took {duration:.0f}ms — consider optimization")

        return lessons
