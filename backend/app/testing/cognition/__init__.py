"""Cognitive Architecture Package.

Provides the "thinking" layer that sits above and coordinates the
individual test modules. Unlike static test scripts, this layer:

- Forms hypotheses about the system under test based on observations
- Revises those hypotheses dynamically as new evidence arrives
- Maintains a persistent knowledge base across test sessions
- Actively selects which experiments will yield maximum information
- Reasons from multiple perspectives simultaneously
- Generates novel verification strategies through conceptual recombination
- Monitors its own reasoning process for biases and blind spots
- Plans across multiple time horizons (reflexes to campaigns)

Components (Core — original 9):
- engine: Main orchestrator integrating all components
- blackboard: Global workspace for coordination
- belief_revision: Dynamic hypothesis formation and evolution
- persistent_memory: Cross-session knowledge accumulation
- experiment_selector: Optimal test selection via information gain
- multi_perspective: Role-based analysis from multiple viewpoints
- emergent_strategy: Novel strategy generation through recombination
- self_reflection: Metacognition and blind spot detection
- multi_timescale_planner: Hierarchical planning across time horizons

Components (Evolution — extended capability):
- hypothesis_manager: Sharded manager for 10,000+ hypotheses
- memory_compressor: Semantic pattern compression with FAISS
- async_pipeline: 4-stage parallel observation processing
- hyperparameter_optimizer: Automatic self-optimization via Optuna
- multi_agent_ensemble: 10-50 parallel analysis agents
- novel_discovery: Cross-domain analogies and side-channel detection

Components (Infrastructure):
- event_bus: Redis-Streams-based real-time event coordination
- improvement_loop: Autonomous self-improvement after each run
- sub_second_cognition: Sub-10ms decisions via cache + speculation
- coverage_mapper: Graph-based test coverage analysis
"""
from app.testing.cognition.engine import CognitiveEngine
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
    MultiPerspectiveReasoner,
    PerspectiveType,
    SynthesizedAnalysis,
)
from app.testing.cognition.emergent_strategy import (
    EmergentStrategyGenerator,
    VerificationStrategy,
)
from app.testing.cognition.self_reflection import SelfReflectionEngine
from app.testing.cognition.multi_timescale_planner import (
    Goal,
    GoalType,
    MultiTimescalePlanner,
    Timescale,
)

# Evolution components
from app.testing.cognition.hypothesis_manager import (
    HypothesisManager,
    HypothesisTier,
    ManagedHypothesis,
)
from app.testing.cognition.memory_compressor import (
    MemoryCompressor,
    ObservationChunk,
)
from app.testing.cognition.async_pipeline import (
    AsyncPipeline,
    AmortizedInferenceCache,
    PipelineStage,
)
from app.testing.cognition.hyperparameter_optimizer import (
    HyperparameterOptimizer,
    Hyperparameter,
    OptimizationResult,
)
from app.testing.cognition.multi_agent_ensemble import (
    MultiAgentEnsemble,
    AgentPerspective,
    AgentBias,
    EnsembleConsensus,
)
from app.testing.cognition.novel_discovery import (
    NovelDiscoveryEngine,
    NovelFinding,
    CrossDomainAnalogy,
    SideChannelResult,
)

# Infrastructure components
from app.testing.cognition.event_bus import (
    EventBus,
    Event,
    EventPriority,
    EventTypes,
)
from app.testing.cognition.improvement_loop import (
    AutonomousImprovementLoop,
    ImprovementCycleResult,
    LearningProgress,
)
from app.testing.cognition.sub_second_cognition import (
    SubSecondCognition,
    CognitiveCache,
    SpeculativeExecutor,
)
from app.testing.cognition.coverage_mapper import (
    CoverageMapper,
    CoverageReport,
    CoverageGap,
    TestRecommendation,
)

__all__ = [
    # Core (original 9)
    "CognitiveEngine",
    "BlackboardWorkspace",
    "CognitiveCycle",
    "AttentionPriority",
    "Coalition",
    "WorkspaceEntry",
    "BeliefRevisionSystem",
    "Evidence",
    "Hypothesis",
    "HypothesisStatus",
    "PersistentMemoryStore",
    "EpisodicMemory",
    "SemanticMemory",
    "ProceduralMemory",
    "ActiveExperimentSelector",
    "Experiment",
    "ExperimentType",
    "ExperimentOutcome",
    "MultiPerspectiveReasoner",
    "PerspectiveType",
    "SynthesizedAnalysis",
    "EmergentStrategyGenerator",
    "VerificationStrategy",
    "SelfReflectionEngine",
    "MultiTimescalePlanner",
    "Goal",
    "GoalType",
    "Timescale",

    # Evolution (6 new)
    "HypothesisManager",
    "HypothesisTier",
    "ManagedHypothesis",
    "MemoryCompressor",
    "ObservationChunk",
    "AsyncPipeline",
    "AmortizedInferenceCache",
    "PipelineStage",
    "HyperparameterOptimizer",
    "Hyperparameter",
    "OptimizationResult",
    "MultiAgentEnsemble",
    "AgentPerspective",
    "AgentBias",
    "EnsembleConsensus",
    "NovelDiscoveryEngine",
    "NovelFinding",
    "CrossDomainAnalogy",
    "SideChannelResult",

    # Infrastructure (4 new)
    "EventBus",
    "Event",
    "EventPriority",
    "EventTypes",
    "AutonomousImprovementLoop",
    "ImprovementCycleResult",
    "LearningProgress",
    "SubSecondCognition",
    "CognitiveCache",
    "SpeculativeExecutor",
    "CoverageMapper",
    "CoverageReport",
    "CoverageGap",
    "TestRecommendation",
]
