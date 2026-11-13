"""Multi-Timescale Planner — Hierarchical Planning Across Time Horizons.

Implements the cognitive ability to plan simultaneously on multiple
time scales — from millisecond reflexes to multi-session campaigns.
Unlike tools that only think about the current test, this component
maintains plans at four levels:

1. REFLEX LEVEL (< 100ms): Immediate reactions to observations
   "This response time is anomalous — flag it now"

2. TACTICAL LEVEL (seconds to minutes): Current test sequence
   "Next, verify the state consistency across v1 and v2 endpoints"

3. STRATEGIC LEVEL (minutes to hours): Overall testing campaign
   "Focus on payment flow consistency for this session, then move
   to subscription lifecycle in the next phase"

4. META LEVEL (across sessions): Learning strategy
   "Based on accumulated experience, prioritize webhook consistency
   checks for systems with this architecture pattern"

Implements concepts from:
- Hierarchical Reinforcement Learning (Options Framework)
- Temporal Abstraction in Planning
- Goal-Stack Management from classical AI planning
- Means-Ends Analysis for goal decomposition

The planner coordinates all four levels simultaneously:
- Reflexes inform tactics (an anomaly triggers a tactical investigation)
- Tactics serve strategies (each test contributes to the session goal)
- Strategies follow meta-strategies (session goals align with learning)
- Meta-strategies adapt based on what strategies discover
"""
from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable
from uuid import uuid4


class Timescale(Enum):
    """The four planning time scales."""
    REFLEX = "reflex"          # < 100ms — immediate reactions
    TACTICAL = "tactical"      # seconds to minutes — current test sequence
    STRATEGIC = "strategic"    # minutes to hours — session-level plan
    META = "meta"              # across sessions — learning strategy


class PlanStatus(Enum):
    """Status of a plan at any level."""
    PENDING = "pending"
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    ABANDONED = "abandoned"
    SUPERSEDED = "superseded"


class GoalType(Enum):
    """Types of goals at different planning levels."""
    # Reflex goals
    FLAG_ANOMALY = "flag_anomaly"
    RECORD_OBSERVATION = "record_observation"
    TRIGGER_ALERT = "trigger_alert"

    # Tactical goals
    VERIFY_CONSISTENCY = "verify_consistency"
    TEST_HYPOTHESIS = "test_hypothesis"
    GATHER_EVIDENCE = "gather_evidence"
    VALIDATE_FINDING = "validate_finding"

    # Strategic goals
    COVER_ENDPOINT_GROUP = "cover_endpoint_group"
    COMPLETE_TEST_PHASE = "complete_test_phase"
    ACHIEVE_COVERAGE_TARGET = "achieve_coverage_target"
    INVESTIGATE_PATTERN = "investigate_pattern"

    # Meta goals
    IMPROVE_TESTING_EFFICIENCY = "improve_testing_efficiency"
    EXPAND_KNOWLEDGE_BASE = "expand_knowledge_base"
    REFINE_STRATEGY_LIBRARY = "refine_strategy_library"
    ADAPT_TO_SYSTEM_TYPE = "adapt_to_system_type"


@dataclass
class Goal:
    """A single goal at any planning level."""
    id: str = field(default_factory=lambda: str(uuid4()))
    goal_type: GoalType = GoalType.GATHER_EVIDENCE
    timescale: Timescale = Timescale.TACTICAL
    description: str = ""
    success_criteria: str = ""
    priority: float = 0.5  # 0.0 to 1.0

    # Hierarchy
    parent_goal_id: str | None = None
    sub_goal_ids: list[str] = field(default_factory=list)

    # Status
    status: PlanStatus = PlanStatus.PENDING
    progress: float = 0.0  # 0.0 to 1.0

    # Timing
    created_at: float = field(default_factory=time.time)
    deadline: float | None = None  # Optional deadline (unix timestamp)
    estimated_duration: float = 0.0  # Seconds
    actual_duration: float = 0.0

    # Context
    context: dict[str, Any] = field(default_factory=dict)
    dependencies: list[str] = field(default_factory=list)  # Other goal IDs this depends on
    blocks: list[str] = field(default_factory=list)  # Goals blocked by this one

    # Results
    outcome: str = ""
    lessons_learned: list[str] = field(default_factory=list)

    @property
    def is_expired(self) -> bool:
        """Whether this goal has passed its deadline."""
        if self.deadline is None:
            return False
        return time.time() > self.deadline

    @property
    def urgency(self) -> float:
        """How urgent this goal is (0.0 to 1.0)."""
        if self.status != PlanStatus.ACTIVE:
            return 0.0

        base_urgency = self.priority

        # Increase urgency if approaching deadline
        if self.deadline:
            time_remaining = self.deadline - time.time()
            if time_remaining < 60:
                base_urgency = min(1.0, base_urgency + 0.3)
            elif time_remaining < 300:
                base_urgency = min(1.0, base_urgency + 0.1)

        # Decrease urgency if progress is good
        base_urgency *= (1.0 - self.progress * 0.5)

        return base_urgency


@dataclass
class PlanStep:
    """A single step in a plan — an executable action."""
    id: str = field(default_factory=lambda: str(uuid4()))
    goal_id: str = ""
    description: str = ""
    action_type: str = ""  # "http_request", "state_check", "analysis", "wait", "branch"
    parameters: dict[str, Any] = field(default_factory=dict)

    # Sequencing
    depends_on: list[str] = field(default_factory=list)  # Step IDs that must complete first
    parallel_with: list[str] = field(default_factory=list)  # Steps that can run in parallel

    # Status
    status: PlanStatus = PlanStatus.PENDING
    started_at: float | None = None
    completed_at: float | None = None
    duration_ms: float = 0.0

    # Results
    result: Any = None
    success: bool | None = None
    error: str = ""

    # Conditional execution
    condition: str | None = None  # If set, only execute if this condition is met
    on_success: str | None = None  # Next step ID if successful
    on_failure: str | None = None  # Next step ID if failed


@dataclass
class Plan:
    """A complete plan at a specific timescale."""
    id: str = field(default_factory=lambda: str(uuid4()))
    timescale: Timescale = Timescale.TACTICAL
    name: str = ""
    description: str = ""
    goal: Goal | None = None

    # Steps
    steps: list[PlanStep] = field(default_factory=list)
    current_step_index: int = 0

    # Status
    status: PlanStatus = PlanStatus.PENDING
    created_at: float = field(default_factory=time.time)
    started_at: float | None = None
    completed_at: float | None = None

    # Hierarchy
    parent_plan_id: str | None = None
    child_plan_ids: list[str] = field(default_factory=list)

    # Adaptation
    adaptation_count: int = 0
    last_adapted_at: float | None = None
    adaptation_reason: str = ""

    @property
    def current_step(self) -> PlanStep | None:
        """Returns the current step to execute."""
        if self.current_step_index < len(self.steps):
            return self.steps[self.current_step_index]
        return None

    @property
    def is_complete(self) -> bool:
        """Whether all steps are complete."""
        return all(
            step.status in (PlanStatus.COMPLETED, PlanStatus.FAILED, PlanStatus.ABANDONED)
            for step in self.steps
        )

    @property
    def progress(self) -> float:
        """Overall plan progress (0.0 to 1.0)."""
        if not self.steps:
            return 0.0
        completed = sum(
            1 for step in self.steps
            if step.status in (PlanStatus.COMPLETED, PlanStatus.FAILED)
        )
        return completed / len(self.steps)


class ReflexController:
    """Manages reflex-level (sub-100ms) responses.

    Reflexes are pre-computed responses to known patterns that don't
    require deliberation. They fire immediately when their trigger
    conditions are met.
    """

    def __init__(self):
        self._reflex_rules: list[dict[str, Any]] = []
        self._reflex_history: deque = deque(maxlen=500)
        self._active_reflexes: list[dict[str, Any]] = []

        # Initialize default reflex rules
        self._initialize_reflexes()

    def _initialize_reflexes(self) -> None:
        """Sets up default reflex rules."""
        self._reflex_rules = [
            {
                "trigger": "timing_anomaly",
                "condition": lambda obs: obs.get("elapsed_ms", 0) > 3000,
                "response": "flag_timing_anomaly",
                "priority": 0.8,
                "description": "Response time exceeds 3 seconds — potential timing side-channel",
            },
            {
                "trigger": "status_anomaly",
                "condition": lambda obs: obs.get("status_code", 200) >= 500,
                "response": "flag_server_error",
                "priority": 0.9,
                "description": "Server error — potential crash or unhandled edge case",
            },
            {
                "trigger": "structure_anomaly",
                "condition": lambda obs: obs.get("body_type") == "unexpected",
                "response": "flag_structure_anomaly",
                "priority": 0.7,
                "description": "Response structure doesn't match expected format",
            },
            {
                "trigger": "consistency_anomaly",
                "condition": lambda obs: obs.get("inconsistent_with_prior", False),
                "response": "flag_consistency_issue",
                "priority": 0.8,
                "description": "Current response is inconsistent with prior responses",
            },
            {
                "trigger": "sensitive_data",
                "condition": lambda obs: obs.get("contains_sensitive_data", False),
                "response": "flag_data_exposure",
                "priority": 0.95,
                "description": "Response contains potentially sensitive data",
            },
        ]

    def process_observation(self, observation: dict[str, Any]) -> list[dict[str, Any]]:
        """Processes an observation and fires any matching reflexes.

        Returns a list of triggered reflexes (empty if none triggered).
        """
        triggered: list[dict[str, Any]] = []

        for rule in self._reflex_rules:
            try:
                if rule["condition"](observation):
                    reflex = {
                        "trigger": rule["trigger"],
                        "response": rule["response"],
                        "priority": rule["priority"],
                        "description": rule["description"],
                        "observation_summary": {
                            k: v for k, v in observation.items()
                            if k in ("status_code", "elapsed_ms", "endpoint", "method")
                        },
                        "timestamp": time.time(),
                    }
                    triggered.append(reflex)
                    self._reflex_history.append(reflex)
            except Exception:
                continue

        # Sort by priority (highest first)
        triggered.sort(key=lambda r: r["priority"], reverse=True)

        return triggered

    def get_recent_reflexes(self, count: int = 10) -> list[dict[str, Any]]:
        """Returns the most recently triggered reflexes."""
        return list(self._reflex_history)[-count:]

    def get_reflex_statistics(self) -> dict[str, Any]:
        """Returns statistics about reflex activity."""
        trigger_counts = defaultdict(int)
        for reflex in self._reflex_history:
            trigger_counts[reflex["trigger"]] += 1

        return {
            "total_reflexes_fired": len(self._reflex_history),
            "trigger_distribution": dict(trigger_counts),
            "most_common_trigger": max(trigger_counts.items(), key=lambda pair: pair[1])[0] if trigger_counts else None,
        }


class TacticalPlanner:
    """Manages tactical-level (minutes) planning — current test sequence.

    The tactical planner decides what specific test to run next,
    based on the current strategic goal and recent observations.
    """

    def __init__(self):
        self._active_plans: dict[str, Plan] = {}
        self._completed_plans: deque = deque(maxlen=100)
        self._plan_templates: dict[str, list[PlanStep]] = {}

        # Initialize common plan templates
        self._initialize_templates()

    def _initialize_templates(self) -> None:
        """Sets up reusable plan templates."""
        # Template: Verify state consistency
        self._plan_templates["verify_consistency"] = [
            PlanStep(description="Get current state via primary endpoint", action_type="http_request"),
            PlanStep(description="Get current state via secondary endpoint", action_type="http_request"),
            PlanStep(description="Compare states for consistency", action_type="analysis"),
            PlanStep(description="If inconsistent, document the discrepancy", action_type="branch"),
        ]

        # Template: Test for race condition
        self._plan_templates["test_race_condition"] = [
            PlanStep(description="Create initial resource", action_type="http_request"),
            PlanStep(description="Send concurrent modifying requests", action_type="http_request"),
            PlanStep(description="Check final resource state", action_type="http_request"),
            PlanStep(description="Analyze for double-processing", action_type="analysis"),
        ]

        # Template: Investigate anomaly
        self._plan_templates["investigate_anomaly"] = [
            PlanStep(description="Record the anomalous observation", action_type="analysis"),
            PlanStep(description="Reproduce the anomaly", action_type="http_request"),
            PlanStep(description="Vary parameters to find the boundary", action_type="http_request"),
            PlanStep(description="Formulate hypothesis about cause", action_type="analysis"),
            PlanStep(description="Design test to confirm/disprove hypothesis", action_type="analysis"),
        ]

    def create_plan(
        self,
        template_name: str | None = None,
        goal: Goal | None = None,
        custom_steps: list[PlanStep] | None = None,
    ) -> Plan:
        """Creates a new tactical plan."""
        plan = Plan(
            timescale=Timescale.TACTICAL,
            goal=goal,
        )

        if template_name and template_name in self._plan_templates:
            # Clone the template steps
            template_steps = self._plan_templates[template_name]
            plan.steps = [
                PlanStep(
                    description=step.description,
                    action_type=step.action_type,
                    parameters=dict(step.parameters),
                    goal_id=goal.id if goal else "",
                )
                for step in template_steps
            ]
            plan.name = f"Tactical: {template_name.replace('_', ' ').title()}"
        elif custom_steps:
            plan.steps = custom_steps
            plan.name = f"Tactical: Custom plan ({len(custom_steps)} steps)"
        elif goal:
            plan.name = f"Tactical: {goal.description[:50]}"
            # Create generic steps from the goal
            plan.steps = self._generate_steps_from_goal(goal)
        else:
            plan.name = "Tactical: Ad-hoc plan"
            plan.steps = [PlanStep(description="Execute test", action_type="http_request")]

        self._active_plans[plan.id] = plan
        return plan

    def _generate_steps_from_goal(self, goal: Goal) -> list[PlanStep]:
        """Generates plan steps from a goal."""
        steps: list[PlanStep] = []

        if goal.goal_type == GoalType.VERIFY_CONSISTENCY:
            steps = [s for s in self._plan_templates.get("verify_consistency", [])]
        elif goal.goal_type == GoalType.TEST_HYPOTHESIS:
            steps = [
                PlanStep(description=f"Design test for: {goal.description}", action_type="analysis"),
                PlanStep(description="Execute the test", action_type="http_request"),
                PlanStep(description="Evaluate results against hypothesis", action_type="analysis"),
            ]
        elif goal.goal_type == GoalType.GATHER_EVIDENCE:
            steps = [
                PlanStep(description="Identify what evidence is needed", action_type="analysis"),
                PlanStep(description="Collect the evidence", action_type="http_request"),
                PlanStep(description="Record and categorize the evidence", action_type="analysis"),
            ]
        else:
            steps = [
                PlanStep(description=f"Work towards: {goal.description}", action_type="http_request"),
                PlanStep(description="Evaluate progress", action_type="analysis"),
            ]

        # Set goal_id on all steps
        for step in steps:
            step.goal_id = goal.id

        return steps

    def get_current_plan(self) -> Plan | None:
        """Returns the currently active plan."""
        active = [p for p in self._active_plans.values() if p.status == PlanStatus.ACTIVE]
        if active:
            return active[0]
        return None

    def advance_plan(self, plan_id: str) -> PlanStep | None:
        """Advances a plan to the next step."""
        plan = self._active_plans.get(plan_id)
        if plan is None:
            return None

        # Mark current step as completed
        current = plan.current_step
        if current:
            current.status = PlanStatus.COMPLETED
            current.completed_at = time.time()

        # Move to next step
        plan.current_step_index += 1

        # Check if plan is complete
        if plan.current_step_index >= len(plan.steps):
            plan.status = PlanStatus.COMPLETED
            plan.completed_at = time.time()
            self._completed_plans.append(plan)
            del self._active_plans[plan_id]
            return None

        # Return the next step
        next_step = plan.current_step
        if next_step:
            next_step.status = PlanStatus.ACTIVE
            next_step.started_at = time.time()

        return next_step

    def adapt_plan(
        self,
        plan_id: str,
        reason: str,
        modification: Callable[[Plan], Plan] | None = None,
    ) -> Plan | None:
        """Adapts a plan mid-execution based on new information."""
        plan = self._active_plans.get(plan_id)
        if plan is None:
            return None

        plan.adaptation_count += 1
        plan.last_adapted_at = time.time()
        plan.adaptation_reason = reason

        if modification:
            modified_plan = modification(plan)
            self._active_plans[plan_id] = modified_plan
            return modified_plan

        return plan

    def get_statistics(self) -> dict[str, Any]:
        """Returns tactical planning statistics."""
        return {
            "active_plans": len(self._active_plans),
            "completed_plans": len(self._completed_plans),
            "available_templates": list(self._plan_templates.keys()),
            "recent_completions": [
                {
                    "name": p.name,
                    "progress": p.progress,
                    "steps": len(p.steps),
                    "adaptations": p.adaptation_count,
                }
                for p in list(self._completed_plans)[-5:]
            ],
        }


class StrategicPlanner:
    """Manages strategic-level (hours) planning — session-level goals.

    The strategic planner determines what the overall testing session
    should focus on, based on the system being tested and the meta-strategy.
    """

    def __init__(self):
        self._session_goals: list[Goal] = []
        self._completed_goals: deque = deque(maxlen=50)
        self._current_phase: str = "reconnaissance"
        self._phase_history: list[str] = []

        # Phase definitions
        self._phases = [
            "reconnaissance",    # Discover the system's structure
            "baseline",          # Establish normal behavior
            "consistency",       # Check for inconsistencies
            "stress",            # Test edge cases and unusual inputs
            "verification",      # Confirm and document findings
        ]

    def plan_session(self, system_context: dict[str, Any]) -> list[Goal]:
        """Plans the goals for a testing session based on system context."""
        self._session_goals = []
        self._phase_history = []

        # Phase 1: Reconnaissance
        recon_goal = Goal(
            goal_type=GoalType.COVER_ENDPOINT_GROUP,
            timescale=Timescale.STRATEGIC,
            description="Discover and categorize all accessible endpoints",
            success_criteria="All endpoints mapped with categories",
            priority=0.9,
        )
        self._session_goals.append(recon_goal)

        # Phase 2: Baseline
        baseline_goal = Goal(
            goal_type=GoalType.COMPLETE_TEST_PHASE,
            timescale=Timescale.STRATEGIC,
            description="Establish normal behavior patterns for key endpoints",
            success_criteria="Timing and response baselines recorded",
            priority=0.7,
        )
        self._session_goals.append(baseline_goal)

        # Phase 3: Consistency (adapt based on what was discovered)
        consistency_goal = Goal(
            goal_type=GoalType.INVESTIGATE_PATTERN,
            timescale=Timescale.STRATEGIC,
            description="Check cross-endpoint and cross-version consistency",
            success_criteria="All version pairs and cross-endpoint references verified",
            priority=0.8,
        )
        self._session_goals.append(consistency_goal)

        # Phase 4: Stress
        stress_goal = Goal(
            goal_type=GoalType.COMPLETE_TEST_PHASE,
            timescale=Timescale.STRATEGIC,
            description="Test unusual inputs, concurrent operations, and edge cases",
            success_criteria="All non-standard input formats tested on key endpoints",
            priority=0.6,
        )
        self._session_goals.append(stress_goal)

        # Phase 5: Verification
        verify_goal = Goal(
            goal_type=GoalType.ACHIEVE_COVERAGE_TARGET,
            timescale=Timescale.STRATEGIC,
            description="Verify all findings and ensure documentation is complete",
            success_criteria="All findings have evidence and recommendations",
            priority=0.8,
        )
        self._session_goals.append(verify_goal)

        return self._session_goals

    def get_current_goal(self) -> Goal | None:
        """Returns the current strategic goal."""
        for goal in self._session_goals:
            if goal.status == PlanStatus.ACTIVE:
                return goal
        # Activate the next pending goal
        for goal in self._session_goals:
            if goal.status == PlanStatus.PENDING:
                goal.status = PlanStatus.ACTIVE
                return goal
        return None

    def advance_phase(self) -> str:
        """Advances to the next strategic phase."""
        current_index = self._phases.index(self._current_phase) if self._current_phase in self._phases else -1

        if current_index < len(self._phases) - 1:
            self._phase_history.append(self._current_phase)
            self._current_phase = self._phases[current_index + 1]
        else:
            # Already at the last phase
            pass

        return self._current_phase

    def get_phase_progress(self) -> float:
        """Returns progress through the strategic phases."""
        if not self._session_goals:
            return 0.0

        completed = sum(
            1 for g in self._session_goals
            if g.status in (PlanStatus.COMPLETED, PlanStatus.FAILED)
        )
        return completed / len(self._session_goals)

    def get_statistics(self) -> dict[str, Any]:
        """Returns strategic planning statistics."""
        return {
            "current_phase": self._current_phase,
            "phase_history": self._phase_history,
            "session_goals": len(self._session_goals),
            "completed_goals": len(self._completed_goals),
            "phase_progress": self.get_phase_progress(),
            "goals_summary": [
                {
                    "description": g.description[:60],
                    "status": g.status.value,
                    "priority": g.priority,
                    "progress": g.progress,
                }
                for g in self._session_goals
            ],
        }


class MetaStrategist:
    """Manages meta-level (cross-session) planning — learning strategy.

    The meta-strategist determines HOW the system should learn and improve
    over time, based on accumulated experience.
    """

    def __init__(self):
        self._learning_priorities: dict[str, float] = defaultdict(lambda: 0.5)
        self._strategy_effectiveness: dict[str, dict[str, float]] = defaultdict(lambda: {"success": 0.0, "attempts": 0.0})
        self._session_history: deque = deque(maxlen=50)
        self._adaptation_history: list[dict[str, Any]] = []

    def record_session_outcome(self, session_summary: dict[str, Any]) -> None:
        """Records the outcome of a testing session for learning."""
        self._session_history.append(session_summary)

        # Update learning priorities based on what worked
        strategies_used = session_summary.get("strategies_used", {})
        for strategy_name, results in strategies_used.items():
            if strategy_name not in self._strategy_effectiveness:
                self._strategy_effectiveness[strategy_name] = {"success": 0.0, "attempts": 0.0}

            self._strategy_effectiveness[strategy_name]["attempts"] += results.get("times_used", 1)
            self._strategy_effectiveness[strategy_name]["success"] += results.get("times_discovered", 0)

        # Update learning priorities
        self._update_learning_priorities(session_summary)

    def _update_learning_priorities(self, session_summary: dict[str, Any]) -> None:
        """Updates what the system should focus on learning."""
        findings = session_summary.get("findings", [])
        coverage_gaps = session_summary.get("coverage_gaps", [])

        # If we found many issues in a category, prioritize learning more about it
        for finding in findings:
            category = finding.get("category", "unknown")
            self._learning_priorities[category] = min(1.0, self._learning_priorities[category] + 0.1)

        # If we have coverage gaps, prioritize filling them
        for gap in coverage_gaps:
            self._learning_priorities[f"gap:{gap}"] = min(1.0, self._learning_priorities[f"gap:{gap}"] + 0.2)

    def get_recommended_focus(self, system_context: dict[str, Any]) -> list[str]:
        """Recommends what to focus on for the next session."""
        recommendations: list[str] = []

        # Based on learning priorities
        top_priorities = sorted(
            self._learning_priorities.items(),
            key=lambda pair: pair[1],
            reverse=True,
        )[:5]

        for priority, score in top_priorities:
            if score > 0.6:
                recommendations.append(f"Focus on: {priority} (priority score: {score:.2f})")

        # Based on strategy effectiveness
        effective_strategies = sorted(
            self._strategy_effectiveness.items(),
            key=lambda pair: pair[1]["success"] / max(1, pair[1]["attempts"]),
            reverse=True,
        )[:3]

        for strategy, stats in effective_strategies:
            if stats["attempts"] > 5:
                success_rate = stats["success"] / stats["attempts"]
                if success_rate > 0.3:
                    recommendations.append(f"Continue using: {strategy} (success rate: {success_rate:.0%})")

        return recommendations

    def get_statistics(self) -> dict[str, Any]:
        """Returns meta-strategy statistics."""
        return {
            "sessions_recorded": len(self._session_history),
            "learning_priorities": dict(self._learning_priorities),
            "strategy_effectiveness": {
                strategy: {
                    "success_rate": stats["success"] / max(1, stats["attempts"]),
                    "total_attempts": int(stats["attempts"]),
                }
                for strategy, stats in self._strategy_effectiveness.items()
            },
            "adaptation_history": len(self._adaptation_history),
            "recommended_focus": self.get_recommended_focus({})[:5],
        }


class MultiTimescalePlanner:
    """Coordinates planning across all four time scales simultaneously.

    This is the component that ensures the system has both immediate
    reactions AND long-term strategy — it doesn't just react to what's
    in front of it, but works towards larger goals while adapting
    to real-time observations.
    """

    def __init__(self):
        self._reflex_controller = ReflexController()
        self._tactical_planner = TacticalPlanner()
        self._strategic_planner = StrategicPlanner()
        self._meta_strategist = MetaStrategist()

        # Cross-scale coordination
        self._scale_interactions: deque = deque(maxlen=100)
        self._last_coordination_time = 0.0

    def process_observation(self, observation: dict[str, Any]) -> dict[str, Any]:
        """Processes an observation through all planning levels.

        Returns the coordination result — what the system should do next.
        """
        coordination_start = time.time()

        # Level 1: REFLEX — Immediate reactions
        reflexes = self._reflex_controller.process_observation(observation)

        # Level 2: TACTICAL — Does this affect the current plan?
        current_plan = self._tactical_planner.get_current_plan()
        tactical_impact = self._assess_tactical_impact(observation, current_plan)

        # Level 3: STRATEGIC — Does this change the session strategy?
        strategic_impact = self._assess_strategic_impact(observation, reflexes)

        # Level 4: META — Does this teach us about our approach?
        meta_impact = self._assess_meta_impact(observation)

        # Coordinate: decide what to do next
        action = self._coordinate_across_scales(
            observation, reflexes, tactical_impact, strategic_impact, meta_impact
        )

        coordination_time = (time.time() - coordination_start) * 1000
        self._scale_interactions.append({
            "timestamp": time.time(),
            "coordination_time_ms": coordination_time,
            "reflexes_triggered": len(reflexes),
            "tactical_impact": tactical_impact,
            "strategic_impact": strategic_impact,
        })

        return action

    def _assess_tactical_impact(
        self, observation: dict[str, Any], current_plan: Plan | None
    ) -> str:
        """Assesses how an observation impacts the current tactical plan."""
        if current_plan is None:
            return "no_active_plan"

        current_step = current_plan.current_step
        if current_step is None:
            return "plan_complete"

        # Check if the observation is relevant to the current step
        if observation.get("endpoint") in current_step.description:
            return "directly_relevant"

        # Check if it contradicts the current plan's assumptions
        if observation.get("unexpected", False):
            return "may_require_adaptation"

        return "no_impact"

    def _assess_strategic_impact(
        self, observation: dict[str, Any], reflexes: list[dict[str, Any]]
    ) -> str:
        """Assesses how an observation impacts the strategic plan."""
        if not reflexes:
            return "none"

        # Critical reflexes may warrant strategic attention
        critical_reflexes = [r for r in reflexes if r["priority"] > 0.8]
        if critical_reflexes:
            return "warrants_attention"

        return "minor"

    def _assess_meta_impact(self, observation: dict[str, Any]) -> str:
        """Assesses what this observation teaches about the approach."""
        # Check if this is a new pattern
        if observation.get("novel_pattern", False):
            return "new_pattern_learned"

        return "no_new_learning"

    def _coordinate_across_scales(
        self,
        observation: dict[str, Any],
        reflexes: list[dict[str, Any]],
        tactical_impact: str,
        strategic_impact: str,
        meta_impact: str,
    ) -> dict[str, Any]:
        """Coordinates across all scales to determine the next action.

        Priority order:
        1. Critical reflexes (immediate action)
        2. Tactical plan execution
        3. Strategic goal progression
        4. Meta-strategy adaptation
        """
        # If critical reflexes fired, they take priority
        critical_reflexes = [r for r in reflexes if r["priority"] > 0.85]
        if critical_reflexes:
            return {
                "action": "handle_critical_reflex",
                "priority": "immediate",
                "reflexes": critical_reflexes,
                "description": f"Critical reflex triggered: {critical_reflexes[0]['trigger']}",
                "timescale": Timescale.REFLEX,
            }

        # If tactical plan needs adaptation
        if tactical_impact == "may_require_adaptation":
            return {
                "action": "adapt_tactical_plan",
                "priority": "high",
                "reason": "Observation contradicts plan assumptions",
                "timescale": Timescale.TACTICAL,
            }

        # Continue with current tactical plan
        if tactical_impact == "directly_relevant":
            current_plan = self._tactical_planner.get_current_plan()
            if current_plan and current_plan.current_step:
                return {
                    "action": "execute_plan_step",
                    "priority": "normal",
                    "step": current_plan.current_step.description,
                    "timescale": Timescale.TACTICAL,
                }

        # Strategic consideration
        if strategic_impact == "warrants_attention":
            return {
                "action": "evaluate_strategic_impact",
                "priority": "medium",
                "description": "Pattern may warrant strategic focus shift",
                "timescale": Timescale.STRATEGIC,
            }

        # Default: continue current plan
        return {
            "action": "continue_current_approach",
            "priority": "low",
            "description": "No significant cross-scale impact",
            "timescale": Timescale.TACTICAL,
        }

    def plan_session(self, system_context: dict[str, Any]) -> list[Goal]:
        """Plans a complete testing session."""
        return self._strategic_planner.plan_session(system_context)

    def get_statistics(self) -> dict[str, Any]:
        """Returns comprehensive statistics across all timescales."""
        return {
            "reflex": self._reflex_controller.get_reflex_statistics(),
            "tactical": self._tactical_planner.get_statistics(),
            "strategic": self._strategic_planner.get_statistics(),
            "meta": self._meta_strategist.get_statistics(),
            "cross_scale": {
                "total_coordinations": len(self._scale_interactions),
                "average_coordination_time_ms": (
                    sum(s["coordination_time_ms"] for s in self._scale_interactions) /
                    len(self._scale_interactions)
                    if self._scale_interactions else 0.0
                ),
            },
        }
