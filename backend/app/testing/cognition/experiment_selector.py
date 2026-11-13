"""Active Experiment Selector — Optimal Test Selection.

Implements the cognitive ability to CHOOSE what to test next based on
expected information gain. Unlike static test runners that execute a
fixed sequence, this component actively decides which experiment will
yield the most new knowledge about the system under test.

Implements concepts from:
- Bayesian Optimal Experiment Design (BOED)
- Expected Information Gain maximization
- Multi-Armed Bandit exploration/exploitation
- Curiosity-driven exploration (intrinsic motivation)
- Optimal Stopping Theory

The selector operates as follows:
1. Given current hypotheses and their confidence levels
2. For each possible experiment, estimate how much it would reduce uncertainty
3. Weight by cost (time, requests, risk)
4. Select the experiment with the best information-per-cost ratio
5. Balance exploration (test uncertain areas) vs exploitation (confirm findings)

This is what makes the system EFFICIENT: instead of blindly running
every test on every endpoint, it intelligently chooses where to focus
effort for maximum discovery.
"""
from __future__ import annotations

import math
import random
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable
from uuid import uuid4

from app.testing.cognition.belief_revision import BeliefRevisionSystem, Hypothesis, HypothesisStatus


class ExperimentType(Enum):
    """Types of experiments the selector can choose from."""
    RACE_CONDITION_CHECK = "race_condition_check"
    STATE_TRANSITION_CHECK = "state_transition_check"
    FORMAT_VARIANT_CHECK = "format_variant_check"
    AUTH_CONSISTENCY_CHECK = "auth_consistency_check"
    BUSINESS_RULE_CHECK = "business_rule_check"
    CROSS_VERSION_CHECK = "cross_version_check"
    ENDPOINT_DISCOVERY = "endpoint_discovery"
    PARAMETER_VARIATION = "parameter_variation"
    TIMING_ANALYSIS = "timing_analysis"
    SEQUENCE_VARIATION = "sequence_variation"


@dataclass
class Experiment:
    """A single experiment that can be selected and executed.

    An experiment is a potential test action that, when executed,
    will produce evidence that either supports or contradicts
    one or more hypotheses.
    """
    id: str = field(default_factory=lambda: str(uuid4()))
    experiment_type: ExperimentType = ExperimentType.PARAMETER_VARIATION
    description: str = ""
    target_endpoint: str = ""  # Which endpoint/resource this experiments with
    method: str = "POST"
    parameters: dict[str, Any] = field(default_factory=dict)

    # Which hypotheses this experiment can provide evidence for/against
    related_hypothesis_ids: list[str] = field(default_factory=list)

    # Cost estimation
    estimated_duration_ms: float = 1000.0  # How long this takes
    estimated_request_count: int = 1  # How many HTTP requests
    risk_level: str = "low"  # "low", "medium", "high" — impact on the target system

    # Expected outcome
    expected_information_gain: float = 0.0  # Calculated by the selector
    exploration_value: float = 0.0  # How much this explores unknown territory
    exploitation_value: float = 0.0  # How much this confirms existing hypotheses

    # Execution tracking
    times_executed: int = 0
    times_informative: int = 0  # How often this produced useful evidence
    last_executed_at: float | None = None

    # Metadata
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def total_score(self) -> float:
        """Combined score for ranking."""
        info_gain = self.expected_information_gain
        cost_factor = 1.0 / (1.0 + self.estimated_duration_ms / 1000.0)
        risk_factor = {"low": 1.0, "medium": 0.7, "high": 0.5}.get(self.risk_level, 0.5)

        # Combine: information gain weighted by cost efficiency and risk
        return info_gain * cost_factor * risk_factor


@dataclass
class ExperimentOutcome:
    """The result of executing an experiment."""
    experiment_id: str = ""
    timestamp: float = field(default_factory=time.time)
    duration_ms: float = 0.0
    informative: bool = False  # Did this produce useful evidence?
    evidence_type: str = ""  # What kind of evidence was produced
    evidence_content: Any = None
    hypothesis_updates: list[dict[str, Any]] = field(default_factory=list)
    discoveries: list[str] = field(default_factory=list)  # New patterns found
    surprise_level: float = 0.0  # How unexpected the result was


class InformationGainCalculator:
    """Calculates expected information gain for experiments.

    Uses entropy-based measures: an experiment is informative if it
    can significantly reduce uncertainty about a hypothesis.

    Information gain = H(prior) - H(posterior)
    Where H is Shannon entropy of the hypothesis confidence.
    """

    @staticmethod
    def binary_entropy(p: float) -> float:
        """Calculates binary Shannon entropy: H(p) = -p*log2(p) - (1-p)*log2(1-p)"""
        p = max(0.001, min(0.999, p))
        return -p * math.log2(p) - (1 - p) * math.log2(1 - p)

    @staticmethod
    def expected_information_gain(
        hypothesis: Hypothesis,
        experiment_discrimination: float = 0.7,
    ) -> float:
        """Calculates how much information an experiment would provide about a hypothesis.

        Args:
            hypothesis: The hypothesis being tested
            experiment_discrimination: How well the experiment distinguishes
                true from false (0.5 = no discrimination, 1.0 = perfect)

        Returns:
            Expected information gain in bits (0.0 to 1.0)
        """
        current_confidence = hypothesis.posterior_probability
        current_entropy = InformationGainCalculator.binary_entropy(current_confidence)

        # If we're already very certain, there's little to gain
        if current_entropy < 0.1:
            return 0.0

        # Estimate posterior entropy after the experiment
        # For a discriminating experiment:
        # - If hypothesis is true (prob = p), we'll likely see supporting evidence
        # - If hypothesis is false (prob = 1-p), we'll likely see contradicting evidence

        p = current_confidence
        d = experiment_discrimination

        # Probability of seeing supporting evidence
        p_support = p * d + (1 - p) * (1 - d)

        # Posterior confidence if we see supporting evidence
        if p_support > 0.01:
            posterior_if_support = (p * d) / p_support
        else:
            posterior_if_support = p

        # Probability of seeing contradicting evidence
        p_contradict = 1 - p_support

        # Posterior confidence if we see contradicting evidence
        if p_contradict > 0.01:
            posterior_if_contradict = (p * (1 - d)) / p_contradict
        else:
            posterior_if_contradict = p

        # Expected posterior entropy
        entropy_if_support = InformationGainCalculator.binary_entropy(posterior_if_support)
        entropy_if_contradict = InformationGainCalculator.binary_entropy(posterior_if_contradict)

        expected_posterior_entropy = (
            p_support * entropy_if_support +
            p_contradict * entropy_if_contradict
        )

        # Information gain = reduction in entropy
        info_gain = current_entropy - expected_posterior_entropy

        return max(0.0, info_gain)

    @staticmethod
    def multi_hypothesis_information_gain(
        hypotheses: list[Hypothesis],
        experiment_discrimination: float = 0.7,
    ) -> float:
        """Calculates total information gain across multiple hypotheses.

        An experiment that provides evidence for multiple uncertain
        hypotheses is more valuable than one that only affects one.
        """
        total_gain = 0.0

        for hypothesis in hypotheses:
            if hypothesis.status in (HypothesisStatus.CONFIRMED, HypothesisStatus.REFUTED):
                continue  # Already resolved, no information to gain

            gain = InformationGainCalculator.expected_information_gain(
                hypothesis, experiment_discrimination
            )
            total_gain += gain

        # Normalize by number of hypotheses to avoid bias toward experiments
        # that touch many already-confirmed hypotheses
        active_count = sum(
            1 for h in hypotheses
            if h.status not in (HypothesisStatus.CONFIRMED, HypothesisStatus.REFUTED)
        )

        if active_count > 0:
            return total_gain / math.sqrt(active_count)  # Square root dampening
        return 0.0


class ExplorationExploitationBalancer:
    """Balances exploration (trying new things) vs exploitation (confirming knowns).

    Uses an epsilon-greedy strategy with adaptive epsilon:
    - High epsilon (more exploration) early in testing or when uncertain
    - Low epsilon (more exploitation) when confident or late in testing
    """

    def __init__(
        self,
        initial_epsilon: float = 0.3,
        min_epsilon: float = 0.05,
        max_epsilon: float = 0.5,
        decay_rate: float = 0.01,
    ):
        self._epsilon = initial_epsilon
        self._min_epsilon = min_epsilon
        self._max_epsilon = max_epsilon
        self._decay_rate = decay_rate

        self._exploration_count = 0
        self._exploitation_count = 0

        # Track which areas have been explored
        self._explored_areas: set[str] = set()
        self._area_visit_counts: dict[str, int] = defaultdict(int)

    def should_explore(self, context: dict[str, Any]) -> bool:
        """Decides whether to explore (try something new) or exploit (confirm knowns)."""
        # Random exploration based on epsilon
        if random.random() < self._epsilon:
            self._exploration_count += 1
            return True

        self._exploitation_count += 1
        return False

    def adjust_epsilon(self, discovery_rate: float, uncertainty_level: float):
        """Adjusts epsilon based on recent performance.

        Args:
            discovery_rate: Rate of new discoveries (0.0 to 1.0)
                High discovery rate = keep exploring
            uncertainty_level: Average hypothesis uncertainty (0.0 to 1.0)
                High uncertainty = explore more to resolve it
        """
        # If we're making lots of discoveries, keep exploring
        if discovery_rate > 0.3:
            self._epsilon = min(self._max_epsilon, self._epsilon + 0.05)
        # If we're not finding anything new and uncertainty is low, exploit more
        elif discovery_rate < 0.05 and uncertainty_level < 0.3:
            self._epsilon = max(self._min_epsilon, self._epsilon - self._decay_rate)
        # If uncertainty is high, explore more
        elif uncertainty_level > 0.6:
            self._epsilon = min(self._max_epsilon, self._epsilon + 0.02)

    def mark_area_explored(self, area: str):
        """Marks an area as explored."""
        self._explored_areas.add(area)
        self._area_visit_counts[area] += 1

    def get_unexplored_areas(self, all_areas: list[str]) -> list[str]:
        """Returns areas that haven't been explored yet."""
        return [area for area in all_areas if area not in self._explored_areas]

    def get_exploration_value(self, area: str) -> float:
        """Returns how valuable it would be to explore this area.

        Unexplored areas have high exploration value.
        Frequently explored areas have low exploration value.
        """
        if area not in self._explored_areas:
            return 1.0  # Completely unexplored — maximum value

        visit_count = self._area_visit_counts[area]
        # Diminishing returns: each visit reduces the value
        return 1.0 / (1.0 + visit_count * 0.3)

    @property
    def statistics(self) -> dict[str, Any]:
        return {
            "current_epsilon": self._epsilon,
            "exploration_count": self._exploration_count,
            "exploitation_count": self._exploitation_count,
            "explored_areas": len(self._explored_areas),
            "exploration_ratio": (
                self._exploration_count /
                (self._exploration_count + self._exploitation_count)
                if (self._exploration_count + self._exploitation_count) > 0
                else 0.0
            ),
        }


class ActiveExperimentSelector:
    """Selects the next experiment to execute for maximum information gain.

    This is the component that makes the system intelligent about
    WHAT to test next, rather than blindly executing a fixed sequence.

    Decision process:
    1. Look at all available experiments
    2. For each, calculate expected information gain
    3. Factor in cost (time, requests, risk)
    4. Consider exploration vs exploitation balance
    5. Select the best overall experiment
    """

    def __init__(
        self,
        belief_system: BeliefRevisionSystem,
        initial_epsilon: float = 0.3,
    ):
        self._belief_system = belief_system
        self._info_gain_calculator = InformationGainCalculator()
        self._exploration_balancer = ExplorationExploitationBalancer(
            initial_epsilon=initial_epsilon
        )

        self._available_experiments: dict[str, Experiment] = {}
        self._experiment_history: list[ExperimentOutcome] = []
        self._experiment_generators: list[Callable[[dict[str, Any]], list[Experiment]]] = []

        # Curiosity tracking — which areas haven't been tested
        self._total_discoveries = 0
        self._total_executions = 0

        # Adaptive parameters
        self._discovery_rate_window: list[float] = []
        self._max_window_size = 50

    def register_experiment_generator(
        self,
        generator: Callable[[dict[str, Any]], list[Experiment]],
    ) -> None:
        """Registers a function that generates available experiments based on context."""
        self._experiment_generators.append(generator)

    def generate_experiments(self, context: dict[str, Any]) -> list[Experiment]:
        """Generates available experiments using registered generators."""
        new_experiments: list[Experiment] = []

        for generator in self._experiment_generators:
            try:
                experiments = generator(context)
                for exp in experiments:
                    self._available_experiments[exp.id] = exp
                    new_experiments.append(exp)
            except Exception:
                continue

        return new_experiments

    def select_next_experiment(self, context: dict[str, Any] | None = None) -> Experiment | None:
        """Selects the best experiment to execute next.

        Selection criteria:
        1. Expected information gain (how much we'll learn)
        2. Cost efficiency (information per unit cost)
        3. Risk assessment (avoid high-risk experiments unless necessary)
        4. Exploration vs exploitation balance
        5. Novelty (avoid repeating recent experiments)

        Returns None if no experiments are available.
        """
        if not self._available_experiments:
            if context:
                self.generate_experiments(context)
            if not self._available_experiments:
                return None

        # Get current active hypotheses
        active_hypotheses = self._belief_system.get_active_hypotheses()

        # Decide whether to explore or exploit
        should_explore = self._exploration_balancer.should_explore(context or {})

        # Score all available experiments
        scored_experiments: list[tuple[Experiment, float]] = []

        for experiment in self._available_experiments.values():
            score = self._score_experiment(
                experiment,
                active_hypotheses,
                should_explore,
                context or {},
            )
            scored_experiments.append((experiment, score))

        if not scored_experiments:
            return None

        # Sort by score (highest first)
        scored_experiments.sort(key=lambda pair: pair[1], reverse=True)

        # Select the top experiment
        best_experiment, best_score = scored_experiments[0]

        # Update exploration tracking
        area = best_experiment.target_endpoint or best_experiment.experiment_type.value
        self._exploration_balancer.mark_area_explored(area)

        return best_experiment

    def _score_experiment(
        self,
        experiment: Experiment,
        active_hypotheses: list[Hypothesis],
        exploring: bool,
        context: dict[str, Any],
    ) -> float:
        """Calculates a composite score for an experiment.

        Higher score = better choice for next execution.
        """
        # Base score from information gain
        if experiment.related_hypothesis_ids:
            # Get related hypotheses
            related = [
                self._belief_system._hypotheses.get(hid)
                for hid in experiment.related_hypothesis_ids
                if hid in self._belief_system._hypotheses
            ]
            related = [h for h in related if h is not None]

            if related:
                info_gain = self._info_gain_calculator.multi_hypothesis_information_gain(
                    related,
                    experiment_discrimination=self._estimate_discrimination(experiment),
                )
            else:
                info_gain = 0.3  # Default moderate gain if no related hypotheses
        else:
            # No specific hypotheses — this is exploratory
            info_gain = 0.3  # Base exploratory value

        # Exploration bonus
        area = experiment.target_endpoint or experiment.experiment_type.value
        exploration_value = self._exploration_balancer.get_exploration_value(area)

        # Apply exploration/exploitation weighting
        if exploring:
            # When exploring, prioritize unexplored areas
            exploration_weight = exploration_value * 1.5
            info_weight = info_gain * 0.5
        else:
            # When exploiting, prioritize information gain
            exploration_weight = exploration_value * 0.3
            info_weight = info_gain * 1.5

        # Cost factor (cheaper is better)
        cost_penalty = (
            experiment.estimated_duration_ms / 1000.0 +
            experiment.estimated_request_count * 0.5
        )
        cost_factor = 1.0 / (1.0 + cost_penalty * 0.1)

        # Risk factor
        risk_factor = {"low": 1.0, "medium": 0.8, "high": 0.5}.get(
            experiment.risk_level, 0.5
        )

        # Novelty factor — penalize recently executed experiments
        recency_penalty = 0.0
        if experiment.last_executed_at:
            time_since = time.time() - experiment.last_executed_at
            if time_since < 60:  # Less than a minute ago
                recency_penalty = 0.5
            elif time_since < 300:  # Less than 5 minutes ago
                recency_penalty = 0.2

        # Historical effectiveness
        effectiveness = 0.5  # Default
        if experiment.times_executed > 0:
            effectiveness = experiment.times_informative / experiment.times_executed

        # Combine all factors
        total_score = (
            (info_weight + exploration_weight) *
            cost_factor *
            risk_factor *
            (1.0 - recency_penalty) *
            (0.5 + effectiveness * 0.5)
        )

        # Update experiment with calculated values
        experiment.expected_information_gain = info_gain
        experiment.exploration_value = exploration_value
        experiment.exploitation_value = info_gain if not exploring else 0.0

        return total_score

    def _estimate_discrimination(self, experiment: Experiment) -> float:
        """Estimates how well an experiment discriminates between hypotheses.

        Higher discrimination means the experiment more clearly
        distinguishes true from false hypotheses.
        """
        # Different experiment types have different discrimination power
        discrimination_by_type = {
            ExperimentType.RACE_CONDITION_CHECK: 0.8,  # Very discriminating
            ExperimentType.STATE_TRANSITION_CHECK: 0.8,
            ExperimentType.FORMAT_VARIANT_CHECK: 0.7,
            ExperimentType.AUTH_CONSISTENCY_CHECK: 0.9,  # Very clear results
            ExperimentType.BUSINESS_RULE_CHECK: 0.7,
            ExperimentType.CROSS_VERSION_CHECK: 0.6,
            ExperimentType.ENDPOINT_DISCOVERY: 0.5,  # Less discriminating
            ExperimentType.PARAMETER_VARIATION: 0.6,
            ExperimentType.TIMING_ANALYSIS: 0.5,  # Noisy measurements
            ExperimentType.SEQUENCE_VARIATION: 0.7,
        }

        base = discrimination_by_type.get(experiment.experiment_type, 0.5)

        # Adjust for experiment-specific factors
        if experiment.metadata.get("high_confidence_method"):
            base = min(1.0, base + 0.1)
        if experiment.metadata.get("noisy_measurement"):
            base = max(0.3, base - 0.2)

        return base

    def record_outcome(self, outcome: ExperimentOutcome) -> None:
        """Records the outcome of an executed experiment and updates the selector."""
        self._experiment_history.append(outcome)
        self._total_executions += 1

        # Update the experiment's tracking
        experiment = self._available_experiments.get(outcome.experiment_id)
        if experiment:
            experiment.times_executed += 1
            if outcome.informative:
                experiment.times_informative += 1
            experiment.last_executed_at = time.time()

        # Track discoveries
        if outcome.discoveries:
            self._total_discoveries += len(outcome.discoveries)

        # Update discovery rate
        discovery_rate = 1.0 if outcome.discoveries else 0.0
        self._discovery_rate_window.append(discovery_rate)
        if len(self._discovery_rate_window) > self._max_window_size:
            self._discovery_rate_window.pop(0)

        # Calculate current metrics for exploration adjustment
        recent_discovery_rate = (
            sum(self._discovery_rate_window) / len(self._discovery_rate_window)
            if self._discovery_rate_window else 0.0
        )

        # Calculate average uncertainty from active hypotheses
        active = self._belief_system.get_active_hypotheses()
        avg_uncertainty = (
            sum(1.0 - abs(h.posterior_probability - 0.5) * 2 for h in active) / len(active)
            if active else 0.0
        )

        # Adjust exploration/exploitation balance
        self._exploration_balancer.adjust_epsilon(recent_discovery_rate, avg_uncertainty)

    def get_recommended_experiments(self, n: int = 5) -> list[Experiment]:
        """Returns the top N recommended experiments without executing them."""
        active_hypotheses = self._belief_system.get_active_hypotheses()

        scored: list[tuple[Experiment, float]] = []
        for experiment in self._available_experiments.values():
            score = self._score_experiment(experiment, active_hypotheses, False, {})
            scored.append((experiment, score))

        scored.sort(key=lambda pair: pair[1], reverse=True)
        return [exp for exp, _ in scored[:n]]

    def get_curiosity_score(self, area: str) -> float:
        """Returns how 'curious' the system is about a specific area.

        High curiosity = area is unexplored or has produced interesting results.
        Low curiosity = area is well-explored with no surprises.
        """
        return self._exploration_balancer.get_exploration_value(area)

    def get_optimal_stopping_recommendation(self) -> dict[str, Any]:
        """Recommends whether to continue testing or stop.

        Uses Optimal Stopping Theory concepts:
        - If expected future information gain is below the cost of
          continuing, recommend stopping.
        - If there are still high-uncertainty hypotheses, recommend continuing.
        """
        active = self._belief_system.get_active_hypotheses()
        confirmed = self._belief_system.get_confirmed_hypotheses()

        if not active:
            return {
                "recommendation": "stop",
                "reason": "No active hypotheses remaining — all have been confirmed or refuted.",
                "confidence": 0.9,
            }

        # Calculate average remaining uncertainty
        avg_uncertainty = sum(
            1.0 - abs(h.posterior_probability - 0.5) * 2
            for h in active
        ) / len(active)

        # Calculate average information gain available
        top_hypotheses = self._belief_system.get_top_hypotheses(5)
        avg_info_gain = sum(
            self._info_gain_calculator.expected_information_gain(h)
            for h in top_hypotheses
        ) / len(top_hypotheses) if top_hypotheses else 0.0

        # Decision logic
        if avg_uncertainty < 0.2 and avg_info_gain < 0.1:
            return {
                "recommendation": "stop",
                "reason": (
                    f"Average uncertainty is low ({avg_uncertainty:.2f}) and expected "
                    f"information gain is minimal ({avg_info_gain:.2f}). "
                    f"Further testing is unlikely to produce significant new findings."
                ),
                "confidence": 0.8,
            }
        elif avg_uncertainty > 0.5 or avg_info_gain > 0.3:
            return {
                "recommendation": "continue",
                "reason": (
                    f"Average uncertainty is high ({avg_uncertainty:.2f}) and/or expected "
                    f"information gain is significant ({avg_info_gain:.2f}). "
                    f"There are still important unresolved questions."
                ),
                "confidence": 0.9,
            }
        else:
            return {
                "recommendation": "continue_with_caution",
                "reason": (
                    f"Moderate uncertainty ({avg_uncertainty:.2f}) and information gain "
                    f"({avg_info_gain:.2f}). Consider focusing on the most uncertain "
                    f"hypotheses before stopping."
                ),
                "confidence": 0.6,
            }

    def get_statistics(self) -> dict[str, Any]:
        """Returns comprehensive statistics about the experiment selector."""
        recent_discovery_rate = (
            sum(self._discovery_rate_window) / len(self._discovery_rate_window)
            if self._discovery_rate_window else 0.0
        )

        return {
            "total_experiments_available": len(self._available_experiments),
            "total_executions": self._total_executions,
            "total_discoveries": self._total_discoveries,
            "discovery_rate": recent_discovery_rate,
            "exploration_stats": self._exploration_balancer.statistics,
            "optimal_stopping": self.get_optimal_stopping_recommendation(),
            "top_recommendations": [
                {
                    "description": exp.description[:100],
                    "type": exp.experiment_type.value,
                    "info_gain": exp.expected_information_gain,
                    "score": exp.total_score,
                }
                for exp in self.get_recommended_experiments(3)
            ],
        }

    def clear_executed(self, max_age_seconds: float = 3600.0):
        """Removes old experiments that haven't been executed recently."""
        cutoff = time.time() - max_age_seconds
        to_remove = [
            exp_id for exp_id, exp in self._available_experiments.items()
            if exp.last_executed_at and exp.last_executed_at < cutoff
            and exp.times_executed > 0  # Only remove if executed at least once
        ]

        for exp_id in to_remove:
            del self._available_experiments[exp_id]
