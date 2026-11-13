"""Belief Revision System — Dynamic Hypothesis Evolution.

Implements the cognitive ability to form, revise, and refine hypotheses
about the system under test based on incoming evidence. Unlike static
test scripts that execute a fixed sequence, this component continuously
updates its beliefs about what the system is doing and what might be
inconsistent.

Implements concepts from:
- AGM Belief Revision (Alchourron, Gardenfors, Makinson, 1985):
  Expansion (add new beliefs), Contraction (remove beliefs),
  Revision (add beliefs while maintaining consistency)
- Bayesian belief updating for probabilistic hypothesis assessment
- Abductive reasoning: "This observation is best explained by hypothesis X"

The system operates as follows:
1. Observations arrive from test execution or the workspace
2. Hypotheses are generated to explain those observations
3. New evidence either strengthens or weakens existing hypotheses
4. Conflicting evidence triggers belief revision (hypotheses are modified)
5. The strongest hypotheses guide next test selection

This is the core component that differentiates a cognitive system from
a static test runner: the ability to CHANGE ITS MIND based on evidence.
"""
from __future__ import annotations

import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable
from uuid import uuid4


class HypothesisStatus(Enum):
    """Lifecycle status of a hypothesis."""
    PROPOSED = "proposed"          # Just formed, not yet tested
    TESTING = "testing"            # Currently being verified
    STRENGTHENED = "strengthened"  # Evidence supports it
    WEAKENED = "weakened"          # Evidence contradicts it
    REVISED = "revised"            # Modified based on new evidence
    CONFIRMED = "confirmed"        # Strong evidence supports it
    REFUTED = "refuted"            # Strong evidence contradicts it
    SUPERSEDED = "superseded"     # Replaced by a better hypothesis


@dataclass
class Evidence:
    """A piece of evidence that affects hypothesis confidence."""
    id: str = field(default_factory=lambda: str(uuid4()))
    evidence_type: str = ""  # "response", "timing", "state_change", "pattern", "correlation"
    content: Any = None
    supports: bool = True  # True = supports hypothesis, False = contradicts
    strength: float = 0.5  # 0.0 to 1.0 — how strong this evidence is
    timestamp: float = field(default_factory=time.time)
    source: str = ""  # Which component produced this evidence
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class Hypothesis:
    """A hypothesis about the system under test.

    A hypothesis is an explanation for observed behavior that can be
    tested and either confirmed or refuted. For example:
    - "This endpoint has a race condition because concurrent requests
      both see the original state"
    - "The refund handler doesn't check the current subscription status"
    - "The v1 API applies different validation rules than v2"
    """
    id: str = field(default_factory=lambda: str(uuid4()))
    description: str = ""
    hypothesis_type: str = ""  # "race_condition", "state_inconsistency", "validation_gap", etc.
    status: HypothesisStatus = HypothesisStatus.PROPOSED

    # Bayesian confidence: P(hypothesis is true | evidence)
    prior_probability: float = 0.5
    posterior_probability: float = 0.5

    # Supporting and contradicting evidence
    supporting_evidence: list[Evidence] = field(default_factory=list)
    contradicting_evidence: list[Evidence] = field(default_factory=list)

    # Metadata about what this hypothesis predicts
    predictions: list[str] = field(default_factory=list)  # What we expect to observe if true
    test_suggestions: list[str] = field(default_factory=list)  # How to verify this

    # Temporal tracking
    created_at: float = field(default_factory=time.time)
    last_updated_at: float = field(default_factory=time.time)
    revision_count: int = 0

    # Lineage: if this hypothesis was revised from another
    parent_hypothesis_id: str | None = None
    child_hypothesis_ids: list[str] = field(default_factory=list)

    # Metadata
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def confidence(self) -> float:
        """Current confidence in this hypothesis (posterior probability)."""
        return self.posterior_probability

    @property
    def evidence_count(self) -> int:
        """Total number of evidence items (supporting + contradicting)."""
        return len(self.supporting_evidence) + len(self.contradicting_evidence)

    @property
    def support_ratio(self) -> float:
        """Ratio of supporting to total evidence (0.0 to 1.0)."""
        if self.evidence_count == 0:
            return 0.5
        return len(self.supporting_evidence) / self.evidence_count

    def bayesian_update(self, evidence: Evidence) -> float:
        """Performs a Bayesian update on the hypothesis confidence.

        Uses a simplified Bayes rule:
        P(H|E) = P(E|H) * P(H) / P(E)

        Where:
        - P(H) is the current confidence (prior)
        - P(E|H) is the likelihood of seeing this evidence if H is true
        - P(E) is the overall probability of seeing this evidence

        For supporting evidence: P(E|H) > P(E), increasing confidence
        For contradicting evidence: P(E|H) < P(E), decreasing confidence
        """
        # Current belief (prior)
        prior = self.posterior_probability
        prior = max(0.01, min(0.99, prior))  # Clamp to avoid 0 and 1

        # Evidence strength affects how much we update
        evidence_strength = max(0.01, min(1.0, evidence.strength))

        if evidence.supports:
            # Supporting evidence: P(E|H) is high
            likelihood_if_true = 0.7 + 0.3 * evidence_strength  # 0.7 to 1.0
            likelihood_if_false = 0.3 * (1.0 - evidence_strength)  # 0.0 to 0.3
        else:
            # Contradicting evidence: P(E|H) is low
            likelihood_if_true = 0.3 * (1.0 - evidence_strength)  # 0.0 to 0.3
            likelihood_if_false = 0.7 + 0.3 * evidence_strength  # 0.7 to 1.0

        # P(E) = P(E|H) * P(H) + P(E|¬H) * P(¬H)
        marginal_likelihood = (
            likelihood_if_true * prior +
            likelihood_if_false * (1.0 - prior)
        )

        # Avoid division by zero
        if marginal_likelihood < 0.0001:
            marginal_likelihood = 0.0001

        # Bayes rule: P(H|E) = P(E|H) * P(H) / P(E)
        posterior = (likelihood_if_true * prior) / marginal_likelihood

        # Apply damping to avoid extreme jumps from single evidence
        # This makes the system more conservative — it takes multiple
        # pieces of evidence to significantly change confidence
        damping = 0.7
        updated = prior + damping * (posterior - prior)

        # Clamp to valid range
        updated = max(0.01, min(0.99, updated))

        self.posterior_probability = updated
        self.last_updated_at = time.time()

        return updated


class BeliefRevisionSystem:
    """Manages the lifecycle of hypotheses about the system under test.

    This component:
    1. Generates hypotheses from observations
    2. Registers evidence for/against hypotheses
    3. Performs Bayesian updates on confidence
    4. Detects conflicts between hypotheses and evidence
    5. Revises hypotheses when evidence contradicts them
    6. Ranks hypotheses by confidence to guide test selection
    """

    def __init__(
        self,
        confirmation_threshold: float = 0.85,
        refutation_threshold: float = 0.15,
        max_hypotheses: int = 100,
    ):
        self._hypotheses: dict[str, Hypothesis] = {}
        self._hypotheses_by_type: dict[str, list[str]] = defaultdict(list)
        self._max_hypotheses = max_hypotheses

        self._confirmation_threshold = confirmation_threshold
        self._refutation_threshold = refutation_threshold

        self._evidence_history: list[Evidence] = []
        self._revision_count = 0
        self._hypothesis_generators: list[Callable[[dict[str, Any]], list[Hypothesis]]] = []

        # Statistics
        self._stats = {
            "hypotheses_created": 0,
            "hypotheses_confirmed": 0,
            "hypotheses_refuted": 0,
            "hypotheses_revised": 0,
            "evidence_processed": 0,
            "bayesian_updates": 0,
        }

    def register_hypothesis_generator(
        self,
        generator: Callable[[dict[str, Any]], list[Hypothesis]],
    ) -> None:
        """Registers a function that generates hypotheses from observations.

        The generator receives an observation dict and returns a list
        of Hypothesis objects that could explain the observation.
        """
        self._hypothesis_generators.append(generator)

    def generate_hypotheses(self, observation: dict[str, Any]) -> list[Hypothesis]:
        """Generates hypotheses from an observation using registered generators."""
        new_hypotheses: list[Hypothesis] = []

        for generator in self._hypothesis_generators:
            try:
                hypotheses = generator(observation)
                for h in hypotheses:
                    self._add_hypothesis(h)
                    new_hypotheses.append(h)
            except Exception:
                continue  # Don't let one generator failure block others

        return new_hypotheses

    def _add_hypothesis(self, hypothesis: Hypothesis) -> None:
        """Adds a hypothesis to the system."""
        self._hypotheses[hypothesis.id] = hypothesis
        self._hypotheses_by_type[hypothesis.hypothesis_type].append(hypothesis.id)
        self._stats["hypotheses_created"] += 1

        # Evict oldest if over capacity
        if len(self._hypotheses) > self._max_hypotheses:
            self._evict_weakest()

    def register_evidence(self, hypothesis_id: str, evidence: Evidence) -> Hypothesis | None:
        """Registers evidence for or against a hypothesis and updates confidence.

        Returns the updated hypothesis, or None if not found.
        """
        hypothesis = self._hypotheses.get(hypothesis_id)
        if hypothesis is None:
            return None

        # Store evidence
        if evidence.supports:
            hypothesis.supporting_evidence.append(evidence)
        else:
            hypothesis.contradicting_evidence.append(evidence)

        self._evidence_history.append(evidence)
        self._stats["evidence_processed"] += 1

        # Perform Bayesian update
        hypothesis.bayesian_update(evidence)
        self._stats["bayesian_updates"] += 1

        # Check status transitions
        self._check_status_transition(hypothesis)

        # If evidence contradicts, consider revision
        if not evidence.supports and evidence.strength > 0.7:
            revised = self._attempt_revision(hypothesis, evidence)
            if revised:
                return revised

        return hypothesis

    def _check_status_transition(self, hypothesis: Hypothesis) -> None:
        """Checks if a hypothesis should transition to a new status based on confidence."""
        if hypothesis.status == HypothesisStatus.REFUTED:
            return  # Terminal state

        if hypothesis.posterior_probability >= self._confirmation_threshold:
            if hypothesis.status != HypothesisStatus.CONFIRMED:
                hypothesis.status = HypothesisStatus.CONFIRMED
                self._stats["hypotheses_confirmed"] += 1
        elif hypothesis.posterior_probability <= self._refutation_threshold:
            if hypothesis.status != HypothesisStatus.REFUTED:
                hypothesis.status = HypothesisStatus.REFUTED
                self._stats["hypotheses_refuted"] += 1
        elif hypothesis.posterior_probability > 0.6:
            hypothesis.status = HypothesisStatus.STRENGTHENED
        elif hypothesis.posterior_probability < 0.4:
            if hypothesis.evidence_count > 2:  # Only weaken after multiple evidence
                hypothesis.status = HypothesisStatus.WEAKENED
        else:
            hypothesis.status = HypothesisStatus.TESTING

    def _attempt_revision(self, hypothesis: Hypothesis, contradicting_evidence: Evidence) -> Hypothesis | None:
        """Attempts to revise a hypothesis when strong contradicting evidence arrives.

        Revision means creating a modified version of the hypothesis that
        accounts for the new evidence while preserving what still works.

        Returns the revised hypothesis, or None if no revision is possible.
        """
        # Only revise if the hypothesis is not already confirmed
        if hypothesis.status == HypothesisStatus.CONFIRMED:
            return None

        # Only revise if there's enough supporting evidence to make it worth revising
        # (a hypothesis with no support should just be refuted)
        if len(hypothesis.supporting_evidence) < 1:
            return None

        # Mark original as superseded
        hypothesis.status = HypothesisStatus.SUPERSEDED

        # Create a revised hypothesis
        revised = Hypothesis(
            description=self._generate_revised_description(hypothesis, contradicting_evidence),
            hypothesis_type=hypothesis.hypothesis_type,
            prior_probability=max(0.3, hypothesis.posterior_probability - 0.1),  # Start slightly lower
            posterior_probability=max(0.3, hypothesis.posterior_probability - 0.1),
            parent_hypothesis_id=hypothesis.id,
            metadata={
                **hypothesis.metadata,
                "revision_reason": f"Contradicting evidence: {contradicting_evidence.evidence_type}",
                "revision_evidence_id": contradicting_evidence.id,
            },
        )

        # Copy over supporting evidence (with reduced strength)
        for ev in hypothesis.supporting_evidence:
            reduced_evidence = Evidence(
                evidence_type=ev.evidence_type,
                content=ev.content,
                supports=True,
                strength=ev.strength * 0.8,  # Reduce strength in revised hypothesis
                source=ev.source,
                metadata={**ev.metadata, "inherited": True},
            )
            revised.supporting_evidence.append(reduced_evidence)

        # The contradicting evidence becomes supporting evidence for the revised version
        # (because the revision accounts for it)
        revised.supporting_evidence.append(
            Evidence(
                evidence_type=contradicting_evidence.evidence_type,
                content=contradicting_evidence.content,
                supports=True,
                strength=0.6,  # Moderate support — the revision explains it
                source="revision",
                metadata={"note": "Accounted for in revision"},
            )
        )

        # Link parent and child
        hypothesis.child_hypothesis_ids.append(revised.id)

        # Add to system
        self._add_hypothesis(revised)
        self._stats["hypotheses_revised"] += 1
        self._revision_count += 1

        return revised

    def _generate_revised_description(self, original: Hypothesis, evidence: Evidence) -> str:
        """Generates a description for a revised hypothesis."""
        # Try to incorporate what the contradicting evidence teaches us
        evidence_note = str(evidence.content)[:100] if evidence.content else "new evidence"

        if original.hypothesis_type == "race_condition":
            return (
                f"{original.description} (REVISED: the timing window may be narrower "
                f"than originally thought, or the concurrent processing has partial "
                f"safeguards — {evidence_note})"
            )
        elif original.hypothesis_type == "state_inconsistency":
            return (
                f"{original.description} (REVISED: the inconsistency may be more "
                f"specific than originally thought — {evidence_note})"
            )
        elif original.hypothesis_type == "validation_gap":
            return (
                f"{original.description} (REVISED: the validation gap may be narrower "
                f"or conditional — {evidence_note})"
            )
        else:
            return f"{original.description} (REVISED based on: {evidence_note})"

    def get_active_hypotheses(self) -> list[Hypothesis]:
        """Returns all hypotheses that are not yet confirmed or refuted."""
        return [
            h for h in self._hypotheses.values()
            if h.status in (
                HypothesisStatus.PROPOSED,
                HypothesisStatus.TESTING,
                HypothesisStatus.STRENGTHENED,
                HypothesisStatus.WEAKENED,
                HypothesisStatus.REVISED,
            )
        ]

    def get_confirmed_hypotheses(self) -> list[Hypothesis]:
        """Returns all confirmed hypotheses."""
        return [
            h for h in self._hypotheses.values()
            if h.status == HypothesisStatus.CONFIRMED
        ]

    def get_refuted_hypotheses(self) -> list[Hypothesis]:
        """Returns all refuted hypotheses."""
        return [
            h for h in self._hypotheses.values()
            if h.status == HypothesisStatus.REFUTED
        ]

    def get_hypotheses_by_type(self, hypothesis_type: str) -> list[Hypothesis]:
        """Returns all hypotheses of a specific type."""
        hypothesis_ids = self._hypotheses_by_type.get(hypothesis_type, [])
        return [self._hypotheses[hid] for hid in hypothesis_ids if hid in self._hypotheses]

    def rank_hypotheses(self) -> list[Hypothesis]:
        """Returns all active hypotheses ranked by confidence (highest first)."""
        active = self.get_active_hypotheses()

        # Sort by posterior probability (descending), then by evidence count (descending)
        ranked = sorted(
            active,
            key=lambda h: (h.posterior_probability, h.evidence_count),
            reverse=True,
        )

        return ranked

    def get_top_hypotheses(self, n: int = 5) -> list[Hypothesis]:
        """Returns the top N most confident active hypotheses."""
        return self.rank_hypotheses()[:n]

    def find_competing_hypotheses(self) -> list[tuple[Hypothesis, Hypothesis]]:
        """Finds pairs of hypotheses that offer competing explanations.

        Two hypotheses compete if they explain the same phenomenon
        but make different predictions.
        """
        competing: list[tuple[Hypothesis, Hypothesis]] = []

        active = self.get_active_hypotheses()

        for i, h1 in enumerate(active):
            for h2 in active[i+1:]:
                # Simple heuristic: same type but different descriptions
                if h1.hypothesis_type == h2.hypothesis_type:
                    if h1.description != h2.description:
                        # Check if they reference the same endpoint/resource
                        h1_resource = h1.metadata.get("endpoint", h1.metadata.get("resource", ""))
                        h2_resource = h2.metadata.get("endpoint", h2.metadata.get("resource", ""))
                        if h1_resource and h1_resource == h2_resource:
                            competing.append((h1, h2))

        return competing

    def detect_conflicts(self) -> list[dict[str, Any]]:
        """Detects internal conflicts in the belief system.

        A conflict exists when:
        1. Two confirmed hypotheses make contradictory predictions
        2. A confirmed hypothesis has strong contradicting evidence
        """
        conflicts: list[dict[str, Any]] = []

        # Check confirmed hypotheses with contradicting evidence
        for h in self.get_confirmed_hypotheses():
            strong_contradicting = [
                e for e in h.contradicting_evidence if e.strength > 0.8
            ]
            if strong_contradicting:
                conflicts.append({
                    "type": "confirmed_with_contradiction",
                    "hypothesis_id": h.id,
                    "description": h.description,
                    "confidence": h.posterior_probability,
                    "contradicting_evidence_count": len(strong_contradicting),
                })

        # Check competing confirmed hypotheses
        competing = self.find_competing_hypotheses()
        for h1, h2 in competing:
            if h1.status == HypothesisStatus.CONFIRMED and h2.status == HypothesisStatus.CONFIRMED:
                conflicts.append({
                    "type": "competing_confirmed",
                    "hypothesis_1": h1.description,
                    "hypothesis_2": h2.description,
                    "confidence_1": h1.posterior_probability,
                    "confidence_2": h2.posterior_probability,
                })

        return conflicts

    def get_information_gain_estimate(self, hypothesis_id: str) -> float:
        """Estimates how much information a test of this hypothesis would provide.

        Higher values indicate that testing this hypothesis would be
        more informative — it would resolve more uncertainty.

        Uses entropy-based measure: hypotheses near 0.5 confidence
        provide the most information when tested.
        """
        hypothesis = self._hypotheses.get(hypothesis_id)
        if hypothesis is None:
            return 0.0

        # Binary entropy: H(p) = -p * log2(p) - (1-p) * log2(1-p)
        p = hypothesis.posterior_probability
        p = max(0.01, min(0.99, p))  # Avoid log(0)

        entropy = -p * math.log2(p) - (1 - p) * math.log2(1 - p)

        # Normalize to 0-1
        max_entropy = 1.0  # Maximum binary entropy
        normalized_entropy = entropy / max_entropy

        # Weight by evidence count (fewer evidence = more informative to test)
        evidence_weight = 1.0 / (1.0 + hypothesis.evidence_count * 0.1)

        # Weight by hypothesis importance (if available)
        importance = hypothesis.metadata.get("importance", 1.0)

        return normalized_entropy * evidence_weight * importance

    def suggest_next_test(self) -> dict[str, Any] | None:
        """Suggests which hypothesis to test next based on information gain.

        Returns a dict with the hypothesis and test suggestions, or None
        if no active hypotheses exist.
        """
        active = self.get_active_hypotheses()
        if not active:
            return None

        # Calculate information gain for each
        gains = [
            (h, self.get_information_gain_estimate(h.id))
            for h in active
        ]

        # Sort by information gain (highest first)
        gains.sort(key=lambda pair: pair[1], reverse=True)

        best_hypothesis, best_gain = gains[0]

        return {
            "hypothesis_id": best_hypothesis.id,
            "description": best_hypothesis.description,
            "type": best_hypothesis.hypothesis_type,
            "confidence": best_hypothesis.posterior_probability,
            "information_gain": best_gain,
            "test_suggestions": best_hypothesis.test_suggestions,
            "predictions": best_hypothesis.predictions,
        }

    def _evict_weakest(self) -> None:
        """Evicts the weakest hypotheses when over capacity.

        Priority for eviction:
        1. REFUTED hypotheses (oldest first)
        2. SUPERSEDED hypotheses (oldest first)
        3. WEAKEST confidence active hypotheses
        """
        # First evict refuted and superseded
        evictable = [
            h for h in self._hypotheses.values()
            if h.status in (HypothesisStatus.REFUTED, HypothesisStatus.SUPERSEDED)
        ]

        if evictable:
            # Sort by timestamp (oldest first)
            evictable.sort(key=lambda h: h.created_at)
            to_remove = evictable[0]
            self._remove_hypothesis(to_remove.id)
            return

        # If no refuted/superseded, evict the weakest active hypothesis
        active = self.get_active_hypotheses()
        if active:
            weakest = min(active, key=lambda h: h.posterior_probability)
            self._remove_hypothesis(weakest.id)

    def _remove_hypothesis(self, hypothesis_id: str) -> None:
        """Removes a hypothesis from the system."""
        hypothesis = self._hypotheses.pop(hypothesis_id, None)
        if hypothesis:
            if hypothesis_id in self._hypotheses_by_type.get(hypothesis.hypothesis_type, []):
                self._hypotheses_by_type[hypothesis.hypothesis_type].remove(hypothesis_id)

    def get_statistics(self) -> dict[str, Any]:
        """Returns comprehensive statistics about the belief system."""
        active = self.get_active_hypotheses()
        confirmed = self.get_confirmed_hypotheses()
        refuted = self.get_refuted_hypotheses()

        return {
            "total_hypotheses": len(self._hypotheses),
            "active_hypotheses": len(active),
            "confirmed_hypotheses": len(confirmed),
            "refuted_hypotheses": len(refuted),
            "hypotheses_by_type": {
                hyp_type: len(ids)
                for hyp_type, ids in self._hypotheses_by_type.items()
            },
            "top_hypotheses": [
                {
                    "description": h.description[:100],
                    "confidence": h.posterior_probability,
                    "type": h.hypothesis_type,
                    "status": h.status.value,
                }
                for h in self.get_top_hypotheses(5)
            ],
            "conflicts_detected": len(self.detect_conflicts()),
            "internal_stats": dict(self._stats),
        }

    def export_state(self) -> dict[str, Any]:
        """Exports the current state for persistence or analysis."""
        return {
            "hypotheses": [
                {
                    "id": h.id,
                    "description": h.description,
                    "type": h.hypothesis_type,
                    "status": h.status.value,
                    "confidence": h.posterior_probability,
                    "supporting_evidence": len(h.supporting_evidence),
                    "contradicting_evidence": len(h.contradicting_evidence),
                    "revision_count": h.revision_count,
                    "created_at": h.created_at,
                }
                for h in self._hypotheses.values()
            ],
            "statistics": self.get_statistics(),
        }
