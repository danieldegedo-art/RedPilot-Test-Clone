"""Self-Reflection Engine — Metacognition and Blind Spot Detection.

Implements the cognitive ability to monitor and evaluate the system's
own reasoning process. Unlike tools that only look outward at the target
system, this component looks INWARD at how the testing itself is going:

- "Am I being thorough enough?"
- "Am I stuck in a pattern that isn't working?"
- "What am I not considering?"
- "Is my confidence in this finding justified?"
- "Should I change my approach?"

Implements concepts from:
- Metacognition: "Thinking about thinking" — monitoring and controlling
  one's own cognitive processes
- Calibration: Matching stated confidence to actual accuracy
- Bias Detection: Identifying systematic errors in reasoning
- Reflective Equilibrium: Adjusting beliefs to maintain consistency
- Self-Verification: Checking one's own conclusions without external validation

The engine operates as follows:
1. Monitors the reasoning process (what hypotheses were formed, tested, confirmed)
2. Tracks prediction accuracy (how often confident predictions were correct)
3. Detects cognitive biases (confirmation bias, anchoring, availability)
4. Identifies blind spots (areas consistently overlooked)
5. Recommends strategy corrections when reasoning quality degrades
6. Maintains calibration (confidence matches reality)

This is the component that prevents the system from confidently being
wrong — it catches its own mistakes before they become findings.
"""
from __future__ import annotations

import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable
from uuid import uuid4


class BiasType(Enum):
    """Types of cognitive biases that can affect reasoning."""
    CONFIRMATION_BIAS = "confirmation_bias"  # Seeking evidence that confirms existing beliefs
    ANCHORING_BIAS = "anchoring_bias"  # Over-relying on first piece of information
    AVAILABILITY_BIAS = "availability_bias"  # Over-weighting recent/vivid information
    REPRESENTATIVENESS_BIAS = "representativeness_bias"  # Judging by similarity rather than probability
    OVERCONFIDENCE_BIAS = "overconfidence_bias"  # Being more certain than justified
    UNDERCONFIDENCE_BIAS = "underconfidence_bias"  # Being less certain than justified
    FRAMING_EFFECT = "framing_effect"  # Being influenced by how information is presented
    SUNK_COST_FALLACY = "sunk_cost_fallacy"  # Continuing a failing approach because invested


class CalibrationStatus(Enum):
    """Calibration of confidence vs. actual accuracy."""
    WELL_CALIBRATED = "well_calibrated"
    OVERCONFIDENT = "overconfident"
    UNDERCONFIDENT = "underconfident"
    INSUFFICIENT_DATA = "insufficient_data"


@dataclass
class PredictionRecord:
    """A prediction made by the system, tracked for accuracy."""
    id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: float = field(default_factory=time.time)
    hypothesis_id: str = ""
    prediction: str = ""
    confidence: float = 0.5  # Stated confidence at time of prediction
    actual_outcome: str = ""  # What actually happened
    correct: bool | None = None  # Whether the prediction was correct
    resolution_timestamp: float | None = None

    def resolve(self, actual_outcome: str, correct: bool) -> None:
        """Resolves the prediction with the actual outcome."""
        self.actual_outcome = actual_outcome
        self.correct = correct
        self.resolution_timestamp = time.time()


@dataclass
class ReasoningTrace:
    """A trace of the reasoning process for a single decision or hypothesis."""
    id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: float = field(default_factory=time.time)
    context: str = ""  # What situation triggered this reasoning
    hypothesis_formed: str = ""
    evidence_considered: list[str] = field(default_factory=list)
    evidence_ignored: list[str] = field(default_factory=list)  # What wasn't considered
    conclusion: str = ""
    confidence: float = 0.5
    time_spent_ms: float = 0.0
    decisions_made: list[str] = field(default_factory=list)
    alternatives_considered: list[str] = field(default_factory=list)
    assumptions_made: list[str] = field(default_factory=list)


@dataclass
class BlindSpot:
    """An identified blind spot in the system's reasoning."""
    id: str = field(default_factory=lambda: str(uuid4()))
    category: str = ""  # What type of blind spot
    description: str = ""
    evidence: str = ""  # How we know this is a blind spot
    impact: str = ""  # What this blind spot might cause us to miss
    recommendation: str = ""  # How to address it
    discovered_at: float = field(default_factory=time.time)
    severity: str = "medium"  # "low", "medium", "high"


@dataclass
class StrategyCorrection:
    """A recommended correction to the reasoning strategy."""
    id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: float = field(default_factory=time.time)
    trigger: str = ""  # What caused this correction to be recommended
    current_behavior: str = ""  # What the system is currently doing
    recommended_behavior: str = ""  # What it should do instead
    rationale: str = ""  # Why this correction is needed
    confidence: float = 0.5
    priority: str = "medium"  # "low", "medium", "high", "critical"


class CalibrationTracker:
    """Tracks whether stated confidence matches actual accuracy.

    A well-calibrated system that says "I'm 70% confident" should be
    correct 70% of the time. This tracker measures the gap between
    stated confidence and actual accuracy.
    """

    def __init__(self, window_size: int = 100):
        self._predictions: deque[PredictionRecord] = deque(maxlen=window_size)
        self._resolved_count = 0
        self._correct_count = 0

        # Confidence buckets for calibration curve
        self._confidence_buckets: dict[float, list[bool]] = defaultdict(list)

    def record_prediction(self, prediction: PredictionRecord) -> None:
        """Records a new prediction."""
        self._predictions.append(prediction)

    def resolve_prediction(self, prediction_id: str, actual_outcome: str, correct: bool) -> None:
        """Resolves a prediction with its actual outcome."""
        for pred in self._predictions:
            if pred.id == prediction_id:
                pred.resolve(actual_outcome, correct)
                self._resolved_count += 1
                if correct:
                    self._correct_count += 1

                # Add to confidence bucket
                bucket = round(pred.confidence, 1)  # Round to nearest 0.1
                self._confidence_buckets[bucket].append(correct)
                break

    def get_calibration_status(self) -> CalibrationStatus:
        """Returns the current calibration status."""
        if self._resolved_count < 20:
            return CalibrationStatus.INSUFFICIENT_DATA

        accuracy = self._correct_count / self._resolved_count
        avg_confidence = sum(p.confidence for p in self._predictions if p.correct is not None) / max(1, self._resolved_count)

        # Compare stated confidence to actual accuracy
        gap = avg_confidence - accuracy

        if gap > 0.15:
            return CalibrationStatus.OVERCONFIDENT
        elif gap < -0.15:
            return CalibrationStatus.UNDERCONFIDENT
        else:
            return CalibrationStatus.WELL_CALIBRATED

    def get_calibration_curve(self) -> list[dict[str, Any]]:
        """Returns the calibration curve data.

        A perfectly calibrated system has a diagonal line from (0,0) to (1,1).
        """
        curve = []
        for confidence in sorted(self._confidence_buckets.keys()):
            outcomes = self._confidence_buckets[confidence]
            if outcomes:
                actual_rate = sum(outcomes) / len(outcomes)
                curve.append({
                    "stated_confidence": confidence,
                    "actual_accuracy": actual_rate,
                    "sample_count": len(outcomes),
                    "gap": confidence - actual_rate,
                })
        return curve

    def get_calibration_score(self) -> float:
        """Returns a calibration score (0.0 to 1.0, higher = better calibrated)."""
        if self._resolved_count < 10:
            return 0.5  # Default with insufficient data

        # Calculate Brier score (lower = better)
        # Brier = average of (confidence - correct)^2
        brier_sum = 0.0
        count = 0

        for pred in self._predictions:
            if pred.correct is not None:
                brier_sum += (pred.confidence - (1.0 if pred.correct else 0.0)) ** 2
                count += 1

        if count == 0:
            return 0.5

        brier_score = brier_sum / count

        # Convert Brier score to calibration score (0 = worst, 1 = perfect)
        # Brier score ranges from 0 (perfect) to 1 (worst)
        calibration_score = 1.0 - brier_score

        return calibration_score

    @property
    def statistics(self) -> dict[str, Any]:
        return {
            "total_predictions": len(self._predictions),
            "resolved_predictions": self._resolved_count,
            "correct_predictions": self._correct_count,
            "accuracy": self._correct_count / self._resolved_count if self._resolved_count > 0 else 0.0,
            "calibration_status": self.get_calibration_status().value,
            "calibration_score": self.get_calibration_score(),
            "calibration_curve": self.get_calibration_curve(),
        }


class BiasDetector:
    """Detects cognitive biases in the system's reasoning patterns.

    Unlike humans, an AI system can be explicitly checked for biases
    because its entire reasoning history is available for analysis.
    """

    def __init__(self):
        self._reasoning_history: list[ReasoningTrace] = []
        self._detected_biases: list[dict[str, Any]] = []

    def record_reasoning(self, trace: ReasoningTrace) -> None:
        """Records a reasoning trace for bias analysis."""
        self._reasoning_history.append(trace)

        # Check for biases periodically
        if len(self._reasoning_history) % 10 == 0:
            self._detect_biases()

    def _detect_biases(self) -> None:
        """Analyzes reasoning history for bias patterns."""
        if len(self._reasoning_history) < 10:
            return

        self._detected_biases = []

        # Detect confirmation bias
        self._detect_confirmation_bias()

        # Detect anchoring bias
        self._detect_anchoring_bias()

        # Detect availability bias
        self._detect_availability_bias()

        # Detect overconfidence
        self._detect_overconfidence()

        # Detect sunk cost fallacy
        self._detect_sunk_cost()

    def _detect_confirmation_bias(self) -> None:
        """Detects confirmation bias — seeking evidence that confirms existing beliefs."""
        # Look for patterns where:
        # - The same hypothesis is repeatedly tested
        # - Contradicting evidence is consistently ignored
        # - Only supporting evidence is cited

        hypothesis_evidence: dict[str, dict[str, int]] = defaultdict(lambda: {"supporting": 0, "contradicting": 0})

        for trace in self._reasoning_history:
            if trace.hypothesis_formed:
                # Check evidence considered vs ignored
                supporting = len([e for e in trace.evidence_considered if "supports" in e.lower()])
                contradicting = len([e for e in trace.evidence_considered if "contradicts" in e.lower()])

                # Check if contradicting evidence was ignored
                if trace.evidence_ignored:
                    ignored_contradicting = len([e for e in trace.evidence_ignored if "contradicts" in e.lower()])
                    contradicting += ignored_contradicting

                hypothesis_key = trace.hypothesis_formed[:50]  # Simple grouping
                hypothesis_evidence[hypothesis_key]["supporting"] += supporting
                hypothesis_evidence[hypothesis_key]["contradicting"] += contradicting

        # Check for hypotheses with high supporting-to-contradicting ratio
        # but low confidence (suggests bias rather than strong evidence)
        for hypothesis, counts in hypothesis_evidence.items():
            total = counts["supporting"] + counts["contradicting"]
            if total >= 5:
                support_ratio = counts["supporting"] / total
                if support_ratio > 0.8 and counts["contradicting"] > 0:
                    self._detected_biases.append({
                        "type": BiasType.CONFIRMATION_BIAS.value,
                        "description": (
                            f"Hypothesis '{hypothesis}...' shows {support_ratio:.0%} supporting "
                            f"evidence with {counts['contradicting']} contradicting evidence points "
                            f"that may have been under-weighted"
                        ),
                        "severity": "medium" if support_ratio > 0.9 else "low",
                    })

    def _detect_anchoring_bias(self) -> None:
        """Detects anchoring bias — over-relying on first information."""
        # Look for patterns where early evidence disproportionately influences later conclusions

        if len(self._reasoning_history) < 5:
            return

        # Check if early traces have outsized influence
        early_traces = self._reasoning_history[:len(self._reasoning_history) // 3]
        late_traces = self._reasoning_history[-len(self._reasoning_history) // 3:]

        # Compare confidence levels
        early_confidence = sum(t.confidence for t in early_traces) / len(early_traces)
        late_confidence = sum(t.confidence for t in late_traces) / len(late_traces)

        # Check if early conclusions are never revised despite new evidence
        early_conclusions = {t.conclusion[:50] for t in early_traces}
        late_conclusions = {t.conclusion[:50] for t in late_traces}

        unchanged = early_conclusions & late_conclusions
        if len(unchanged) > len(early_conclusions) * 0.7 and len(self._reasoning_history) > 10:
            self._detected_biases.append({
                "type": BiasType.ANCHORING_BIAS.value,
                "description": (
                    f"{len(unchanged)} conclusions from early reasoning remain unchanged "
                    f"despite later evidence — early hypotheses may be anchoring later analysis"
                ),
                "severity": "low" if len(unchanged) < 5 else "medium",
            })

    def _detect_availability_bias(self) -> None:
        """Detects availability bias — over-weighting recent/vivid information."""
        # Look for patterns where recent events disproportionately influence decisions

        if len(self._reasoning_history) < 10:
            return

        # Compare hypothesis diversity in early vs late reasoning
        early_hypotheses = {t.hypothesis_formed[:30] for t in self._reasoning_history[:10] if t.hypothesis_formed}
        late_hypotheses = {t.hypothesis_formed[:30] for t in self._reasoning_history[-10:] if t.hypothesis_formed}

        # If late hypotheses are all variations of the same theme
        if late_hypotheses and len(late_hypotheses) < len(early_hypotheses) * 0.5:
            self._detected_biases.append({
                "type": BiasType.AVAILABILITY_BIAS.value,
                "description": (
                    f"Hypothesis diversity has decreased — late reasoning focuses on "
                    f"{len(late_hypotheses)} themes vs {len(early_hypotheses)} earlier. "
                    f"Recent findings may be over-weighted"
                ),
                "severity": "low",
            })

    def _detect_overconfidence(self) -> None:
        """Detects overconfidence — being more certain than justified."""
        # Look for high confidence with limited evidence

        high_confidence_traces = [
            t for t in self._reasoning_history
            if t.confidence > 0.8 and len(t.evidence_considered) < 2
        ]

        if len(high_confidence_traces) > 3:
            self._detected_biases.append({
                "type": BiasType.OVERCONFIDENCE_BIAS.value,
                "description": (
                    f"{len(high_confidence_traces)} reasoning traces show >80% confidence "
                    f"with fewer than 2 pieces of evidence — conclusions may be premature"
                ),
                "severity": "medium",
            })

    def _detect_sunk_cost(self) -> None:
        """Detects sunk cost fallacy — continuing failing approaches."""
        # Look for repeated testing of the same hypothesis that never resolves

        hypothesis_attempts: dict[str, int] = defaultdict(int)
        for trace in self._reasoning_history:
            if trace.hypothesis_formed:
                hypothesis_attempts[trace.hypothesis_formed[:50]] += 1

        persistent_hypotheses = {
            h: count for h, count in hypothesis_attempts.items()
            if count >= 5
        }

        if persistent_hypotheses:
            self._detected_biases.append({
                "type": BiasType.SUNK_COST_FALLACY.value,
                "description": (
                    f"{len(persistent_hypotheses)} hypothesis/hypotheses tested 5+ times "
                    f"without resolution — may indicate continued investment in failing approaches"
                ),
                "severity": "medium" if len(persistent_hypotheses) > 2 else "low",
            })

    @property
    def detected_biases(self) -> list[dict[str, Any]]:
        """Returns currently detected biases."""
        return self._detected_biases

    def get_bias_summary(self) -> dict[str, Any]:
        """Returns a summary of detected biases."""
        by_type = defaultdict(list)
        for bias in self._detected_biases:
            by_type[bias["type"]].append(bias)

        return {
            "total_biases_detected": len(self._detected_biases),
            "by_type": {
                bias_type: {
                    "count": len(biases),
                    "max_severity": max(b.get("severity", "low") for b in biases),
                }
                for bias_type, biases in by_type.items()
            },
            "recommendations": self._get_bias_recommendations(),
        }

    def _get_bias_recommendations(self) -> list[str]:
        """Returns recommendations for addressing detected biases."""
        recommendations = []

        for bias in self._detected_biases:
            bias_type = bias["type"]
            if bias_type == BiasType.CONFIRMATION_BIAS.value:
                recommendations.append(
                    "Actively seek contradicting evidence for current hypotheses. "
                    "Consider alternative explanations for observed patterns."
                )
            elif bias_type == BiasType.ANCHORING_BIAS.value:
                recommendations.append(
                    "Re-evaluate early conclusions in light of new evidence. "
                    "Consider whether initial assumptions still hold."
                )
            elif bias_type == BiasType.AVAILABILITY_BIAS.value:
                recommendations.append(
                    "Broaden hypothesis space — consider types of inconsistencies "
                    "beyond those recently encountered."
                )
            elif bias_type == BiasType.OVERCONFIDENCE_BIAS.value:
                recommendations.append(
                    "Gather more evidence before drawing conclusions. "
                    "Lower confidence thresholds for hypotheses with limited support."
                )
            elif bias_type == BiasType.SUNK_COST_FALLACY.value:
                recommendations.append(
                    "Abandon hypotheses that have been tested multiple times without "
                    "resolution. Redirect effort to new approaches."
                )

        return list(set(recommendations))  # Remove duplicates


class SelfReflectionEngine:
    """Monitors and evaluates the system's own reasoning process.

    This is the metacognitive layer — it watches how the system thinks
    and corrects problems in the thinking process itself.

    Key capabilities:
    1. Calibration tracking: "Is my confidence justified?"
    2. Bias detection: "Am I thinking in systematically wrong ways?"
    3. Blind spot identification: "What am I consistently missing?"
    4. Strategy correction: "Should I change my approach?"
    5. Self-verification: "Can I check my own conclusions?"
    """

    def __init__(self, window_size: int = 100):
        self._calibration = CalibrationTracker(window_size=window_size)
        self._bias_detector = BiasDetector()
        self._reasoning_traces: deque[ReasoningTrace] = deque(maxlen=window_size)

        self._blind_spots: list[BlindSpot] = []
        self._strategy_corrections: list[StrategyCorrection] = []

        self._last_reflection_time = 0.0
        self._reflection_count = 0

        # Performance tracking
        self._hypothesis_success_rate: deque[float] = deque(maxlen=20)
        self._discovery_rate_history: deque[float] = deque(maxlen=20)

    def record_reasoning(
        self,
        context: str,
        hypothesis_formed: str,
        evidence_considered: list[str],
        conclusion: str,
        confidence: float,
        evidence_ignored: list[str] | None = None,
        alternatives_considered: list[str] | None = None,
        assumptions_made: list[str] | None = None,
    ) -> ReasoningTrace:
        """Records a reasoning trace for later reflection."""
        trace = ReasoningTrace(
            context=context,
            hypothesis_formed=hypothesis_formed,
            evidence_considered=evidence_considered,
            evidence_ignored=evidence_ignored or [],
            conclusion=conclusion,
            confidence=confidence,
            alternatives_considered=alternatives_considered or [],
            assumptions_made=assumptions_made or [],
        )

        self._reasoning_traces.append(trace)
        self._bias_detector.record_reasoning(trace)

        return trace

    def record_prediction(
        self,
        hypothesis_id: str,
        prediction: str,
        confidence: float,
    ) -> PredictionRecord:
        """Records a prediction for calibration tracking."""
        record = PredictionRecord(
            hypothesis_id=hypothesis_id,
            prediction=prediction,
            confidence=confidence,
        )
        self._calibration.record_prediction(record)
        return record

    def resolve_prediction(
        self,
        prediction_id: str,
        actual_outcome: str,
        correct: bool,
    ) -> None:
        """Resolves a prediction to update calibration."""
        self._calibration.resolve_prediction(prediction_id, actual_outcome, correct)

    def reflect(self) -> dict[str, Any]:
        """Performs a self-reflection cycle.

        Returns a comprehensive analysis of the system's own reasoning quality.
        """
        self._reflection_count += 1
        self._last_reflection_time = time.time()

        # Get calibration status
        calibration = self._calibration.statistics

        # Get bias analysis
        bias_summary = self._bias_detector.get_bias_summary()

        # Identify blind spots
        self._identify_blind_spots()

        # Generate strategy corrections
        self._generate_strategy_corrections()

        # Compile reflection report
        report = {
            "reflection_number": self._reflection_count,
            "timestamp": self._last_reflection_time,
            "calibration": calibration,
            "biases": bias_summary,
            "blind_spots": [bs.__dict__ for bs in self._blind_spots],
            "strategy_corrections": [sc.__dict__ for sc in self._strategy_corrections],
            "reasoning_quality": self._assess_reasoning_quality(),
            "recommendations": self._generate_overall_recommendations(),
        }

        return report

    def _identify_blind_spots(self) -> None:
        """Identifies blind spots in the reasoning process."""
        new_blind_spots: list[BlindSpot] = []

        # Blind spot 1: Endpoint types never tested
        if len(self._reasoning_traces) >= 10:
            tested_contexts = {t.context for t in self._reasoning_traces}
            # Look for patterns in what's been tested vs. what's available
            context_types = defaultdict(int)
            for context in tested_contexts:
                # Extract endpoint type from context
                if "payment" in context.lower():
                    context_types["payment"] += 1
                elif "subscription" in context.lower():
                    context_types["subscription"] += 1
                elif "auth" in context.lower() or "session" in context.lower():
                    context_types["auth"] += 1
                elif "webhook" in context.lower():
                    context_types["webhook"] += 1

            # If certain types are never/rarely tested
            common_types = ["payment", "subscription", "auth", "webhook"]
            for expected_type in common_types:
                if context_types.get(expected_type, 0) == 0:
                    new_blind_spots.append(BlindSpot(
                        category="untested_resource_type",
                        description=f"No reasoning traces involve {expected_type} endpoints",
                        evidence=f"0 traces out of {len(self._reasoning_traces)} mention {expected_type}",
                        impact=f"May miss {expected_type}-specific inconsistencies",
                        recommendation=f"Actively test {expected_type} endpoints",
                        severity="high",
                    ))

        # Blind spot 2: Only testing what's expected
        # Look for reasoning that only considers "normal" scenarios
        normal_only = sum(
            1 for t in self._reasoning_traces
            if "normal" in t.context.lower() or "expected" in t.context.lower()
        )
        if normal_only > len(self._reasoning_traces) * 0.8:
            new_blind_spots.append(BlindSpot(
                category="conventional_thinking",
                description="Reasoning focuses predominantly on expected/normal scenarios",
                evidence=f"{normal_only}/{len(self._reasoning_traces)} traces involve normal scenarios",
                impact="May miss unusual or unexpected inconsistencies",
                recommendation="Actively generate unusual test scenarios",
                severity="medium",
            ))

        # Blind spot 3: Ignoring evidence
        traces_with_ignored = [
            t for t in self._reasoning_traces if t.evidence_ignored
        ]
        if len(traces_with_ignored) > len(self._reasoning_traces) * 0.3:
            new_blind_spots.append(BlindSpot(
                category="ignored_evidence",
                description="Significant amount of evidence is being ignored during reasoning",
                evidence=f"{len(traces_with_ignored)}/{len(self._reasoning_traces)} traces have ignored evidence",
                impact="May miss important contradicting information",
                recommendation="Review why evidence is being ignored — is it truly irrelevant?",
                severity="medium",
            ))

        self._blind_spots = new_blind_spots

    def _generate_strategy_corrections(self) -> None:
        """Generates strategy corrections based on reflection."""
        corrections: list[StrategyCorrection] = []

        # Correction 1: Overconfidence → reduce confidence thresholds
        if self._calibration.get_calibration_status() == CalibrationStatus.OVERCONFIDENT:
            corrections.append(StrategyCorrection(
                trigger="System is overconfident",
                current_behavior="High confidence with insufficient evidence",
                recommended_behavior="Lower confidence for hypotheses with <3 pieces of evidence",
                rationale=f"Calibration score: {self._calibration.get_calibration_score():.2f} — stated confidence exceeds actual accuracy",
                confidence=0.8,
                priority="high",
            ))

        # Correction 2: Confirmation bias → seek contradicting evidence
        bias_types = {b["type"] for b in self._bias_detector.detected_biases}
        if BiasType.CONFIRMATION_BIAS.value in bias_types:
            corrections.append(StrategyCorrection(
                trigger="Confirmation bias detected",
                current_behavior="Favoring supporting evidence",
                recommended_behavior="Actively generate tests that could disprove current hypotheses",
                rationale="Bias analysis shows systematic preference for confirming evidence",
                confidence=0.7,
                priority="medium",
            ))

        # Correction 3: Sunk cost → abandon failing approaches
        if BiasType.SUNK_COST_FALLACY.value in bias_types:
            corrections.append(StrategyCorrection(
                trigger="Sunk cost fallacy detected",
                current_behavior="Continuing to test hypotheses that haven't resolved",
                recommended_behavior="Set explicit abandonment criteria — if a hypothesis hasn't resolved after N attempts, deprioritize it",
                rationale="Multiple hypotheses tested 5+ times without resolution",
                confidence=0.7,
                priority="medium",
            ))

        # Correction 4: High blind spots → broaden search
        high_severity_blind_spots = [bs for bs in self._blind_spots if bs.severity == "high"]
        if high_severity_blind_spots:
            corrections.append(StrategyCorrection(
                trigger="High-severity blind spots identified",
                current_behavior="Narrow focus on specific areas",
                recommended_behavior="Broaden testing to cover identified blind spots",
                rationale=f"{len(high_severity_blind_spots)} high-severity blind spots detected",
                confidence=0.8,
                priority="high",
            ))

        self._strategy_corrections = corrections

    def _assess_reasoning_quality(self) -> dict[str, Any]:
        """Assesses the overall quality of reasoning."""
        if not self._reasoning_traces:
            return {"quality": "unknown", "reason": "No reasoning traces available"}

        # Calculate metrics
        avg_confidence = sum(t.confidence for t in self._reasoning_traces) / len(self._reasoning_traces)
        avg_evidence = sum(len(t.evidence_considered) for t in self._reasoning_traces) / len(self._reasoning_traces)
        avg_alternatives = sum(len(t.alternatives_considered) for t in self._reasoning_traces) / len(self._reasoning_traces)

        # Quality assessment
        quality_score = 0.0

        # Good: considering multiple alternatives
        if avg_alternatives > 2:
            quality_score += 0.3
        elif avg_alternatives > 1:
            quality_score += 0.15

        # Good: using sufficient evidence
        if avg_evidence > 3:
            quality_score += 0.3
        elif avg_evidence > 1:
            quality_score += 0.15

        # Good: well-calibrated confidence
        calibration_score = self._calibration.get_calibration_score()
        quality_score += calibration_score * 0.4

        # Determine quality label
        if quality_score > 0.7:
            quality = "high"
        elif quality_score > 0.5:
            quality = "moderate"
        else:
            quality = "low"

        return {
            "quality": quality,
            "score": quality_score,
            "average_confidence": avg_confidence,
            "average_evidence_count": avg_evidence,
            "average_alternatives_considered": avg_alternatives,
            "calibration_score": calibration_score,
        }

    def _generate_overall_recommendations(self) -> list[str]:
        """Generates overall recommendations based on self-reflection."""
        recommendations = []

        # From calibration
        calibration_status = self._calibration.get_calibration_status()
        if calibration_status == CalibrationStatus.OVERCONFIDENT:
            recommendations.append(
                "Reduce confidence in current hypotheses — stated confidence exceeds actual accuracy"
            )
        elif calibration_status == CalibrationStatus.UNDERCONFIDENT:
            recommendations.append(
                "Increase confidence in well-supported hypotheses — being too conservative may miss findings"
            )

        # From biases
        for bias in self._bias_detector.detected_biases:
            if bias.get("severity") in ("medium", "high"):
                recommendations.append(f"Address {bias['type']}: {bias.get('description', '')[:80]}")

        # From blind spots
        for blind_spot in self._blind_spots:
            if blind_spot.severity == "high":
                recommendations.append(f"Address blind spot: {blind_spot.description}")

        return recommendations

    def get_self_verification(self) -> dict[str, Any]:
        """Performs self-verification — checks conclusions without external validation.

        This asks: "If I were to check my own work, what would I look for?"
        """
        verification_checks: list[dict[str, Any]] = []

        # Check 1: Are confirmed hypotheses well-supported?
        for trace in self._reasoning_traces:
            if trace.confidence > 0.8:
                supporting_evidence = len(trace.evidence_considered)
                if supporting_evidence < 2:
                    verification_checks.append({
                        "check": "evidence_sufficiency",
                        "concern": f"High confidence ({trace.confidence:.0%}) with only {supporting_evidence} evidence points",
                        "recommendation": "Gather additional evidence before fully trusting this conclusion",
                    })

        # Check 2: Are there contradictions between conclusions?
        conclusions = [t.conclusion for t in self._reasoning_traces if t.conclusion]
        for i, c1 in enumerate(conclusions):
            for c2 in conclusions[i+1:]:
                if self._are_contradictory(c1, c2):
                    verification_checks.append({
                        "check": "internal_consistency",
                        "concern": f"Potentially contradictory conclusions: '{c1[:40]}' vs '{c2[:40]}'",
                        "recommendation": "Investigate whether both conclusions can be simultaneously true",
                    })

        return {
            "verification_checks": verification_checks,
            "overall_verification_status": "passed" if not verification_checks else "needs_review",
        }

    def _are_contradictory(self, conclusion1: str, conclusion2: str) -> bool:
        """Simple check for contradictory conclusions."""
        # Look for negation patterns
        negation_words = {"not", "no", "cannot", "never", "doesn't", "isn't"}
        words1 = set(conclusion1.lower().split())
        words2 = set(conclusion2.lower().split())

        has_neg1 = bool(words1 & negation_words)
        has_neg2 = bool(words2 & negation_words)

        if has_neg1 != has_neg2:
            shared = words1 & words2 - negation_words
            if len(shared) > len(words1) * 0.4:
                return True

        return False

    def get_statistics(self) -> dict[str, Any]:
        """Returns comprehensive statistics about self-reflection."""
        return {
            "reflection_count": self._reflection_count,
            "last_reflection_age": time.time() - self._last_reflection_time if self._last_reflection_time else None,
            "reasoning_traces_recorded": len(self._reasoning_traces),
            "calibration": self._calibration.statistics,
            "biases": self._bias_detector.get_bias_summary(),
            "blind_spots": len(self._blind_spots),
            "strategy_corrections": len(self._strategy_corrections),
            "reasoning_quality": self._assess_reasoning_quality(),
        }
