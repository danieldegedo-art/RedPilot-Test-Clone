"""Multi-Perspective Reasoning Engine — Role-Based Analysis.

Implements the cognitive ability to analyze the same situation from
multiple viewpoints simultaneously. Unlike single-perspective tools
that only think like an attacker, this component considers:

- Attacker: "How can I exploit this?"
- Defender: "How would I protect against this?"
- Developer: "What assumptions did I make that could be wrong?"
- Auditor: "What evidence do I need to prove this is safe?"

This multi-perspective approach catches blind spots that any single
viewpoint would miss. A pure attacker perspective might miss defensive
mechanisms that partially work. A pure defender perspective might miss
creative circumvention paths. Only by considering ALL viewpoints can
the system develop a complete understanding.

Implements concepts from:
- Multi-Agent Cognitive Argumentation (MACAA)
- Role-based reasoning in multi-agent systems
- Adversarial self-play (the system argues with itself)
- Devil's Advocate methodology for identifying weaknesses in reasoning

The engine operates as follows:
1. A situation/observation is presented to all perspectives
2. Each perspective generates its own analysis and hypotheses
3. Perspectives debate and challenge each other's conclusions
4. The argumentation framework resolves conflicts
5. A synthesized understanding emerges that incorporates all viewpoints
"""
from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable
from uuid import uuid4


class PerspectiveType(Enum):
    """The different perspectives from which to analyze a situation."""
    ATTACKER = "attacker"
    DEFENDER = "defender"
    DEVELOPER = "developer"
    AUDITOR = "auditor"
    USER = "user"  # Legitimate user perspective


class ArgumentStrength(Enum):
    """How strong an argument is in the debate."""
    WEAK = 1
    MODERATE = 2
    STRONG = 3
    VERY_STRONG = 4


@dataclass
class Perspective:
    """A single analytical perspective with its own reasoning style."""
    perspective_type: PerspectiveType
    name: str = ""
    description: str = ""
    focus_areas: list[str] = field(default_factory=list)
    typical_questions: list[str] = field(default_factory=list)
    bias_tendencies: list[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.name:
            self.name = self.perspective_type.value.title()

        # Set up default focus areas and questions per perspective type
        if self.perspective_type == PerspectiveType.ATTACKER:
            self.focus_areas = self.focus_areas or [
                "exploitation paths", "bypass opportunities", "timing windows",
                "input manipulation", "sequence abuse", "resource exhaustion",
            ]
            self.typical_questions = self.typical_questions or [
                "What happens if I send this before that?",
                "Can I skip this validation step?",
                "What if I send two of these simultaneously?",
                "Can I modify this parameter to change the outcome?",
                "What assumptions does this system make about input?",
            ]
            self.bias_tendencies = self.bias_tendencies or [
                "assumes controls are weak", "may miss layered defenses",
                "focuses on single points of failure",
            ]

        elif self.perspective_type == PerspectiveType.DEFENDER:
            self.focus_areas = self.focus_areas or [
                "defense layers", "validation completeness", "monitoring coverage",
                "incident response", "fail-safe defaults", "least privilege",
            ]
            self.typical_questions = self.typical_questions or [
                "What controls are in place here?",
                "What happens when this control fails?",
                "Is there defense-in-depth for this scenario?",
                "How would I detect this if it happened?",
                "What's the blast radius if this is compromised?",
            ]
            self.bias_tendencies = self.bias_tendencies or [
                "assumes controls work as documented", "may underestimate creative attacks",
                "focuses on known threat models",
            ]

        elif self.perspective_type == PerspectiveType.DEVELOPER:
            self.focus_areas = self.focus_areas or [
                "implementation details", "edge cases in code", "error handling",
                "concurrency issues", "data consistency", "assumptions in logic",
            ]
            self.typical_questions = self.typical_questions or [
                "What did I assume about the input here?",
                "What happens with unexpected data types?",
                "Is this operation truly atomic?",
                "Did I handle all error paths correctly?",
                "What race conditions exist in this code path?",
            ]
            self.bias_tendencies = self.bias_tendencies or [
                "assumes code works as intended", "may miss integration issues",
                "focuses on happy path",
            ]

        elif self.perspective_type == PerspectiveType.AUDITOR:
            self.focus_areas = self.focus_areas or [
                "compliance requirements", "evidence completeness", "control effectiveness",
                "documentation accuracy", "process adherence", "risk assessment",
            ]
            self.typical_questions = self.typical_questions or [
                "Can I prove this control is effective?",
                "What evidence would I need to demonstrate compliance?",
                "Is this documented behavior consistent with actual behavior?",
                "What risks are not being addressed?",
                "How would I verify this independently?",
            ]
            self.bias_tendencies = self.bias_tendencies or [
                "focuses on documented controls", "may miss undocumented risks",
                "requires high standard of proof",
            ]

        elif self.perspective_type == PerspectiveType.USER:
            self.focus_areas = self.focus_areas or [
                "usability under stress", "error messages", "workflow interruptions",
                "data integrity from user perspective", "trust and transparency",
            ]
            self.typical_questions = self.typical_questions or [
                "What does the user see when this happens?",
                "Is the error message helpful or confusing?",
                "Can the user accidentally trigger this?",
                "Does the user know their data is safe?",
                "What happens to the user's session/workflow?",
            ]
            self.bias_tendencies = self.bias_tendencies or [
                "assumes users follow the happy path", "may miss malicious intent",
                "focuses on experience over security",
            ]


@dataclass
class Argument:
    """An argument presented by one perspective during analysis."""
    id: str = field(default_factory=lambda: str(uuid4()))
    perspective: PerspectiveType = PerspectiveType.ATTACKER
    claim: str = ""
    supporting_evidence: list[str] = field(default_factory=list)
    counter_arguments: list[str] = field(default_factory=list)
    strength: ArgumentStrength = ArgumentStrength.MODERATE
    confidence: float = 0.5
    timestamp: float = field(default_factory=time.time)

    @property
    def weight(self) -> float:
        """Numerical weight for comparison."""
        return self.strength.value * self.confidence


@dataclass
class PerspectiveAnalysis:
    """The complete analysis from a single perspective."""
    perspective: PerspectiveType
    perspective_name: str = ""
    observations: list[str] = field(default_factory=list)
    hypotheses: list[str] = field(default_factory=list)
    concerns: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    arguments: list[Argument] = field(default_factory=list)
    confidence: float = 0.5
    timestamp: float = field(default_factory=time.time)


@dataclass
class SynthesizedAnalysis:
    """The combined result of multi-perspective analysis."""
    id: str = field(default_factory=lambda: str(uuid4()))
    situation: str = ""
    perspective_analyses: list[PerspectiveAnalysis] = field(default_factory=list)
    dominant_perspective: PerspectiveType | None = None
    consensus_findings: list[str] = field(default_factory=list)
    contested_findings: list[str] = field(default_factory=list)
    blind_spots_identified: list[str] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)
    overall_confidence: float = 0.5
    timestamp: float = field(default_factory=time.time)

    @property
    def perspectives_covered(self) -> list[str]:
        return [pa.perspective_name for pa in self.perspective_analyses]


class ArgumentationFramework:
    """Resolves conflicts between perspectives through structured argumentation.

    Implements a simplified version of abstract argumentation frameworks
    (Dung, 1995) where arguments can defeat each other.

    An argument A defeats argument B if:
    - A directly contradicts B's claim
    - A's evidence undermines B's supporting evidence
    - A has stronger evidence for an opposing conclusion
    """

    def __init__(self):
        self._arguments: dict[str, Argument] = {}
        self._defeat_relations: dict[str, list[str]] = defaultdict(list)  # arg_id -> [defeated_arg_ids]

    def add_argument(self, argument: Argument) -> None:
        """Adds an argument to the framework."""
        self._arguments[argument.id] = argument

        # Find defeat relations
        for existing_id, existing in self._arguments.items():
            if existing_id == argument.id:
                continue

            # Check if the new argument defeats the existing one
            if self._defeats(argument, existing):
                self._defeat_relations[argument.id].append(existing_id)

            # Check if the existing argument defeats the new one
            if self._defeats(existing, argument):
                self._defeat_relations[existing_id].append(argument.id)

    def _defeats(self, attacker: Argument, defender: Argument) -> bool:
        """Determines if one argument defeats another."""
        # Arguments from different perspectives can defeat each other
        # when they make contradictory claims

        # Same perspective arguments don't defeat each other
        if attacker.perspective == defender.perspective:
            return False

        # Check for direct contradiction
        if self._are_contradictory(attacker.claim, defender.claim):
            # The stronger argument wins
            return attacker.weight > defender.weight

        # Check if attacker undermines defender's evidence
        for evidence in attacker.supporting_evidence:
            if any(evidence in counter for counter in defender.counter_arguments):
                return True

        return False

    def _are_contradictory(self, claim1: str, claim2: str) -> bool:
        """Heuristic check for contradictory claims."""
        # Simple heuristic: look for negation patterns
        negation_words = {"not", "no", "cannot", "won't", "doesn't", "isn't", "aren't", "never"}

        words1 = set(claim1.lower().split())
        words2 = set(claim2.lower().split())

        # If one claim contains a negation of the other's subject
        has_negation_1 = bool(words1 & negation_words)
        has_negation_2 = bool(words2 & negation_words)

        # If exactly one has negation and they share most other words
        if has_negation_1 != has_negation_2:
            shared_words = words1 & words2 - negation_words
            if len(shared_words) > len(words1) * 0.5:
                return True

        return False

    def get_acceptable_arguments(self) -> list[Argument]:
        """Returns arguments that are acceptable (not defeated by stronger arguments).

        An argument is acceptable if:
        - It is not defeated by any other argument, OR
        - All arguments that defeat it are themselves defeated
        """
        acceptable: list[Argument] = []

        for arg_id, argument in self._arguments.items():
            # Find arguments that defeat this one
            defeaters = [
                self._arguments[defeater_id]
                for defeater_id, defeated_ids in self._defeat_relations.items()
                if arg_id in defeated_ids
            ]

            if not defeaters:
                # Not defeated by anything — acceptable
                acceptable.append(argument)
            else:
                # Check if all defeaters are themselves defeated
                all_defeated = True
                for defeater in defeaters:
                    defeater_defeated = any(
                        defeater.id in defeated_ids
                        for defeated_ids in self._defeat_relations.values()
                    )
                    if not defeater_defeated:
                        all_defeated = False
                        break

                if all_defeated:
                    acceptable.append(argument)

        return acceptable

    def get_perspective_strength(self) -> dict[PerspectiveType, float]:
        """Returns the relative strength of each perspective based on
        the acceptability of its arguments."""
        acceptable = self.get_acceptable_arguments()

        perspective_scores: dict[PerspectiveType, float] = defaultdict(float)
        perspective_totals: dict[PerspectiveType, float] = defaultdict(float)

        for argument in self._arguments.values():
            perspective_totals[argument.perspective] += argument.weight

        for argument in acceptable:
            perspective_scores[argument.perspective] += argument.weight

        # Normalize
        result: dict[PerspectiveType, float] = {}
        for perspective, total in perspective_totals.items():
            if total > 0:
                result[perspective] = perspective_scores[perspective] / total
            else:
                result[perspective] = 0.0

        return result


class MultiPerspectiveReasoner:
    """Coordinates analysis from multiple perspectives and synthesizes results.

    This is the component that ensures the system doesn't have blind spots.
    By forcing analysis from at least 4 different viewpoints, it catches
    issues that any single perspective would miss.
    """

    def __init__(self):
        self._perspectives: dict[PerspectiveType, Perspective] = {}
        self._argumentation = ArgumentationFramework()

        # Initialize default perspectives
        self._initialize_perspectives()

        # Analysis history
        self._analysis_history: list[SynthesizedAnalysis] = []

        # Perspective-specific reasoning functions
        self._reasoning_functions: dict[PerspectiveType, Callable] = {}

    def _initialize_perspectives(self) -> None:
        """Sets up the default perspectives."""
        for perspective_type in PerspectiveType:
            self._perspectives[perspective_type] = Perspective(perspective_type=perspective_type)

    def register_reasoning_function(
        self,
        perspective: PerspectiveType,
        func: Callable[[dict[str, Any], Perspective], PerspectiveAnalysis],
    ) -> None:
        """Registers a custom reasoning function for a perspective."""
        self._reasoning_functions[perspective] = func

    def analyze_situation(
        self,
        situation: dict[str, Any],
        perspectives_to_use: list[PerspectiveType] | None = None,
    ) -> SynthesizedAnalysis:
        """Performs multi-perspective analysis of a situation.

        Args:
            situation: The situation/observation to analyze
            perspectives_to_use: Which perspectives to use (default: all)

        Returns:
            A synthesized analysis incorporating all perspectives
        """
        if perspectives_to_use is None:
            perspectives_to_use = list(PerspectiveType)

        analyses: list[PerspectiveAnalysis] = []

        # Generate analysis from each perspective
        for perspective_type in perspectives_to_use:
            perspective = self._perspectives.get(perspective_type)
            if perspective is None:
                continue

            analysis = self._analyze_from_perspective(situation, perspective)
            analyses.append(analysis)

            # Add arguments to the argumentation framework
            for argument in analysis.arguments:
                self._argumentation.add_argument(argument)

        # Synthesize results
        synthesized = self._synthesize(analyses, situation)

        # Record in history
        self._analysis_history.append(synthesized)

        return synthesized

    def _analyze_from_perspective(
        self,
        situation: dict[str, Any],
        perspective: Perspective,
    ) -> PerspectiveAnalysis:
        """Generates analysis from a single perspective.

        Uses registered reasoning functions if available, otherwise
        falls back to generic perspective-based reasoning.
        """
        # Use custom reasoning function if registered
        reasoning_func = self._reasoning_functions.get(perspective.perspective_type)
        if reasoning_func:
            return reasoning_func(situation, perspective)

        # Generic analysis based on perspective characteristics
        analysis = PerspectiveAnalysis(
            perspective=perspective.perspective_type,
            perspective_name=perspective.name,
        )

        # Generate observations based on what this perspective focuses on
        for focus_area in perspective.focus_areas:
            observation = self._generate_observation(situation, focus_area, perspective)
            if observation:
                analysis.observations.append(observation)

        # Generate hypotheses based on typical questions
        for question in perspective.typical_questions:
            hypothesis = self._generate_hypothesis(situation, question, perspective)
            if hypothesis:
                analysis.hypotheses.append(hypothesis)

        # Generate concerns based on bias tendencies (things this perspective
        # is likely to miss, which the analysis should flag)
        for bias in perspective.bias_tendencies:
            concern = self._generate_bias_concern(situation, bias, perspective)
            if concern:
                analysis.concerns.append(concern)

        # Generate arguments
        for hypothesis in analysis.hypotheses[:3]:  # Limit arguments
            argument = Argument(
                perspective=perspective.perspective_type,
                claim=hypothesis,
                supporting_evidence=analysis.observations[:2],
                strength=ArgumentStrength.MODERATE,
                confidence=0.5,
            )
            analysis.arguments.append(argument)

        # Set confidence based on how well the situation matches the perspective's focus
        focus_match = sum(
            1 for area in perspective.focus_areas
            if any(area.lower() in str(v).lower() for v in situation.values())
        )
        analysis.confidence = min(0.9, 0.3 + focus_match * 0.1)

        return analysis

    def _generate_observation(
        self, situation: dict[str, Any], focus_area: str, perspective: Perspective
    ) -> str | None:
        """Generates an observation from the perspective of a focus area."""
        # Look for relevant information in the situation
        for key, value in situation.items():
            if focus_area.lower() in str(value).lower() or focus_area.lower() in key.lower():
                if perspective.perspective_type == PerspectiveType.ATTACKER:
                    return f"From an exploitation perspective: {key} = {value} is relevant to {focus_area}"
                elif perspective.perspective_type == PerspectiveType.DEFENDER:
                    return f"From a defensive perspective: {key} = {value} relates to {focus_area} — need to verify controls"
                elif perspective.perspective_type == PerspectiveType.DEVELOPER:
                    return f"From a development perspective: {key} = {value} in {focus_area} may have edge cases"
                elif perspective.perspective_type == PerspectiveType.AUDITOR:
                    return f"From an audit perspective: {key} = {value} in {focus_area} needs evidence of control effectiveness"
                else:
                    return f"From a user perspective: {key} = {value} affects {focus_area}"

        # Generic observation if no specific match
        if perspective.perspective_type == PerspectiveType.ATTACKER:
            return f"Attack surface: {focus_area} — looking for ways to manipulate this"
        elif perspective.perspective_type == PerspectiveType.DEFENDER:
            return f"Defense check: {focus_area} — verifying protection is in place"
        elif perspective.perspective_type == PerspectiveType.DEVELOPER:
            return f"Code review: {focus_area} — checking implementation assumptions"
        elif perspective.perspective_type == PerspectiveType.AUDITOR:
            return f"Audit trail: {focus_area} — need evidence of control"
        else:
            return f"User impact: {focus_area} — how this affects the user experience"

        return None

    def _generate_hypothesis(
        self, situation: dict[str, Any], question: str, perspective: Perspective
    ) -> str | None:
        """Generates a hypothesis based on a perspective-specific question."""
        # Apply the question to the situation
        endpoint = situation.get("endpoint", situation.get("path", "this endpoint"))
        operation = situation.get("operation", situation.get("method", "this operation"))

        if perspective.perspective_type == PerspectiveType.ATTACKER:
            return f"Hypothesis ({perspective.name}): {question} — specifically for {operation} on {endpoint}"
        elif perspective.perspective_type == PerspectiveType.DEFENDER:
            return f"Hypothesis ({perspective.name}): {question} — controls for {operation} on {endpoint}"
        elif perspective.perspective_type == PerspectiveType.DEVELOPER:
            return f"Hypothesis ({perspective.name}): {question} — implementation of {operation} on {endpoint}"
        elif perspective.perspective_type == PerspectiveType.AUDITOR:
            return f"Hypothesis ({perspective.name}): {question} — evidence for {operation} on {endpoint}"
        else:
            return f"Hypothesis ({perspective.name}): {question} — impact on users of {endpoint}"

        return None

    def _generate_bias_concern(
        self, situation: dict[str, Any], bias: str, perspective: Perspective
    ) -> str | None:
        """Generates a concern about potential blind spots from this perspective."""
        return (
            f"Potential blind spot ({perspective.name}): This perspective tends to {bias}. "
            f"Consider whether other perspectives would catch what this one misses."
        )

    def _synthesize(
        self,
        analyses: list[PerspectiveAnalysis],
        situation: dict[str, Any],
    ) -> SynthesizedAnalysis:
        """Synthesizes multiple perspective analyses into a unified understanding."""
        synthesized = SynthesizedAnalysis(
            situation=str(situation.get("description", situation.get("endpoint", "Unknown situation"))),
            perspective_analyses=analyses,
        )

        # Find consensus findings (things multiple perspectives agree on)
        all_hypotheses = [h for a in analyses for h in a.hypotheses]
        hypothesis_keywords: dict[str, int] = defaultdict(int)

        for hypothesis in all_hypotheses:
            # Simple keyword extraction for grouping
            words = [w.lower() for w in hypothesis.split() if len(w) > 4]
            for word in set(words):
                hypothesis_keywords[word] += 1

        # Find keywords that appear in multiple perspectives
        consensus_keywords = [
            word for word, count in hypothesis_keywords.items()
            if count >= 2 and word not in {"perspective", "hypothesis", "specifically", "endpoint"}
        ]

        for keyword in consensus_keywords[:10]:
            related_hypotheses = [h for h in all_hypotheses if keyword in h.lower()]
            if related_hypotheses:
                synthesized.consensus_findings.append(
                    f"Multiple perspectives converge on '{keyword}': "
                    + "; ".join(h[:80] for h in related_hypotheses[:3])
                )

        # Find contested findings (things perspectives disagree on)
        perspective_strengths = self._argumentation.get_perspective_strength()
        if perspective_strengths:
            strongest = max(perspective_strengths.items(), key=lambda pair: pair[1])
            synthesized.dominant_perspective = strongest[0]

        # Identify blind spots
        for analysis in analyses:
            for concern in analysis.concerns:
                synthesized.blind_spots_identified.append(concern)

        # Generate recommended actions
        for analysis in analyses:
            if analysis.perspective == PerspectiveType.ATTACKER:
                synthesized.recommended_actions.extend(
                    f"[TEST] {h}" for h in analysis.hypotheses[:2]
                )
            elif analysis.perspective == PerspectiveType.DEFENDER:
                synthesized.recommended_actions.extend(
                    f"[VERIFY] {h}" for h in analysis.hypotheses[:2]
                )
            elif analysis.perspective == PerspectiveType.DEVELOPER:
                synthesized.recommended_actions.extend(
                    f"[REVIEW] {h}" for h in analysis.hypotheses[:2]
                )
            elif analysis.perspective == PerspectiveType.AUDITOR:
                synthesized.recommended_actions.extend(
                    f"[EVIDENCE] {h}" for h in analysis.hypotheses[:2]
                )

        # Calculate overall confidence
        if analyses:
            synthesized.overall_confidence = sum(a.confidence for a in analyses) / len(analyses)

        return synthesized

    def identify_blind_spots(self, situation: dict[str, Any]) -> list[str]:
        """Identifies blind spots by comparing what different perspectives notice.

        A blind spot exists when one perspective identifies a concern
        that others completely miss.
        """
        blind_spots: list[str] = []

        # Analyze from all perspectives
        result = self.analyze_situation(situation)

        # Check for areas where only one perspective has observations
        all_focus_areas = set()
        perspective_coverage: dict[str, set[str]] = {}

        for analysis in result.perspective_analyses:
            covered_areas = set()
            for observation in analysis.observations:
                for area in self._perspectives[analysis.perspective].focus_areas:
                    if area.lower() in observation.lower():
                        covered_areas.add(area)
                        all_focus_areas.add(area)
            perspective_coverage[analysis.perspective_name] = covered_areas

        # Find areas covered by only one perspective
        for area in all_focus_areas:
            covering_perspectives = [
                name for name, areas in perspective_coverage.items()
                if area in areas
            ]
            if len(covering_perspectives) == 1:
                blind_spots.append(
                    f"'{area}' is only considered by {covering_perspectives[0]} — "
                    f"other perspectives may miss important aspects of this area"
                )

        return blind_spots

    def get_devils_advocate_analysis(
        self,
        situation: dict[str, Any],
        primary_perspective: PerspectiveType = PerspectiveType.ATTACKER,
    ) -> SynthesizedAnalysis:
        """Performs adversarial self-analysis — the system argues against itself.

        The primary perspective's analysis is challenged by all other
        perspectives acting as devil's advocates.
        """
        # Get the primary analysis
        primary_analysis = self._analyze_from_perspective(
            situation, self._perspectives[primary_perspective]
        )

        # Challenge each hypothesis from the primary perspective
        challenges: list[PerspectiveAnalysis] = []

        for hypothesis in primary_analysis.hypotheses:
            # Create counter-arguments from other perspectives
            for other_type in PerspectiveType:
                if other_type == primary_perspective:
                    continue

                other = self._perspectives[other_type]
                counter_analysis = PerspectiveAnalysis(
                    perspective=other.perspective_type,
                    perspective_name=f"{other.name} (Devil's Advocate)",
                )

                # Generate counter-arguments
                counter_claim = (
                    f"CHALLENGE to '{hypothesis[:60]}...': From the {other.name} perspective, "
                    f"this may not hold because {other.typical_questions[0].lower() if other.typical_questions else 'of unconsidered factors'}"
                )

                argument = Argument(
                    perspective=other.perspective_type,
                    claim=counter_claim,
                    supporting_evidence=[f"{other.name} typically considers: {', '.join(other.focus_areas[:3])}"],
                    strength=ArgumentStrength.STRONG if other_type == PerspectiveType.DEFENDER else ArgumentStrength.MODERATE,
                    confidence=0.7,
                )

                counter_analysis.arguments.append(argument)
                counter_analysis.hypotheses.append(counter_claim)
                challenges.append(counter_analysis)

        # Synthesize the adversarial analysis
        synthesized = SynthesizedAnalysis(
            situation=f"Devil's Advocate analysis of: {str(situation.get('description', 'situation'))[:100]}",
            perspective_analyses=[primary_analysis] + challenges[:5],  # Limit challenges
        )

        # Identify what the primary perspective might have missed
        for challenge in challenges[:5]:
            for hyp in challenge.hypotheses:
                if "CHALLENGE" in hyp:
                    synthesized.blind_spots_identified.append(
                        f"Primary perspective ({primary_perspective.value}) may miss: {hyp[10:100]}"
                    )

        return synthesized

    def get_statistics(self) -> dict[str, Any]:
        """Returns statistics about the multi-perspective reasoner."""
        perspective_strengths = self._argumentation.get_perspective_strength()

        return {
            "total_analyses": len(self._analysis_history),
            "perspectives_available": [p.value for p in self._perspectives],
            "perspective_strengths": {
                p.value: s for p, s in perspective_strengths.items()
            },
            "argumentation_stats": {
                "total_arguments": len(self._argumentation._arguments),
                "acceptable_arguments": len(self._argumentation.get_acceptable_arguments()),
            },
            "recent_analyses": [
                {
                    "situation": a.situation[:100],
                    "perspectives": a.perspectives_covered,
                    "confidence": a.overall_confidence,
                    "blind_spots": len(a.blind_spots_identified),
                }
                for a in self._analysis_history[-5:]
            ],
        }
