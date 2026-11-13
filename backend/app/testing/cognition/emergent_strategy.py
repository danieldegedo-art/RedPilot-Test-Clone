"""Emergent Strategy Generator — Novel Verification Through Recombination.

Implements the cognitive ability to GENERATE new verification strategies
by creatively combining existing techniques, rather than only executing
predefined test cases. This is the component that produces discoveries
no human tester would think to look for.

Implements concepts from:
- Genetic Algorithms / Genetic Programming: Evolve strategies through
  selection, crossover, and mutation
- Conceptual Blending Theory (Fauconnier & Turner): Combine concepts
  from different domains to produce emergent meaning
- Analogical Reasoning: Apply solutions from one domain to another
- Divergent Thinking: Generate multiple diverse approaches to a problem

The generator operates as follows:
1. Maintain a population of verification strategies
2. Track which strategies have been successful/failed
3. Recombine successful strategies in novel ways
4. Mutate strategies to explore variations
5. Apply cross-domain analogies ("How would X work in Y context?")
6. Produce genuinely novel test sequences

This is what differentiates creative discovery from mechanical testing:
the ability to invent NEW approaches rather than just running known ones.
"""
from __future__ import annotations

import random
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from itertools import combinations
from typing import Any, Callable
from uuid import uuid4


class StrategyComponent(Enum):
    """Building blocks from which strategies are composed."""
    # Input manipulation components
    DUPLICATE_PARAMS = "duplicate_params"
    TYPE_VARIANT = "type_variant"
    ENCODING_VARIANT = "encoding_variant"
    STRUCTURE_VARIANT = "structure_variant"
    SEQUENCE_SKIP = "sequence_skip"
    SEQUENCE_REPEAT = "sequence_repeat"
    PARAMETER_SUBSTITUTION = "parameter_substitution"
    BOUNDARY_VALUE = "boundary_value"

    # Timing components
    CONCURRENT_REQUESTS = "concurrent_requests"
    DELAYED_SEQUENCE = "delayed_sequence"
    RAPID_BURST = "rapid_burst"
    INTERLEAVED_OPERATIONS = "interleaved_operations"

    # State manipulation components
    STATE_CHECK_BEFORE = "state_check_before"
    STATE_CHECK_AFTER = "state_check_after"
    STATE_ROLLBACK = "state_rollback"
    PARTIAL_COMPLETION = "partial_completion"

    # Cross-cutting components
    CROSS_VERSION = "cross_version"
    CROSS_ENDPOINT = "cross_endpoint"
    CROSS_FORMAT = "cross_format"
    CROSS_SESSION = "cross_session"

    # Verification components
    INDEPENDENT_READBACK = "independent_readback"
    TIMING_MEASUREMENT = "timing_measurement"
    RESPONSE_COMPARISON = "response_comparison"
    STATE_COMPARISON = "state_comparison"


@dataclass
class StrategyGene:
    """A single gene in the strategy genome — one component of a verification strategy."""
    component: StrategyComponent
    parameters: dict[str, Any] = field(default_factory=dict)
    weight: float = 1.0  # How important this component is
    source: str = "initial"  # Where this gene came from

    def mutate(self, mutation_rate: float = 0.1) -> StrategyGene:
        """Returns a mutated copy of this gene."""
        mutated = StrategyGene(
            component=self.component,
            parameters=dict(self.parameters),
            weight=self.weight,
            source="mutation",
        )

        # Mutate parameters
        if random.random() < mutation_rate:
            for key in mutated.parameters:
                value = mutated.parameters[key]
                if isinstance(value, (int, float)):
                    mutated.parameters[key] = value * random.uniform(0.5, 2.0)
                elif isinstance(value, str):
                    mutated.parameters[key] = f"{value}_mutated"
                elif isinstance(value, bool):
                    mutated.parameters[key] = not value

        # Mutate weight
        if random.random() < mutation_rate:
            mutated.weight = max(0.1, min(3.0, self.weight * random.uniform(0.7, 1.3)))

        return mutated

    def to_dict(self) -> dict[str, Any]:
        return {
            "component": self.component.value,
            "parameters": self.parameters,
            "weight": self.weight,
            "source": self.source,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> StrategyGene:
        return cls(
            component=StrategyComponent(data["component"]),
            parameters=data.get("parameters", {}),
            weight=data.get("weight", 1.0),
            source=data.get("source", "initial"),
        )


@dataclass
class VerificationStrategy:
    """A complete verification strategy composed of multiple genes.

    A strategy describes HOW to verify something: what sequence of
    actions to take, what to manipulate, and what to check.
    """
    id: str = field(default_factory=lambda: str(uuid4()))
    name: str = ""
    description: str = ""
    genes: list[StrategyGene] = field(default_factory=list)

    # Fitness tracking
    times_executed: int = 0
    times_discovered: int = 0  # How many new findings this produced
    times_informative: int = 0  # How many times it produced useful evidence
    fitness_score: float = 0.5

    # Lineage
    generation: int = 0
    parent_ids: list[str] = field(default_factory=list)
    creation_method: str = "initial"  # "initial", "crossover", "mutation", "analogy", "blending"

    # Metadata
    target_types: list[str] = field(default_factory=list)  # What types of systems/endpoints this works on
    discovery_history: list[dict[str, Any]] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)

    @property
    def success_rate(self) -> float:
        """Rate of producing discoveries."""
        if self.times_executed == 0:
            return 0.0
        return self.times_discovered / self.times_executed

    @property
    def informative_rate(self) -> float:
        """Rate of producing useful evidence (even without discoveries)."""
        if self.times_executed == 0:
            return 0.0
        return self.times_informative / self.times_executed

    @property
    def component_types(self) -> list[str]:
        """Returns the component types used in this strategy."""
        return [gene.component.value for gene in self.genes]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "genes": [g.to_dict() for g in self.genes],
            "times_executed": self.times_executed,
            "times_discovered": self.times_discovered,
            "times_informative": self.times_informative,
            "fitness_score": self.fitness_score,
            "generation": self.generation,
            "parent_ids": self.parent_ids,
            "creation_method": self.creation_method,
            "target_types": self.target_types,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> VerificationStrategy:
        genes = [StrategyGene.from_dict(g) for g in data.get("genes", [])]
        return cls(
            id=data.get("id", str(uuid4())),
            name=data.get("name", ""),
            description=data.get("description", ""),
            genes=genes,
            times_executed=data.get("times_executed", 0),
            times_discovered=data.get("times_discovered", 0),
            times_informative=data.get("times_informative", 0),
            fitness_score=data.get("fitness_score", 0.5),
            generation=data.get("generation", 0),
            parent_ids=data.get("parent_ids", []),
            creation_method=data.get("creation_method", "initial"),
            target_types=data.get("target_types", []),
        )


@dataclass
class StrategyPopulation:
    """Manages a population of verification strategies for evolution."""
    strategies: dict[str, VerificationStrategy] = field(default_factory=dict)
    generation_count: int = 0
    max_population: int = 50
    elite_count: int = 10  # Top strategies preserved each generation

    def add(self, strategy: VerificationStrategy) -> None:
        self.strategies[strategy.id] = strategy

    def get_elite(self) -> list[VerificationStrategy]:
        """Returns the top-performing strategies."""
        sorted_strategies = sorted(
            self.strategies.values(),
            key=lambda s: s.fitness_score,
            reverse=True,
        )
        return sorted_strategies[:self.elite_count]

    def get_diverse(self, n: int = 5) -> list[VerificationStrategy]:
        """Returns strategies that are most different from each other."""
        if not self.strategies:
            return []

        selected: list[VerificationStrategy] = []
        remaining = list(self.strategies.values())

        # Start with the fittest
        fittest = max(remaining, key=lambda s: s.fitness_score)
        selected.append(fittest)
        remaining.remove(fittest)

        # Select strategies most different from already-selected ones
        while remaining and len(selected) < n:
            best_candidate = None
            best_diversity = -1

            for candidate in remaining:
                # Calculate diversity as average component difference from selected
                diversity = sum(
                    len(set(candidate.component_types) - set(sel.component_types)) +
                    len(set(sel.component_types) - set(candidate.component_types))
                    for sel in selected
                ) / len(selected)

                if diversity > best_diversity:
                    best_diversity = diversity
                    best_candidate = candidate

            if best_candidate:
                selected.append(best_candidate)
                remaining.remove(best_candidate)

        return selected

    def cull(self) -> None:
        """Removes weak strategies to maintain population size."""
        if len(self.strategies) <= self.max_population:
            return

        # Sort by fitness
        sorted_strategies = sorted(
            self.strategies.values(),
            key=lambda s: s.fitness_score,
        )

        # Remove the weakest until under max population
        to_remove = len(self.strategies) - self.max_population
        for strategy in sorted_strategies[:to_remove]:
            del self.strategies[strategy.id]


class ConceptualBlender:
    """Blends concepts from different domains to create novel strategies.

    Conceptual Blending Theory (Fauconnier & Turner) describes how humans
    create new ideas by combining elements from different mental spaces.
    This implements a computational version for verification strategies.

    Example: Blend "concurrent bank withdrawals" (banking domain) with
    "API rate limiting" (web domain) to produce "concurrent rate-limit
    circumvention testing" (novel strategy).
    """

    # Source domains with their characteristic patterns
    _DOMAIN_PATTERNS: dict[str, list[str]] = {
        "banking": [
            "concurrent withdrawal", "balance check timing", "double spending",
            "audit trail", "transaction atomicity", "reconciliation",
        ],
        "gaming": [
            "speed run", "sequence break", "out of bounds", "clip through",
            "buffer overflow", "state corruption", "input manipulation",
        ],
        "physical_security": [
            "tailgating", "social engineering", "lock picking", "replay attack",
            "bypass checkpoint", "privilege escalation", "insider threat",
        ],
        "networking": [
            "packet fragmentation", "protocol downgrade", "man in middle",
            "routing loop", "queue overflow", "connection hijacking",
        ],
        "biology": [
            "immune evasion", "mutation rate", "selective pressure",
            "symbiosis", "parasitism", "adaptation", "ecological niche",
        ],
        "linguistics": [
            "ambiguity", "double meaning", "context shift", "translation error",
            "grammar bypass", "semantic drift",
        ],
    }

    def blend(
        self,
        source_domain: str,
        target_context: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Blends patterns from a source domain with the target context.

        Returns a list of blended strategy concepts.
        """
        patterns = self._DOMAIN_PATTERNS.get(source_domain, [])
        if not patterns:
            return []

        blends: list[dict[str, Any]] = []

        endpoint = target_context.get("endpoint", "the target endpoint")
        operation = target_context.get("operation", "the operation")
        resource_type = target_context.get("resource_type", "the resource")

        for pattern in patterns:
            # Create a blended concept
            blend = {
                "source_domain": source_domain,
                "source_pattern": pattern,
                "target_context": target_context,
                "blended_strategy": self._apply_pattern_to_context(pattern, endpoint, operation, resource_type),
                "novelty_score": self._estimate_novelty(pattern),
                "applicability_score": self._estimate_applicability(pattern, target_context),
            }
            blends.append(blend)

        return blends

    def _apply_pattern_to_context(
        self, pattern: str, endpoint: str, operation: str, resource_type: str
    ) -> str:
        """Translates a domain pattern into a verification strategy description."""
        # Map domain-specific language to QA language
        translations = {
            "concurrent withdrawal": f"Send concurrent {operation} requests to {endpoint} and verify only one is processed",
            "balance check timing": f"Check {resource_type} state immediately before and after {operation} on {endpoint} to verify consistency",
            "double spending": f"Attempt to use the same {resource_type} reference twice in {operation} on {endpoint}",
            "speed run": f"Skip intermediate steps and jump directly to the final step of {operation} on {endpoint}",
            "sequence break": f"Execute {operation} steps out of order on {endpoint} and verify the system rejects the sequence",
            "out of bounds": f"Send {operation} requests with values outside the expected range to {endpoint}",
            "tailgating": f"Follow a valid {operation} request with an invalid one on {endpoint} in rapid succession",
            "replay attack": f"Repeat a previously valid {operation} request to {endpoint} and verify it's detected as a repeat",
            "protocol downgrade": f"Send {operation} to {endpoint} using an older API version or format",
            "packet fragmentation": f"Split {operation} parameters across multiple requests to {endpoint} and verify the system doesn't reassemble them incorrectly",
            "immune evasion": f"Modify {operation} parameters slightly on each attempt to {endpoint} to find validation gaps",
            "mutation rate": f"Systematically vary each parameter of {operation} on {endpoint} to find which ones lack validation",
            "ambiguity": f"Send {operation} requests with ambiguous parameter values to {endpoint} that could be interpreted differently",
        }

        return translations.get(pattern, f"Apply '{pattern}' concept to {operation} on {endpoint}")

    def _estimate_novelty(self, pattern: str) -> float:
        """Estimates how novel a blend is (higher = more novel)."""
        # Patterns from less obvious domains tend to be more novel
        domain_novelty = {
            "banking": 0.3,  # Well-known in security
            "gaming": 0.5,   # Less common in API testing
            "physical_security": 0.4,
            "networking": 0.3,
            "biology": 0.7,   # Very novel for API testing
            "linguistics": 0.8,  # Most novel
        }

        # Find which domain this pattern belongs to
        for domain, patterns in self._DOMAIN_PATTERNS.items():
            if pattern in patterns:
                return domain_novelty.get(domain, 0.5)

        return 0.5

    def _estimate_applicability(self, pattern: str, context: dict[str, Any]) -> float:
        """Estimates how applicable a blend is to the given context."""
        # Simple heuristic based on context type
        context_type = context.get("resource_type", context.get("endpoint_type", ""))

        # Some patterns are more applicable to certain context types
        applicability_map = {
            "payment": {"concurrent withdrawal": 0.9, "double spending": 0.9, "balance check timing": 0.8},
            "subscription": {"sequence break": 0.8, "state corruption": 0.7, "replay attack": 0.8},
            "user": {"tailgating": 0.7, "privilege escalation": 0.9, "social engineering": 0.6},
            "api": {"protocol downgrade": 0.8, "packet fragmentation": 0.7, "ambiguity": 0.8},
        }

        for context_key, pattern_scores in applicability_map.items():
            if context_key in str(context_type).lower():
                return pattern_scores.get(pattern, 0.5)

        return 0.5


class AnalogicalReasoner:
    """Finds analogies between known and unknown situations.

    When encountering a new type of endpoint or system, this component
    searches for similar situations it has seen before and transfers
    the verification approaches that worked.
    """

    def __init__(self):
        self._known_situations: list[dict[str, Any]] = []
        self._situation_solutions: dict[str, list[str]] = {}

    def register_situation(
        self,
        situation_description: str,
        characteristics: dict[str, Any],
        successful_strategies: list[str],
    ) -> None:
        """Registers a known situation with its successful strategies."""
        situation_id = str(uuid4())
        self._known_situations.append({
            "id": situation_id,
            "description": situation_description,
            "characteristics": characteristics,
            "strategies": successful_strategies,
        })
        self._situation_solutions[situation_id] = successful_strategies

    def find_analogies(
        self,
        new_situation: dict[str, Any],
        max_results: int = 5,
    ) -> list[dict[str, Any]]:
        """Finds analogous situations from the known set.

        Returns situations that are similar to the new one, along with
        their successful strategies.
        """
        if not self._known_situations:
            return []

        scored_situations: list[tuple[dict[str, Any], float]] = []

        for known in self._known_situations:
            similarity = self._calculate_similarity(
                new_situation, known["characteristics"]
            )
            scored_situations.append((known, similarity))

        # Sort by similarity
        scored_situations.sort(key=lambda pair: pair[1], reverse=True)

        # Return top matches
        results = []
        for situation, similarity in scored_situations[:max_results]:
            if similarity > 0.3:  # Minimum similarity threshold
                results.append({
                    "situation": situation["description"],
                    "similarity": similarity,
                    "successful_strategies": situation["strategies"],
                    "transferable": similarity > 0.5,
                })

        return results

    def _calculate_similarity(
        self,
        situation1: dict[str, Any],
        situation2: dict[str, Any],
    ) -> float:
        """Calculates similarity between two situations based on characteristics."""
        if not situation1 or not situation2:
            return 0.0

        # Compare common keys
        common_keys = set(situation1.keys()) & set(situation2.keys())
        if not common_keys:
            return 0.0

        matches = 0
        for key in common_keys:
            val1 = str(situation1[key]).lower()
            val2 = str(situation2[key]).lower()

            if val1 == val2:
                matches += 1
            elif val1 in val2 or val2 in val1:
                matches += 0.5
            else:
                # Check for partial overlap
                words1 = set(val1.split())
                words2 = set(val2.split())
                overlap = len(words1 & words2)
                if overlap > 0:
                    matches += overlap / max(len(words1), len(words2)) * 0.5

        return matches / len(common_keys)


class EmergentStrategyGenerator:
    """Generates novel verification strategies through evolutionary recombination.

    This is the creative engine of the cognitive architecture. It:
    1. Maintains a population of strategies
    2. Evolves them through selection, crossover, and mutation
    3. Blends concepts from other domains
    4. Finds analogies to transfer successful approaches
    5. Produces genuinely novel verification sequences
    """

    def __init__(
        self,
        initial_population_size: int = 20,
        mutation_rate: float = 0.15,
        crossover_rate: float = 0.7,
        blending_rate: float = 0.1,
    ):
        self._population = StrategyPopulation(max_population=initial_population_size * 2)
        self._blender = ConceptualBlender()
        self._analogizer = AnalogicalReasoner()

        self._mutation_rate = mutation_rate
        self._crossover_rate = crossover_rate
        self._blending_rate = blending_rate

        # Component combinations that have been proven useful
        self._proven_combinations: list[tuple[StrategyComponent, StrategyComponent]] = []

        # Statistics (must exist before _initialize_population, which
        # increments strategies_created for every seed strategy it creates)
        self._stats = {
            "strategies_created": 0,
            "crossovers_performed": 0,
            "mutations_performed": 0,
            "blends_created": 0,
            "analogies_applied": 0,
            "novel_discoveries": 0,
        }

        # Initialize population
        self._initialize_population(initial_population_size)

    def _initialize_population(self, count: int) -> None:
        """Creates the initial population of strategies."""
        # Create simple strategies from single components
        for component in StrategyComponent:
            strategy = VerificationStrategy(
                name=f"Basic {component.value.replace('_', ' ').title()}",
                description=f"Basic verification using {component.value.replace('_', ' ')}",
                genes=[StrategyGene(component=component)],
                creation_method="initial",
                generation=0,
            )
            self._population.add(strategy)
            self._stats["strategies_created"] += 1

        # Create some initial combinations
        for _ in range(count - len(StrategyComponent)):
            strategy = self._create_random_combination()
            if strategy:
                self._population.add(strategy)
                self._stats["strategies_created"] += 1

    def _create_random_combination(self) -> VerificationStrategy | None:
        """Creates a strategy with a random combination of components."""
        num_components = random.randint(2, 4)
        components = random.sample(list(StrategyComponent), num_components)

        genes = [StrategyGene(component=c) for c in components]

        return VerificationStrategy(
            name=f"Combination: {' + '.join(c.value.replace('_', ' ') for c in components)}",
            description=f"Combined verification using {num_components} techniques",
            genes=genes,
            creation_method="initial",
            generation=0,
        )

    def evolve_generation(self, feedback: dict[str, Any] | None = None) -> list[VerificationStrategy]:
        """Evolves the population to create a new generation of strategies.

        Args:
            feedback: Recent execution feedback to guide evolution.

        Returns:
            New strategies created in this generation.
        """
        self._population.generation_count += 1
        new_strategies: list[VerificationStrategy] = []

        # Update fitness scores based on feedback
        if feedback:
            self._update_fitness(feedback)

        # Get elite strategies (preserved unchanged)
        elite = self._population.get_elite()

        # Generate new strategies through crossover
        crossover_count = int(len(self._population.strategies) * self._crossover_rate * 0.3)
        for _ in range(crossover_count):
            child = self._crossover()
            if child:
                new_strategies.append(child)
                self._population.add(child)
                self._stats["crossovers_performed"] += 1

        # Generate new strategies through mutation
        mutation_count = int(len(self._population.strategies) * self._mutation_rate * 0.3)
        for _ in range(mutation_count):
            mutant = self._mutate()
            if mutant:
                new_strategies.append(mutant)
                self._population.add(mutant)
                self._stats["mutations_performed"] += 1

        # Occasionally generate strategies through conceptual blending
        if random.random() < self._blending_rate:
            blended = self._generate_blended_strategy()
            if blended:
                new_strategies.append(blended)
                self._population.add(blended)
                self._stats["blends_created"] += 1

        # Cull weak strategies
        self._population.cull()

        return new_strategies

    def _update_fitness(self, feedback: dict[str, Any]) -> None:
        """Updates fitness scores based on execution feedback."""
        for strategy_id, results in feedback.items():
            strategy = self._population.strategies.get(strategy_id)
            if strategy is None:
                continue

            strategy.times_executed += results.get("executions", 1)
            strategy.times_discovered += results.get("discoveries", 0)
            strategy.times_informative += results.get("informative", 0)

            # Update fitness score
            # Fitness = weighted combination of discovery rate and informative rate
            discovery_component = strategy.success_rate * 0.6
            informative_component = strategy.informative_rate * 0.4

            # Bonus for novel strategies (haven't been executed many times)
            novelty_bonus = max(0.0, 1.0 - strategy.times_executed / 20.0) * 0.1

            strategy.fitness_score = (
                discovery_component +
                informative_component +
                novelty_bonus
            )

    def _crossover(self) -> VerificationStrategy | None:
        """Performs crossover between two parent strategies."""
        # Select parents using tournament selection
        parent1 = self._tournament_select()
        parent2 = self._tournament_select()

        if parent1 is None or parent2 is None:
            return None

        if parent1.id == parent2.id:
            return None

        # Perform crossover
        # Take genes from both parents
        all_genes = parent1.genes + parent2.genes

        # Remove duplicates (by component type)
        seen_components: set[StrategyComponent] = set()
        unique_genes: list[StrategyGene] = []
        for gene in all_genes:
            if gene.component not in seen_components:
                unique_genes.append(gene)
                seen_components.add(gene.component)

        # Randomly select a subset for the child
        num_genes = random.randint(
            max(2, min(len(parent1.genes), len(parent2.genes))),
            min(5, len(unique_genes)),
        )
        child_genes = random.sample(unique_genes, min(num_genes, len(unique_genes)))

        # Create child strategy
        child = VerificationStrategy(
            name=f"Cross: {parent1.name[:20]} + {parent2.name[:20]}",
            description=(
                f"Evolved from '{parent1.name}' and '{parent2.name}' — "
                f"combines {len(child_genes)} verification techniques"
            ),
            genes=child_genes,
            generation=self._population.generation_count,
            parent_ids=[parent1.id, parent2.id],
            creation_method="crossover",
        )

        return child

    def _mutate(self) -> VerificationStrategy | None:
        """Mutates a randomly selected strategy."""
        # Select a strategy to mutate
        candidates = list(self._population.strategies.values())
        if not candidates:
            return None

        parent = random.choice(candidates)

        # Mutate each gene
        mutated_genes = [gene.mutate(self._mutation_rate) for gene in parent.genes]

        # Occasionally add a new random gene
        if random.random() < self._mutation_rate:
            available_components = set(StrategyComponent) - {g.component for g in mutated_genes}
            if available_components:
                new_component = random.choice(list(available_components))
                mutated_genes.append(StrategyGene(component=new_component, source="mutation"))

        # Occasionally remove a gene
        if len(mutated_genes) > 2 and random.random() < self._mutation_rate:
            mutated_genes.pop(random.randrange(len(mutated_genes)))

        mutant = VerificationStrategy(
            name=f"Mutation: {parent.name[:25]} (gen {self._population.generation_count})",
            description=f"Mutated variant of '{parent.name}' with altered parameters",
            genes=mutated_genes,
            generation=self._population.generation_count,
            parent_ids=[parent.id],
            creation_method="mutation",
        )

        return mutant

    def _tournament_select(self, tournament_size: int = 3) -> VerificationStrategy | None:
        """Selects a strategy using tournament selection."""
        candidates = list(self._population.strategies.values())
        if not candidates:
            return None

        # Randomly select tournament participants
        participants = random.sample(candidates, min(tournament_size, len(candidates)))

        # Return the fittest participant
        return max(participants, key=lambda s: s.fitness_score)

    def _generate_blended_strategy(self) -> VerificationStrategy | None:
        """Generates a strategy through conceptual blending."""
        # Choose a random source domain
        domains = list(self._blender._DOMAIN_PATTERNS.keys())
        if not domains:
            return None

        source_domain = random.choice(domains)

        # Create a simple context
        context = {
            "endpoint": "target endpoint",
            "operation": "state-changing operation",
            "resource_type": "payment/subscription resource",
        }

        # Get blends
        blends = self._blender.blend(source_domain, context)
        if not blends:
            return None

        # Select the best blend
        best_blend = max(
            blends,
            key=lambda b: b["novelty_score"] * 0.6 + b["applicability_score"] * 0.4,
        )

        # Convert the blend into strategy genes
        # This is a simplified mapping — in practice, each blended concept
        # would be mapped to specific StrategyComponents
        blend_components = self._map_blend_to_components(best_blend)

        if not blend_components:
            return None

        genes = [StrategyGene(component=c, source=f"blend:{source_domain}") for c in blend_components]

        strategy = VerificationStrategy(
            name=f"Blended: {best_blend['source_pattern']} → {source_domain} concept applied to API",
            description=best_blend["blended_strategy"],
            genes=genes,
            generation=self._population.generation_count,
            creation_method=f"blending:{source_domain}",
            target_types=[context.get("resource_type", "")],
        )

        return strategy

    def _map_blend_to_components(self, blend: dict[str, Any]) -> list[StrategyComponent]:
        """Maps a blended concept to strategy components."""
        pattern = blend.get("source_pattern", "")
        strategy_description = blend.get("blended_strategy", "").lower()

        components: list[StrategyComponent] = []

        # Map pattern keywords to components
        component_mappings = {
            "concurrent": StrategyComponent.CONCURRENT_REQUESTS,
            "timing": StrategyComponent.TIMING_MEASUREMENT,
            "double": StrategyComponent.SEQUENCE_REPEAT,
            "skip": StrategyComponent.SEQUENCE_SKIP,
            "out of bounds": StrategyComponent.BOUNDARY_VALUE,
            "replay": StrategyComponent.SEQUENCE_REPEAT,
            "protocol": StrategyComponent.CROSS_VERSION,
            "fragmentation": StrategyComponent.CROSS_FORMAT,
            "mutation": StrategyComponent.PARAMETER_SUBSTITUTION,
            "ambiguity": StrategyComponent.TYPE_VARIANT,
            "privilege": StrategyComponent.CROSS_SESSION,
            "state": StrategyComponent.STATE_CHECK_AFTER,
        }

        for keyword, component in component_mappings.items():
            if keyword in strategy_description or keyword in pattern.lower():
                if component not in components:
                    components.append(component)

        # Always add verification
        if StrategyComponent.INDEPENDENT_READBACK not in components:
            components.append(StrategyComponent.INDEPENDENT_READBACK)

        return components[:4]  # Limit to 4 components

    def generate_novel_strategies(
        self,
        context: dict[str, Any],
        count: int = 3,
    ) -> list[VerificationStrategy]:
        """Generates completely novel strategies for a specific context.

        Uses conceptual blending and analogical reasoning to create
        strategies that haven't been tried before.
        """
        novel_strategies: list[VerificationStrategy] = []

        # Try conceptual blending from multiple domains
        domains = list(self._blender._DOMAIN_PATTERNS.keys())
        random.shuffle(domains)

        for domain in domains[:count]:
            blend_strategy = self._generate_blended_strategy()
            if blend_strategy:
                novel_strategies.append(blend_strategy)

        # Try analogical reasoning
        analogies = self._analogizer.find_analogies(context)
        for analogy in analogies:
            if analogy.get("transferable"):
                strategy = self._create_strategy_from_analogy(analogy, context)
                if strategy:
                    novel_strategies.append(strategy)
                    self._stats["analogies_applied"] += 1

        return novel_strategies[:count]

    def _create_strategy_from_analogy(
        self,
        analogy: dict[str, Any],
        context: dict[str, Any],
    ) -> VerificationStrategy | None:
        """Creates a strategy based on an analogy to a known situation."""
        strategies = analogy.get("successful_strategies", [])
        if not strategies:
            return None

        # Map the analogous strategies to components
        # This is simplified — in practice, it would be more sophisticated
        description = f"Analogous to: {analogy['situation']} (similarity: {analogy['similarity']:.2f})"

        # Create a strategy that applies the analogous approach
        genes = [
            StrategyGene(component=StrategyComponent.PARAMETER_SUBSTITUTION, source="analogy"),
            StrategyGene(component=StrategyComponent.INDEPENDENT_READBACK, source="analogy"),
        ]

        return VerificationStrategy(
            name=f"Analogy: {analogy['situation'][:30]}",
            description=description,
            genes=genes,
            generation=self._population.generation_count,
            creation_method="analogy",
            target_types=[str(context.get("resource_type", ""))],
        )

    def record_discovery(self, strategy_id: str, discovery_description: str) -> None:
        """Records that a strategy produced a novel discovery."""
        strategy = self._population.strategies.get(strategy_id)
        if strategy:
            strategy.times_discovered += 1
            strategy.discovery_history.append({
                "description": discovery_description,
                "timestamp": time.time(),
            })
            strategy.fitness_score = min(1.0, strategy.fitness_score + 0.2)
            self._stats["novel_discoveries"] += 1

    def get_best_strategies(self, context: dict[str, Any], n: int = 5) -> list[VerificationStrategy]:
        """Returns the best strategies for a given context."""
        # Filter by target types if specified
        relevant = [
            s for s in self._population.strategies.values()
            if not s.target_types or any(t in str(context) for t in s.target_types)
        ]

        # If no context-specific strategies, use all
        if not relevant:
            relevant = list(self._population.strategies.values())

        # Sort by fitness
        sorted_strategies = sorted(relevant, key=lambda s: s.fitness_score, reverse=True)

        return sorted_strategies[:n]

    def get_diverse_strategies(self, n: int = 5) -> list[VerificationStrategy]:
        """Returns strategies that are most different from each other."""
        return self._population.get_diverse(n)

    def get_statistics(self) -> dict[str, Any]:
        """Returns comprehensive statistics about the strategy generator."""
        population = list(self._population.strategies.values())

        return {
            "population_size": len(population),
            "generation_count": self._population.generation_count,
            "average_fitness": sum(s.fitness_score for s in population) / len(population) if population else 0.0,
            "top_strategies": [
                {
                    "name": s.name[:50],
                    "fitness": s.fitness_score,
                    "creation_method": s.creation_method,
                    "generation": s.generation,
                    "components": s.component_types,
                }
                for s in self.get_best_strategies({}, 5)
            ],
            "component_usage": dict(
                defaultdict(int, {
                    comp.value: sum(1 for s in population if comp in [g.component for g in s.genes])
                    for comp in StrategyComponent
                })
            ),
            "creation_methods": dict(
                defaultdict(int, {
                    method: sum(1 for s in population if s.creation_method == method)
                    for method in {s.creation_method for s in population}
                })
            ),
            "internal_stats": dict(self._stats),
        }

    def export_strategies(self) -> list[dict[str, Any]]:
        """Exports all strategies for persistence."""
        return [s.to_dict() for s in self._population.strategies.values()]

    def import_strategies(self, strategy_data: list[dict[str, Any]]) -> None:
        """Imports strategies from persisted data."""
        for data in strategy_data:
            strategy = VerificationStrategy.from_dict(data)
            self._population.add(strategy)
