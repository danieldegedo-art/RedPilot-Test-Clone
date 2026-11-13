"""Multi-Agent Ensemble — Parallele Analyse aus mehreren Perspektiven.

Erweitert MultiPerspectiveReasoner von 4 fixen Perspektiven auf
10-50 dynamische Agenten mit verschiedenen Analyse-Foki.

Jeder Agent hat:
  - Eine spezifische Analyse-Perspektive (Sicherheit, Performance, etc.)
  - Einen Bias der seine Bewertung beeinflusst (vorsichtig vs. aggressiv)
  - Ein Expertise-Level das seine Konfidenz bestimmt
  - Spezialisierte Heuristiken für seinen Fokus

Der Konsens-Mechanismus:
  1. Alle Agenten analysieren dieselbe Observation parallel
  2. Jeder Agent gibt Severity + Confidence + Empfehlung zurück
  3. Gewichteter Durchschnitt bildet den Konsens
  4. Hohe Abweichung zwischen Agenten = Unsicherheit → weitere Untersuchung

Diversität ist der Schlüssel:
  → 10 verschiedene Perspektiven finden mehr als 4
  → Verschiedene Biases verhindern Groupthink
  → Verschiedene Expertise-Levelen erlauben sowohl schnelle
    Standard-Analysen als auch tiefe Experten-Analysen
"""
from __future__ import annotations

import asyncio
import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

try:
    import numpy as np
except ImportError:
    np = None


class AgentPerspective(Enum):
    """Analyse-Perspektiven die ein Agent einnehmen kann."""
    SECURITY = "security"
    PERFORMANCE = "performance"
    RELIABILITY = "reliability"
    DATA_INTEGRITY = "data_integrity"
    ACCESS_CONTROL = "access_control"
    BUSINESS_LOGIC = "business_logic"
    INFRASTRUCTURE = "infrastructure"
    COMPLIANCE = "compliance"
    USER_EXPERIENCE = "user_experience"
    MAINTAINABILITY = "maintainability"


class AgentBias(Enum):
    """Bias der die Bewertung eines Agenten beeinflusst."""
    CONSERVATIVE = "consative"    # Neigt zu niedrigeren Severity-Bewertungen
    NEUTRAL = "neutral"           # Keine Verzerrung
    AGGRESSIVE = "aggressive"     # Neigt zu höheren Severity-Bewertungen
    PARANOID = "paranoid"         # Sieht überall Probleme


@dataclass
class AgentProfile:
    """Profil eines Analyse-Agenten."""
    agent_id: str
    perspective: AgentPerspective
    bias: AgentBias
    expertise: float  # 0.0 (Novize) bis 1.0 (Experte)
    heuristics: List[str] = field(default_factory=list)
    analysis_count: int = 0
    correct_predictions: int = 0
    last_active: float = 0.0

    @property
    def accuracy(self) -> float:
        """Trefferquote des Agenten."""
        if self.analysis_count == 0:
            return 0.5
        return self.correct_predictions / self.analysis_count

    @property
    def weight(self) -> float:
        """Gewicht des Agenten im Konsens (Expertise × Genauigkeit)."""
        return self.expertise * (0.5 + self.accuracy * 0.5)


@dataclass
class AgentAnalysis:
    """Analyse-Ergebnis eines einzelnen Agenten."""
    agent_id: str
    perspective: str
    severity: float  # 0.0 bis 1.0
    confidence: float  # 0.0 bis 1.0
    findings: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    analysis_time_ms: float = 0.0


@dataclass
class EnsembleConsensus:
    """Konsens-Ergebnis des gesamten Ensembles."""
    severity: float
    confidence: float
    agreement: float  # 0.0 (keine Übereinstimmung) bis 1.0 (vollständig)
    dominant_perspective: str
    contributing_agents: List[str] = field(default_factory=list)
    all_analyses: List[AgentAnalysis] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    diversity_score: float = 0.0
    outlier_agents: List[str] = field(default_factory=list)
    total_time_ms: float = 0.0


# ---------------------------------------------------------------------------
# Heuristiken pro Perspektive
# ---------------------------------------------------------------------------

PERSPECTIVE_HEURISTICS: Dict[AgentPerspective, List[str]] = {
    AgentPerspective.SECURITY: [
        "authentication_bypass", "authorization_gap", "input_validation",
        "output_encoding", "session_management", "cryptographic_weakness",
        "injection_point", "data_exposure",
    ],
    AgentPerspective.PERFORMANCE: [
        "response_time_anomaly", "resource_exhaustion", "slow_query",
        "memory_leak", "connection_pool_exhaustion", "timeout_risk",
        "bottleneck_identification", "load_handling",
    ],
    AgentPerspective.RELIABILITY: [
        "error_handling_gap", "crash_risk", "data_loss_risk",
        "inconsistent_state", "race_condition", "partial_failure",
        "recovery_gap", "cascading_failure",
    ],
    AgentPerspective.DATA_INTEGRITY: [
        "data_corruption", "validation_gap", "consistency_violation",
        "duplicate_handling", "transaction_integrity", "referential_integrity",
        "concurrent_write_risk", "stale_data",
    ],
    AgentPerspective.ACCESS_CONTROL: [
        "privilege_escalation", "role_bypass", "resource_ownership",
        "tenant_isolation", "api_scope_creep", "permission_gap",
        "unauthorized_access", "data_leakage",
    ],
    AgentPerspective.BUSINESS_LOGIC: [
        "workflow_bypass", "pricing_error", "discount_abuse",
        "order_manipulation", "subscription_integrity", "refund_abuse",
        "trial_extension", "coupon_stacking",
    ],
    AgentPerspective.INFRASTRUCTURE: [
        "configuration_exposure", "debug_endpoint", "internal_service_access",
        "network_segmentation", "dependency_vulnerability", "version_disclosure",
        "secret_exposure", "logging_gap",
    ],
    AgentPerspective.COMPLIANCE: [
        "pii_exposure", "audit_trail_gap", "data_retention_violation",
        "consent_handling", "encryption_gap", "access_logging",
        "regulatory_violation", "privacy_risk",
    ],
    AgentPerspective.USER_EXPERIENCE: [
        "error_message_quality", "response_clarity", "workflow_confusion",
        "timeout_handling", "graceful_degradation", "feedback_gap",
        "usability_issue", "accessibility_gap",
    ],
    AgentPerspective.MAINTAINABILITY: [
        "code_quality_indicator", "technical_debt_signal", "testability_gap",
        "documentation_gap", "coupling_risk", "complexity_indicator",
        "duplication_signal", "naming_inconsistency",
    ],
}

# Bias-Anpassungsfaktoren für Severity
BIAS_FACTORS: Dict[AgentBias, Tuple[float, float]] = {
    AgentBias.CONSERVATIVE: (0.7, -0.10),  # (Konfidenz-Multiplikator, Severity-Offset)
    AgentBias.NEUTRAL: (1.0, 0.0),
    AgentBias.AGGRESSIVE: (1.1, 0.10),
    AgentBias.PARANOID: (1.2, 0.20),
}


# ---------------------------------------------------------------------------
# Haupt-Klasse
# ---------------------------------------------------------------------------

class MultiAgentEnsemble:
    """Ensemble aus 10-50 Agenten mit verschiedenen Perspektiven.

    Usage:
        ensemble = MultiAgentEnsemble(num_agents=15)

        # Observation analysieren
        consensus = await ensemble.analyze(observation)

        if consensus.severity > 0.7:
            print(f"Critical issue detected by {consensus.dominant_perspective}")
    """

    def __init__(
        self,
        num_agents: int = 15,
        seed: int = 42,
    ):
        import random
        self.random = random.Random(seed)

        self.agents: List[AgentProfile] = []
        self._create_agents(num_agents)

        # Statistiken
        self.total_analyses = 0
        self.total_consensus_reached = 0
        self.total_high_disagreement = 0

    def _create_agents(self, num_agents: int) -> None:
        """Erstellt eine diverse Agenten-Population."""
        perspectives = list(AgentPerspective)
        biases = list(AgentBias)

        for i in range(num_agents):
            # Perspektive rotieren für Vielfalt
            perspective = perspectives[i % len(perspectives)]

            # Bias zufällig aber gewichtet (Neutral am häufigsten)
            bias_weights = [1, 3, 2, 1]  # conservative, neutral, aggressive, paranoid
            bias = self.random.choices(biases, weights=bias_weights, k=1)[0]

            # Expertise zwischen 0.4 und 1.0
            expertise = self.random.uniform(0.4, 1.0)

            # Heuristiken aus der Perspektiv-Definition
            heuristics = PERSPECTIVE_HEURISTICS.get(perspective, [])

            # Agenten-ID deterministisch
            agent_id = f"agent_{i:03d}_{perspective.value[:4]}"

            self.agents.append(AgentProfile(
                agent_id=agent_id,
                perspective=perspective,
                bias=bias,
                expertise=expertise,
                heuristics=heuristics,
            ))

    # ------------------------------------------------------------------
    # Analyse
    # ------------------------------------------------------------------

    async def analyze(
        self,
        observation: Dict[str, Any],
        custom_analyzers: Optional[Dict[str, Callable]] = None,
    ) -> EnsembleConsensus:
        """Analysiert eine Observation mit allen Agenten parallel.

        Args:
            observation: Die zu analysierende Observation.
            custom_analyzers: Optional benutzerdefinierte Analyse-Funktionen
                pro Perspektive.

        Returns:
            EnsembleConsensus mit dem gewichteten Konsens aller Agenten.
        """
        start_time = time.perf_counter()

        self.total_analyses += 1

        # Alle Agenten parallel analysieren lassen
        tasks = [
            self._analyze_with_agent(agent, observation, custom_analyzers)
            for agent in self.agents
        ]
        analyses = await asyncio.gather(*tasks)

        # Konsens berechnen
        consensus = self._calculate_consensus(analyses)

        # Performance-Tracking der Agenten aktualisieren
        for agent, analysis in zip(self.agents, analyses):
            agent.analysis_count += 1
            agent.last_active = time.time()

        consensus.total_time_ms = (time.perf_counter() - start_time) * 1000

        return consensus

    async def _analyze_with_agent(
        self,
        agent: AgentProfile,
        observation: Dict[str, Any],
        custom_analyzers: Optional[Dict[str, Callable]],
    ) -> AgentAnalysis:
        """Führt die Analyse eines einzelnen Agenten durch."""
        agent_start = time.perf_counter()

        # Basis-Analyse basierend auf Perspektive
        severity, findings = self._perspective_analysis(agent, observation)

        # Bias anwenden
        bias_factor, severity_offset = BIAS_FACTORS.get(
            agent.bias, (1.0, 0.0)
        )
        severity = max(0.0, min(1.0, severity + severity_offset))

        # Confidence basierend auf Expertise und Fund-Anzahl
        base_confidence = 0.3 + agent.expertise * 0.4
        if findings:
            base_confidence += min(0.2, len(findings) * 0.05)
        confidence = min(1.0, base_confidence * bias_factor)

        # Empfehlungen generieren
        recommendations = self._generate_recommendations(agent, findings)

        # Custom-Analyzer aufrufen falls vorhanden
        if custom_analyzers and agent.perspective.value in custom_analyzers:
            try:
                custom_result = custom_analyzers[agent.perspective.value](observation)
                if isinstance(custom_result, dict):
                    severity = max(severity, custom_result.get("severity", 0))
                    findings.extend(custom_result.get("findings", []))
                    recommendations.extend(custom_result.get("recommendations", []))
            except Exception:
                pass  # Custom-Analyzer-Fehler ignorieren

        elapsed = (time.perf_counter() - agent_start) * 1000

        return AgentAnalysis(
            agent_id=agent.agent_id,
            perspective=agent.perspective.value,
            severity=round(severity, 3),
            confidence=round(confidence, 3),
            findings=findings,
            recommendations=recommendations,
            analysis_time_ms=elapsed,
        )

    def _perspective_analysis(
        self,
        agent: AgentProfile,
        observation: Dict[str, Any],
    ) -> Tuple[float, List[str]]:
        """Führt eine perspektiv-spezifische Analyse durch.

        Returns:
            Tuple aus (severity, findings).
        """
        severity = 0.0
        findings: List[str] = []

        body = observation.get("body", {})
        headers = observation.get("headers", {})
        status_code = observation.get("status_code", 0)
        endpoint = observation.get("endpoint", "")
        method = observation.get("method", "GET")

        body_str = str(body).lower() if body else ""
        headers_str = str(headers).lower()

        # Basis-Severity aus Status-Code
        if status_code >= 500:
            severity = 0.6
            findings.append(f"Server error ({status_code})")
        elif status_code == 200:
            severity = 0.2

        # Perspektiv-spezifische Checks
        if agent.perspective == AgentPerspective.SECURITY:
            security_markers = [
                "password", "secret", "token", "key", "credential",
                "admin", "debug", "internal", "bypass", "override",
            ]
            for marker in security_markers:
                if marker in body_str or marker in headers_str:
                    severity = max(severity, 0.7)
                    findings.append(f"Security-relevant field '{marker}' detected")

        elif agent.perspective == AgentPerspective.PERFORMANCE:
            elapsed = observation.get("elapsed_ms", 0)
            if elapsed > 1000:
                severity = max(severity, 0.5)
                findings.append(f"Slow response time: {elapsed}ms")
            elif elapsed > 500:
                severity = max(severity, 0.3)
                findings.append(f"Elevated response time: {elapsed}ms")

        elif agent.perspective == AgentPerspective.RELIABILITY:
            if status_code >= 500:
                findings.append("Potential unhandled error")
            if "timeout" in body_str or "timed out" in body_str:
                severity = max(severity, 0.6)
                findings.append("Timeout indication in response")

        elif agent.perspective == AgentPerspective.DATA_INTEGRITY:
            if isinstance(body, dict):
                if "duplicate" in body_str or "conflict" in body_str:
                    severity = max(severity, 0.6)
                    findings.append("Data conflict indication")

        elif agent.perspective == AgentPerspective.ACCESS_CONTROL:
            if isinstance(body, dict):
                role_fields = [k for k in body if "role" in k.lower() or "admin" in k.lower()]
                if role_fields:
                    severity = max(severity, 0.7)
                    findings.append(f"Role/admin fields in response: {role_fields}")

        elif agent.perspective == AgentPerspective.BUSINESS_LOGIC:
            logic_markers = ["bypass", "override", "skip", "free", "discount", "trial"]
            for marker in logic_markers:
                if marker in body_str:
                    severity = max(severity, 0.7)
                    findings.append(f"Business logic concern: '{marker}' field")

        elif agent.perspective == AgentPerspective.INFRASTRUCTURE:
            infra_markers = ["config", "env", "internal", "debug", "version", "build"]
            for marker in infra_markers:
                if marker in body_str or marker in headers_str:
                    severity = max(severity, 0.5)
                    findings.append(f"Infrastructure detail exposed: '{marker}'")

        elif agent.perspective == AgentPerspective.COMPLIANCE:
            pii_markers = ["email", "phone", "address", "ssn", "name", "dob"]
            for marker in pii_markers:
                if marker in body_str:
                    severity = max(severity, 0.4)
                    findings.append(f"Potential PII in response: '{marker}'")

        # Heuristik-basierte Checks
        for heuristic in agent.heuristics[:3]:  # Nur Top-3 Heuristiken prüfen
            heuristic_marker = heuristic.split("_")[0]  # Erster Teil als Marker
            if heuristic_marker in body_str:
                severity = max(severity, 0.4)
                findings.append(f"Heuristic triggered: {heuristic}")

        return severity, findings

    def _generate_recommendations(
        self,
        agent: AgentProfile,
        findings: List[str],
    ) -> List[str]:
        """Generiert Empfehlungen basierend auf Funden und Perspektive."""
        if not findings:
            return []

        recommendations = []
        perspective_name = agent.perspective.value.replace("_", " ").title()

        for finding in findings[:3]:  # Max 3 Empfehlungen
            recommendations.append(
                f"[{perspective_name}] {finding} — verify and remediate"
            )

        return recommendations

    # ------------------------------------------------------------------
    # Konsens-Berechnung
    # ------------------------------------------------------------------

    def _calculate_consensus(
        self,
        analyses: List[AgentAnalysis],
    ) -> EnsembleConsensus:
        """Berechnet den gewichteten Konsens aus allen Agenten-Analysen."""
        if not analyses:
            return EnsembleConsensus(
                severity=0.0, confidence=0.0, agreement=0.0,
                dominant_perspective="none",
            )

        # Agenten-Profile nach ID mappen für Gewichtungs-Lookup
        agent_map = {a.agent_id: a for a in self.agents}

        # Gewichteter Severity-Durchschnitt
        total_weight = 0.0
        weighted_severity = 0.0
        weighted_confidence = 0.0

        severity_scores: List[float] = []
        contributing_agents: List[str] = []

        for analysis in analyses:
            agent = agent_map.get(analysis.agent_id)
            weight = agent.weight if agent else 0.5

            weighted_severity += analysis.severity * weight
            weighted_confidence += analysis.confidence * weight
            total_weight += weight

            if analysis.severity > 0.3:
                contributing_agents.append(analysis.agent_id)

            severity_scores.append(analysis.severity)

        avg_severity = weighted_severity / total_weight if total_weight > 0 else 0
        avg_confidence = weighted_confidence / total_weight if total_weight > 0 else 0

        # Agreement (Übereinstimmung zwischen Agenten)
        if np is not None and len(severity_scores) > 1:
            severity_std = float(np.std(severity_scores))
            agreement = max(0.0, 1.0 - severity_std / 0.5)
        else:
            # Fallback ohne numpy
            mean_sev = sum(severity_scores) / len(severity_scores)
            variance = sum((s - mean_sev) ** 2 for s in severity_scores) / len(severity_scores)
            agreement = max(0.0, 1.0 - (variance ** 0.5) / 0.5)

        # Dominante Perspektive (höchste Severity)
        dominant = max(analyses, key=lambda a: a.severity)
        dominant_perspective = dominant.perspective

        # Diversitäts-Score (wie viele verschiedene Perspektiven haben etwas gefunden)
        perspectives_with_findings = set(
            a.perspective for a in analyses if a.severity > 0.3
        )
        diversity_score = len(perspectives_with_findings) / len(AgentPerspective)

        # Outlier-Agenten (weichen stark vom Konsens ab)
        outlier_agents = []
        if len(severity_scores) > 3:
            for analysis in analyses:
                if abs(analysis.severity - avg_severity) > 0.4:
                    outlier_agents.append(analysis.agent_id)

        # Alle Findings und Empfehlungen sammeln
        all_findings = []
        all_recommendations = []
        for analysis in analyses:
            all_findings.extend(analysis.findings)
            all_recommendations.extend(analysis.recommendations)

        # Deduplizieren
        all_findings = list(dict.fromkeys(all_findings))
        all_recommendations = list(dict.fromkeys(all_recommendations))

        # Konsens-Statistiken
        if agreement < 0.3:
            self.total_high_disagreement += 1
        else:
            self.total_consensus_reached += 1

        return EnsembleConsensus(
            severity=round(avg_severity, 3),
            confidence=round(avg_confidence, 3),
            agreement=round(agreement, 3),
            dominant_perspective=dominant_perspective,
            contributing_agents=contributing_agents,
            all_analyses=analyses,
            findings=all_findings[:15],
            recommendations=all_recommendations[:10],
            diversity_score=round(diversity_score, 3),
            outlier_agents=outlier_agents,
        )

    # ------------------------------------------------------------------
    # Agenten-Feedback
    # ------------------------------------------------------------------

    def update_agent_accuracy(
        self,
        agent_id: str,
        was_correct: bool,
    ) -> None:
        """Aktualisiert die Genauigkeit eines Agenten basierend auf Feedback.

        Wird aufgerufen wenn bekannt ist ob eine Vorhersage korrekt war.
        """
        for agent in self.agents:
            if agent.agent_id == agent_id:
                if was_correct:
                    agent.correct_predictions += 1
                break

    def get_top_agents(self, n: int = 5) -> List[Dict[str, Any]]:
        """Gibt die besten Agenten nach Gewicht zurück."""
        sorted_agents = sorted(
            self.agents,
            key=lambda a: a.weight,
            reverse=True,
        )

        return [
            {
                "agent_id": a.agent_id,
                "perspective": a.perspective.value,
                "bias": a.bias.value,
                "expertise": round(a.expertise, 2),
                "accuracy": round(a.accuracy, 2),
                "weight": round(a.weight, 3),
                "analyses": a.analysis_count,
            }
            for a in sorted_agents[:n]
        ]

    # ------------------------------------------------------------------
    # Statistiken
    # ------------------------------------------------------------------

    def get_statistics(self) -> Dict[str, Any]:
        """Gibt Ensemble-Statistiken zurück."""
        perspective_dist: Dict[str, int] = {}
        bias_dist: Dict[str, int] = {}

        for agent in self.agents:
            perspective_dist[agent.perspective.value] = \
                perspective_dist.get(agent.perspective.value, 0) + 1
            bias_dist[agent.bias.value] = \
                bias_dist.get(agent.bias.value, 0) + 1

        return {
            "num_agents": len(self.agents),
            "total_analyses": self.total_analyses,
            "total_consensus_reached": self.total_consensus_reached,
            "total_high_disagreement": self.total_high_disagreement,
            "perspective_distribution": perspective_dist,
            "bias_distribution": bias_dist,
            "avg_expertise": round(
                sum(a.expertise for a in self.agents) / len(self.agents), 2
            ),
            "top_agents": self.get_top_agents(5),
        }

    def reset(self) -> None:
        """Setzt alle Agenten-Statistiken zurück."""
        for agent in self.agents:
            agent.analysis_count = 0
            agent.correct_predictions = 0
        self.total_analyses = 0
        self.total_consensus_reached = 0
        self.total_high_disagreement = 0


if __name__ == "__main__":
    # Echter Test mit paralleler Analyse
    async def main():
        print("=" * 70)
        print("MULTI-AGENT ENSEMBLE — STANDALONE TEST")
        print("=" * 70)

        ensemble = MultiAgentEnsemble(num_agents=15, seed=42)

        print(f"\nAgents created: {len(ensemble.agents)}")

        # Agenten-Profile anzeigen
        print("\n1. Agent Profiles (first 5):")
        for agent in ensemble.agents[:5]:
            print(f"  {agent.agent_id}:")
            print(f"    Perspective: {agent.perspective.value}")
            print(f"    Bias: {agent.bias.value}")
            print(f"    Expertise: {agent.expertise:.2f}")
            print(f"    Heuristics: {agent.heuristics[:3]}")

        # Test 2: Observation analysieren
        print("\n2. Analyzing suspicious observation:")
        suspicious_obs = {
            "endpoint": "/api/payment/confirm",
            "method": "POST",
            "status_code": 200,
            "elapsed_ms": 850,
            "body": {
                "status": "confirmed",
                "bypass_validation": True,
                "admin_override": True,
                "internal_debug": {"verbose": True},
                "secret_key": "sk_live_...",
            },
            "headers": {"content-type": "application/json"},
        }

        consensus = await ensemble.analyze(suspicious_obs)

        print(f"  Severity: {consensus.severity:.3f}")
        print(f"  Confidence: {consensus.confidence:.3f}")
        print(f"  Agreement: {consensus.agreement:.3f}")
        print(f"  Diversity: {consensus.diversity_score:.3f}")
        print(f"  Dominant Perspective: {consensus.dominant_perspective}")
        print(f"  Contributing Agents: {len(consensus.contributing_agents)}")
        print(f"  Total Time: {consensus.total_time_ms:.1f}ms")

        print(f"\n  Findings ({len(consensus.findings)}):")
        for finding in consensus.findings[:8]:
            print(f"    • {finding}")

        print(f"\n  Recommendations ({len(consensus.recommendations)}):")
        for rec in consensus.recommendations[:5]:
            print(f"    • {rec}")

        # Test 3: Normale Observation
        print("\n3. Analyzing normal observation:")
        normal_obs = {
            "endpoint": "/api/users/123",
            "method": "GET",
            "status_code": 200,
            "elapsed_ms": 45,
            "body": {"id": 123, "name": "Test User", "email": "test@example.com"},
            "headers": {"content-type": "application/json"},
        }

        normal_consensus = await ensemble.analyze(normal_obs)

        print(f"  Severity: {normal_consensus.severity:.3f}")
        print(f"  Confidence: {normal_consensus.confidence:.3f}")
        print(f"  Agreement: {normal_consensus.agreement:.3f}")
        print(f"  Dominant Perspective: {normal_consensus.dominant_perspective}")
        print(f"  Findings: {len(normal_consensus.findings)}")

        # Test 4: Statistiken
        print("\n4. Statistics:")
        stats = ensemble.get_statistics()
        print(f"  Agents: {stats['num_agents']}")
        print(f"  Total analyses: {stats['total_analyses']}")
        print(f"  Consensus reached: {stats['total_consensus_reached']}")
        print(f"  High disagreement: {stats['total_high_disagreement']}")
        print(f"  Perspective distribution: {stats['perspective_distribution']}")
        print(f"  Top agents:")
        for agent in stats['top_agents'][:3]:
            print(f"    {agent['agent_id']}: weight={agent['weight']}, "
                  f"perspective={agent['perspective']}")

        print("\n✅ Multi-Agent Ensemble test completed")

    asyncio.run(main())
