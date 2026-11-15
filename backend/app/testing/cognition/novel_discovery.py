"""Novel Discovery Engine — Entdeckung neuer Konsistenz-Muster.

Findet Schwachstellen-Kategorien die NICHT in den vordefinierten
Templates enthalten sind, durch:

  1. Cross-Domain-Analogien:
     "Wie funktioniert ein Problem in Domäne A (z.B. Banking)?
      → Was wäre das Äquivalent in Domäne B (z.B. Web-API)?"

  2. Side-Channel-Checks:
     Prüft Informations-Kanäle die normalerweise ignoriert werden:
     → Response-Zeit-Differenzen
     → Content-Length-Differenzen
     → Header-Ordering-Differenzen
     → Error-Message-Vergleiche
     → Cache-Verhalten

  3. Kombinationstester:
     Kombiniert zwei einzeln sichere Features und prüft ob die
     KOMBINATION unsicher ist:
     → Feature A (sicher) + Feature B (sicher) = Kombination (unsicher?)

Jede Entdeckung wird als NovelFinding gespeichert und kann
in zukünftigen Läufen als neuer Check-Type genutzt werden.
"""
from __future__ import annotations

import difflib
import hashlib
import itertools
import json
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Daten-Klassen
# ---------------------------------------------------------------------------

@dataclass
class CrossDomainAnalogy:
    """Eine Analogie zwischen zwei Domänen."""
    source_domain: str
    target_domain: str
    source_pattern: str
    target_translation: str
    description: str
    check_steps: List[str] = field(default_factory=list)
    applicability: float = 0.5


@dataclass
class SideChannelResult:
    """Ergebnis eines Side-Channel-Checks."""
    channel_type: str
    endpoint: str
    baseline_value: Any
    test_value: Any
    difference: Any
    is_significant: bool
    significance_score: float
    description: str


@dataclass
class CombinationTestResult:
    """Ergebnis eines Kombinationstests."""
    feature_a: str
    feature_b: str
    combined_endpoint: str
    feature_a_alone_safe: bool
    feature_b_alone_safe: bool
    combination_safe: bool
    description: str
    severity: str = "unknown"


@dataclass
class NovelFinding:
    """Ein neu entdecktes Muster."""
    finding_id: str
    discovery_method: str  # "cross_domain", "side_channel", "combination"
    description: str
    check_type: str  # Neuer Check-Type der daraus abgeleitet wird
    severity: str
    confidence: float
    evidence: List[str] = field(default_factory=list)
    reproduction_steps: List[str] = field(default_factory=list)
    discovered_at: str = ""
    app_seed: int = 0


# ---------------------------------------------------------------------------
# Cross-Domain-Analogien (vordefiniert)
# ---------------------------------------------------------------------------

CROSS_DOMAIN_ANALOGIES: List[CrossDomainAnalogy] = [
    CrossDomainAnalogy(
        source_domain="banking",
        target_domain="web_api",
        source_pattern="Concurrent withdrawal from same account",
        target_translation="Concurrent state-modification on same endpoint",
        description="In banking: Two simultaneous withdrawals can both succeed if balance check happens before lock. In APIs: Two simultaneous PATCH requests can both modify state if validation happens before locking.",
        check_steps=[
            "Send two identical PATCH requests to same endpoint simultaneously",
            "Use asyncio.gather() with identical payloads",
            "Check if both requests return 200",
            "Verify final state — was it modified twice?",
        ],
        applicability=0.85,
    ),
    CrossDomainAnalogy(
        source_domain="banking",
        target_domain="web_api",
        source_pattern="Check tampering (modifying amount between client and server)",
        target_translation="Request body manipulation between client and API",
        description="In banking: Altering a check amount before deposit. In APIs: Modifying price/amount fields in request body between client validation and server processing.",
        check_steps=[
            "Identify endpoints that accept amount/price/quantity fields",
            "Send request with original amount — verify acceptance",
            "Send same request with modified amount (e.g., 0.01 instead of 99.99)",
            "Check if server validates or trusts client-provided amount",
        ],
        applicability=0.90,
    ),
    CrossDomainAnalogy(
        source_domain="physics",
        target_domain="web_api",
        source_pattern="Resonance (system amplifies at specific frequency)",
        target_translation="Timing-based state amplification",
        description="In physics: Systems amplify responses at resonance frequencies. In APIs: Specific request timing can amplify race conditions — sending requests at the 'right' moment maximizes impact.",
        check_steps=[
            "Identify state-modifying endpoint",
            "Send requests at various delays (0ms, 10ms, 50ms, 100ms, 500ms)",
            "Measure which delay produces most inconsistencies",
            "Check if specific timing window reliably triggers issue",
        ],
        applicability=0.70,
    ),
    CrossDomainAnalogy(
        source_domain="biology",
        target_domain="web_api",
        source_pattern="Immune system evasion (pathogen mimics host cells)",
        target_translation="Request validation evasion (malformed request mimics valid format)",
        description="In biology: Pathogens evade detection by mimicking host cells. In APIs: Requests with unusual encoding (UTF-16, charset tricks, type coercion) can evade validation while still being processed.",
        check_steps=[
            "Identify endpoint with input validation",
            "Send request with standard encoding — verify it's accepted/rejected correctly",
            "Send same request with alternative encodings (UTF-16, URL-encoded, base64)",
            "Send same request with type variations (string 'true' vs boolean true, array vs scalar)",
            "Check if any encoding bypasses validation",
        ],
        applicability=0.80,
    ),
    CrossDomainAnalogy(
        source_domain="chemistry",
        target_domain="web_api",
        source_pattern="Catalytic reaction (small trigger causes chain reaction)",
        target_translation="Cascading state changes from single request",
        description="In chemistry: A catalyst triggers a chain reaction. In APIs: A single request can trigger cascading side effects (webhook → state change → notification → further processing).",
        check_steps=[
            "Identify endpoint that triggers webhooks or notifications",
            "Send a request that initiates a processing chain",
            "Monitor all downstream effects (state changes, notifications, logs)",
            "Check if interrupting the chain at various points causes inconsistent state",
        ],
        applicability=0.65,
    ),
    CrossDomainAnalogy(
        source_domain="engineering",
        target_domain="web_api",
        source_pattern="Structural failure under critical load",
        target_translation="System failure under concurrent load",
        description="In engineering: Structures fail when load exceeds capacity. In APIs: Systems fail when concurrent requests exceed processing capacity — but the failure mode may be silent data corruption.",
        check_steps=[
            "Identify critical endpoint",
            "Gradually increase concurrent load (10, 50, 100, 200 requests)",
            "Monitor for: errors, timeouts, data inconsistencies",
            "Check if system recovers cleanly after load decreases",
            "Look for silent failures (200 OK but incorrect state)",
        ],
        applicability=0.85,
    ),
]


# ---------------------------------------------------------------------------
# Side-Channel-Check-Definitionen
# ---------------------------------------------------------------------------

@dataclass
class SideChannelCheck:
    """Definition eines Side-Channel-Checks."""
    channel_type: str
    description: str
    check_function: str  # Name der Methode die den Check durchführt
    threshold: float = 0.5


SIDE_CHANNEL_CHECKS: List[SideChannelCheck] = [
    SideChannelCheck(
        channel_type="response_time",
        description="Vergleicht Response-Zeit zwischen normaler und ungewöhnlicher Anfrage",
        check_function="check_response_time",
        threshold=0.5,
    ),
    SideChannelCheck(
        channel_type="content_length",
        description="Vergleicht Content-Length zwischen bekannter und unbekannter Resource",
        check_function="check_content_length",
        threshold=100,
    ),
    SideChannelCheck(
        channel_type="header_ordering",
        description="Prüft ob Header-Reihenfolge sich zwischen Requests unterscheidet",
        check_function="check_header_ordering",
        threshold=0.3,
    ),
    SideChannelCheck(
        channel_type="error_message",
        description="Vergleicht Fehlermeldungen für bekannte vs. unbekannte Eingaben",
        check_function="check_error_messages",
        threshold=0.6,
    ),
    SideChannelCheck(
        channel_type="cache_behavior",
        description="Prüft ob Responses gecacht werden und Cache-Invalidierung funktioniert",
        check_function="check_cache_behavior",
        threshold=0.4,
    ),
    SideChannelCheck(
        channel_type="status_code_variance",
        description="Prüft ob verschiedene Eingaben zu unerwartet unterschiedlichen Status-Codes führen",
        check_function="check_status_code_variance",
        threshold=0.3,
    ),
]


# ---------------------------------------------------------------------------
# Haupt-Klasse
# ---------------------------------------------------------------------------

class NovelDiscoveryEngine:
    """Entdeckt neue Konsistenz-Muster die nicht vordefiniert sind.

    Drei Entdeckungs-Methoden:
      1. Cross-Domain-Analogien (6 vordefinierte + lernbare)
      2. Side-Channel-Checks (6 Kanäle)
      3. Kombinationstester (2er/3er-Kombinationen)

    Usage:
        engine = NovelDiscoveryEngine()

        # Nach einem Benchmark-Lauf:
        findings = await engine.discover_novel(
            observations=results,
            executor=real_test_executor,
            base_url="http://127.0.0.1:8001",
        )

        for finding in findings:
            print(f"[{finding.severity}] {finding.description}")
    """

    def __init__(self, db_path: str = "qa_cognition/novel_findings.db"):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self._setup_database()

        # Analogy-Erweiterungen die gelernt wurden
        self.learned_analogies: List[CrossDomainAnalogy] = []

        # Statistiken
        self.total_discoveries = 0
        self.cross_domain_discoveries = 0
        self.side_channel_discoveries = 0
        self.combination_discoveries = 0

    def _setup_database(self) -> None:
        """Erstellt das Datenbank-Schema."""
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS novel_findings (
                finding_id TEXT PRIMARY KEY,
                discovery_method TEXT,
                description TEXT,
                check_type TEXT,
                severity TEXT,
                confidence REAL,
                evidence TEXT,
                reproduction_steps TEXT,
                discovered_at TEXT,
                app_seed INTEGER
            )
        """)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    # ------------------------------------------------------------------
    # Haupt-Methode
    # ------------------------------------------------------------------

    async def discover_novel(
        self,
        observations: List[Dict[str, Any]],
        executor=None,
        base_url: str = "",
        app_seed: int = 0,
    ) -> List[NovelFinding]:
        """Führt alle drei Entdeckungs-Methoden aus.

        Args:
            observations: Ergebnisse aus dem Benchmark-Lauf.
            executor: Optional ein RealTestExecutor für Side-Channel-Checks.
            base_url: Die URL der laufenden App (für Side-Channel-Checks).
            app_seed: Der Seed der App.

        Returns:
            Liste neu entdeckter Muster.
        """
        findings: List[NovelFinding] = []

        # Methode 1: Cross-Domain-Analogien
        cross_domain = self._check_cross_domain_analogies(observations, app_seed)
        findings.extend(cross_domain)

        # Methode 2: Side-Channel-Checks (nur wenn Executor verfügbar)
        if executor is not None and base_url:
            side_channel = await self._check_side_channels(
                executor, base_url, app_seed
            )
            findings.extend(side_channel)

        # Methode 3: Kombinationstests
        combinations = self._check_combinations(observations, app_seed)
        findings.extend(combinations)

        # Alle Findings in DB speichern
        for finding in findings:
            self._store_finding(finding)

        # Statistiken aktualisieren
        self.total_discoveries += len(findings)
        self.cross_domain_discoveries += len(cross_domain)
        self.side_channel_discoveries += len(side_channel) if executor else 0
        self.combination_discoveries += len(combinations)

        return findings

    # ------------------------------------------------------------------
    # Methode 1: Cross-Domain-Analogien
    # ------------------------------------------------------------------

    def _check_cross_domain_analogies(
        self,
        observations: List[Dict[str, Any]],
        app_seed: int,
    ) -> List[NovelFinding]:
        """Prüft ob Cross-Domain-Analogien auf die Observationen zutreffen.

        Für jede Analogie:
          1. Prüfe ob das Quell-Pattern in den Observationen erkennbar ist
          2. Wenn ja: Erzeuge eine NovelFinding mit dem Ziel-Pattern
        """
        findings: List[NovelFinding] = []

        # Alle Analysieren (vordefinierte + gelernte)
        all_analogies = CROSS_DOMAIN_ANALOGIES + self.learned_analogies

        for analogy in all_analogies:
            # Prüfe ob das Quell-Pattern in den Observationen erkennbar ist
            match_score = self._score_analogy_match(analogy, observations)

            if match_score > 0.5:
                finding_id = hashlib.md5(
                    f"cross_{analogy.source_domain}_{analogy.target_domain}_{app_seed}".encode()
                ).hexdigest()[:16]

                findings.append(NovelFinding(
                    finding_id=finding_id,
                    discovery_method="cross_domain",
                    description=(
                        f"Cross-domain pattern detected: {analogy.description}. "
                        f"Source: {analogy.source_domain}, "
                        f"Target: {analogy.target_domain}. "
                        f"Match score: {match_score:.2f}."
                    ),
                    check_type=f"novel_{analogy.target_domain}_{analogy.source_pattern[:20].lower().replace(' ', '_')}",
                    severity="high" if match_score > 0.7 else "medium",
                    confidence=min(0.9, match_score * analogy.applicability),
                    evidence=[
                        f"Source pattern: {analogy.source_pattern}",
                        f"Target translation: {analogy.target_translation}",
                        f"Match score: {match_score:.2f}",
                        f"Applicability: {analogy.applicability:.2f}",
                    ],
                    reproduction_steps=analogy.check_steps,
                    discovered_at=datetime.now().isoformat(),
                    app_seed=app_seed,
                ))

        return findings

    def _score_analogy_match(
        self,
        analogy: CrossDomainAnalogy,
        observations: List[Dict[str, Any]],
    ) -> float:
        """Bewertet wie gut eine Analogie zu den Observationen passt."""
        score = 0.0
        total_signals = 0

        # Signal 1: Endpunkt-Typ passt zur Ziel-Domäne
        for obs in observations:
            endpoint = obs.get("endpoint", "").lower()
            method = obs.get("method", "GET").upper()

            # Banking → Web-API Analogie
            if analogy.source_domain == "banking":
                if any(kw in endpoint for kw in ("payment", "order", "charge", "billing")):
                    score += 0.3
                if method in ("POST", "PATCH", "PUT"):
                    score += 0.2

            # Physics → Timing-Analogie
            if analogy.source_domain == "physics":
                elapsed = obs.get("elapsed_ms", 0)
                if elapsed > 100:
                    score += 0.2
                if "concurrent" in str(obs.get("test_case", {})).lower():
                    score += 0.3

            # Biology → Encoding-Analogie
            if analogy.source_domain == "biology":
                body = str(obs.get("body", "")).lower()
                if any(kw in body for kw in ("encoding", "charset", "content-type")):
                    score += 0.3

            total_signals += 1

        if total_signals == 0:
            return 0.0

        return min(1.0, score / max(1, total_signals // 4))

    # ------------------------------------------------------------------
    # Methode 2: Side-Channel-Checks
    # ------------------------------------------------------------------

    async def _check_side_channels(
        self,
        executor,
        base_url: str,
        app_seed: int,
    ) -> List[NovelFinding]:
        """Führt Side-Channel-Checks gegen die laufende App durch.

        Nutzt den RealTestExecutor um echte Requests zu senden
        und die Side-Channel-Signale zu vergleichen.
        """
        findings: List[NovelFinding] = []
        results: List[SideChannelResult] = []

        # Check 1: Response-Time-Differenzen
        time_result = await self._check_response_time(executor, base_url)
        if time_result:
            results.append(time_result)

        # Check 2: Content-Length-Differenzen
        length_result = await self._check_content_length(executor, base_url)
        if length_result:
            results.append(length_result)

        # Check 3: Error-Message-Vergleich
        error_result = await self._check_error_messages(executor, base_url)
        if error_result:
            results.append(error_result)

        # Check 4: Status-Code-Varianz
        status_result = await self._check_status_code_variance(executor, base_url)
        if status_result:
            results.append(status_result)

        # Signifikante Results in Findings umwandeln
        for result in results:
            if result.is_significant:
                finding_id = hashlib.md5(
                    f"side_{result.channel_type}_{app_seed}".encode()
                ).hexdigest()[:16]

                findings.append(NovelFinding(
                    finding_id=finding_id,
                    discovery_method="side_channel",
                    description=(
                        f"Side-channel signal detected via {result.channel_type}: "
                        f"{result.description}"
                    ),
                    check_type=f"novel_side_channel_{result.channel_type}",
                    severity="medium" if result.significance_score > 0.6 else "low",
                    confidence=result.significance_score,
                    evidence=[
                        f"Baseline: {result.baseline_value}",
                        f"Test value: {result.test_value}",
                        f"Difference: {result.difference}",
                        f"Significance: {result.significance_score:.2f}",
                    ],
                    reproduction_steps=[
                        f"Send baseline request and measure {result.channel_type}",
                        f"Send test request and measure {result.channel_type}",
                        f"Compare: difference is {result.difference}",
                    ],
                    discovered_at=datetime.now().isoformat(),
                    app_seed=app_seed,
                ))

        return findings

    async def _check_response_time(self, executor, base_url: str) -> Optional[SideChannelResult]:
        """Prüft Response-Zeit-Differenzen zwischen bekannten und unbekannten Resources."""
        try:
            # Baseline: Bekannte Resource
            known_response = await executor.send_request("/api/users/1", "GET")

            # Test: Unbekannte Resource
            unknown_response = await executor.send_request("/api/users/99999", "GET")

            known_time = known_response.get("elapsed_ms", 0)
            unknown_time = unknown_response.get("elapsed_ms", 0)
            difference = unknown_time - known_time

            # Signifikant wenn unbekannte Resource deutlich länger braucht
            # (deutet auf interne Suche/Verarbeitung hin)
            is_significant = difference > 100  # >100ms Unterschied

            significance = min(1.0, difference / 500) if difference > 0 else 0

            return SideChannelResult(
                channel_type="response_time",
                endpoint="/api/users/{id}",
                baseline_value=f"{known_time:.1f}ms",
                test_value=f"{unknown_time:.1f}ms",
                difference=f"{difference:.1f}ms",
                is_significant=is_significant,
                significance_score=significance,
                description=(
                    f"Response time differs between known ({known_time:.0f}ms) "
                    f"and unknown ({unknown_time:.0f}ms) resources — "
                    f"may indicate information leakage through timing"
                ),
            )
        except Exception:
            return None

    async def _check_content_length(self, executor, base_url: str) -> Optional[SideChannelResult]:
        """Prüft Content-Length-Differenzen."""
        try:
            # Baseline: Erfolgreiche Response
            success_response = await executor.send_request("/api/users/1", "GET")

            # Test: Fehler-Response
            error_response = await executor.send_request("/api/users/99999", "GET")

            success_len = len(str(success_response.get("body", "")))
            error_len = len(str(error_response.get("body", "")))
            difference = abs(error_len - success_len)

            # Signifikant wenn Fehler-Response deutlich länger ist
            # (kann auf verbose Fehlermeldungen hindeuten)
            is_significant = error_len > success_len * 2 and difference > 100

            return SideChannelResult(
                channel_type="content_length",
                endpoint="/api/users/{id}",
                baseline_value=f"{success_len} bytes",
                test_value=f"{error_len} bytes",
                difference=f"{difference} bytes",
                is_significant=is_significant,
                significance_score=min(1.0, difference / 1000),
                description=(
                    f"Content length differs significantly: success={success_len}, "
                    f"error={error_len} — verbose error messages may leak information"
                ),
            )
        except Exception:
            return None

    async def _check_error_messages(self, executor, base_url: str) -> Optional[SideChannelResult]:
        """Vergleicht Fehlermeldungen für verschiedene Eingaben."""
        try:
            # Verschiedene ungültige Eingaben
            responses = []
            test_inputs = [
                ("?", "/api/users/invalid_id"),
                ("?", "/api/users/0"),
                ("?", "/api/users/-1"),
                ("?", "/api/users/abc"),
            ]

            for _, path in test_inputs:
                resp = await executor.send_request(path, "GET")
                body_str = str(resp.get("body", ""))
                responses.append(body_str)

            # Prüfe ob alle Fehlermeldungen identisch sind (gut) oder verschieden (schlecht)
            unique_responses = len(set(responses))

            is_significant = unique_responses > 1  # Verschiedene Meldungen = Information Leak

            if is_significant:
                # Berechne wie verschieden sie sind
                similarities = []
                for i in range(len(responses)):
                    for j in range(i + 1, len(responses)):
                        sim = difflib.SequenceMatcher(
                            None, responses[i], responses[j]
                        ).ratio()
                        similarities.append(sim)

                avg_similarity = sum(similarities) / len(similarities) if similarities else 1.0
                significance = 1.0 - avg_similarity

                return SideChannelResult(
                    channel_type="error_message",
                    endpoint="/api/users/{id}",
                    baseline_value="identical error messages",
                    test_value=f"{unique_responses} different error messages",
                    difference=f"similarity: {avg_similarity:.2f}",
                    is_significant=is_significant,
                    significance_score=significance,
                    description=(
                        f"Error messages differ for different invalid inputs — "
                        f"may allow input enumeration or internal state inference"
                    ),
                )

            return None
        except Exception:
            return None

    async def _check_status_code_variance(self, executor, base_url: str) -> Optional[SideChannelResult]:
        """Prüft ob verschiedene Eingaben zu unerwartet unterschiedlichen Status-Codes führen."""
        try:
            # Sende Requests mit verschiedenen Eingabe-Typen
            test_cases = [
                ("/api/users/1", "GET", None),         # Valide
                ("/api/users/99999", "GET", None),     # Nicht existierend
                ("/api/users/abc", "GET", None),       # Ungültiger Typ
                ("/api/users/-1", "GET", None),        # Negativ
                ("/api/users/0", "GET", None),         # Null
            ]

            status_codes = []
            for path, method, body in test_cases:
                resp = await executor.send_request(path, method, body)
                status_codes.append(resp.get("status_code", 0))

            unique_codes = len(set(status_codes))

            # Mehr als 2 verschiedene Status-Codes für ähnliche Eingaben = verdächtig
            is_significant = unique_codes > 2

            if is_significant:
                return SideChannelResult(
                    channel_type="status_code_variance",
                    endpoint="/api/users/{id}",
                    baseline_value="consistent status codes",
                    test_value=f"{unique_codes} different status codes: {set(status_codes)}",
                    difference=f"codes: {status_codes}",
                    is_significant=is_significant,
                    significance_score=min(1.0, unique_codes / 5),
                    description=(
                        f"Different status codes for similar inputs — "
                        f"may reveal internal routing or processing logic"
                    ),
                )

            return None
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Methode 3: Kombinationstests
    # ------------------------------------------------------------------

    def _check_combinations(
        self,
        observations: List[Dict[str, Any]],
        app_seed: int,
    ) -> List[NovelFinding]:
        """Prüft ob Kombinationen von einzeln sicheren Features unsicher sind.

        Logik:
          Wenn Feature A sicher ist UND Feature B sicher ist,
          aber A+B zusammen unsicher ist → Novel Finding
        """
        findings: List[NovelFinding] = []

        # Gruppiere Observationen nach Endpunkt
        by_endpoint: Dict[str, List[Dict[str, Any]]] = {}
        for obs in observations:
            endpoint = obs.get("endpoint", "")
            if endpoint:
                by_endpoint.setdefault(endpoint, []).append(obs)

        # Prüfe alle 2er-Kombinationen von Endpunkten
        endpoints = list(by_endpoint.keys())

        for endpoint_a, endpoint_b in itertools.combinations(endpoints, 2):
            obs_a = by_endpoint[endpoint_a]
            obs_b = by_endpoint[endpoint_b]

            # Prüfe ob beide einzeln "sicher" sind (keine Funde)
            a_safe = not any(o.get("detected") for o in obs_a)
            b_safe = not any(o.get("detected") for o in obs_b)

            if not (a_safe and b_safe):
                continue  # Mindestens eines ist bereits unsicher — keine Novel Discovery

            # Prüfe ob es eine Interaktion zwischen den Endpunkten geben könnte
            interaction_score = self._score_endpoint_interaction(
                endpoint_a, endpoint_b, obs_a, obs_b
            )

            if interaction_score > 0.5:
                finding_id = hashlib.md5(
                    f"combo_{endpoint_a}_{endpoint_b}_{app_seed}".encode()
                ).hexdigest()[:16]

                findings.append(NovelFinding(
                    finding_id=finding_id,
                    discovery_method="combination",
                    description=(
                        f"Potential interaction between {endpoint_a} and {endpoint_b}: "
                        f"Both are individually safe but their combination may "
                        f"create an inconsistency (interaction score: {interaction_score:.2f})"
                    ),
                    check_type=f"novel_combination_{endpoint_a.replace('/', '_')}_{endpoint_b.replace('/', '_')}",
                    severity="medium",
                    confidence=interaction_score * 0.7,  # Niedriger als direkte Funde
                    evidence=[
                        f"{endpoint_a}: individually safe ({len(obs_a)} observations)",
                        f"{endpoint_b}: individually safe ({len(obs_b)} observations)",
                        f"Interaction score: {interaction_score:.2f}",
                    ],
                    reproduction_steps=[
                        f"Test {endpoint_a} alone — verify it's safe",
                        f"Test {endpoint_b} alone — verify it's safe",
                        f"Test both in sequence — check for state interactions",
                        f"Look for: state set by A affecting B, or vice versa",
                    ],
                    discovered_at=datetime.now().isoformat(),
                    app_seed=app_seed,
                ))

        return findings

    def _score_endpoint_interaction(
        self,
        endpoint_a: str,
        endpoint_b: str,
        obs_a: List[Dict[str, Any]],
        obs_b: List[Dict[str, Any]],
    ) -> float:
        """Bewertet ob zwei Endpunkte interagieren könnten."""
        score = 0.0

        # Signal 1: Gemeinsame Resource-Namen
        words_a = set(endpoint_a.lower().split("/"))
        words_b = set(endpoint_b.lower().split("/"))
        shared_words = words_a & words_b - {"api", "v1", "v2"}
        if shared_words:
            score += 0.3

        # Signal 2: Einer schreibt, der andere liest
        methods_a = {o.get("method", "GET").upper() for o in obs_a}
        methods_b = {o.get("method", "GET").upper() for o in obs_b}

        writes_a = bool(methods_a & {"POST", "PUT", "PATCH", "DELETE"})
        reads_b = bool(methods_b & {"GET"})

        if (writes_a and reads_b) or (writes_a and reads_b):
            score += 0.3

        # Signal 3: Beide modifizieren denselben Datentyp
        if writes_a and bool(methods_b & {"POST", "PUT", "PATCH"}):
            score += 0.2

        # Signal 4: Parent-Child-Beziehung
        if endpoint_a in endpoint_b or endpoint_b in endpoint_a:
            score += 0.2

        return min(1.0, score)

    # ------------------------------------------------------------------
    # Lernbare Analogien
    # ------------------------------------------------------------------

    def learn_analogy(
        self,
        source_domain: str,
        target_domain: str,
        source_pattern: str,
        target_translation: str,
        description: str,
        check_steps: List[str],
    ) -> None:
        """Fügt eine gelernte Analogie hinzu.

        Kann vom PatternExtractionEngine aufgerufen werden wenn
        ein wiederholt erfolgreiches Muster entdeckt wurde.
        """
        analogy = CrossDomainAnalogy(
            source_domain=source_domain,
            target_domain=target_domain,
            source_pattern=source_pattern,
            target_translation=target_translation,
            description=description,
            check_steps=check_steps,
            applicability=0.6,  # Gelernte Analogien starten mit mittlerer Anwendbarkeit
        )
        self.learned_analogies.append(analogy)

    # ------------------------------------------------------------------
    # Speicherung
    # ------------------------------------------------------------------

    def _store_finding(self, finding: NovelFinding) -> None:
        """Speichert ein Novel Finding in der Datenbank."""
        self.conn.execute(
            """
            INSERT OR REPLACE INTO novel_findings
            (finding_id, discovery_method, description, check_type,
             severity, confidence, evidence, reproduction_steps,
             discovered_at, app_seed)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                finding.finding_id,
                finding.discovery_method,
                finding.description,
                finding.check_type,
                finding.severity,
                finding.confidence,
                json.dumps(finding.evidence),
                json.dumps(finding.reproduction_steps),
                finding.discovered_at,
                finding.app_seed,
            ),
        )
        self.conn.commit()

    def get_all_findings(self) -> List[Dict[str, Any]]:
        """Gibt alle gespeicherten Novel Findings zurück."""
        rows = self.conn.execute(
            "SELECT * FROM novel_findings ORDER BY discovered_at DESC"
        ).fetchall()

        return [
            {
                "finding_id": row["finding_id"],
                "discovery_method": row["discovery_method"],
                "description": row["description"],
                "check_type": row["check_type"],
                "severity": row["severity"],
                "confidence": row["confidence"],
                "discovered_at": row["discovered_at"],
            }
            for row in rows
        ]

    # ------------------------------------------------------------------
    # Statistiken
    # ------------------------------------------------------------------

    def get_statistics(self) -> Dict[str, Any]:
        """Gibt Engine-Statistiken zurück."""
        return {
            "total_discoveries": self.total_discoveries,
            "cross_domain_discoveries": self.cross_domain_discoveries,
            "side_channel_discoveries": self.side_channel_discoveries,
            "combination_discoveries": self.combination_discoveries,
            "predefined_analogies": len(CROSS_DOMAIN_ANALOGIES),
            "learned_analogies": len(self.learned_analogies),
            "side_channel_checks": len(SIDE_CHANNEL_CHECKS),
            "stored_findings": len(self.get_all_findings()),
        }


if __name__ == "__main__":
    # Echter Test mit Observationen
    async def main():
        print("=" * 70)
        print("NOVEL DISCOVERY ENGINE — STANDALONE TEST")
        print("=" * 70)

        engine = NovelDiscoveryEngine("qa_cognition/test_novel.db")

        # Simulierte Observationen (die von RealTestExecutor kommen würden)
        observations = [
            {
                "endpoint": "/api/payment/confirm",
                "method": "POST",
                "status_code": 200,
                "elapsed_ms": 250,
                "body": {"status": "confirmed", "bypass_validation": True},
                "headers": {"content-type": "application/json"},
                "detected": False,
                "test_case": {"check_type": "input_field_whitelisting"},
            },
            {
                "endpoint": "/api/orders/1",
                "method": "GET",
                "status_code": 200,
                "elapsed_ms": 45,
                "body": {"id": 1, "status": "pending"},
                "headers": {},
                "detected": False,
                "test_case": {"check_type": "resource_ownership_consistency"},
            },
            {
                "endpoint": "/api/orders/1/status",
                "method": "PATCH",
                "status_code": 200,
                "elapsed_ms": 180,
                "body": {"status": "paid"},
                "headers": {},
                "detected": False,
                "test_case": {"check_type": "concurrent_state_consistency"},
            },
        ]

        # Test 1: Cross-Domain-Analogien prüfen
        print("\n1. Checking cross-domain analogies...")
        cross_findings = engine._check_cross_domain_analogies(observations, app_seed=42)
        print(f"   Found {len(cross_findings)} cross-domain findings:")
        for f in cross_findings:
            print(f"   • [{f.severity}] {f.description[:80]}...")
            print(f"     Method: {f.discovery_method}")
            print(f"     Confidence: {f.confidence:.2f}")

        # Test 2: Kombinationstests
        print("\n2. Checking combinations...")
        combo_findings = engine._check_combinations(observations, app_seed=42)
        print(f"   Found {len(combo_findings)} combination findings:")
        for f in combo_findings:
            print(f"   • [{f.severity}] {f.description[:80]}...")

        # Test 3: Analogy hinzufügen (Simulation)
        print("\n3. Learning a new analogy...")
        engine.learn_analogy(
            source_domain="aerospace",
            target_domain="web_api",
            source_pattern="Redundancy failure (backup systems fail simultaneously)",
            target_translation="Fallback mechanism failure in API error handling",
            description="In aerospace: Redundant systems can fail together if they share a common flaw. In APIs: Fallback error handlers can fail together if they share the same validation gap.",
            check_steps=[
                "Identify primary and fallback error handling paths",
                "Send request that triggers primary error handler",
                "Send same request in a way that bypasses to fallback",
                "Check if fallback has the same validation gap",
            ],
        )
        print(f"   Learned analogies: {len(engine.learned_analogies)}")

        # Statistiken
        print("\n4. Statistics:")
        stats = engine.get_statistics()
        for key, value in stats.items():
            print(f"   {key}: {value}")

        engine.close()
        print("\n✅ Novel Discovery Engine test completed")

    asyncio.run(main())
