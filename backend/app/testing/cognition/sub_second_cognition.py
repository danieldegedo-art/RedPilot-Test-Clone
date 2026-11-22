"""Sub-Second Cognition — Multi-Level-Caching + Spekulative Ausführung.

Reduziert die kognitive Entscheidungszeit von ~150ms auf <10ms durch:

  1. CognitiveCache (LRU-basierter Ergebnis-Cache):
     Wenn dieselbe Art von Beobachtung bereits verarbeitet wurde,
     wird das gecachte Ergebnis sofort zurückgegeben.
     Cache-Key: Endpunkt-Pattern + Status-Code-Bereich + Check-Type

  2. SpeculativeExecutor (Vorhersage des nächsten Tests):
     WÄHREND der aktuelle Test läuft, berechnet das System die
     5 wahrscheinlichsten nächsten Tests und bereitet sie VOR.
     Wenn der aktuelle Test fertig ist, ist der nächste bereits
     vorbereitet → 0ms Übergangszeit.

  3. PredictivePrefetcher (Ressourcen-Vorladen):
     Lädt Hypothesen, Patterns und Regeln die wahrscheinlich
     als nächstes gebraucht werden INDENDEM der aktuelle
     Test noch läuft.

Zusammenspiel:
  Beobachtung kommt an
    → [Cache] 5ms: Gecachtes Ergebnis?
      → JA: Sofort zurückgeben (Cache-Hit)
      → NEIN: [Speculative] War dieser Fall vorbereitet?
        → JA: Vorbereitetes Ergebnis nutzen (Speculation-Hit)
        → NEIN: [Normal] Tatsächlich berechnen (~100ms)
          → [Prefetcher] Während der Berechnung: Nächste vorbereiten

Ziel: >80% Cache-Hit-Rate nach 100 Beobachtungen.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import time
from collections import OrderedDict, defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Cognitive Cache
# ---------------------------------------------------------------------------

@dataclass
class CacheEntry:
    """Ein Eintrag im kognitiven Cache."""
    key: str
    value: Any
    created_at: float
    access_count: int = 0
    last_accessed: float = 0.0
    ttl: float = 3600.0  # 1 Stunde Standard-TTL

    @property
    def is_expired(self) -> bool:
        return time.time() - self.created_at > self.ttl

    def touch(self) -> None:
        self.access_count += 1
        self.last_accessed = time.time()


class CognitiveCache:
    """LRU-Cache für kognitive Entscheidungen.

    Cache-Key wird gebildet aus:
      - Endpunkt-Pattern (Zahlen durch {id} ersetzt)
      - HTTP-Methode
      - Status-Code-Bereich (2xx, 4xx, 5xx)
      - Check-Type (falls vorhanden)
      - Severity (falls vorhanden)

    Verschiedene TTLs für verschiedene Eventualitäten:
      - CRITICAL findings: 5 Min (kann sich schnell ändern)
      - HIGH findings: 15 Min
      - MEDIUM: 1 Stunde
      - LOW/INFO: 4 Stunden
    """

    # TTL nach Severity (in Sekunden)
    TTL_BY_SEVERITY = {
        "critical": 300,    # 5 Minuten
        "high": 900,        # 15 Minuten
        "medium": 3600,     # 1 Stunde
        "low": 14400,       # 4 Stunden
        "info": 14400,      # 4 Stunden
        "none": 3600,       # 1 Stunde
    }

    def __init__(self, max_size: int = 5000):
        self.max_size = max_size
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()

        # Statistiken
        self.hits = 0
        self.misses = 0
        self.evictions = 0
        self.total_time_saved_ms = 0.0

    def _make_key(self, observation: Dict[str, Any]) -> str:
        """Generiert einen Cache-Schlüssel aus einer Observation."""
        import re

        endpoint = observation.get("endpoint", "")
        method = observation.get("method", "GET").upper()
        status_code = observation.get("status_code", 0)
        check_type = observation.get("check_type", "")
        severity = observation.get("severity", "none")

        # Endpunkt-Pattern
        endpoint_pattern = re.sub(r"/\d+", "/{id}", endpoint)
        endpoint_pattern = re.sub(
            r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            "/{uuid}", endpoint_pattern, flags=re.IGNORECASE
        )

        # Status-Code-Bereich
        status_range = f"{status_code // 100}xx" if status_code and status_code > 0 else "0"

        key_data = f"{method}:{endpoint_pattern}:{status_range}:{check_type}:{severity}"
        return hashlib.md5(key_data.encode()).hexdigest()

    def get(self, observation: Dict[str, Any]) -> Optional[Tuple[Any, float]]:
        """Gibt gecachtes Ergebnis zurück.

        Returns:
            Tuple aus (cached_value, time_saved_ms) oder None.
        """
        key = self._make_key(observation)

        if key in self._cache:
            entry = self._cache[key]

            if entry.is_expired:
                # Abgelaufen — entfernen
                del self._cache[key]
                self.misses += 1
                return None

            # Cache-Hit
            entry.touch()
            self.hits += 1

            # LRU: ans Ende verschieben
            self._cache.move_to_end(key)

            # Geschätzte Zeit-Ersparnis (wie lange hätte die Berechnung gedauert)
            time_saved = 50.0  # Konservative Schätzung: ~50ms pro Berechnung

            return entry.value, time_saved

        self.misses += 1
        return None

    def put(
        self,
        observation: Dict[str, Any],
        value: Any,
        severity: str = "none",
    ) -> None:
        """Speichert ein Ergebnis im Cache."""
        key = self._make_key(observation)
        ttl = self.TTL_BY_SEVERITY.get(severity, 3600)

        self._cache[key] = CacheEntry(
            key=key,
            value=value,
            created_at=time.time(),
            ttl=ttl,
        )

        # LRU-Eviction
        while len(self._cache) > self.max_size:
            oldest_key = next(iter(self._cache))
            del self._cache[oldest_key]
            self.evictions += 1

    def invalidate_pattern(self, endpoint_pattern: str) -> int:
        """Invalidiert alle Cache-Einträge für ein Endpunkt-Muster."""
        import re
        pattern = re.sub(r"/\d+", "/{id}", endpoint_pattern)

        to_remove = []
        for key, entry in self._cache.items():
            if pattern in str(entry.value):
                to_remove.append(key)

        for key in to_remove:
            del self._cache[key]

        return len(to_remove)

    def clear(self) -> None:
        self._cache.clear()
        self.hits = 0
        self.misses = 0
        self.evictions = 0
        self.total_time_saved_ms = 0.0

    @property
    def hit_rate(self) -> float:
        total = self.hits + self.misses
        return self.hits / total if total > 0 else 0.0

    @property
    def size(self) -> int:
        return len(self._cache)

    def get_stats(self) -> Dict[str, Any]:
        return {
            "size": self.size,
            "max_size": self.max_size,
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": round(self.hit_rate, 3),
            "evictions": self.evictions,
            "estimated_time_saved_ms": round(self.hits * 50.0, 1),
        }


# ---------------------------------------------------------------------------
# Speculative Executor
# ---------------------------------------------------------------------------

@dataclass
class SpeculationResult:
    """Ergebnis einer spekulativen Ausführung."""
    observation: Dict[str, Any]
    result: Any
    was_speculated: bool
    preparation_time_ms: float = 0.0
    execution_time_ms: float = 0.0


class SpeculativeExecutor:
    """Berechnet wahrscheinliche nächste Tests während der aktuelle läuft.

    Wie es funktioniert:
      1. Beobachtung A kommt an und wird verarbeitet (100ms)
      2. WÄHREND A verarbeitet wird:
         → SpeculativeExecutor sagt voraus: "Nach A kommt wahrscheinlich B"
         → Bereitet B VOR (in einem Background-Task)
      3. Beobachtung B kommt an
         → SpeculativeExecutor prüft: "Habe ich B vorbereitet?"
         → JA: Ergebnis ist bereits da → 0ms Übergangszeit
         → NEIN: Normal verarbeiten

    Vorhersage basiert auf:
      - Historie: Welche Check-Types folgten aufeinander?
      - Muster: "webhook_integrity_gap" → "duplicate_handling_gap"
      - Sequenzen: FindingSequenceAnalyzer's Auto-Trigger-Matrix
    """

    # Auto-Trigger-Matrix (welche Checks folgen auf welche)
    SEQUENCE_MAP: Dict[str, List[str]] = {
        "webhook_integrity_gap": ["duplicate_handling_gap", "input_field_whitelisting"],
        "query_construction_issue": ["access_control_inconsistency", "response_field_filtering"],
        "output_encoding_gap": ["session_integrity", "header_value_validation"],
        "access_control_inconsistency": ["resource_ownership_consistency", "authorization_enforcement_gap"],
        "concurrent_state_consistency": ["duplicate_handling_gap", "audit_trail_completeness"],
        "input_field_whitelisting": ["resource_ownership_consistency"],
        "file_path_validation": ["upload_content_validation", "xml_parser_configuration"],
        "token_signature_integrity": ["session_integrity", "access_control_inconsistency"],
        "configuration_hardening_gap": ["error_message_disclosure", "dependency_version_check"],
    }

    def __init__(
        self,
        evaluator: Optional[Callable] = None,
        max_speculations: int = 5,
    ):
        self.evaluator = evaluator
        self.max_speculations = max_speculations

        # Spekulations-Speicher
        self._speculated_results: Dict[str, Any] = {}
        self._speculation_tasks: List[asyncio.Task] = []

        # Vorhersage-Historie
        self._prediction_history: deque = deque(maxlen=100)

        # Statistiken
        self.total_speculations = 0
        self.successful_speculations = 0
        self.failed_speculations = 0

    def predict_next_observations(
        self,
        current_observation: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Sagt die wahrscheinlichsten nächsten Beobachtungen voraus."""
        check_type = current_observation.get("check_type", "")
        endpoint = current_observation.get("endpoint", "")
        method = current_observation.get("method", "GET")

        predictions = []

        # Sequenz-basierte Vorhersage
        next_check_types = self.SEQUENCE_MAP.get(check_type, [])

        for next_check in next_check_types[:self.max_speculations]:
            predictions.append({
                "endpoint": endpoint,
                "method": method,
                "check_type": next_check,
                "status_code": current_observation.get("status_code", 200),
                "severity": current_observation.get("severity", "none"),
            })

        # Historien-basierte Vorhersage
        if len(self._prediction_history) >= 5:
            # Was kam in der Historie am häufigsten nach diesem Check-Type?
            follow_ups: Dict[str, int] = defaultdict(int)

            for i, (prev_check, next_check) in enumerate(
                zip(self._prediction_history, list(self._prediction_history)[1:])
            ):
                if prev_check == check_type:
                    follow_ups[next_check] += 1

            # Top-Follow-Ups die nicht schon durch Sequenz abgedeckt sind
            for next_check, count in sorted(
                follow_ups.items(), key=lambda x: x[1], reverse=True
            ):
                if next_check not in next_check_types:
                    predictions.append({
                        "endpoint": endpoint,
                        "method": method,
                        "check_type": next_check,
                        "status_code": current_observation.get("status_code", 200),
                        "severity": "none",
                    })
                    if len(predictions) >= self.max_speculations:
                        break

        return predictions[:self.max_speculations]

    async def speculate(
        self,
        current_observation: Dict[str, Any],
    ) -> List[asyncio.Task]:
        """Startet spekulative Berechnungen für wahrscheinliche nächste Beobachtungen.

        Wird aufgerufen WÄHREND die aktuelle Beobachtung verarbeitet wird.
        """
        predictions = self.predict_next_observations(current_observation)

        tasks = []
        for pred in predictions:
            # Key für die spekulierte Beobachtung
            pred_key = self._make_prediction_key(pred)

            # Background-Task starten
            task = asyncio.create_task(
                self._speculative_evaluate(pred, pred_key)
            )
            tasks.append(task)
            self._speculation_tasks.append(task)
            self.total_speculations += 1

        # Alte Tasks aufräumen
        self._speculation_tasks = [
            t for t in self._speculation_tasks if not t.done()
        ]

        return tasks

    async def _speculative_evaluate(
        self,
        observation: Dict[str, Any],
        key: str,
    ) -> None:
        """Führt eine spekulative Evaluation durch."""
        try:
            if self.evaluator is not None:
                result = self.evaluator(observation)
                if asyncio.iscoroutine(result):
                    result = await result
                self._speculated_results[key] = result
            else:
                # Standard-Ergebnis
                self._speculated_results[key] = {
                    "speculated": True,
                    "check_type": observation.get("check_type"),
                    "timestamp": time.time(),
                }
        except Exception:
            self.failed_speculations += 1

    def get_speculated_result(
        self,
        observation: Dict[str, Any],
    ) -> Optional[Any]:
        """Gibt ein spekuliertes Ergebnis zurück falls vorhanden."""
        key = self._make_prediction_key(observation)

        if key in self._speculated_results:
            result = self._speculated_results.pop(key)
            self.successful_speculations += 1
            return result

        return None

    def _make_prediction_key(self, observation: Dict[str, Any]) -> str:
        """Generiert einen Schlüssel für eine Vorhersage."""
        endpoint = observation.get("endpoint", "")
        method = observation.get("method", "GET").upper()
        check_type = observation.get("check_type", "")

        key_data = f"{method}:{endpoint}:{check_type}"
        return hashlib.md5(key_data.encode()).hexdigest()

    def record_actual_next(
        self,
        previous_check: str,
        actual_next_check: str,
    ) -> None:
        """Zeichnet auf welcher Check tatsächlich auf welchen folgte.

        Verbessert die Vorhersagegenauigkeit über Zeit.
        """
        self._prediction_history.append((previous_check, actual_next_check))

    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_speculations": self.total_speculations,
            "successful": self.successful_speculations,
            "failed": self.failed_speculations,
            "accuracy": round(
                self.successful_speculations / self.total_speculations
                if self.total_speculations > 0 else 0, 3
            ),
            "pending_results": len(self._speculated_results),
            "active_tasks": len([
                t for t in self._speculation_tasks if not t.done()
            ]),
        }


# ---------------------------------------------------------------------------
# Predictive Prefetcher
# ---------------------------------------------------------------------------

class PredictivePrefetcher:
    """Lädt Ressourcen vor die wahrscheinlich als nächstes gebraucht werden.

    Statt zu warten bis eine Ressource angefragt wird:
    → Beobachte was gerade verarbeitet wird
    → Sage voraus was als nächstes gebraucht wird
    → Lade es BEREITS (im Hintergrund)
    → Wenn es dann gebraucht wird: Sofort verfügbar
    """

    def __init__(self, max_prefetched: int = 50):
        self.max_prefetched = max_prefetched

        # Prefetch-Queue
        self._prefetch_queue: asyncio.Queue = asyncio.Queue(maxsize=100)

        # Prefetched Ressourcen
        self._prefetched: Dict[str, Any] = {}

        # Statistiken
        self.total_prefetches = 0
        self.successful_prefetches = 0

    async def request_prefetch(
        self,
        resource_type: str,
        resource_id: str,
        loader: Callable,
    ) -> None:
        """Fordert das Vorladen einer Ressource an (non-blocking)."""
        try:
            await self._prefetch_queue.put_nowait({
                "type": resource_type,
                "id": resource_id,
                "loader": loader,
            })
        except asyncio.QueueFull:
            pass  # Queue voll — nicht kritisch

    async def get_prefetched(
        self,
        resource_type: str,
        resource_id: str,
    ) -> Optional[Any]:
        """Gibt eine vorgeladene Ressource zurück."""
        key = f"{resource_type}:{resource_id}"
        return self._prefetched.pop(key, None)

    async def run_prefetch_loop(self) -> None:
        """Hintergrund-Loop der Prefetch-Anfragen verarbeitet."""
        while True:
            try:
                request = await asyncio.wait_for(
                    self._prefetch_queue.get(), timeout=1.0
                )

                resource_type = request["type"]
                resource_id = request["id"]
                loader = request["loader"]

                key = f"{resource_type}:{resource_id}"

                try:
                    result = loader()
                    if asyncio.iscoroutine(result):
                        result = await result

                    self._prefetched[key] = result
                    self.successful_prefetches += 1

                    # Älteste Prefetches entfernen
                    if len(self._prefetched) > self.max_prefetched:
                        oldest_key = next(iter(self._prefetched))
                        del self._prefetched[oldest_key]

                except Exception:
                    pass

                self._prefetch_queue.task_done()

            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break


# ---------------------------------------------------------------------------
# Haupt-Klasse: Sub-Second Cognition
# ---------------------------------------------------------------------------

class SubSecondCognition:
    """Kombiniert Cache + Speculation + Prefetching für <10ms Entscheidungen.

    Usage:
        cognition = SubSecondCognition(evaluator=my_evaluator)

        # Beobachtung verarbeiten
        result = await cognition.make_decision(observation)

        # Ergebnis enthält:
        # result["decision"] → Die tatsächliche Entscheidung
        # result["decision_time_ms"] → Wie lange es gedauert hat
        # result["cache_hit"] → Kam es aus dem Cache?
        # result["speculated"] → War es spekulativ vorbereitet?
    """

    def __init__(
        self,
        evaluator: Optional[Callable] = None,
        cache_size: int = 5000,
        max_speculations: int = 5,
    ):
        self.cache = CognitiveCache(max_size=cache_size)
        self.speculator = SpeculativeExecutor(
            evaluator=evaluator,
            max_speculations=max_speculations,
        )
        self.prefetcher = PredictivePrefetcher()

        # Statistiken
        self.total_decisions = 0
        self.cache_hit_decisions = 0
        self.speculation_hit_decisions = 0
        self.computed_decisions = 0
        self.total_decision_time_ms = 0.0

    async def make_decision(
        self,
        observation: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Trifft eine kognitive Entscheidung in <10ms (wenn möglich).

        Decision-Flow:
          1. Cache prüfen (5ms) → Hit: sofort zurück
          2. Speculation prüfen (2ms) → Hit: vorbereitetes Ergebnis
          3. Berechnen (~100ms) → Cache + Speculation starten
        """
        start_time = time.perf_counter()
        self.total_decisions += 1

        # Ebene 1: Cache
        cached = self.cache.get(observation)
        if cached is not None:
            value, time_saved = cached
            elapsed = (time.perf_counter() - start_time) * 1000
            self.cache_hit_decisions += 1
            self.total_decision_time_ms += elapsed

            return {
                "decision": value,
                "decision_time_ms": round(elapsed, 3),
                "cache_hit": True,
                "speculated": False,
                "time_saved_ms": time_saved,
            }

        # Ebene 2: Speculation
        speculated = self.speculator.get_speculated_result(observation)
        if speculated is not None:
            elapsed = (time.perf_counter() - start_time) * 1000
            self.speculation_hit_decisions += 1
            self.total_decision_time_ms += elapsed

            # Auch im Cache speichern für zukünftige Zugriffe
            self.cache.put(observation, speculated)

            return {
                "decision": speculated,
                "decision_time_ms": round(elapsed, 3),
                "cache_hit": False,
                "speculated": True,
                "time_saved_ms": 50.0,  # Geschätzte Ersparnis
            }

        # Ebene 3: Tatsächlich berechnen
        self.computed_decisions += 1

        # Spekulative Vorbereitung für NÄCHSTE Beobachtung starten
        # (non-blocking — läuft im Hintergrund während wir berechnen)
        speculation_task = asyncio.create_task(
            self.speculator.speculate(observation)
        )

        # Berechnung durchführen
        if self.speculator.evaluator is not None:
            result = self.speculator.evaluator(observation)
            if asyncio.iscoroutine(result):
                result = await result
        else:
            result = self._default_decision(observation)

        # Ergebnis im Cache speichern
        severity = observation.get("severity", "none")
        self.cache.put(observation, result, severity=severity)

        elapsed = (time.perf_counter() - start_time) * 1000
        self.total_decision_time_ms += elapsed

        return {
            "decision": result,
            "decision_time_ms": round(elapsed, 3),
            "cache_hit": False,
            "speculated": False,
        }

    def _default_decision(self, observation: Dict[str, Any]) -> Dict[str, Any]:
        """Standard-Entscheidung wenn kein Evaluator gesetzt wurde."""
        status_code = observation.get("status_code", 0)
        check_type = observation.get("check_type", "")

        if status_code >= 500:
            severity = "high"
            action = "investigate_error"
        elif status_code == 200 and observation.get("severity") in ("high", "critical"):
            severity = "critical"
            action = "verify_unexpected_success"
        else:
            severity = "none"
            action = "standard_processing"

        return {
            "action": action,
            "check_type": check_type,
            "severity": severity,
            "confidence": 0.6,
            "timestamp": time.time(),
        }

    def get_stats(self) -> Dict[str, Any]:
        avg_time = (
            self.total_decision_time_ms / self.total_decisions
            if self.total_decisions > 0 else 0
        )

        return {
            "total_decisions": self.total_decisions,
            "cache_hits": self.cache_hit_decisions,
            "cache_hit_rate": round(
                self.cache_hit_decisions / self.total_decisions
                if self.total_decisions > 0 else 0, 3
            ),
            "speculation_hits": self.speculation_hit_decisions,
            "speculation_hit_rate": round(
                self.speculation_hit_decisions / self.total_decisions
                if self.total_decisions > 0 else 0, 3
            ),
            "computed": self.computed_decisions,
            "avg_decision_time_ms": round(avg_time, 3),
            "cache_stats": self.cache.get_stats(),
            "speculator_stats": self.speculator.get_stats(),
        }


if __name__ == "__main__":
    # Echter Performance-Test
    async def main():
        print("=" * 70)
        print("SUB-SECOND COGNITION — STANDALONE PERFORMANCE TEST")
        print("=" * 70)

        cognition = SubSecondCognition(
            evaluator=None,  # Standard-Evaluator
            cache_size=1000,
            max_speculations=5,
        )

        # Test 1: Erste Verarbeitung (Cache-Miss → Berechnung)
        print("\n1. First processing (should compute, ~100ms):")
        obs1 = {
            "endpoint": "/api/users/123",
            "method": "GET",
            "status_code": 200,
            "check_type": "resource_ownership_consistency",
            "severity": "none",
        }

        result1 = await cognition.make_decision(obs1)
        print(f"   Decision time: {result1['decision_time_ms']:.2f}ms")
        print(f"   Cache hit: {result1['cache_hit']}")
        print(f"   Speculated: {result1['speculated']}")
        print(f"   Decision: {result1['decision']}")

        # Test 2: Gleiche Beobachtung (Cache-Hit → <5ms)
        print("\n2. Same observation (should be cache hit, <5ms):")
        result2 = await cognition.make_decision(obs1)
        print(f"   Decision time: {result2['decision_time_ms']:.2f}ms")
        print(f"   Cache hit: {result2['cache_hit']}")
        print(f"   Time saved: {result2.get('time_saved_ms', 0):.1f}ms")

        # Test 3: Ähnliche Beobachtung (gleiche Endpunkt-Pattern → Cache-Hit)
        print("\n3. Similar observation (same pattern, different ID):")
        obs3 = {
            "endpoint": "/api/users/456",  # Andere ID, gleiches Pattern
            "method": "GET",
            "status_code": 200,
            "check_type": "resource_ownership_consistency",
            "severity": "none",
        }

        result3 = await cognition.make_decision(obs3)
        print(f"   Decision time: {result3['decision_time_ms']:.2f}ms")
        print(f"   Cache hit: {result3['cache_hit']}")

        # Test 4: Batch von 100 Beobachtungen (Performance-Test)
        print("\n4. Batch of 100 observations (performance test):")

        observations = []
        for i in range(100):
            observations.append({
                "endpoint": f"/api/resource/{i % 10}",  # 10 verschiedene Endpunkte
                "method": "GET",
                "status_code": 200 if i % 3 != 0 else 500,
                "check_type": "test_check",
                "severity": "high" if i % 5 == 0 else "none",
            })

        start = time.perf_counter()
        results = []
        for obs in observations:
            r = await cognition.make_decision(obs)
            results.append(r)
        batch_time = (time.perf_counter() - start) * 1000

        cache_hits = sum(1 for r in results if r["cache_hit"])
        speculated = sum(1 for r in results if r["speculated"])
        computed = sum(1 for r in results if not r["cache_hit"] and not r["speculated"])

        print(f"   Total time for 100 decisions: {batch_time:.1f}ms")
        print(f"   Avg per decision: {batch_time / 100:.2f}ms")
        print(f"   Cache hits: {cache_hits}/100")
        print(f"   Speculation hits: {speculated}/100")
        print(f"   Computed: {computed}/100")

        # Test 5: Nochmal 100 (sollte fast alle Cache-Hits sein)
        print("\n5. Same 100 again (should be mostly cache hits):")
        start = time.perf_counter()
        results2 = []
        for obs in observations:
            r = await cognition.make_decision(obs)
            results2.append(r)
        batch_time2 = (time.perf_counter() - start) * 1000

        cache_hits2 = sum(1 for r in results2 if r["cache_hit"])

        print(f"   Total time: {batch_time2:.1f}ms")
        print(f"   Avg per decision: {batch_time2 / 100:.2f}ms")
        print(f"   Cache hits: {cache_hits2}/100")
        print(f"   Speedup: {batch_time / batch_time2:.1f}x" if batch_time2 > 0 else "")

        # Statistiken
        print("\n6. Statistics:")
        stats = cognition.get_stats()
        print(f"   Total decisions: {stats['total_decisions']}")
        print(f"   Cache hit rate: {stats['cache_hit_rate']:.1%}")
        print(f"   Speculation hit rate: {stats['speculation_hit_rate']:.1%}")
        print(f"   Avg decision time: {stats['avg_decision_time_ms']:.3f}ms")
        print(f"   Cache: {stats['cache_stats']}")

        print("\n✅ Sub-Second Cognition test completed")

    asyncio.run(main())
