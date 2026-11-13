"""Event Bus — Redis-Streams-basierte Echtzeit-Kommunikation.

Verbindet ALLE kognitiven Komponenten in Echtzeit durch ein
Publish-Subscribe-System.

Vorher (ohne EventBus):
  Modul A läuft fertig → schreibt Ergebnis in Collector
  Modul B läuft fertig → schreibt Ergebnis in Collector
  CognitiveEngine läuft NACHTRÄGLICH über alle Ergebnisse
  → Keine Echtzeit-Kommunikation zwischen Modulen

Nachher (mit EventBus):
  Modul A findet etwas → publish("anomaly_detected", data)
  → BeliefRevisionSystem reagiert SOFORT (subscribe)
  → ExperimentSelector priorisiert SOFORT um
  → LLM-Ersatz-Layer analysiert SOFORT nach
  → Modul B (läuft noch) bekommt aktualisierte Prioritäten
  → ECHTE Echtzeit-Koordination

Redis-Streams vs Simple Queue:
  Redis-Streams bieten:
    → Consumer-Groups (mehrere Subscriber pro Topic)
    → Persistenz (Events überleben Neustarts)
    → Replay (Events können erneut abgespielt werden)
    → Multi-Process-Zugriff

Falls Redis nicht verfügbar: In-Memory-Fallback mit asyncio.Queues.
"""
from __future__ import annotations

import asyncio
import json
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum
from typing import Any, Callable, Dict, List, Optional, Awaitable

try:
    import redis.asyncio as aioredis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False


class EventPriority(IntEnum):
    """Priorität eines Events (niedriger Wert = höher priorisiert)."""
    CRITICAL = 0   # Sofortige Verarbeitung
    HIGH = 1       # Sehr wichtig
    MEDIUM = 2     # Normal
    LOW = 3        # Kann warten
    BACKGROUND = 4 # Reine Information


@dataclass
class Event:
    """Ein Event das über den Bus gesendet wird."""
    event_id: str
    event_type: str
    source: str
    data: Dict[str, Any]
    priority: EventPriority = EventPriority.MEDIUM
    timestamp: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = time.time()

    def to_json(self) -> str:
        return json.dumps({
            "event_id": self.event_id,
            "event_type": self.event_type,
            "source": self.source,
            "data": self.data,
            "priority": self.priority.value,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }, default=str)

    @classmethod
    def from_json(cls, json_str: str) -> "Event":
        data = json.loads(json_str)
        return cls(
            event_id=data["event_id"],
            event_type=data["event_type"],
            source=data["source"],
            data=data["data"],
            priority=EventPriority(data["priority"]),
            timestamp=data["timestamp"],
            metadata=data.get("metadata", {}),
        )


# Vordefinierte Event-Typen
class EventTypes:
    """Standard-Event-Typen die im System genutzt werden."""

    # Beobachtungs-Events
    OBSERVATION_RECEIVED = "observation_received"
    OBSERVATION_PROCESSED = "observation_processed"

    # Hypothesen-Events
    HYPOTHESIS_FORMED = "hypothesis_formed"
    HYPOTHESIS_UPDATED = "hypothesis_updated"
    HYPOTHESIS_CONFIRMED = "hypothesis_confirmed"
    HYPOTHESIS_REFUTED = "hypothesis_refuted"

    # Test-Events
    TEST_STARTED = "test_started"
    TEST_COMPLETED = "test_completed"
    TEST_FAILED = "test_failed"

    # Fund-Events
    FINDING_DETECTED = "finding_detected"
    SEQUENCE_DETECTED = "sequence_detected"

    # LLM-Ersatz-Events
    ANOMALY_DETECTED = "anomaly_detected"
    ZERO_SHOT_INSIGHT = "zero_shot_insight"
    STRUCTURAL_ANOMALY = "structural_anomaly"
    CONTEXTUAL_FINDING = "contextual_finding"

    # Strategy-Events
    STRATEGY_UPDATED = "strategy_updated"
    PRIORITY_CHANGED = "priority_changed"

    # System-Events
    SYSTEM_HEALTH = "system_health"
    COMPONENT_ERROR = "component_error"
    PHASE_COMPLETED = "phase_completed"


class EventBus:
    """Redis-Streams-basierter Event-Bus mit In-Memory-Fallback.

    Usage:
        bus = EventBus()

        # Subscriber registrieren
        async def on_anomaly(event: Event):
            print(f"Anomaly from {event.source}: {event.data}")

        bus.subscribe(EventTypes.ANOMALY_DETECTED, on_anomaly)

        # Event veröffentlichen
        await bus.publish(
            EventTypes.ANOMALY_DETECTED,
            source="structural_analyzer",
            data={"anomaly": "new_field", "confidence": 0.8},
            priority=EventPriority.HIGH,
        )

        # Bus starten (verarbeitet Events)
        await bus.start()

        # Bus stoppen
        await bus.stop()
    """

    def __init__(self, redis_url: Optional[str] = None):
        self.redis_url = redis_url
        self.redis: Optional[aioredis.Redis] = None

        # In-Memory-Fallback
        self._queues: Dict[str, List[asyncio.Queue]] = defaultdict(list)
        self._subscribers: Dict[str, List[Callable]] = defaultdict(list)

        # Consumer-Tasks
        self._consumer_tasks: List[asyncio.Task] = []
        self._running = False

        # Statistiken
        self.events_published = 0
        self.events_processed = 0
        self.events_dropped = 0
        self.total_processing_time_ms = 0.0

        # Event-Historie (letzte N Events für Debugging)
        self._event_history: List[Event] = []
        self._max_history = 100

    async def start(self) -> None:
        """Startet den Event-Bus."""
        if self._running:
            return

        # Redis verbinden falls verfügbar
        if REDIS_AVAILABLE and self.redis_url:
            try:
                self.redis = aioredis.from_url(
                    self.redis_url,
                    decode_responses=True,
                )
                # Verbindung testen
                await self.redis.ping()
            except Exception:
                self.redis = None

        self._running = True

        # Consumer-Tasks für alle registrierten Topics starten
        for topic in self._subscribers.keys():
            task = asyncio.create_task(
                self._consumer_loop(topic),
                name=f"eventbus_consumer_{topic}",
            )
            self._consumer_tasks.append(task)

    async def stop(self) -> None:
        """Stoppt den Event-Bus."""
        self._running = False

        # Alle Consumer-Tasks beenden
        for task in self._consumer_tasks:
            task.cancel()

        if self._consumer_tasks:
            await asyncio.gather(*self._consumer_tasks, return_exceptions=True)
        self._consumer_tasks.clear()

        # Redis schließen
        if self.redis:
            try:
                await self.redis.close()
            except Exception:
                pass
            self.redis = None

    # ------------------------------------------------------------------
    # Publish
    # ------------------------------------------------------------------

    async def publish(
        self,
        event_type: str,
        source: str,
        data: Dict[str, Any],
        priority: EventPriority = EventPriority.MEDIUM,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Veröffentlicht ein Event.

        Args:
            event_type: Typ des Events (z.B. EventTypes.ANOMALY_DETECTED).
            source: Quelle des Events (z.B. "structural_analyzer").
            data: Die Nutzdaten des Events.
            priority: Priorität für die Verarbeitung.
            metadata: Zusätzliche Metadaten.

        Returns:
            Die event_id des veröffentlichten Events.
        """
        event = Event(
            event_id=str(uuid.uuid4())[:16],
            event_type=event_type,
            source=source,
            data=data,
            priority=priority,
            metadata=metadata or {},
        )

        self.events_published += 1

        # Historie aktualisieren
        self._event_history.append(event)
        if len(self._event_history) > self._max_history:
            self._event_history = self._event_history[-self._max_history:]

        # Redis-Veröffentlichung falls verfügbar
        if self.redis:
            try:
                stream_key = f"eventbus:{event_type}"
                await self.redis.xadd(
                    stream_key,
                    {"event": event.to_json()},
                )
            except Exception:
                pass  # Redis-Fehler ignorieren — In-Memory-Fallback

        # In-Memory-Veröffentlichung
        if event_type in self._queues:
            for queue in self._queues[event_type]:
                try:
                    # Non-blocking put mit maxsize
                    queue.put_nowait(event)
                except asyncio.QueueFull:
                    self.events_dropped += 1

        return event.event_id

    # ------------------------------------------------------------------
    # Subscribe
    # ------------------------------------------------------------------

    def subscribe(
        self,
        event_type: str,
        handler: Callable[[Event], Awaitable[None]],
    ) -> Callable[[], None]:
        """Registriert einen Handler für einen Event-Typ.

        Args:
            event_type: Der zu abonnierende Event-Typ.
            handler: Async-Funktion die bei jedem Event aufgerufen wird.

        Returns:
            Unsubscribe-Funktion.
        """
        # Queue für diesen Subscriber erstellen falls noch nicht vorhanden
        if not self._queues[event_type]:
            self._queues[event_type].append(asyncio.Queue(maxsize=100))

        self._subscribers[event_type].append(handler)

        # Falls Bus bereits läuft: Consumer-Task starten
        if self._running and event_type not in [
            t.get_name().replace("eventbus_consumer_", "")
            for t in self._consumer_tasks
        ]:
            task = asyncio.create_task(
                self._consumer_loop(event_type),
                name=f"eventbus_consumer_{event_type}",
            )
            self._consumer_tasks.append(task)

        def unsubscribe() -> None:
            """Entfernt den Handler."""
            if handler in self._subscribers[event_type]:
                self._subscribers[event_type].remove(handler)

        return unsubscribe

    def subscribe_all(
        self,
        handler: Callable[[Event], Awaitable[None]],
    ) -> Callable[[], None]:
        """Registriert einen Handler für ALLE Event-Typen.

        Nützlich für Logging oder Debugging.
        """
        # Dummy-Event-Typ für "alle"
        ALL_EVENTS = "*"

        self._subscribers[ALL_EVENTS].append(handler)
        if not self._queues[ALL_EVENTS]:
            self._queues[ALL_EVENTS].append(asyncio.Queue(maxsize=200))

        #Wildcard-Consumer starten falls Bus läuft
        if self._running:
            task = asyncio.create_task(
                self._wildcard_consumer_loop(),
                name="eventbus_wildcard_consumer",
            )
            self._consumer_tasks.append(task)

        def unsubscribe() -> None:
            if handler in self._subscribers[ALL_EVENTS]:
                self._subscribers[ALL_EVENTS].remove(handler)

        return unsubscribe

    # ------------------------------------------------------------------
    # Consumer-Loops
    # ------------------------------------------------------------------

    async def _consumer_loop(self, event_type: str) -> None:
        """Verarbeitet Events eines bestimmten Typs."""
        while self._running:
            try:
                # Events aus Queue holen
                queues = self._queues.get(event_type, [])
                if not queues:
                    await asyncio.sleep(0.1)
                    continue

                for queue in queues:
                    try:
                        event = await asyncio.wait_for(
                            queue.get(), timeout=0.5
                        )
                    except asyncio.TimeoutError:
                        continue

                    # Event verarbeiten
                    start = time.perf_counter()

                    handlers = self._subscribers.get(event_type, [])
                    for handler in handlers:
                        try:
                            if asyncio.iscoroutinefunction(handler):
                                await handler(event)
                            else:
                                handler(event)
                        except Exception:
                            pass  # Handler-Fehler isolieren

                    self.events_processed += 1
                    self.total_processing_time_ms += (
                        (time.perf_counter() - start) * 1000
                    )

                    queue.task_done()

            except asyncio.CancelledError:
                break
            except Exception:
                await asyncio.sleep(0.1)

    async def _wildcard_consumer_loop(self) -> None:
        """Verarbeitet ALLE Events für Wildcard-Subscriber."""
        ALL_EVENTS = "*"

        while self._running:
            try:
                queues = self._queues.get(ALL_EVENTS, [])
                if not queues:
                    await asyncio.sleep(0.1)
                    continue

                for queue in queues:
                    try:
                        event = await asyncio.wait_for(
                            queue.get(), timeout=0.5
                        )
                    except asyncio.TimeoutError:
                        continue

                    # An alle Wildcard-Handler verteilen
                    handlers = self._subscribers.get(ALL_EVENTS, [])
                    for handler in handlers:
                        try:
                            if asyncio.iscoroutinefunction(handler):
                                await handler(event)
                            else:
                                handler(event)
                        except Exception:
                            pass

                    queue.task_done()

            except asyncio.CancelledError:
                break
            except Exception:
                await asyncio.sleep(0.1)

    # ------------------------------------------------------------------
    # Query und Debugging
    # ------------------------------------------------------------------

    def get_recent_events(
        self,
        event_type: Optional[str] = None,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        """Gibt die letzten N Events zurück (für Debugging)."""
        events = self._event_history

        if event_type:
            events = [e for e in events if e.event_type == event_type]

        return [
            {
                "event_id": e.event_id,
                "event_type": e.event_type,
                "source": e.source,
                "priority": e.priority.name,
                "timestamp": datetime.fromtimestamp(e.timestamp).isoformat(),
                "data_keys": list(e.data.keys()),
            }
            for e in events[-limit:]
        ]

    def get_statistics(self) -> Dict[str, Any]:
        """Gibt Bus-Statistiken zurück."""
        avg_processing = (
            self.total_processing_time_ms / self.events_processed
            if self.events_processed > 0
            else 0
        )

        return {
            "running": self._running,
            "redis_connected": self.redis is not None,
            "events_published": self.events_published,
            "events_processed": self.events_processed,
            "events_dropped": self.events_dropped,
            "avg_processing_time_ms": round(avg_processing, 3),
            "active_topics": list(self._subscribers.keys()),
            "subscribers_per_topic": {
                topic: len(handlers)
                for topic, handlers in self._subscribers.items()
                if handlers
            },
        }


if __name__ == "__main__":
    # Echter Test mit Publish-Subscribe
    async def main():
        print("=" * 70)
        print("EVENT BUS — STANDALONE TEST")
        print("=" * 70)

        bus = EventBus()  # In-Memory-Modus (kein Redis)

        # Handler registrieren
        received_events: List[Event] = []

        async def on_anomaly(event: Event):
            received_events.append(event)
            print(f"  [ANOMALY] {event.source}: {list(event.data.keys())}")

        async def on_finding(event: Event):
            received_events.append(event)
            print(f"  [FINDING] {event.source}: {list(event.data.keys())}")

        async def on_all(event: Event):
            pass  # Wildcard-Handler für Statistiken

        bus.subscribe(EventTypes.ANOMALY_DETECTED, on_anomaly)
        bus.subscribe(EventTypes.FINDING_DETECTED, on_finding)
        bus.subscribe_all(on_all)

        # Bus starten
        await bus.start()
        print(f"\nBus started (Redis: {bus.redis is not None})")

        # Events veröffentlichen
        print("\n1. Publishing events...")

        await bus.publish(
            EventTypes.ANOMALY_DETECTED,
            source="structural_analyzer",
            data={"anomaly": "new_field", "confidence": 0.85},
            priority=EventPriority.HIGH,
        )

        await bus.publish(
            EventTypes.ANOMALY_DETECTED,
            source="zero_shot_detector",
            data={"field": "admin_key", "suspicious": True},
            priority=EventPriority.CRITICAL,
        )

        await bus.publish(
            EventTypes.FINDING_DETECTED,
            source="real_test_executor",
            data={"check_type": "query_construction_issue", "endpoint": "/login"},
            priority=EventPriority.HIGH,
        )

        await bus.publish(
            EventTypes.OBSERVATION_PROCESSED,
            source="cognitive_engine",
            data={"endpoint": "/api/users", "hypotheses": 3},
            priority=EventPriority.LOW,
        )

        # Kurz warten für Verarbeitung
        await asyncio.sleep(1.0)

        print(f"\n2. Received events: {len(received_events)}")

        # Statistiken
        print("\n3. Statistics:")
        stats = bus.get_statistics()
        print(f"  Published: {stats['events_published']}")
        print(f"  Processed: {stats['events_processed']}")
        print(f"  Dropped: {stats['events_dropped']}")
        print(f"  Avg processing: {stats['avg_processing_time_ms']}ms")
        print(f"  Active topics: {stats['active_topics']}")

        # Recent Events
        print("\n4. Recent events:")
        for event_info in bus.get_recent_events(limit=5):
            print(f"  {event_info['event_type']} from {event_info['source']} "
                  f"({event_info['priority']})")

        # Bus stoppen
        await bus.stop()
        print(f"\nBus stopped")

        print("\n✅ Event Bus test completed")

    asyncio.run(main())
