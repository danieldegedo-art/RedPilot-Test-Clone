"""Global Workspace / Blackboard Architecture.

Coordinates all cognitive components through a shared knowledge
workspace. Implements the "consciousness" layer that decides what
deserves attention and facilitates communication between specialized
reasoning modules.

Architecture based on Global Workspace Theory (Baars, 1988):
- Multiple specialized modules run in parallel
- A central workspace broadcasts important findings
- Attention mechanisms filter what enters the workspace
- Coalition formation decides which findings are most relevant
- Broadcast cycles coordinate all modules

Implementation inspired by:
- LIDA (Learning Intelligent Distribution Agent) — Franklin et al.
- SOAR (State, Operator, And Result) — Laird et al.
- Blackboard Systems — Hayes-Roth et al.
"""
from __future__ import annotations

import asyncio
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Awaitable
from uuid import uuid4


class AttentionPriority(Enum):
    """Priority levels for workspace entries."""
    CRITICAL = 5    # Immediate action required (reflex-level)
    HIGH = 4        # Important finding that changes strategy
    MEDIUM = 3      # Noteworthy observation
    LOW = 2         # Background information
    MINIMAL = 1     # Archival data only


@dataclass
class WorkspaceEntry:
    """A single piece of information in the shared workspace."""
    id: str = field(default_factory=lambda: str(uuid4()))
    entry_type: str = ""  # "observation", "hypothesis", "plan", "finding", "question"
    content: Any = None
    priority: AttentionPriority = AttentionPriority.MEDIUM
    source: str = ""  # Which component created this entry
    timestamp: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)
    references: list[str] = field(default_factory=list)  # IDs of related entries
    confidence: float = 0.5  # 0.0 to 1.0


@dataclass
class Coalition:
    """A group of workspace entries that together form a coherent
    pattern worth broadcasting to all modules."""
    id: str = field(default_factory=lambda: str(uuid4()))
    entries: list[WorkspaceEntry] = field(default_factory=list)
    strength: float = 0.0  # Combined salience score
    topic: str = ""  # What this coalition is about
    created_at: float = field(default_factory=time.time)


class BlackboardWorkspace:
    """Central shared workspace for all cognitive components.

    Implements the Global Workspace Theory coordination model:
    1. Components post entries to the workspace
    2. Attention mechanisms identify the most salient entries
    3. Coalitions form around important patterns
    4. Winning coalitions are broadcast to all components
    5. Components respond to broadcasts with new entries
    """

    def __init__(self, max_entries: int = 10000, broadcast_interval: float = 0.1):
        self._entries: dict[str, WorkspaceEntry] = {}
        self._entries_by_type: dict[str, list[str]] = defaultdict(list)
        self._entries_by_source: dict[str, list[str]] = defaultdict(list)

        self._max_entries = max_entries
        self._broadcast_interval = broadcast_interval

        self._subscribers: dict[str, list[Callable[[Coalition], Awaitable[None]]]] = defaultdict(list)

        self._attention_history: deque = deque(maxlen=1000)
        self._broadcast_history: deque = deque(maxlen=100)

        self._active_coalitions: list[Coalition] = []
        self._last_broadcast_time = 0.0
        self._broadcast_count = 0

        self._lock = asyncio.Lock()

    async def post(
        self,
        entry_type: str,
        content: Any,
        source: str,
        priority: AttentionPriority = AttentionPriority.MEDIUM,
        confidence: float = 0.5,
        metadata: dict[str, Any] | None = None,
        references: list[str] | None = None,
    ) -> WorkspaceEntry:
        """Posts a new entry to the workspace."""
        entry = WorkspaceEntry(
            entry_type=entry_type,
            content=content,
            source=source,
            priority=priority,
            confidence=confidence,
            metadata=metadata or {},
            references=references or [],
        )

        async with self._lock:
            self._entries[entry.id] = entry
            self._entries_by_type[entry_type].append(entry.id)
            self._entries_by_source[source].append(entry.id)

            # Evict oldest entries if we're over capacity
            if len(self._entries) > self._max_entries:
                self._evict_oldest()

        return entry

    async def get(self, entry_id: str) -> WorkspaceEntry | None:
        """Retrieves a specific entry by ID."""
        return self._entries.get(entry_id)

    async def get_by_type(self, entry_type: str, limit: int = 50) -> list[WorkspaceEntry]:
        """Retrieves entries of a specific type, most recent first."""
        entry_ids = self._entries_by_type.get(entry_type, [])
        entries = [self._entries[eid] for eid in entry_ids[-limit:] if eid in self._entries]
        return sorted(entries, key=lambda e: e.timestamp, reverse=True)

    async def get_by_source(self, source: str, limit: int = 50) -> list[WorkspaceEntry]:
        """Retrieves entries from a specific source component."""
        entry_ids = self._entries_by_source.get(source, [])
        entries = [self._entries[eid] for eid in entry_ids[-limit:] if eid in self._entries]
        return sorted(entries, key=lambda e: e.timestamp, reverse=True)

    async def get_recent(self, seconds: float = 60.0) -> list[WorkspaceEntry]:
        """Retrieves all entries posted within the last N seconds."""
        cutoff = time.time() - seconds
        recent = [
            e for e in self._entries.values()
            if e.timestamp >= cutoff
        ]
        return sorted(recent, key=lambda e: e.timestamp, reverse=True)

    async def search(self, predicate: Callable[[WorkspaceEntry], bool]) -> list[WorkspaceEntry]:
        """Searches entries matching a predicate function."""
        return [e for e in self._entries.values() if predicate(e)]

    async def update_confidence(self, entry_id: str, new_confidence: float) -> None:
        """Updates the confidence score of an entry."""
        entry = self._entries.get(entry_id)
        if entry:
            entry.confidence = max(0.0, min(1.0, new_confidence))

    async def add_reference(self, entry_id: str, referenced_id: str) -> None:
        """Adds a reference from one entry to another."""
        entry = self._entries.get(entry_id)
        if entry and referenced_id not in entry.references:
            entry.references.append(referenced_id)

    def subscribe(
        self,
        topic: str,
        callback: Callable[[Coalition], Awaitable[None]],
    ) -> Callable[[], None]:
        """Subscribes a component to broadcasts on a specific topic.

        Returns an unsubscribe function.
        """
        self._subscribers[topic].append(callback)

        def unsubscribe() -> None:
            if callback in self._subscribers[topic]:
                self._subscribers[topic].remove(callback)

        return unsubscribe

    async def form_coalitions(self) -> list[Coalition]:
        """Identifies patterns among entries and forms coalitions.

        A coalition is a group of entries that together suggest something
        important — for example, multiple timing anomalies on the same
        endpoint might form a coalition suggesting a race condition.
        """
        recent_entries = await self.get_recent(seconds=30.0)

        if not recent_entries:
            return []

        # Group entries by potential patterns
        coalitions: list[Coalition] = []

        # Pattern 1: Multiple entries about the same endpoint/resource
        endpoint_groups: dict[str, list[WorkspaceEntry]] = defaultdict(list)
        for entry in recent_entries:
            endpoint = entry.metadata.get("endpoint", entry.metadata.get("path", ""))
            if endpoint:
                endpoint_groups[endpoint].append(entry)

        for endpoint, entries in endpoint_groups.items():
            if len(entries) >= 2:
                # Calculate coalition strength based on entry priorities and confidence
                strength = sum(
                    e.priority.value * e.confidence
                    for e in entries
                ) / len(entries)

                coalition = Coalition(
                    entries=entries,
                    strength=strength,
                    topic=f"endpoint:{endpoint}",
                )
                coalitions.append(coalition)

        # Pattern 2: Entries with the same hypothesis type
        hypothesis_groups: dict[str, list[WorkspaceEntry]] = defaultdict(list)
        for entry in recent_entries:
            if entry.entry_type == "hypothesis":
                hypothesis_key = str(entry.content)[:100]  # Group by content prefix
                hypothesis_groups[hypothesis_key].append(entry)

        for hypothesis_key, entries in hypothesis_groups.items():
            if len(entries) >= 2:
                strength = sum(e.confidence for e in entries) / len(entries)
                coalition = Coalition(
                    entries=entries,
                    strength=strength,
                    topic=f"hypothesis:{hypothesis_key[:50]}",
                )
                coalitions.append(coalition)

        # Pattern 3: Cross-type correlations (observation + hypothesis + question)
        type_groups: dict[str, list[WorkspaceEntry]] = defaultdict(list)
        for entry in recent_entries:
            type_groups[entry.entry_type].append(entry)

        if all(t in type_groups for t in ("observation", "hypothesis")):
            # There are both observations and hypotheses — see if they relate
            obs_entries = type_groups["observation"]
            hyp_entries = type_groups["hypothesis"]
            if len(obs_entries) >= 1 and len(hyp_entries) >= 1:
                # Simple heuristic: combine highest-priority observation with highest-confidence hypothesis
                top_obs = max(obs_entries, key=lambda e: e.priority.value)
                top_hyp = max(hyp_entries, key=lambda e: e.confidence)
                coalition = Coalition(
                    entries=[top_obs, top_hyp],
                    strength=(top_obs.priority.value * top_obs.confidence + top_hyp.confidence) / 2,
                    topic="cross_type_correlation",
                )
                coalitions.append(coalition)

        # Sort coalitions by strength (most important first)
        coalitions.sort(key=lambda c: c.strength, reverse=True)

        # Keep only the top N coalitions
        self._active_coalitions = coalitions[:10]

        return self._active_coalitions

    async def broadcast(self) -> Coalition | None:
        """Broadcasts the winning (strongest) coalition to all subscribers.

        Returns the broadcast coalition, or None if no coalition is
        strong enough to warrant broadcasting.
        """
        if not self._active_coalitions:
            await self.form_coalitions()

        if not self._active_coalitions:
            return None

        # Select the winning coalition (highest strength)
        winning_coalition = self._active_coalitions[0]

        # Broadcast to subscribers of this coalition's topic and "all"
        topics_to_notify = [winning_coalition.topic, "all"]

        for topic in topics_to_notify:
            subscribers = self._subscribers.get(topic, [])
            for callback in subscribers:
                try:
                    await callback(winning_coalition)
                except Exception:
                    pass  # Don't let one subscriber failure block others

        # Record broadcast
        self._broadcast_history.append({
            "coalition_id": winning_coalition.id,
            "topic": winning_coalition.topic,
            "strength": winning_coalition.strength,
            "entry_count": len(winning_coalition.entries),
            "timestamp": time.time(),
        })
        self._broadcast_count += 1
        self._last_broadcast_time = time.time()

        return winning_coalition

    async def run_attention_cycle(self) -> Coalition | None:
        """Runs one complete attention cycle: form coalitions, select winner, broadcast."""
        coalitions = await self.form_coalitions()

        if not coalitions:
            return None

        # Record attention state
        self._attention_history.append({
            "timestamp": time.time(),
            "coalition_count": len(coalitions),
            "top_topic": coalitions[0].topic if coalitions else None,
            "top_strength": coalitions[0].strength if coalitions else 0.0,
        })

        # Only broadcast if enough time has passed since the last broadcast
        if time.time() - self._last_broadcast_time < self._broadcast_interval:
            return None

        return await self.broadcast()

    def get_statistics(self) -> dict[str, Any]:
        """Returns statistics about the workspace."""
        return {
            "total_entries": len(self._entries),
            "entries_by_type": {
                entry_type: len(ids)
                for entry_type, ids in self._entries_by_type.items()
            },
            "entries_by_source": {
                source: len(ids)
                for source, ids in self._entries_by_source.items()
            },
            "active_coalitions": len(self._active_coalitions),
            "broadcast_count": self._broadcast_count,
            "subscriber_count": sum(len(subs) for subs in self._subscribers.values()),
            "last_broadcast_age": time.time() - self._last_broadcast_time if self._last_broadcast_time else None,
        }

    def _evict_oldest(self) -> None:
        """Evicts the oldest, lowest-priority entries when over capacity."""
        # Sort entries by (priority, timestamp) — evict lowest priority, oldest first
        sorted_entries = sorted(
            self._entries.values(),
            key=lambda e: (e.priority.value, e.timestamp),
        )

        # Evict the bottom 10%
        evict_count = max(1, len(sorted_entries) // 10)
        for entry in sorted_entries[:evict_count]:
            self._remove_entry(entry.id)

    def _remove_entry(self, entry_id: str) -> None:
        """Removes an entry from the workspace."""
        entry = self._entries.pop(entry_id, None)
        if entry:
            if entry.id in self._entries_by_type.get(entry.entry_type, []):
                self._entries_by_type[entry.entry_type].remove(entry.id)
            if entry.id in self._entries_by_source.get(entry.source, []):
                self._entries_by_source[entry.source].remove(entry.id)


class CognitiveCycle:
    """Orchestrates the 8-step cognitive cycle.

    The cognitive cycle is the fundamental processing loop:
    1. PERCEPTION: Gather new observations from test results
    2. ATTENTION: Determine what deserves focus
    3. UNDERSTANDING: Interpret what the observations mean
    4. HYPOTHESIS: Formulate explanations for patterns
    5. PLANNING: Decide what to do next
    6. ACTION: Execute the planned tests
    7. LEARNING: Extract lessons from outcomes
    8. UPDATE: Revise beliefs and strategies
    """

    def __init__(self, workspace: BlackboardWorkspace):
        self.workspace = workspace
        self._cycle_count = 0
        self._last_cycle_time = 0.0
        self._cycle_history: deque = deque(maxlen=100)

    async def run_cycle(self, new_observations: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        """Runs one complete cognitive cycle.

        Args:
            new_observations: Raw observations from test execution to process.

        Returns:
            Dictionary describing the cycle outcome.
        """
        cycle_start = time.time()
        self._cycle_count += 1

        # Step 1: PERCEPTION — Post new observations to workspace
        if new_observations:
            for obs in new_observations:
                priority = self._determine_priority(obs)
                await self.workspace.post(
                    entry_type="observation",
                    content=obs,
                    source="perception",
                    priority=priority,
                    confidence=obs.get("confidence", 0.5),
                    metadata=obs.get("metadata", {}),
                )

        # Step 2: ATTENTION — Form coalitions and identify what's important
        winning_coalition = await self.workspace.run_attention_cycle()

        # Steps 3-7 are handled by specialized components that respond
        # to broadcasts. Here we just orchestrate the cycle.

        # Step 8: UPDATE — Record cycle completion
        cycle_duration = time.time() - cycle_start
        cycle_result = {
            "cycle_number": self._cycle_count,
            "duration_ms": round(cycle_duration * 1000, 2),
            "observations_processed": len(new_observations) if new_observations else 0,
            "winning_coalition": {
                "topic": winning_coalition.topic,
                "strength": winning_coalition.strength,
                "entry_count": len(winning_coalition.entries),
            } if winning_coalition else None,
            "workspace_stats": self.workspace.get_statistics(),
        }

        self._cycle_history.append(cycle_result)
        self._last_cycle_time = time.time()

        return cycle_result

    def _determine_priority(self, observation: dict[str, Any]) -> AttentionPriority:
        """Determines the attention priority of an observation."""
        obs_type = observation.get("type", "")
        severity = observation.get("severity", "")

        if severity in ("critical", "fail"):
            return AttentionPriority.CRITICAL
        if severity in ("warning", "anomaly"):
            return AttentionPriority.HIGH
        if obs_type in ("state_change", "hypothesis_confirmed"):
            return AttentionPriority.HIGH
        if obs_type in ("timing_anomaly", "pattern_match"):
            return AttentionPriority.MEDIUM
        return AttentionPriority.LOW

    def get_statistics(self) -> dict[str, Any]:
        """Returns statistics about the cognitive cycle."""
        return {
            "total_cycles": self._cycle_count,
            "last_cycle_age": time.time() - self._last_cycle_time if self._last_cycle_time else None,
            "average_cycle_duration": (
                sum(c["duration_ms"] for c in self._cycle_history) / len(self._cycle_history)
                if self._cycle_history else 0.0
            ),
            "recent_cycles": list(self._cycle_history)[-5:],
        }
