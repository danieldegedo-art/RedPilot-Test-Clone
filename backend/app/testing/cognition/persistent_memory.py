"""Persistent Memory System — Cross-Session Knowledge Accumulation.

Implements long-term memory that survives across test sessions.
Unlike stateless test runners that forget everything between runs,
this system accumulates knowledge about:

- System architectures and their typical patterns
- Which verification strategies work and which don't
- Timing baselines for specific types of endpoints
- Common inconsistency patterns and their root causes
- Success rates of different approaches on different system types

Architecture inspired by:
- Episodic Memory: Specific test executions and their outcomes
- Semantic Memory: Generalized patterns and rules extracted from episodes
- Procedural Memory: How-to knowledge for effective verification
- Working Memory: Current session's active context

The system uses a layered storage approach:
- Layer 1 (Hot): In-memory cache for current session (fast access)
- Layer 2 (Warm): SQLite for recent sessions (fast disk access)
- Layer 3 (Cold): Aggregated patterns for long-term storage

Consolidation ("sleep") occurs between sessions:
- Recurring patterns are promoted from episodic to semantic memory
- Irrelevant details are pruned
- Confidence in patterns is updated based on accumulated evidence
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4


@dataclass
class EpisodicMemory:
    """A specific memory of a test execution or observation.

    Episodic memories are concrete: 'I observed X at time Y when testing Z.'
    They are the raw material from which semantic memories (patterns)
    are extracted.
    """
    id: str = field(default_factory=lambda: str(uuid4()))
    session_id: str = ""
    timestamp: float = field(default_factory=time.time)
    memory_type: str = ""  # "test_result", "observation", "pattern_match", "hypothesis_outcome"
    content: dict[str, Any] = field(default_factory=dict)
    context: dict[str, Any] = field(default_factory=dict)  # System type, endpoint, etc.
    outcome: str = ""  # "pass", "fail", "warning", "info", "error"
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "session_id": self.session_id,
            "timestamp": self.timestamp,
            "memory_type": self.memory_type,
            "content": self.content,
            "context": self.context,
            "outcome": self.outcome,
            "tags": self.tags,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EpisodicMemory:
        return cls(**data)


@dataclass
class SemanticMemory:
    """A generalized pattern extracted from multiple episodic memories.

    Semantic memories are abstract: 'Endpoints with X characteristic
    tend to have Y type of inconsistency.'
    They represent accumulated wisdom from many test sessions.
    """
    id: str = field(default_factory=lambda: str(uuid4()))
    pattern_type: str = ""  # "timing_pattern", "validation_pattern", "state_pattern"
    description: str = ""
    conditions: dict[str, Any] = field(default_factory=dict)  # When this applies
    expected_behavior: str = ""
    observed_behavior: str = ""
    confidence: float = 0.5  # How reliable this pattern is
    occurrence_count: int = 0  # How many times we've seen evidence for this
    success_rate: float = 0.0  # How often verification based on this pattern succeeds
    source_episodes: list[str] = field(default_factory=list)  # Episodic memory IDs
    created_at: float = field(default_factory=time.time)
    last_accessed_at: float = field(default_factory=time.time)
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "pattern_type": self.pattern_type,
            "description": self.description,
            "conditions": self.conditions,
            "expected_behavior": self.expected_behavior,
            "observed_behavior": self.observed_behavior,
            "confidence": self.confidence,
            "occurrence_count": self.occurrence_count,
            "success_rate": self.success_rate,
            "source_episodes": self.source_episodes,
            "created_at": self.created_at,
            "last_accessed_at": self.last_accessed_at,
            "tags": self.tags,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SemanticMemory:
        return cls(**data)


@dataclass
class ProceduralMemory:
    """Knowledge about how to effectively verify specific patterns.

    Procedural memories are practical: 'To test for race conditions
    on payment endpoints, use concurrent requests with 0.005s delay.'
    They encode the "how-to" knowledge that experienced testers accumulate.
    """
    id: str = field(default_factory=lambda: str(uuid4()))
    procedure_type: str = ""  # "race_condition_test", "state_validation", "format_test"
    description: str = ""
    steps: list[str] = field(default_factory=list)
    best_for: dict[str, Any] = field(default_factory=dict)  # What conditions this works for
    effectiveness: float = 0.5  # How well this procedure works
    times_used: int = 0
    times_successful: int = 0
    parameter_recommendations: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "procedure_type": self.procedure_type,
            "description": self.description,
            "steps": self.steps,
            "best_for": self.best_for,
            "effectiveness": self.effectiveness,
            "times_used": self.times_used,
            "times_successful": self.times_successful,
            "parameter_recommendations": self.parameter_recommendations,
            "created_at": self.created_at,
            "tags": self.tags,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProceduralMemory:
        return cls(**data)


class PersistentMemoryStore:
    """Manages all layers of persistent memory.

    This is the component that makes the system get smarter over time.
    Every test session adds new episodic memories, which are periodically
    consolidated into semantic patterns and procedural knowledge.
    """

    def __init__(self, storage_path: str | Path = "qa_memory"):
        # Guards self._conn: record_outcome()/learn_from_execution() in
        # CognitiveEngine offload store_episodic() via asyncio.to_thread so
        # a blocking SQLite commit never stalls the event loop, which means
        # this connection is genuinely touched from more than one thread
        # over its lifetime (main thread for reads like get_statistics(),
        # a worker thread for that offloaded write) -- check_same_thread
        # below only disables Python's same-thread assertion, it does not
        # make the connection safe for *simultaneous* access, so every
        # method that touches self._conn still serializes through this lock.
        self._lock = threading.RLock()

        self._storage_path = Path(storage_path)
        self._storage_path.mkdir(parents=True, exist_ok=True)

        self._db_path = self._storage_path / "memory.db"

        # Layer 1: Hot (in-memory) — current session
        self._current_session_id: str = str(uuid4())
        self._working_memory: list[EpisodicMemory] = []
        self._active_semantic: dict[str, SemanticMemory] = {}
        self._active_procedural: dict[str, ProceduralMemory] = {}

        # Layer 2 & 3: SQLite — persistent across sessions
        self._init_database()

        # Load relevant semantic and procedural memories into hot cache
        self._load_relevant_memories()

        # Statistics
        self._stats = {
            "episodic_stored": 0,
            "semantic_stored": 0,
            "procedural_stored": 0,
            "consolidations_performed": 0,
            "patterns_promoted": 0,
        }

    def _init_database(self) -> None:
        """Initializes the SQLite database for persistent storage."""
        self._conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row

        # WAL instead of the default rollback-journal mode: this store is
        # now genuinely read-while-write (get_statistics()/query_episodic()
        # from the main thread while record_outcome()'s asyncio.to_thread
        # write is in flight -- see this class's own __init__ comment on
        # exactly that access pattern). Under the default journal mode a
        # writer blocks every reader for the duration of its transaction;
        # under WAL, readers see the pre-write snapshot instead of
        # blocking. synchronous=NORMAL is the documented pairing for WAL
        # (full durability of the WAL file itself, without an fsync on
        # every single commit) -- safe here because a lost handful of the
        # most recent episodic writes after an OS crash is an acceptable
        # cost for a knowledge store that keeps accumulating either way,
        # which durability=FULL's extra fsync latency is not worth paying
        # on every one of potentially hundreds of writes per run.
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")

        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS episodic_memories (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                timestamp REAL NOT NULL,
                memory_type TEXT NOT NULL,
                content TEXT NOT NULL,
                context TEXT NOT NULL,
                outcome TEXT NOT NULL,
                tags TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS semantic_memories (
                id TEXT PRIMARY KEY,
                pattern_type TEXT NOT NULL,
                description TEXT NOT NULL,
                conditions TEXT NOT NULL,
                expected_behavior TEXT NOT NULL,
                observed_behavior TEXT NOT NULL,
                confidence REAL NOT NULL,
                occurrence_count INTEGER NOT NULL,
                success_rate REAL NOT NULL,
                source_episodes TEXT NOT NULL,
                created_at REAL NOT NULL,
                last_accessed_at REAL NOT NULL,
                tags TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS procedural_memories (
                id TEXT PRIMARY KEY,
                procedure_type TEXT NOT NULL,
                description TEXT NOT NULL,
                steps TEXT NOT NULL,
                best_for TEXT NOT NULL,
                effectiveness REAL NOT NULL,
                times_used INTEGER NOT NULL,
                times_successful INTEGER NOT NULL,
                parameter_recommendations TEXT NOT NULL,
                created_at REAL NOT NULL,
                tags TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS session_summaries (
                session_id TEXT PRIMARY KEY,
                started_at REAL NOT NULL,
                completed_at REAL,
                system_type TEXT,
                total_tests INTEGER DEFAULT 0,
                total_findings INTEGER DEFAULT 0,
                summary TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_episodic_session ON episodic_memories(session_id);
            CREATE INDEX IF NOT EXISTS idx_episodic_type ON episodic_memories(memory_type);
            -- Added: query_episodic()'s "ORDER BY timestamp DESC LIMIT ?"
            -- and get_statistics()'s age-bucketed counts both filter/sort
            -- on this column; without an index both do a full-table scan
            -- + sort. Harmless while cross-session accumulation was
            -- broken (every run started from an empty table -- see the
            -- Wissensspeicher fix this project already made), but that
            -- fix means this table now genuinely grows across every
            -- future run against a target, so this stops being free.
            CREATE INDEX IF NOT EXISTS idx_episodic_timestamp ON episodic_memories(timestamp);
            CREATE INDEX IF NOT EXISTS idx_semantic_type ON semantic_memories(pattern_type);
            CREATE INDEX IF NOT EXISTS idx_procedural_type ON procedural_memories(procedure_type);
        """)
        self._conn.commit()

    def _load_relevant_memories(self) -> None:
        """Loads the most relevant semantic and procedural memories into hot cache."""
        # Load high-confidence semantic memories
        rows = self._conn.execute(
            "SELECT * FROM semantic_memories WHERE confidence > 0.3 ORDER BY confidence DESC, occurrence_count DESC LIMIT 100"
        ).fetchall()

        for row in rows:
            memory = SemanticMemory(
                id=row["id"],
                pattern_type=row["pattern_type"],
                description=row["description"],
                conditions=json.loads(row["conditions"]),
                expected_behavior=row["expected_behavior"],
                observed_behavior=row["observed_behavior"],
                confidence=row["confidence"],
                occurrence_count=row["occurrence_count"],
                success_rate=row["success_rate"],
                source_episodes=json.loads(row["source_episodes"]),
                created_at=row["created_at"],
                last_accessed_at=row["last_accessed_at"],
                tags=json.loads(row["tags"]),
            )
            self._active_semantic[memory.id] = memory

        # Load effective procedural memories
        rows = self._conn.execute(
            "SELECT * FROM procedural_memories WHERE effectiveness > 0.3 ORDER BY effectiveness DESC, times_used DESC LIMIT 50"
        ).fetchall()

        for row in rows:
            memory = ProceduralMemory(
                id=row["id"],
                procedure_type=row["procedure_type"],
                description=row["description"],
                steps=json.loads(row["steps"]),
                best_for=json.loads(row["best_for"]),
                effectiveness=row["effectiveness"],
                times_used=row["times_used"],
                times_successful=row["times_successful"],
                parameter_recommendations=json.loads(row["parameter_recommendations"]),
                created_at=row["created_at"],
                tags=json.loads(row["tags"]),
            )
            self._active_procedural[memory.id] = memory

    # -- Episodic Memory Operations -----------------------------------------

    def store_episodic(
        self,
        memory_type: str,
        content: dict[str, Any],
        context: dict[str, Any] | None = None,
        outcome: str = "",
        tags: list[str] | None = None,
    ) -> EpisodicMemory:
        """Stores a new episodic memory (specific test execution)."""
        memory = EpisodicMemory(
            session_id=self._current_session_id,
            memory_type=memory_type,
            content=content,
            context=context or {},
            outcome=outcome,
            tags=tags or [],
        )

        # Store in working memory (hot layer)
        self._working_memory.append(memory)

        # Store in SQLite (persistent layer)
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO episodic_memories
                (id, session_id, timestamp, memory_type, content, context, outcome, tags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    memory.id,
                    memory.session_id,
                    memory.timestamp,
                    memory.memory_type,
                    json.dumps(memory.content),
                    json.dumps(memory.context),
                    memory.outcome,
                    json.dumps(memory.tags),
                )
            )
            self._conn.commit()
            self._stats["episodic_stored"] += 1

        return memory

    def query_episodic(
        self,
        memory_type: str | None = None,
        session_id: str | None = None,
        outcome: str | None = None,
        tag: str | None = None,
        limit: int = 50,
    ) -> list[EpisodicMemory]:
        """Queries episodic memories matching criteria."""
        query = "SELECT * FROM episodic_memories WHERE 1=1"
        params: list[Any] = []

        if memory_type:
            query += " AND memory_type = ?"
            params.append(memory_type)
        if session_id:
            query += " AND session_id = ?"
            params.append(session_id)
        if outcome:
            query += " AND outcome = ?"
            params.append(outcome)
        if tag:
            query += " AND tags LIKE ?"
            params.append(f"%{tag}%")

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with self._lock:
            rows = self._conn.execute(query, params).fetchall()

        memories = []
        for row in rows:
            memories.append(EpisodicMemory(
                id=row["id"],
                session_id=row["session_id"],
                timestamp=row["timestamp"],
                memory_type=row["memory_type"],
                content=json.loads(row["content"]),
                context=json.loads(row["context"]),
                outcome=row["outcome"],
                tags=json.loads(row["tags"]),
            ))

        return memories

    def prune_episodic_older_than(self, max_age_seconds: float) -> int:
        """Deletes episodic memories older than `max_age_seconds` and
        returns the number of rows removed.

        Cross-session accumulation (the whole point of this class -- see
        module docstring) means episodic_memories now genuinely grows
        without bound across every future run against a target. Nothing
        in this codebase called this before it existed; a target that
        gets tested continuously for months would otherwise carry an
        ever-growing table forever. Not run automatically by this class
        -- see CognitiveEngine.end_session, which calls this with a
        configurable retention window so an operator can tune or disable
        it per deployment rather than this module deciding for them.
        """
        cutoff = time.time() - max_age_seconds
        with self._lock:
            cursor = self._conn.execute("DELETE FROM episodic_memories WHERE timestamp < ?", (cutoff,))
            self._conn.commit()
            return cursor.rowcount

    # -- Semantic Memory Operations -----------------------------------------

    def store_semantic(self, memory: SemanticMemory) -> SemanticMemory:
        """Stores or updates a semantic memory (generalized pattern)."""
        self._active_semantic[memory.id] = memory

        self._conn.execute(
            """INSERT OR REPLACE INTO semantic_memories
            (id, pattern_type, description, conditions, expected_behavior, observed_behavior,
             confidence, occurrence_count, success_rate, source_episodes, created_at, last_accessed_at, tags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                memory.id,
                memory.pattern_type,
                memory.description,
                json.dumps(memory.conditions),
                memory.expected_behavior,
                memory.observed_behavior,
                memory.confidence,
                memory.occurrence_count,
                memory.success_rate,
                json.dumps(memory.source_episodes),
                memory.created_at,
                memory.last_accessed_at,
                json.dumps(memory.tags),
            )
        )
        self._conn.commit()
        self._stats["semantic_stored"] += 1

        return memory

    def get_semantic_by_type(self, pattern_type: str) -> list[SemanticMemory]:
        """Returns semantic memories of a specific pattern type."""
        return [
            m for m in self._active_semantic.values()
            if m.pattern_type == pattern_type
        ]

    def get_applicable_semantic(self, context: dict[str, Any]) -> list[SemanticMemory]:
        """Returns semantic memories whose conditions match the given context.

        This is the key method for using accumulated wisdom: given a new
        system or endpoint, find patterns that have been relevant in
        similar situations before.
        """
        applicable = []

        for memory in self._active_semantic.values():
            if self._conditions_match(memory.conditions, context):
                applicable.append(memory)
                memory.last_accessed_at = time.time()  # Update access time

        # Sort by confidence and occurrence count
        applicable.sort(
            key=lambda m: (m.confidence, m.occurrence_count),
            reverse=True,
        )

        return applicable

    def _conditions_match(self, conditions: dict[str, Any], context: dict[str, Any]) -> bool:
        """Checks if memory conditions match the current context."""
        for key, value in conditions.items():
            if key not in context:
                continue  # Missing context keys don't disqualify

            context_value = context[key]
            condition_value = value

            # Handle different types of conditions
            if isinstance(condition_value, str):
                if condition_value.lower() not in str(context_value).lower():
                    return False
            elif isinstance(condition_value, (list, tuple)):
                if context_value not in condition_value:
                    return False
            elif isinstance(condition_value, (int, float)):
                if context_value != condition_value:
                    return False
            elif isinstance(condition_value, dict):
                # Nested condition — check each sub-key
                if not self._conditions_match(condition_value, {key: context_value}):
                    return False

        return True

    # -- Procedural Memory Operations -----------------------------------------

    def store_procedural(self, memory: ProceduralMemory) -> ProceduralMemory:
        """Stores or updates a procedural memory (how-to knowledge)."""
        self._active_procedural[memory.id] = memory

        self._conn.execute(
            """INSERT OR REPLACE INTO procedural_memories
            (id, procedure_type, description, steps, best_for, effectiveness,
             times_used, times_successful, parameter_recommendations, created_at, tags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                memory.id,
                memory.procedure_type,
                memory.description,
                json.dumps(memory.steps),
                json.dumps(memory.best_for),
                memory.effectiveness,
                memory.times_used,
                memory.times_successful,
                json.dumps(memory.parameter_recommendations),
                memory.created_at,
                json.dumps(memory.tags),
            )
        )
        self._conn.commit()
        self._stats["procedural_stored"] += 1

        return memory

    def get_procedural_by_type(self, procedure_type: str) -> list[ProceduralMemory]:
        """Returns procedural memories of a specific type."""
        return [
            m for m in self._active_procedural.values()
            if m.procedure_type == procedure_type
        ]

    def get_best_procedure(self, procedure_type: str, context: dict[str, Any]) -> ProceduralMemory | None:
        """Returns the most effective procedural memory for a given context."""
        candidates = self.get_procedural_by_type(procedure_type)
        if not candidates:
            return None

        # Score each candidate by effectiveness and context match
        scored = []
        for proc in candidates:
            # Base score from effectiveness
            score = proc.effectiveness

            # Bonus for context match
            for key, value in proc.best_for.items():
                if key in context and str(context[key]).lower() in str(value).lower():
                    score += 0.2

            # Bonus for being well-tested
            if proc.times_used > 10:
                score += 0.1

            scored.append((proc, score))

        # Return the highest-scoring procedure
        scored.sort(key=lambda pair: pair[1], reverse=True)
        return scored[0][0] if scored else None

    def record_procedure_outcome(self, procedure_id: str, successful: bool) -> None:
        """Records whether a procedure was successful, updating its effectiveness."""
        proc = self._active_procedural.get(procedure_id)
        if proc is None:
            return

        proc.times_used += 1
        if successful:
            proc.times_successful += 1

        # Update effectiveness using exponential moving average
        proc.effectiveness = (
            0.9 * proc.effectiveness +
            0.1 * (1.0 if successful else 0.0)
        )

        # Persist the update
        self.store_procedural(proc)

    # -- Consolidation ("Sleep") ----------------------------------------------

    def consolidate(self) -> dict[str, Any]:
        """Performs memory consolidation — extracts patterns from episodic memories.

        This should be called periodically (e.g., between test sessions or
        after every N test executions) to promote recurring patterns from
        episodic memory to semantic memory.

        Consolidation process:
        1. Group episodic memories by similarity
        2. For groups with enough members, extract a pattern
        3. Store the pattern as a semantic memory
        4. Link the source episodic memories
        """
        # Get recent episodic memories
        recent = self.query_episodic(limit=200)

        if not recent:
            return {"patterns_extracted": 0, "reason": "No recent memories to consolidate"}

        # Group by memory_type and context similarity
        groups: dict[str, list[EpisodicMemory]] = defaultdict(list)
        for memory in recent:
            # Simple grouping: by memory_type + endpoint/resource from context
            group_key = memory.memory_type
            resource = memory.context.get("endpoint", memory.context.get("resource", ""))
            if resource:
                group_key += f":{resource}"
            groups[group_key].append(memory)

        patterns_extracted = 0
        new_semantic: list[SemanticMemory] = []

        for group_key, memories in groups.items():
            # Only extract patterns from groups with enough evidence
            if len(memories) < 3:
                continue

            # Calculate pattern statistics
            outcomes = [m.outcome for m in memories]
            pass_rate = outcomes.count("pass") / len(outcomes) if outcomes else 0.0
            fail_rate = outcomes.count("fail") / len(outcomes) if outcomes else 0.0

            # Extract the pattern type from the group key
            pattern_type = group_key.split(":")[0]

            # Create a semantic memory
            semantic = SemanticMemory(
                pattern_type=pattern_type,
                description=(
                    f"Pattern observed across {len(memories)} test executions on "
                    f"{group_key.split(':', 1)[1] if ':' in group_key else 'various endpoints'}: "
                    f"{pass_rate:.0%} pass rate, {fail_rate:.0%} fail rate"
                ),
                conditions={
                    "memory_type": pattern_type,
                    "resource": group_key.split(":", 1)[1] if ":" in group_key else "",
                },
                expected_behavior="Consistent behavior across all endpoints of this type",
                observed_behavior=f"Pass rate: {pass_rate:.0%}, Fail rate: {fail_rate:.0%}",
                confidence=min(0.9, 0.3 + len(memories) * 0.1),  # More evidence = higher confidence
                occurrence_count=len(memories),
                success_rate=pass_rate,
                source_episodes=[m.id for m in memories[:20]],  # Link to first 20 source episodes
                tags=list(set(tag for m in memories for tag in m.tags)),
            )

            new_semantic.append(semantic)
            patterns_extracted += 1

        # Store new semantic memories
        for semantic in new_semantic:
            self.store_semantic(semantic)

        self._stats["consolidations_performed"] += 1
        self._stats["patterns_promoted"] += patterns_extracted

        return {
            "patterns_extracted": patterns_extracted,
            "episodic_memories_analyzed": len(recent),
            "groups_found": len(groups),
            "new_semantic_memories": len(new_semantic),
        }

    # -- Session Management ---------------------------------------------------

    def start_session(self, system_context: dict[str, Any] | None = None) -> str:
        """Starts a new test session."""
        self._current_session_id = str(uuid4())
        self._working_memory = []

        # Record session start
        self._conn.execute(
            "INSERT OR REPLACE INTO session_summaries (session_id, started_at, system_type) VALUES (?, ?, ?)",
            (self._current_session_id, time.time(), json.dumps(system_context or {})),
        )
        self._conn.commit()

        return self._current_session_id

    def end_session(self, summary: dict[str, Any] | None = None) -> None:
        """Ends the current session and triggers consolidation."""
        self._conn.execute(
            "UPDATE session_summaries SET completed_at = ?, summary = ? WHERE session_id = ?",
            (time.time(), json.dumps(summary or {}), self._current_session_id),
        )
        self._conn.commit()

        # Trigger consolidation
        consolidation_result = self.consolidate()

        return consolidation_result

    # -- Statistics -------------------------------------------------------------

    def get_statistics(self) -> dict[str, Any]:
        """Returns comprehensive memory statistics."""
        with self._lock:
            # Count total memories in database
            cursor = self._conn.execute("SELECT COUNT(*) as count FROM episodic_memories")
            total_episodic = cursor.fetchone()["count"]

            cursor = self._conn.execute("SELECT COUNT(*) as count FROM semantic_memories")
            total_semantic = cursor.fetchone()["count"]

            cursor = self._conn.execute("SELECT COUNT(*) as count FROM procedural_memories")
            total_procedural = cursor.fetchone()["count"]

            cursor = self._conn.execute("SELECT COUNT(*) as count FROM session_summaries")
            total_sessions = cursor.fetchone()["count"]

        return {
            "total_sessions": total_sessions,
            "total_episodic": total_episodic,
            "total_semantic": total_semantic,
            "total_procedural": total_procedural,
            "active_semantic": len(self._active_semantic),
            "active_procedural": len(self._active_procedural),
            "current_session_memories": len(self._working_memory),
            "internal_stats": dict(self._stats),
        }

    def get_relevant_memories_for_context(self, context: dict[str, Any]) -> dict[str, Any]:
        """Returns all memories relevant to a given testing context.

        This is the primary method used during test execution to
        leverage accumulated knowledge.
        """
        applicable_semantic = self.get_applicable_semantic(context)
        best_procedures = {}

        # Find the best procedure for each relevant type
        procedure_types = {m.pattern_type for m in applicable_semantic}
        for proc_type in procedure_types:
            best = self.get_best_procedure(proc_type, context)
            if best:
                best_procedures[proc_type] = best

        return {
            "applicable_patterns": [
                {
                    "description": m.description,
                    "confidence": m.confidence,
                    "occurrence_count": m.occurrence_count,
                    "expected_behavior": m.expected_behavior,
                }
                for m in applicable_semantic[:10]
            ],
            "recommended_procedures": {
                proc_type: {
                    "description": proc.description,
                    "effectiveness": proc.effectiveness,
                    "parameter_recommendations": proc.parameter_recommendations,
                    "times_used": proc.times_used,
                }
                for proc_type, proc in best_procedures.items()
            },
            "total_applicable": len(applicable_semantic),
        }

    def close(self) -> None:
        """Closes the database connection."""
        if hasattr(self, "_conn"):
            self._conn.close()
