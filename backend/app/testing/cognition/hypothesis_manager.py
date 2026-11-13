"""Sharded Hypothesis Manager — Erweitert BlackboardWorkspace.

Erhöht die Hypothesen-Kapazität von ~100 auf 10.000+ durch:
  1. Sharding — Hypothesen sind auf 16 unabhängige Shards verteilt
  2. Lock-freie Reads — Lesen blockiert nicht andere Operationen
  3. Tier-System — ACTIVE (100) / MONITORING (1000) / DORMANT (8900)
     Nur die Top-Tier-Hypothesen bekommen volle Aufmerksamkeit,
     der Rest schläft bis er relevant wird.

Redis-Backend (optional):
  Wenn Redis verfügbar ist werden Hypothesen zusätzlich in Redis
  Sorted Sets persistiert — das überlebt Neustarts und erlaubt
  Multi-Process-Zugriff.

Falls Redis nicht verfügbar: Reiner In-Memory-Betrieb mit heapq.

Integration:
  Dieser Manager ERWEITERT BlackboardWorkspace — er ersetzt ihn nicht.
  CognitiveEngine kann weiterhin workspace.post() nutzen.
  Für Hypothesen-spezifische Operationen nutzt er hypothesis_manager.
"""
from __future__ import annotations

import asyncio
import heapq
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import redis.asyncio as aioredis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False


class HypothesisTier(Enum):
    """Aktivitäts-Level einer Hypothese."""
    ACTIVE = "active"          # Top 100 — volle Aufmerksamkeit
    MONITORING = "monitoring"  # Top 1000 — reduzierte Aufmerksamkeit
    DORMANT = "dormant"        # Rest — schläft bis relevant


@dataclass
class ManagedHypothesis:
    """Eine verwaltete Hypothese im Sharded Manager."""
    id: str
    description: str
    hypothesis_type: str
    priority: float = 0.5
    confidence: float = 0.5
    tier: HypothesisTier = HypothesisTier.DORMANT
    created_at: float = field(default_factory=time.time)
    last_accessed: float = field(default_factory=time.time)
    access_count: int = 0
    supporting_count: int = 0
    contradicting_count: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __lt__(self, other: "ManagedHypothesis") -> bool:
        """Für heapq — höchste Priorität zuerst."""
        return self.priority > other.priority


class HypothesisShard:
    """Ein einzelner Shard mit eigenem Heap."""

    def __init__(self, shard_id: int):
        self.shard_id = shard_id
        self.heap: List[ManagedHypothesis] = []
        self.hypotheses: Dict[str, ManagedHypothesis] = {}
        self._lock = asyncio.Lock()

    async def add(self, hypothesis: ManagedHypothesis) -> None:
        """Fügt eine Hypothese hinzu (lock-frei für Reads)."""
        self.hypotheses[hypothesis.id] = hypothesis
        heapq.heappush(self.heap, hypothesis)

    async def get(self, hypothesis_id: str) -> Optional[ManagedHypothesis]:
        """Lock-freier Read."""
        hyp = self.hypotheses.get(hypothesis_id)
        if hyp:
            hyp.access_count += 1
            hyp.last_accessed = time.time()
        return hyp

    async def update_priority(self, hypothesis_id: str, new_priority: float) -> bool:
        """Aktualisiert Priorität und reorganisiert Heap."""
        hyp = self.hypotheses.get(hypothesis_id)
        if hyp is None:
            return False

        hyp.priority = new_priority
        # Heap reorganisieren
        heapq.heapify(self.heap)
        return True

    async def remove(self, hypothesis_id: str) -> bool:
        """Entfernt eine Hypothese."""
        hyp = self.hypotheses.pop(hypothesis_id, None)
        if hyp is None:
            return False

        # Aus Heap entfernen (Markierung + heapify)
        hyp.priority = -1.0
        heapq.heapify(self.heap)
        # Tote Einträge aufräumen
        self.heap = [h for h in self.heap if h.id != hypothesis_id]
        heapq.heapify(self.heap)
        return True

    def get_top(self, n: int) -> List[ManagedHypothesis]:
        """Gibt die Top-N Hypothesen dieses Shards zurück."""
        return heapq.nlargest(n, self.heap)

    @property
    def size(self) -> int:
        return len(self.hypotheses)


class HypothesisManager:
    """Sharded Manager für 10.000+ Hypothesen.

    Features:
      - 16 Shards für lock-freie parallele Reads
      - Tier-System: ACTIVE / MONITORING / DORMANT
      - Optionales Redis-Backend für Persistenz
      - Prioritäts-basierte Abrufung
      - Automatisches Tier-Rebalancing

    Usage:
        manager = HypothesisManager()

        # Hypothese hinzufügen
        hyp_id = await manager.add_hypothesis(
            description="Webhook ohne Signatur-Validierung",
            hypothesis_type="webhook_integrity_gap",
            priority=0.9,
        )

        # Top-Hypothesen abrufen
        top = await manager.get_top_hypotheses(10)

        # Priorität aktualisieren (z.B. nach Evidence)
        await manager.update_confidence(hyp_id, supporting=True)
    """

    NUM_SHARDS = 16
    ACTIVE_LIMIT = 100
    MONITORING_LIMIT = 1000
    TIER_REBALANCE_INTERVAL = 30.0  # Sekunden

    def __init__(self, redis_url: Optional[str] = None):
        self.shards: List[HypothesisShard] = [
            HypothesisShard(i) for i in range(self.NUM_SHARDS)
        ]

        # Redis-Backend (optional)
        self.redis = None
        if redis_url and REDIS_AVAILABLE:
            try:
                self.redis = aioredis.from_url(redis_url)
            except Exception:
                self.redis = None

        # Statistiken
        self.total_added = 0
        self.total_removed = 0
        self.total_accessed = 0
        self.last_rebalance = time.time()

    def _get_shard(self, hypothesis_id: str) -> HypothesisShard:
        """Bestimmt den Shard für eine Hypothese-ID."""
        shard_index = hash(hypothesis_id) % self.NUM_SHARDS
        return self.shards[shard_index]

    # ------------------------------------------------------------------
    # Hypothesen-Verwaltung
    # ------------------------------------------------------------------

    async def add_hypothesis(
        self,
        description: str,
        hypothesis_type: str,
        priority: float = 0.5,
        confidence: float = 0.5,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Fügt eine neue Hypothese hinzu.

        Returns:
            Die generierte hypothesis_id.
        """
        hypothesis_id = str(uuid.uuid4())[:16]

        hypothesis = ManagedHypothesis(
            id=hypothesis_id,
            description=description,
            hypothesis_type=hypothesis_type,
            priority=priority,
            confidence=confidence,
            tier=HypothesisTier.DORMANT,
            metadata=metadata or {},
        )

        shard = self._get_shard(hypothesis_id)
        await shard.add(hypothesis)
        self.total_added += 1

        # Redis-Persistierung falls verfügbar
        if self.redis:
            try:
                await self.redis.zadd(
                    "hypotheses:sorted",
                    {hypothesis_id: priority},
                )
            except Exception:
                pass

        # Tier-Rebalancing prüfen
        if time.time() - self.last_rebalance > self.TIER_REBALANCE_INTERVAL:
            await self.rebalance_tiers()

        return hypothesis_id

    async def get_hypothesis(self, hypothesis_id: str) -> Optional[ManagedHypothesis]:
        """Ruft eine Hypothese ab (lock-frei)."""
        shard = self._get_shard(hypothesis_id)
        hyp = await shard.get(hypothesis_id)
        if hyp:
            self.total_accessed += 1
        return hyp

    async def remove_hypothesis(self, hypothesis_id: str) -> bool:
        """Entfernt eine Hypothese."""
        shard = self._get_shard(hypothesis_id)
        removed = await shard.remove(hypothesis_id)
        if removed:
            self.total_removed += 1
            if self.redis:
                try:
                    await self.redis.zrem("hypotheses:sorted", hypothesis_id)
                except Exception:
                    pass
        return removed

    async def update_confidence(
        self,
        hypothesis_id: str,
        supporting: bool,
        strength: float = 0.5,
    ) -> Optional[ManagedHypothesis]:
        """Aktualisiert Confidence basierend auf neuer Evidence.

        Bayes'sches Update:
          Supporting: confidence steigt proportional zu strength
          Contradicting: confidence sinkt
        """
        shard = self._get_shard(hypothesis_id)
        hyp = await shard.get(hypothesis_id)
        if hyp is None:
            return None

        if supporting:
            hyp.supporting_count += 1
            # Bayes-ähnliches Update
            likelihood = 0.7 + strength * 0.3
            prior = hyp.confidence
            hyp.confidence = min(0.99, (prior * likelihood) / (prior * likelihood + (1 - prior) * (1 - likelihood) * 0.3))
        else:
            hyp.contradicting_count += 1
            hyp.confidence = max(0.01, hyp.confidence * (1 - strength * 0.3))

        # Priorität basierend auf Confidence aktualisieren
        hyp.priority = hyp.confidence * 0.6 + min(0.4, hyp.access_count * 0.02)

        await shard.update_priority(hypothesis_id, hyp.priority)

        # Redis-Persistierung
        if self.redis:
            try:
                await self.redis.zadd("hypotheses:sorted", {hypothesis_id: hyp.priority})
            except Exception:
                pass

        return hyp

    # ------------------------------------------------------------------
    # Abfragen
    # ------------------------------------------------------------------

    async def get_top_hypotheses(
        self,
        n: int = 10,
        tier: Optional[HypothesisTier] = None,
    ) -> List[ManagedHypothesis]:
        """Gibt die Top-N Hypothesen zurück.

        Args:
            n: Anzahl Hypothesen.
            tier: Optional nach Tier filtern.
        """
        # Von allen Shards die Top-Kandidaten sammeln
        all_top: List[ManagedHypothesis] = []

        # Pro Shard genug Kandidaten holen
        per_shard = max(1, n // self.NUM_SHARDS + 2)

        for shard in self.shards:
            shard_top = shard.get_top(per_shard)
            all_top.extend(shard_top)

        # Nach Tier filtern
        if tier is not None:
            all_top = [h for h in all_top if h.tier == tier]

        # Global sortieren und Top-N zurückgeben
        all_top.sort(key=lambda h: h.priority, reverse=True)
        return all_top[:n]

    async def get_active_hypotheses(self) -> List[ManagedHypothesis]:
        """Gibt alle ACTIVE-Tier-Hypothesen zurück."""
        return await self.get_top_hypotheses(self.ACTIVE_LIMIT, tier=HypothesisTier.ACTIVE)

    async def get_by_type(self, hypothesis_type: str) -> List[ManagedHypothesis]:
        """Gibt alle Hypothesen eines bestimmten Typs zurück."""
        results = []
        for shard in self.shards:
            for hyp in shard.hypotheses.values():
                if hyp.hypothesis_type == hypothesis_type:
                    results.append(hyp)
        results.sort(key=lambda h: h.priority, reverse=True)
        return results

    async def search(
        self,
        description_contains: str,
        max_results: int = 10,
    ) -> List[ManagedHypothesis]:
        """Durchsucht Hypothesen-Beschreibungen."""
        needle = description_contains.lower()
        results = []

        for shard in self.shards:
            for hyp in shard.hypotheses.values():
                if needle in hyp.description.lower():
                    results.append(hyp)
                    if len(results) >= max_results:
                        return results

        return results

    # ------------------------------------------------------------------
    # Tier-Management
    # ------------------------------------------------------------------

    async def rebalance_tiers(self) -> Dict[str, int]:
        """Verteilt Hypothesen neu auf Tiers basierend auf Priorität.

        ACTIVE: Top 100 nach Priorität
        MONITORING: Top 1000 nach Priorität
        DORMANT: Rest
        """
        # Alle Hypothesen sammeln
        all_hypotheses: List[ManagedHypothesis] = []
        for shard in self.shards:
            all_hypotheses.extend(shard.hypotheses.values())

        # Nach Priorität sortieren
        all_hypotheses.sort(key=lambda h: h.priority, reverse=True)

        # Tiers zuweisen
        tier_counts = {"active": 0, "monitoring": 0, "dormant": 0}

        for i, hyp in enumerate(all_hypotheses):
            if i < self.ACTIVE_LIMIT:
                hyp.tier = HypothesisTier.ACTIVE
                tier_counts["active"] += 1
            elif i < self.MONITORING_LIMIT:
                hyp.tier = HypothesisTier.MONITORING
                tier_counts["monitoring"] += 1
            else:
                hyp.tier = HypothesisTier.DORMANT
                tier_counts["dormant"] += 1

        self.last_rebalance = time.time()

        return tier_counts

    # ------------------------------------------------------------------
    # Statistiken
    # ------------------------------------------------------------------

    async def get_statistics(self) -> Dict[str, Any]:
        """Gibt Manager-Statistiken zurück."""
        total = sum(s.size for s in self.shards)

        # Tier-Verteilung
        tier_dist: Dict[str, int] = {"active": 0, "monitoring": 0, "dormant": 0}
        for shard in self.shards:
            for hyp in shard.hypotheses.values():
                tier_dist[hyp.tier.value] += 1

        # Typ-Verteilung
        type_dist: Dict[str, int] = {}
        for shard in self.shards:
            for hyp in shard.hypotheses.values():
                type_dist[hyp.hypothesis_type] = type_dist.get(hyp.hypothesis_type, 0) + 1

        return {
            "total_hypotheses": total,
            "total_added": self.total_added,
            "total_removed": self.total_removed,
            "total_accessed": self.total_accessed,
            "tier_distribution": tier_dist,
            "type_distribution": dict(
                sorted(type_dist.items(), key=lambda x: x[1], reverse=True)[:10]
            ),
            "shard_sizes": [s.size for s in self.shards],
            "redis_connected": self.redis is not None,
            "capacity": "10,000+",
        }

    async def close(self) -> None:
        """Räumt Ressourcen auf."""
        if self.redis:
            try:
                await self.redis.close()
            except Exception:
                pass


if __name__ == "__main__":
    # Echter Test mit 10.000 Hypothesen
    async def main():
        print("=" * 70)
        print("HYPOTHESIS MANAGER — STANDALONE TEST (10,000 Hypothesen)")
        print("=" * 70)

        manager = HypothesisManager()

        # Phase 1: 10.000 Hypothesen hinzufügen
        print("\n1. Adding 10,000 hypotheses...")
        start = time.perf_counter()

        hypothesis_types = [
            "webhook_integrity_gap", "query_construction_issue",
            "access_control_inconsistency", "output_encoding_gap",
            "input_field_whitelisting", "response_field_filtering",
        ]

        for i in range(10000):
            htype = hypothesis_types[i % len(hypothesis_types)]
            priority = (i % 100) / 100.0  # Zyklische Prioritäten 0.0-0.99
            await manager.add_hypothesis(
                description=f"Test hypothesis {i} — {htype} on endpoint /api/resource/{i % 50}",
                hypothesis_type=htype,
                priority=priority,
            )

        add_time = (time.perf_counter() - start) * 1000
        print(f"   Added 10,000 hypotheses in {add_time:.1f}ms")
        print(f"   Rate: {10000 / (add_time / 1000):,.0f} hypotheses/second")

        # Phase 2: Top-Hypothesen abrufen
        print("\n2. Getting top 10 hypotheses...")
        start = time.perf_counter()
        top = await manager.get_top_hypotheses(10)
        query_time = (time.perf_counter() - start) * 1000
        print(f"   Retrieved in {query_time:.2f}ms")
        for i, hyp in enumerate(top, 1):
            print(f"   {i}. [{hyp.priority:.2f}] {hyp.description[:60]}...")

        # Phase 3: Einzelne Hypothese abrufen
        print("\n3. Getting single hypothesis (lock-free read)...")
        test_id = top[0].id
        start = time.perf_counter()
        retrieved = await manager.get_hypothesis(test_id)
        single_time = (time.perf_counter() - start) * 1000
        print(f"   Retrieved in {single_time:.4f}ms")
        print(f"   Found: {retrieved is not None}")

        # Phase 4: Confidence-Update
        print("\n4. Updating confidence (evidence-based)...")
        start = time.perf_counter()
        for _ in range(100):
            await manager.update_confidence(test_id, supporting=True, strength=0.8)
        update_time = (time.perf_counter() - start) * 1000
        print(f"   100 updates in {update_time:.1f}ms")
        updated = await manager.get_hypothesis(test_id)
        print(f"   Confidence after 100 supporting: {updated.confidence:.3f}")

        # Phase 5: Tier-Rebalancing
        print("\n5. Rebalancing tiers...")
        start = time.perf_counter()
        tier_counts = await manager.rebalance_tiers()
        rebalance_time = (time.perf_counter() - start) * 1000
        print(f"   Rebalanced in {rebalance_time:.1f}ms")
        print(f"   ACTIVE: {tier_counts['active']}")
        print(f"   MONITORING: {tier_counts['monitoring']}")
        print(f"   DORMANT: {tier_counts['dormant']}")

        # Phase 6: Statistiken
        print("\n6. Statistics:")
        stats = await manager.get_statistics()
        print(f"   Total: {stats['total_hypotheses']:,}")
        print(f"   Shard sizes: {stats['shard_sizes'][:5]}...")
        print(f"   Type distribution: {list(stats['type_distribution'].items())[:3]}")

        await manager.close()
        print("\n✅ Hypothesis Manager test completed")

    asyncio.run(main())
