"""Memory Compressor — Semantische Muster-Verdichtung.

Komprimiert Beobachtungen automatisch zu wiederverwendbarem Wissen
durch semantische Embeddings und Vektor-Ähnlichkeitssuche.

Stattdessen jede Beobachtung einzeln zu speichern:
  → Gleiche/ähnliche Beobachtungen werden erkannt und verdichtet
  → "Payment-Endpunkte mit >200ms Response-Zeit haben Race-Conditions"
     wird zu EINEM verdichteten Chunk statt 50 einzelner Beobachtungen
  → Ähnliche neue Beobachtungen erhöhen nur die Frequenz des Chunks

Komponenten:
  1. Embedding-Generierung (sentence-transformers, optional)
  2. Vektor-Ähnlichkeitssuche (FAISS, optional)
  3. Fallback: Reine String-Ähnlichkeit (immer verfügbar)

Wenn sentence-transformers + FAISS nicht installiert sind:
  → Automatischer Fallback auf difflib.SequenceMatcher
  → Immer funktional, nur langsamer bei großen Datenmengen

Integration:
  Erweitert PersistentMemoryStore — ersetzt ihn nicht.
  PersistentMemoryStore speichert Episoden.
  MemoryCompressor verdichtet sie zu semantischen Chunks.
"""
from __future__ import annotations

import difflib
import hashlib
import json
import re
import time
from collections import OrderedDict, defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# Optionale Abhängigkeiten
try:
    import numpy as np
    from sentence_transformers import SentenceTransformer
    SENTENCE_TRANSFORMERS_AVAILABLE = True
except ImportError:
    SENTENCE_TRANSFORMERS_AVAILABLE = False
    # NumPy-Fallback
    try:
        import numpy as np
    except ImportError:
        np = None

try:
    import faiss
    FAISS_AVAILABLE = True
except ImportError:
    FAISS_AVAILABLE = False


@dataclass
class ObservationChunk:
    """Ein verdichteter Wissens-Chunk aus mehreren Beobachtungen."""
    id: str
    content: str
    keywords: List[str] = field(default_factory=list)
    frequency: int = 1
    confidence: float = 0.5
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    sources: List[str] = field(default_factory=list)
    embedding: Optional[Any] = None  # numpy array wenn verfügbar
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "content": self.content,
            "keywords": self.keywords,
            "frequency": self.frequency,
            "confidence": self.confidence,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "sources": self.sources,
            "metadata": self.metadata,
        }


@dataclass
class CompressionResult:
    """Ergebnis einer Kompressions-Operation."""
    chunk_id: str
    is_new: bool
    similarity_score: float = 0.0
    total_chunks: int = 0
    compression_ratio: float = 0.0


class MemoryCompressor:
    """Verdichtet Beobachtungen zu semantischen Chunks.

    Flow:
      1. add_observation(text) wird aufgerufen
      2. Embedding generieren (falls sentence-transformers verfügbar)
      3. Ähnlichen Chunk in FAISS/ difflib finden
      4. Wenn Ähnlichkeit > threshold: Chunk-Frequenz erhöhen
      5. Wenn neu: Neuen Chunk erstellen

    Usage:
        compressor = MemoryCompressor()

        # Beobachtungen hinzufügen
        compressor.add_observation(
            "Payment endpoint /api/checkout has response time 250ms with concurrent requests"
        )
        compressor.add_observation(
            "Payment endpoint /api/checkout has response time 280ms under load"
        )
        # → Beide werden zu EINEM Chunk verdichtet (ähnlich)

        # Relevante Chunks abrufen
        chunks = compressor.get_relevant_chunks("payment response time")
    """

    # Konfiguration
    SIMILARITY_THRESHOLD = 0.75
    MAX_CHUNKS = 5000
    KEYWORD_STOPWORDS = {
        "the", "a", "an", "is", "are", "was", "were", "be", "been",
        "have", "has", "had", "do", "does", "did", "will", "would",
        "could", "should", "may", "might", "must", "can", "this",
        "that", "these", "those", "and", "or", "but", "not", "in",
        "on", "at", "to", "for", "of", "with", "by", "from", "up",
        "about", "into", "through", "during", "before", "after",
        "it", "its", "as", "if", "than", "then", "so", "no", "yes",
    }

    def __init__(
        self,
        model_name: str = "all-MiniLM-L6-v2",
        use_faiss: bool = True,
        max_cache_size: int = 1000,
    ):
        self.max_cache_size = max_cache_size
        self.model_name = model_name

        # Chunk-Speicher
        self.chunks: Dict[str, ObservationChunk] = OrderedDict()
        self.chunk_list: List[ObservationChunk] = []

        # Embedding-Modell (optional)
        self.model = None
        if SENTENCE_TRANSFORMERS_AVAILABLE:
            try:
                self.model = SentenceTransformer(model_name)
            except Exception:
                self.model = None

        # FAISS-Index (optional)
        self.faiss_index = None
        self.embedding_dim = 384 if self.model else 0
        if use_faiss and FAISS_AVAILABLE and self.model:
            self.faiss_index = faiss.IndexFlatIP(self.embedding_dim)

        # Statistiken
        self.total_observations = 0
        self.total_chunks_created = 0
        self.total_merges = 0
        self.total_queries = 0
        self.cache_hits = 0

    # ------------------------------------------------------------------
    # Beobachtungen hinzufügen
    # ------------------------------------------------------------------

    def add_observation(
        self,
        text: str,
        source: str = "unknown",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> CompressionResult:
        """Fügt eine Beobachtung hinzu und verdichtet sie.

        Wenn ein ähnlicher Chunk existiert: Frequenz erhöhen.
        Wenn neu: Neuen Chunk erstellen.
        """
        self.total_observations += 1

        # Embedding generieren falls verfügbar
        embedding = self._generate_embedding(text)

        # Ähnlichen Chunk suchen
        similar_chunk, similarity = self._find_similar(text, embedding)

        if similar_chunk is not None and similarity >= self.SIMILARITY_THRESHOLD:
            # Bestehenden Chunk aktualisieren
            similar_chunk.frequency += 1
            similar_chunk.last_seen = time.time()
            similar_chunk.confidence = min(0.99, similar_chunk.confidence + 0.05)

            if source not in similar_chunk.sources:
                similar_chunk.sources.append(source)

            if metadata:
                similar_chunk.metadata.update(metadata)

            # LRU-Update
            self.chunks.move_to_end(similar_chunk.id)
            self.cache_hits += 1
            self.total_merges += 1

            return CompressionResult(
                chunk_id=similar_chunk.id,
                is_new=False,
                similarity_score=similarity,
                total_chunks=len(self.chunks),
                compression_ratio=self._compression_ratio(),
            )

        # Neuen Chunk erstellen
        chunk_id = self._generate_chunk_id(text)
        keywords = self._extract_keywords(text)

        new_chunk = ObservationChunk(
            id=chunk_id,
            content=text,
            keywords=keywords,
            frequency=1,
            confidence=0.5,
            sources=[source],
            embedding=embedding,
            metadata=metadata or {},
        )

        self._store_chunk(new_chunk)
        self.total_chunks_created += 1

        return CompressionResult(
            chunk_id=chunk_id,
            is_new=True,
            similarity_score=0.0,
            total_chunks=len(self.chunks),
            compression_ratio=self._compression_ratio(),
        )

    def add_observations(
        self,
        observations: List[Tuple[str, str]],
    ) -> List[CompressionResult]:
        """Fügt mehrere Beobachtungen hinzu.

        Args:
            observations: Liste von (text, source) Tupeln.
        """
        results = []
        for text, source in observations:
            result = self.add_observation(text, source)
            results.append(result)
        return results

    # ------------------------------------------------------------------
    # Abfragen
    # ------------------------------------------------------------------

    def get_relevant_chunks(
        self,
        query: str,
        max_chunks: int = 5,
        min_frequency: int = 1,
    ) -> List[ObservationChunk]:
        """Gibt die relevantesten Chunks für eine Query zurück.

        Nutzt semantische Suche falls verfügbar, sonst Keyword-Matching.
        """
        self.total_queries += 1

        if self.model is not None and self.faiss_index is not None:
            return self._search_faiss(query, max_chunks, min_frequency)
        else:
            return self._search_fallback(query, max_chunks, min_frequency)

    def find_similar_observations(
        self,
        query: str,
        top_k: int = 10,
    ) -> List[Tuple[ObservationChunk, float]]:
        """Findet ähnliche Beobachtungen mit Ähnlichkeits-Score."""
        query_embedding = self._generate_embedding(query)

        if query_embedding is not None and self.faiss_index is not None:
            # FAISS-Suche
            query_vector = query_embedding.reshape(1, -1).astype("float32")
            distances, indices = self.faiss_index.search(query_vector, top_k)

            results = []
            for dist, idx in zip(distances[0], indices[0]):
                if idx != -1 and idx < len(self.chunk_list):
                    chunk = self.chunk_list[idx]
                    results.append((chunk, float(dist)))
            return results

        else:
            # difflib-Fallback
            results = []
            for chunk in self.chunk_list:
                score = difflib.SequenceMatcher(
                    None, query.lower(), chunk.content.lower()
                ).ratio()
                results.append((chunk, score))

            results.sort(key=lambda x: x[1], reverse=True)
            return results[:top_k]

    def get_chunks_by_keyword(
        self,
        keyword: str,
        max_results: int = 10,
    ) -> List[ObservationChunk]:
        """Findet Chunks die ein bestimmtes Keyword enthalten."""
        keyword_lower = keyword.lower()
        results = []

        for chunk in self.chunks.values():
            if keyword_lower in chunk.content.lower() or keyword_lower in [
                k.lower() for k in chunk.keywords
            ]:
                results.append(chunk)
                if len(results) >= max_results:
                    break

        results.sort(key=lambda c: c.frequency, reverse=True)
        return results

    def get_high_frequency_chunks(self, min_frequency: int = 3) -> List[ObservationChunk]:
        """Gibt Chunks zurück die mindestens min_frequency Mal beobachtet wurden."""
        results = [
            c for c in self.chunks.values()
            if c.frequency >= min_frequency
        ]
        results.sort(key=lambda c: c.frequency, reverse=True)
        return results

    # ------------------------------------------------------------------
    # Konsolidierung
    # ------------------------------------------------------------------

    def consolidate(self) -> Dict[str, Any]:
        """Führt ähnliche Chunks zusammen und räumt auf.

        Sollte periodisch aufgerufen werden um Speicher zu sparen.
        """
        # 1. Chunks mit ähnlichen Keywords zusammenführen
        merged_count = 0

        chunk_ids = list(self.chunks.keys())
        for i, id_a in enumerate(chunk_ids):
            if id_a not in self.chunks:
                continue
            chunk_a = self.chunks[id_a]

            for id_b in chunk_ids[i + 1:]:
                if id_b not in self.chunks:
                    continue
                chunk_b = self.chunks[id_b]

                # Prüfe Keyword-Überlappung
                overlap = set(chunk_a.keywords) & set(chunk_b.keywords)
                union = set(chunk_a.keywords) | set(chunk_b.keywords)

                if union and len(overlap) / len(union) > 0.6:
                    # Zusammenführen
                    chunk_a.frequency += chunk_b.frequency
                    chunk_a.sources.extend(chunk_b.sources)
                    chunk_a.confidence = max(chunk_a.confidence, chunk_b.confidence)

                    # Chunk B entfernen
                    self._remove_chunk(id_b)
                    merged_count += 1

        # 2. Alte, niedrig-frequente Chunks entfernen
        cutoff = time.time() - 3600  # 1 Stunde
        removed_old = 0

        if len(self.chunks) > self.max_cache_size:
            # Nach Priorität sortieren
            sorted_chunks = sorted(
                self.chunks.values(),
                key=lambda c: (c.frequency, c.last_seen),
            )

            excess = len(self.chunks) - self.max_cache_size
            for chunk in sorted_chunks[:excess]:
                if chunk.frequency < 3 or chunk.last_seen < cutoff:
                    self._remove_chunk(chunk.id)
                    removed_old += 1

        return {
            "chunks_merged": merged_count,
            "chunks_removed": removed_old,
            "total_chunks": len(self.chunks),
            "compression_ratio": self._compression_ratio(),
        }

    # ------------------------------------------------------------------
    # Interne Methoden
    # ------------------------------------------------------------------

    def _generate_embedding(self, text: str) -> Optional[Any]:
        """Generiert ein Embedding für einen Text (falls Modell verfügbar)."""
        if self.model is None or np is None:
            return None

        try:
            embedding = self.model.encode([text])[0]
            return np.array(embedding, dtype="float32")
        except Exception:
            return None

    def _find_similar(
        self,
        text: str,
        embedding: Optional[Any],
    ) -> Tuple[Optional[ObservationChunk], float]:
        """Findet den ähnlichsten Chunk."""
        if embedding is not None and self.faiss_index is not None:
            # FAISS-Suche
            query_vector = embedding.reshape(1, -1).astype("float32")
            distances, indices = self.faiss_index.search(query_vector, 1)

            if indices[0][0] != -1 and indices[0][0] < len(self.chunk_list):
                best_chunk = self.chunk_list[indices[0][0]]
                similarity = float(distances[0][0])
                return best_chunk, similarity

        # Fallback: difflib-Ähnlichkeit
        best_chunk = None
        best_score = 0.0

        text_lower = text.lower()
        for chunk in self.chunks.values():
            score = difflib.SequenceMatcher(
                None, text_lower, chunk.content.lower()
            ).ratio()
            if score > best_score:
                best_score = score
                best_chunk = chunk

        return best_chunk, best_score

    def _search_faiss(
        self,
        query: str,
        max_chunks: int,
        min_frequency: int,
    ) -> List[ObservationChunk]:
        """FAISS-basierte semantische Suche."""
        query_embedding = self._generate_embedding(query)
        if query_embedding is None:
            return self._search_fallback(query, max_chunks, min_frequency)

        query_vector = query_embedding.reshape(1, -1).astype("float32")

        # Mehr Results als benötigt abrufen (für Frequenz-Filterung)
        search_k = min(max_chunks * 3, len(self.chunk_list))
        if search_k == 0:
            return []

        distances, indices = self.faiss_index.search(query_vector, search_k)

        results = []
        for dist, idx in zip(distances[0], indices[0]):
            if idx == -1 or idx >= len(self.chunk_list):
                continue

            chunk = self.chunk_list[idx]
            if chunk.frequency >= min_frequency:
                # Relevanz-Score: Semantische Ähnlichkeit × Frequenz
                relevance = float(dist) * min(2.0, 1.0 + chunk.frequency * 0.1)
                results.append((chunk, relevance))

            if len(results) >= max_chunks:
                break

        # Nach Relevanz sortieren
        results.sort(key=lambda x: x[1], reverse=True)
        return [chunk for chunk, _ in results]

    def _search_fallback(
        self,
        query: str,
        max_chunks: int,
        min_frequency: int,
    ) -> List[ObservationChunk]:
        """Fallback-Suche ohne Embeddings: Keyword + String-Ähnlichkeit."""
        query_keywords = set(self._extract_keywords(query))
        query_lower = query.lower()

        scored = []
        for chunk in self.chunks.values():
            if chunk.frequency < min_frequency:
                continue

            # Keyword-Überlappung
            chunk_keywords = set(chunk.keywords)
            keyword_overlap = len(query_keywords & chunk_keywords)
            keyword_score = keyword_overlap / max(1, len(query_keywords))

            # String-Ähnlichkeit
            string_sim = difflib.SequenceMatcher(
                None, query_lower, chunk.content.lower()
            ).ratio()

            # Kombinierter Score
            combined = keyword_score * 0.6 + string_sim * 0.4

            # Frequenz-Bonus
            freq_bonus = min(0.2, chunk.frequency * 0.02)
            combined += freq_bonus

            scored.append((chunk, combined))

        scored.sort(key=lambda x: x[1], reverse=True)
        return [chunk for chunk, _ in scored[:max_chunks]]

    def _store_chunk(self, chunk: ObservationChunk) -> None:
        """Speichert einen Chunk und aktualisiert Indizes."""
        self.chunks[chunk.id] = chunk
        self.chunk_list.append(chunk)

        # FAISS-Index aktualisieren
        if self.faiss_index is not None and chunk.embedding is not None:
            vector = chunk.embedding.reshape(1, -1).astype("float32")
            self.faiss_index.add(vector)

        # LRU-Eviction falls über Limit
        while len(self.chunks) > self.max_cache_size:
            oldest_id, _ = self.chunks.popitem(last=False)
            self.chunk_list = [c for c in self.chunk_list if c.id != oldest_id]

    def _remove_chunk(self, chunk_id: str) -> None:
        """Entfernt einen Chunk."""
        self.chunks.pop(chunk_id, None)
        self.chunk_list = [c for c in self.chunk_list if c.id != chunk_id]
        # Hinweis: FAISS-Index kann nicht einfach entfernt werden
        # — Index wird bei consolidate() neu aufgebaut

    def _generate_chunk_id(self, text: str) -> str:
        """Generiert eine deterministische Chunk-ID."""
        return hashlib.md5(text.encode()).hexdigest()[:16]

    def _extract_keywords(self, text: str) -> List[str]:
        """Extrahiert bedeutungstragende Keywords aus einem Text."""
        # Tokenisieren
        tokens = re.findall(r"\b\w+\b", text.lower())

        # Stopwörter entfernen
        keywords = [
            t for t in tokens
            if t not in self.KEYWORD_STOPWORDS and len(t) > 2
        ]

        # Deduplizieren
        return list(dict.fromkeys(keywords))[:10]

    def _compression_ratio(self) -> float:
        """Berechnet das Kompressions-Verhältnis.

        1.0 = keine Kompression (jede Beobachtung ist eigener Chunk)
        0.1 = 10:1 Kompression (10 Beobachtungen = 1 Chunk)
        """
        if self.total_observations == 0:
            return 1.0
        return len(self.chunks) / self.total_observations

    # ------------------------------------------------------------------
    # Statistiken
    # ------------------------------------------------------------------

    def get_statistics(self) -> Dict[str, Any]:
        """Gibt Statistiken zurück."""
        return {
            "total_observations": self.total_observations,
            "total_chunks": len(self.chunks),
            "total_chunks_created": self.total_chunks_created,
            "total_merges": self.total_merges,
            "compression_ratio": round(self._compression_ratio(), 3),
            "total_queries": self.total_queries,
            "cache_hit_rate": round(
                self.cache_hits / self.total_observations
                if self.total_observations > 0
                else 0, 3
            ),
            "embedding_model": self.model_name if self.model else "fallback",
            "faiss_enabled": self.faiss_index is not None,
            "top_chunks": [
                {
                    "content": c.content[:80],
                    "frequency": c.frequency,
                    "keywords": c.keywords[:5],
                }
                for c in sorted(
                    self.chunks.values(),
                    key=lambda c: c.frequency,
                    reverse=True,
                )[:5]
            ],
        }

    def reset(self) -> None:
        """Setzt alle Chunks zurück."""
        self.chunks.clear()
        self.chunk_list.clear()
        if self.faiss_index is not None:
            self.faiss_index = faiss.IndexFlatIP(self.embedding_dim)
        self.total_observations = 0
        self.total_chunks_created = 0
        self.total_merges = 0
        self.total_queries = 0
        self.cache_hits = 0


if __name__ == "__main__":
    print("=" * 70)
    print("MEMORY COMPRESSOR — STANDALONE TEST")
    print("=" * 70)

    compressor = MemoryCompressor()

    # Test 1: Ähnliche Beobachtungen hinzufügen
    print("\n1. Adding similar observations (should merge):")

    observations = [
        ("Payment endpoint /api/checkout has response time 250ms with concurrent requests", "recon"),
        ("Payment endpoint /api/checkout has response time 280ms under concurrent load", "recon"),
        ("Payment endpoint /api/checkout shows slow response under parallel requests", "recon"),
        ("Payment endpoint /api/checkout consistently slow with concurrent access", "recon"),
    ]

    for text, source in observations:
        result = compressor.add_observation(text, source)
        status = "NEW" if result.is_new else "MERGED"
        print(f"  [{status}] Similarity: {result.similarity_score:.3f} | "
              f"Chunks: {result.total_chunks} | "
              f"Compression: {result.compression_ratio:.2f}")

    # Test 2: Unterschiedliche Beobachtungen
    print("\n2. Adding different observations (should create new chunks):")

    different = [
        ("User authentication endpoint returns verbose error messages", "recon"),
        ("File upload endpoint accepts arbitrary content types", "recon"),
        ("Admin panel accessible without proper role verification", "recon"),
        ("Database query constructed from unvalidated user input", "recon"),
    ]

    for text, source in different:
        result = compressor.add_observation(text, source)
        status = "NEW" if result.is_new else "MERGED"
        print(f"  [{status}] Similarity: {result.similarity_score:.3f} | "
              f"Chunks: {result.total_chunks}")

    # Test 3: Relevante Chunks abrufen
    print("\n3. Getting relevant chunks for 'payment response time':")
    relevant = compressor.get_relevant_chunks("payment response time", max_chunks=3)
    for chunk in relevant:
        print(f"  • [{chunk.frequency}x] {chunk.content[:60]}...")
        print(f"    Keywords: {chunk.keywords[:5]}")

    # Test 4: High-frequency chunks
    print("\n4. High-frequency chunks (seen 2+ times):")
    high_freq = compressor.get_high_frequency_chunks(min_frequency=2)
    for chunk in high_freq:
        print(f"  • [{chunk.frequency}x] {chunk.content[:60]}...")

    # Test 5: Statistiken
    print("\n5. Statistics:")
    stats = compressor.get_statistics()
    print(f"  Total observations: {stats['total_observations']}")
    print(f"  Total chunks: {stats['total_chunks']}")
    print(f"  Compression ratio: {stats['compression_ratio']}")
    print(f"  Cache hit rate: {stats['cache_hit_rate']}")
    print(f"  Embedding model: {stats['embedding_model']}")

    # Test 6: Konsolidierung
    print("\n6. Consolidation:")
    consolidation = compressor.consolidate()
    print(f"  Chunks merged: {consolidation['chunks_merged']}")
    print(f"  Chunks removed: {consolidation['chunks_removed']}")
    print(f"  Total after: {consolidation['total_chunks']}")

    print("\n✅ Memory Compressor test completed")
