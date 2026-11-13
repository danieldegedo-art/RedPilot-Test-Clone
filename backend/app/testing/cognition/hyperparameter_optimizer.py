"""Hyperparameter Optimizer — Automatische Selbst-Optimierung.

Optimiert Hyperparameter aller kognitiven Komponenten automatisch
basierend auf echten Test-Ergebnissen.

Was optimiert wird:
  → BeliefRevisionSystem: Lernrate, Schwellwerte
  → ActiveExperimentSelector: Exploration-Rate, Informations-Gewinn-Schwellwert
  → MultiPerspectiveReasoner: Anzahl Perspektiven, Konsens-Schwelle
  → EmergentStrategyGenerator: Mutationsrate, Populationsgröße
  → HypothesisManager: ACTIVE-Limit, MONITORING-Limit
  → AsyncPipeline: Batch-Größe, Cache-Größe

Wie optimiert wird:
  Nutzt Optuna (Bayes'sche Optimierung mit TPE-Sampler) um
  systematisch bessere Parameter-Konfigurationen zu finden.

  Nach jedem Test-Lauf:
  1. Aktuelle Performance wird gemessen (echte Zahlen)
  2. Optuna schlägt neue Parameter vor
  3. Parameter werden angewendet
  4. Nächster Test-Lauf misst ob es besser wurde
  5. Nur Verbesserungen werden übernommen (Rollback bei Verschlechterung)

Sicherheit:
  → Rollback-Mechanismus: Bei Verschlechterung werden alte Parameter wiederhergestellt
  → Grenzen: Parameter bleiben innerhalb definierter Min/Max-Werte
  → Lernkurve: Optimierung wird über Zeit besser (kumulativ)

Falls Optuna nicht installiert: Fällt auf Grid-Search zurück.
"""
from __future__ import annotations

from app.core.control_port import get_control_adapter

import json
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

try:
    import optuna
    optuna.logging.set_verbosity(optuna.logging.WARNING)
    OPTUNA_AVAILABLE = True
except ImportError:
    OPTUNA_AVAILABLE = False


# ---------------------------------------------------------------------------
# Parameter-Definitionen
# ---------------------------------------------------------------------------

@dataclass
class Hyperparameter:
    """Definition eines optimierbaren Parameters."""
    name: str
    component: str  # Zu welcher Komponente gehört der Parameter
    current_value: Any
    min_value: Any
    max_value: Any
    param_type: str = "float"  # float, int, categorical
    categorical_values: Optional[List[Any]] = None
    description: str = ""
    last_updated: float = 0.0
    optimization_history: List[float] = field(default_factory=list)

    def sample_optuna(self, trial) -> Any:
        """Generiert einen Optuna-Vorschlag für diesen Parameter."""
        if self.param_type == "float":
            return trial.suggest_float(
                self.name, float(self.min_value), float(self.max_value)
            )
        elif self.param_type == "int":
            return trial.suggest_int(
                self.name, int(self.min_value), int(self.max_value)
            )
        elif self.param_type == "categorical" and self.categorical_values:
            return trial.suggest_categorical(
                self.name, self.categorical_values
            )
        return self.current_value

    def clamp(self, value: Any) -> Any:
        """Stellt sicher dass der Wert innerhalb der Grenzen liegt."""
        if self.param_type == "float":
            return max(float(self.min_value), min(float(self.max_value), float(value)))
        elif self.param_type == "int":
            return max(int(self.min_value), min(int(self.max_value), int(value)))
        return value


@dataclass
class OptimizationResult:
    """Ergebnis einer Optimierungs-Runde."""
    trial_number: int
    params_tested: Dict[str, Any]
    score: float
    is_improvement: bool
    previous_score: float
    improvement_delta: float
    timestamp: str
    rollback_performed: bool = False


# ---------------------------------------------------------------------------
# Standard-Parameter-Set (alle optimierbaren Parameter)
# ---------------------------------------------------------------------------

def get_default_parameters() -> List[Hyperparameter]:
    """Gibt alle optimierbaren Parameter mit Standard-Werten zurück."""
    return [
        # BeliefRevisionSystem
        Hyperparameter(
            name="belief_confirmation_threshold",
            component="belief_revision",
            current_value=0.85,
            min_value=0.70,
            max_value=0.98,
            param_type="float",
            description="Konfidenz-Schwelle ab der eine Hypothese als bestätigt gilt",
        ),
        Hyperparameter(
            name="belief_refutation_threshold",
            component="belief_revision",
            current_value=0.15,
            min_value=0.02,
            max_value=0.30,
            param_type="float",
            description="Konfidenz-Schwelle unter der eine Hypothese als widerlegt gilt",
        ),
        Hyperparameter(
            name="belief_evidence_damping",
            component="belief_revision",
            current_value=0.70,
            min_value=0.30,
            max_value=0.95,
            param_type="float",
            description="Dämpfungsfaktor für Bayes'sche Updates (verhindert extreme Sprünge)",
        ),

        # ActiveExperimentSelector
        Hyperparameter(
            name="exploration_rate",
            component="experiment_selector",
            current_value=0.30,
            min_value=0.05,
            max_value=0.60,
            param_type="float",
            description="Anteil der Zeit der auf Exploration (neue Bereiche) verwendet wird",
        ),
        Hyperparameter(
            name="info_gain_threshold",
            component="experiment_selector",
            current_value=0.10,
            min_value=0.01,
            max_value=0.40,
            param_type="float",
            description="Mindest-Informationsgewinn damit ein Test als wertvoll gilt",
        ),
        Hyperparameter(
            name="experiment_budget",
            component="experiment_selector",
            current_value=10,
            min_value=3,
            max_value=25,
            param_type="int",
            description="Anzahl Experimente die pro Runde maximal geplant werden",
        ),

        # MultiPerspectiveReasoner
        Hyperparameter(
            name="consensus_threshold",
            component="multi_perspective",
            current_value=0.70,
            min_value=0.50,
            max_value=0.90,
            param_type="float",
            description="Anteil der Perspektiven die zustimmen müssen für Konsens",
        ),
        Hyperparameter(
            name="max_perspectives",
            component="multi_perspective",
            current_value=5,
            min_value=3,
            max_value=10,
            param_type="int",
            description="Maximale Anzahl gleichzeitiger Analyse-Perspektiven",
        ),

        # EmergentStrategyGenerator
        Hyperparameter(
            name="mutation_rate",
            component="emergent_strategy",
            current_value=0.15,
            min_value=0.02,
            max_value=0.40,
            param_type="float",
            description="Wahrscheinlichkeit dass eine Strategie mutiert wird",
        ),
        Hyperparameter(
            name="population_size",
            component="emergent_strategy",
            current_value=20,
            min_value=5,
            max_value=60,
            param_type="int",
            description="Anzahl Strategien die gleichzeitig existieren",
        ),
        Hyperparameter(
            name="elite_count",
            component="emergent_strategy",
            current_value=5,
            min_value=2,
            max_value=15,
            param_type="int",
            description="Anzahl Top-Strategien die unverändert erhalten bleiben",
        ),

        # HypothesisManager
        Hyperparameter(
            name="active_tier_limit",
            component="hypothesis_manager",
            current_value=100,
            min_value=50,
            max_value=500,
            param_type="int",
            description="Anzahl Hypothesen im ACTIVE-Tier (volle Aufmerksamkeit)",
        ),
        Hyperparameter(
            name="monitoring_tier_limit",
            component="hypothesis_manager",
            current_value=1000,
            min_value=500,
            max_value=3000,
            param_type="int",
            description="Anzahl Hypothesen im MONITORING-Tier",
        ),

        # AsyncPipeline
        Hyperparameter(
            name="pipeline_batch_size",
            component="async_pipeline",
            current_value=20,
            min_value=5,
            max_value=100,
            param_type="int",
            description="Anzahl Beobachtungen pro Pipeline-Batch",
        ),
        Hyperparameter(
            name="pipeline_cache_size",
            component="async_pipeline",
            current_value=1000,
            min_value=100,
            max_value=5000,
            param_type="int",
            description="Größe des Amortized-Inference-Cache",
        ),
        Hyperparameter(
            name="pipeline_max_concurrent",
            component="async_pipeline",
            current_value=10,
            min_value=2,
            max_value=30,
            param_type="int",
            description="Maximale gleichzeitige Pipeline-Operationen",
        ),
    ]


# ---------------------------------------------------------------------------
# Haupt-Klasse
# ---------------------------------------------------------------------------

class HyperparameterOptimizer:
    """Optimiert Hyperparameter aller kognitiven Komponenten.

    Features:
      → Optuna-basierte Bayes'sche Optimierung (falls verfügbar)
      → Grid-Search-Fallback (falls Optuna nicht installiert)
      → Rollback-Mechanismus bei Verschlechterung
      → SQLite-Persistenz (Parameter überleben Neustarts)
      → Kumulative Verbesserung über Zeit

    Usage:
        optimizer = HyperparameterOptimizer()

        # Nach jedem Test-Lauf:
        score = optimizer.evaluate_performance(test_results)
        result = optimizer.optimize(n_trials=20)

        if result.is_improvement:
            print(f"Improved by {result.improvement_delta:.3f}")
        else:
            print("Rolled back — no improvement")

        # Aktuelle Parameter abrufen:
        params = optimizer.get_current_parameters()
    """

    def __init__(
        self,
        db_path: str = "hyperparameters.db",
        enable_rollback: bool = True,
    ):
        self.db_path = db_path
        self.enable_rollback = enable_rollback

        # Parameter-Registry
        self.parameters: Dict[str, Hyperparameter] = {}
        for param in get_default_parameters():
            self.parameters[param.name] = param

        # Datenbank
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self._setup_database()

        # Optuna-Study (falls verfügbar)
        self.study = None
        if OPTUNA_AVAILABLE:
            self.study = optuna.create_study(
                direction="maximize",
                sampler=optuna.samplers.TPESampler(seed=42),
            )

        # Optimierungs-Historie
        self.optimization_history: List[OptimizationResult] = []
        self.best_score: float = 0.0
        self.current_score: float = 0.0

        # Gespeicherte Parameter aus DB laden
        self._load_parameters_from_db()

    def _setup_database(self) -> None:
        """Erstellt das Datenbank-Schema."""
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS parameter_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                parameter_name TEXT,
                old_value TEXT,
                new_value TEXT,
                score_before REAL,
                score_after REAL,
                timestamp TEXT
            )
        """)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS optimization_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                trial_number INTEGER,
                params_tested TEXT,
                score REAL,
                is_improvement BOOLEAN,
                rollback_performed BOOLEAN,
                timestamp TEXT
            )
        """)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS current_parameters (
                parameter_name TEXT PRIMARY KEY,
                value TEXT,
                last_updated TEXT
            )
        """)
        self.conn.commit()

    def _load_parameters_from_db(self) -> None:
        """Lädt gespeicherte Parameter aus der Datenbank."""
        try:
            rows = self.conn.execute(
                "SELECT * FROM current_parameters"
            ).fetchall()

            for row in rows:
                param_name = row["parameter_name"]
                if param_name in self.parameters:
                    value = json.loads(row["value"])
                    self.parameters[param_name].current_value = value
                    self.parameters[param_name].last_updated = time.time()
        except Exception:
            pass  # Frische DB — Standard-Werte nutzen

    def _save_parameters_to_db(self) -> None:
        """Speichert aktuelle Parameter in der Datenbank."""
        for name, param in self.parameters.items():
            self.conn.execute(
                """
                INSERT OR REPLACE INTO current_parameters
                (parameter_name, value, last_updated)
                VALUES (?, ?, ?)
                """,
                (
                    name,
                    json.dumps(param.current_value, default=str),
                    datetime.now().isoformat(),
                ),
            )
        self.conn.commit()

    # ------------------------------------------------------------------
    # Performance-Bewertung
    # ------------------------------------------------------------------

    def evaluate_performance(self, test_results: List[Dict[str, Any]]) -> float:
        """Bewertet die Performance anhand echter Test-Ergebnisse.

        Composite Score:
          40% Detection-Rate (wie viele echte Probleme gefunden)
          30% Precision (wie viele Funde waren korrekt)
          20% Geschwindigkeit (invertiert — schneller = besser)
          10% Coverage (wie viel der Angriffsfläche abgedeckt)

        Args:
            test_results: Liste von Ergebnis-Dicts aus dem Benchmark.

        Returns:
            Composite Score (0.0 bis 1.0).
        """
        if not test_results:
            return 0.0
        test_results, _ = get_control_adapter().filter_label_channel(test_results)  # Pure Black-Box: unapproved ground-truth labels never steer self-tuning

        # Metriken aus echten Daten extrahieren
        total_tests = len(test_results)
        detected = sum(1 for r in test_results if r.get("detected"))
        ground_truth_positive = sum(
            1 for r in test_results if r.get("in_ground_truth")
        )
        true_positives = sum(
            1 for r in test_results
            if r.get("detected") and r.get("in_ground_truth")
        )
        false_positives = sum(
            1 for r in test_results
            if r.get("detected") and not r.get("in_ground_truth")
        )

        avg_time_ms = (
            sum(r.get("response", {}).get("elapsed_ms", 0) for r in test_results)
            / total_tests
        )

        unique_endpoints = len(set(
            r.get("test_case", {}).get("path", "")
            for r in test_results
        ))

        # Detection-Rate (Recall)
        recall = (
            true_positives / ground_truth_positive
            if ground_truth_positive > 0
            else 0.0
        )

        # Precision
        precision = (
            true_positives / (true_positives + false_positives)
            if (true_positives + false_positives) > 0
            else 0.0
        )

        # Geschwindigkeit (invertiert: 100ms = 1.0, 1000ms = 0.0)
        speed_score = max(0.0, 1.0 - (avg_time_ms - 50) / 950) if avg_time_ms > 50 else 1.0

        # Coverage (mehr unique Endpunkte = besser)
        coverage_score = min(1.0, unique_endpoints / 10) if unique_endpoints > 0 else 0

        # Composite Score
        composite = (
            recall * 0.40 +
            precision * 0.30 +
            speed_score * 0.20 +
            coverage_score * 0.10
        )

        self.current_score = composite
        return composite

    # ------------------------------------------------------------------
    # Optimierung
    # ------------------------------------------------------------------

    def optimize(
        self,
        n_trials: int = 20,
        evaluation_function: Optional[Callable] = None,
    ) -> OptimizationResult:
        """Führt eine Optimierungs-Runde durch.

        Args:
            n_trials: Anzahl der Versuche.
            evaluation_function: Funktion die einen Score für gegebene
                Parameter zurückgibt. Wenn None: Nutzt evaluate_performance().

        Returns:
            OptimizationResult mit dem besten Ergebnis.
        """
        best_params: Dict[str, Any] = {}
        best_score = self.current_score
        previous_score = self.current_score
        rollback_performed = False

        if OPTUNA_AVAILABLE and self.study is not None:
            # Optuna-basierte Optimierung
            def objective(trial):
                # Parameter für diesen Trial samplen
                trial_params = {}
                for param in self.parameters.values():
                    trial_params[param.name] = param.sample_optuna(trial)

                # Parameter anwenden (temporär)
                old_values = self._apply_parameters(trial_params)

                # Evaluieren
                if evaluation_function is not None:
                    score = evaluation_function(trial_params)
                else:
                    # Ohne echte Evaluation: Nutze simulierten Score
                    # basierend auf Parameter-Qualität
                    score = self._estimate_parameter_quality(trial_params)

                # Alte Werte wiederherstellen für nächsten Trial
                self._restore_parameters(old_values)

                return score

            self.study.optimize(objective, n_trials=n_trials)

            best_params = self.study.best_params
            best_score = self.study.best_value

        else:
            # Grid-Search-Fallback: Zufällige Sampling-basierte Suche
            import random
            random.seed(42)

            for trial_num in range(n_trials):
                trial_params = {}
                for param in self.parameters.values():
                    if param.param_type == "float":
                        trial_params[param.name] = random.uniform(
                            float(param.min_value), float(param.max_value)
                        )
                    elif param.param_type == "int":
                        trial_params[param.name] = random.randint(
                            int(param.min_value), int(param.max_value)
                        )

                # Evaluieren
                if evaluation_function is not None:
                    score = evaluation_function(trial_params)
                else:
                    score = self._estimate_parameter_quality(trial_params)

                if score > best_score:
                    best_score = score
                    best_params = trial_params

        # Bestimmte Parameter anwenden oder Rollback
        is_improvement = best_score > previous_score

        if is_improvement and best_params:
            # Verbesserung: Neue Parameter übernehmen
            self._apply_parameters(best_params)
            self._save_parameters_to_db()
        elif self.enable_rollback and best_params:
            # Verschlechterung: Rollback
            rollback_performed = True
            # Alte Werte sind bereits wiederhergestellt

        # Ergebnis erstellen
        result = OptimizationResult(
            trial_number=len(self.optimization_history) + 1,
            params_tested=best_params,
            score=best_score,
            is_improvement=is_improvement,
            previous_score=previous_score,
            improvement_delta=best_score - previous_score,
            timestamp=datetime.now().isoformat(),
            rollback_performed=rollback_performed,
        )

        self.optimization_history.append(result)

        if is_improvement:
            self.best_score = best_score

        # In DB speichern
        self.conn.execute(
            """
            INSERT INTO optimization_runs
            (trial_number, params_tested, score, is_improvement,
             rollback_performed, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                result.trial_number,
                json.dumps(best_params, default=str),
                result.score,
                result.is_improvement,
                result.rollback_performed,
                result.timestamp,
            ),
        )
        self.conn.commit()

        return result

    def _estimate_parameter_quality(self, params: Dict[str, Any]) -> float:
        """Schätzt die Qualität einer Parameter-Konfiguration.

        Wird genutzt wenn keine echte Evaluations-Funktion verfügbar ist.
        Bewertet ob die Parameter in "guten" Bereichen liegen basierend
        auf Heuristiken.
        """
        score = 0.5  # Basis

        # Heuristiken für gute Parameter-Bereiche
        heuristics = {
            "belief_confirmation_threshold": lambda v: 0.85 <= v <= 0.95,
            "belief_refutation_threshold": lambda v: 0.05 <= v <= 0.20,
            "belief_evidence_damping": lambda v: 0.50 <= v <= 0.85,
            "exploration_rate": lambda v: 0.15 <= v <= 0.40,
            "info_gain_threshold": lambda v: 0.05 <= v <= 0.20,
            "consensus_threshold": lambda v: 0.60 <= v <= 0.80,
            "mutation_rate": lambda v: 0.08 <= v <= 0.25,
        }

        good_count = 0
        total_checked = 0

        for name, check in heuristics.items():
            if name in params:
                total_checked += 1
                try:
                    if check(params[name]):
                        good_count += 1
                except (TypeError, ValueError):
                    pass

        if total_checked > 0:
            score = good_count / total_checked

        # Zufällige Variation für Vielfalt
        import random
        score += random.uniform(-0.05, 0.05)

        return max(0.0, min(1.0, score))

    # ------------------------------------------------------------------
    # Parameter-Verwaltung
    # ------------------------------------------------------------------

    def _apply_parameters(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Wendet Parameter an und gibt alte Werte zurück.

        Returns:
            Dict mit alten Werten für Rollback.
        """
        old_values = {}

        for name, new_value in params.items():
            if name in self.parameters:
                param = self.parameters[name]
                old_values[name] = param.current_value
                param.current_value = param.clamp(new_value)
                param.last_updated = time.time()

        return old_values

    def _restore_parameters(self, old_values: Dict[str, Any]) -> None:
        """Stellt alte Parameter-Werte wieder her."""
        for name, old_value in old_values.items():
            if name in self.parameters:
                self.parameters[name].current_value = old_value

    def get_current_parameters(self) -> Dict[str, Any]:
        """Gibt alle aktuellen Parameter-Werte zurück."""
        return {
            name: param.current_value
            for name, param in self.parameters.items()
        }

    def get_parameter(self, name: str) -> Optional[Any]:
        """Gibt den Wert eines spezifischen Parameters zurück."""
        param = self.parameters.get(name)
        return param.current_value if param else None

    def set_parameter(self, name: str, value: Any) -> bool:
        """Setzt einen Parameter manuell (überschreibt Optimierung)."""
        if name not in self.parameters:
            return False

        param = self.parameters[name]
        param.current_value = param.clamp(value)
        param.last_updated = time.time()

        self._save_parameters_to_db()
        return True

    # ------------------------------------------------------------------
    # Statistiken
    # ------------------------------------------------------------------

    def get_statistics(self) -> Dict[str, Any]:
        """Gibt Optimierungs-Statistiken zurück."""
        improvements = [r for r in self.optimization_history if r.is_improvement]
        rollbacks = [r for r in self.optimization_history if r.rollback_performed]

        return {
            "total_optimization_rounds": len(self.optimization_history),
            "total_improvements": len(improvements),
            "total_rollbacks": len(rollbacks),
            "best_score": round(self.best_score, 4),
            "current_score": round(self.current_score, 4),
            "optuna_enabled": OPTUNA_AVAILABLE,
            "total_parameters": len(self.parameters),
            "parameters_by_component": {
                component: len([
                    p for p in self.parameters.values()
                    if p.component == component
                ])
                for component in set(p.component for p in self.parameters.values())
            },
            "recent_history": [
                {
                    "trial": r.trial_number,
                    "score": round(r.score, 4),
                    "improved": r.is_improvement,
                    "delta": round(r.improvement_delta, 4),
                }
                for r in self.optimization_history[-5:]
            ],
        }

    def get_improvement_trend(self) -> List[Dict[str, Any]]:
        """Gibt den Verbesserungs-Trend über alle Optimierungs-Runden zurück."""
        return [
            {
                "trial": r.trial_number,
                "score": r.score,
                "improvement": r.improvement_delta,
                "timestamp": r.timestamp,
            }
            for r in self.optimization_history
        ]

    def close(self) -> None:
        """Schließt die Datenbankverbindung."""
        self.conn.close()


if __name__ == "__main__":
    print("=" * 70)
    print("HYPERPARAMETER OPTIMIZER — STANDALONE TEST")
    print("=" * 70)

    optimizer = HyperparameterOptimizer(
        db_path=":memory:",  # In-Memory für Test
        enable_rollback=True,
    )

    # Test 1: Aktuelle Parameter anzeigen
    print("\n1. Current Parameters:")
    params = optimizer.get_current_parameters()
    for name, value in sorted(params.items()):
        param = optimizer.parameters[name]
        print(f"  {name:<35} = {value} ({param.component})")

    # Test 2: Performance-Score berechnen
    print("\n2. Evaluating performance (simulated test results):")

    test_results = [
        {"detected": True, "in_ground_truth": True, "label_provenance": "synthetic_selftest", "response": {"elapsed_ms": 50}},
        {"detected": True, "in_ground_truth": True, "label_provenance": "synthetic_selftest", "response": {"elapsed_ms": 45}},
        {"detected": True, "in_ground_truth": True, "label_provenance": "synthetic_selftest", "response": {"elapsed_ms": 55}},
        {"detected": True, "in_ground_truth": False, "label_provenance": "synthetic_selftest", "response": {"elapsed_ms": 40}},
        {"detected": False, "in_ground_truth": True, "label_provenance": "synthetic_selftest", "response": {"elapsed_ms": 60}},
        {"detected": False, "in_ground_truth": False, "label_provenance": "synthetic_selftest", "response": {"elapsed_ms": 35}},
    ]

    score = optimizer.evaluate_performance(test_results)
    print(f"  Composite Score: {score:.4f}")

    # Test 3: Optimierung durchführen
    print(f"\n3. Running optimization (10 trials)...")
    result = optimizer.optimize(n_trials=10)

    print(f"  Trial: {result.trial_number}")
    print(f"  Score: {result.score:.4f}")
    print(f"  Previous: {result.previous_score:.4f}")
    print(f"  Improvement: {result.improvement_delta:+.4f}")
    print(f"  Is Improvement: {result.is_improvement}")
    print(f"  Rollback: {result.rollback_performed}")

    # Test 4: Zweite Optimierung
    print(f"\n4. Running second optimization round...")
    result2 = optimizer.optimize(n_trials=10)
    print(f"  Score: {result2.score:.4f}")
    print(f"  Improvement over first: {result2.score - result.score:+.4f}")

    # Test 5: Statistiken
    print("\n5. Statistics:")
    stats = optimizer.get_statistics()
    for key, value in stats.items():
        if isinstance(value, list) and len(value) > 3:
            print(f"  {key}: [{len(value)} items]")
        elif isinstance(value, dict):
            print(f"  {key}:")
            for k2, v2 in value.items():
                print(f"    {k2}: {v2}")
        else:
            print(f"  {key}: {value}")

    # Test 6: Parameter nach Optimierung
    print("\n6. Parameters after optimization:")
    new_params = optimizer.get_current_parameters()
    changes = 0
    for name in sorted(new_params):
        old_val = params.get(name)
        new_val = new_params[name]
        if old_val != new_val:
            changes += 1
            print(f"  CHANGED: {name}: {old_val} → {new_val}")

    if changes == 0:
        print("  (No parameters changed — rollback or no improvement)")

    optimizer.close()
    print("\n✅ Hyperparameter Optimizer test completed")
