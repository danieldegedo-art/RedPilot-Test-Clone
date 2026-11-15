"""Coverage Mapper — Graph-basierte Test-Abdeckungs-Analyse.

Kartiert die gesamte Test-Reichweite des Systems unter Test und
berechnet wie viel davon bereits durch Tests abgedeckt ist.

Was kartiert wird:
  → Alle verfügbaren Endpunkte (aus openapi.json oder Recon)
  → Alle Parameter pro Endpunkt
  → Alle HTTP-Methoden pro Endpunkt
  → Alle Datenflüsse zwischen Endpunkten

Was berechnet wird:
  → Coverage-Percentage: Wie viel ist getestet?
  → Ungedeckte Bereiche: Was fehlt noch?
  → Lücken-Erkennung: Welche Endpunkte/Parameter wurden nie geprüft?
  → Test-Empfehlungen: Was sollte als nächstes getestet werden?

Der Mapper nutzt NetworkX für Graph-basierte Analyse:
  → Endpunkte = Nodes
  → Datenflüsse = Edges
  → Coverage = gefärbte Nodes (getestet vs. ungetestet)
  → Lücken = ungefärbte Bereiche im Graph
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import networkx as nx
    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False


# ---------------------------------------------------------------------------
# Daten-Klassen
# ---------------------------------------------------------------------------

@dataclass
class EndpointNode:
    """Ein Endpunkt im Coverage-Graph."""
    path: str
    method: str
    parameters: List[str] = field(default_factory=list)
    has_auth: bool = False
    is_tested: bool = False
    test_count: int = 0
    last_tested: Optional[str] = None
    check_types_tested: Set[str] = field(default_factory=set)
    node_id: str = ""

    def __post_init__(self):
        if not self.node_id:
            self.node_id = f"{self.method}:{self.path}"


@dataclass
class DataFlow:
    """Ein Datenfluss zwischen Endpunkten."""
    source_id: str
    target_id: str
    data_type: str = "unknown"
    description: str = ""


@dataclass
class CoverageGap:
    """Eine identifizierte Lücke in der Test-Abdeckung."""
    gap_type: str  # "endpoint_untested", "method_untested", "parameter_untested", "flow_untested"
    endpoint: str
    method: str = ""
    parameter: str = ""
    description: str = ""
    severity: str = "medium"  # "high" wenn auth erforderlich, "medium" sonst
    recommended_check: str = ""
    estimated_test_time_s: float = 2.0


@dataclass
class CoverageReport:
    """Vollständiger Abdeckungs-Bericht."""
    total_endpoints: int = 0
    tested_endpoints: int = 0
    coverage_percentage: float = 0.0
    total_methods: int = 0
    tested_methods: int = 0
    method_coverage_percentage: float = 0.0
    total_parameters: int = 0
    tested_parameters: int = 0
    parameter_coverage_percentage: float = 0.0
    gaps: List[CoverageGap] = field(default_factory=list)
    recommendations: List[Dict[str, Any]] = field(default_factory=list)
    graph_density: float = 0.0
    untested_critical_paths: List[List[str]] = field(default_factory=list)


@dataclass
class TestRecommendation:
    """Empfohlener nächster Test basierend auf Lücken."""
    priority: str  # "HIGH", "MEDIUM", "LOW"
    check_type: str
    endpoint: str
    method: str
    reason: str
    estimated_time_s: float
    potential_impact: str


# ---------------------------------------------------------------------------
# Check-Type-Empfehlungs-Matrix
# ---------------------------------------------------------------------------

# Welche Check-Types sind für welche Endpunkt-Muster relevant?
ENDPOINT_CHECK_MATRIX: Dict[str, List[str]] = {
    "/login": ["query_construction_issue", "session_integrity", "request_frequency_control"],
    "/auth": ["access_control_inconsistency", "token_signature_integrity", "session_integrity"],
    "/admin": ["access_control_inconsistency", "authorization_enforcement_gap", "response_field_filtering"],
    "/user": ["resource_ownership_consistency", "input_field_whitelisting", "response_field_filtering"],
    "/order": ["concurrent_state_consistency", "input_field_whitelisting", "query_construction_issue"],
    "/payment": ["input_field_whitelisting", "webhook_integrity_gap", "duplicate_handling_gap"],
    "/webhook": ["webhook_integrity_gap", "duplicate_handling_gap", "response_field_filtering"],
    "/upload": ["upload_content_validation", "file_path_validation", "process_execution_validation"],
    "/search": ["query_construction_issue", "output_encoding_gap", "document_store_query_validation"],
    "/config": ["configuration_hardening_gap", "response_field_filtering"],
    "/debug": ["configuration_hardening_gap", "error_message_disclosure"],
    "/api": ["query_construction_issue", "access_control_inconsistency", "response_field_filtering"],
}


# ---------------------------------------------------------------------------
# Haupt-Klasse
# ---------------------------------------------------------------------------

class CoverageMapper:
    """Kartiert Test-Abdeckung und identifiziert Lücken.

    Usage:
        mapper = CoverageMapper()

        # Endpunkte aus openapi.json hinzufügen
        mapper.add_endpoints_from_openapi(openapi_spec)

        # Manuell Endpunkte hinzufügen
        mapper.add_endpoint("/api/users", "GET", parameters=["id", "fields"])
        mapper.add_endpoint("/api/users", "POST", parameters=["name", "email"])

        # Test-Ergebnisse aufzeichnen
        mapper.record_test("/api/users", "GET", "resource_ownership_consistency")
        mapper.record_test("/api/users", "POST", "input_field_whitelisting")

        # Abdeckung berechnen
        report = mapper.calculate_coverage()

        # Lücken finden
        gaps = mapper.find_gaps()

        # Empfehlungen generieren
        recommendations = mapper.generate_test_recommendations()
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path

        # Graph (falls NetworkX verfügbar)
        self.graph = nx.DiGraph() if NETWORKX_AVAILABLE else None

        # Endpunkt-Registry
        self.endpoints: Dict[str, EndpointNode] = {}
        self.data_flows: List[DataFlow] = []

        # Test-Historie -- COUNT only, not the rows themselves. Verified
        # (grep across the whole backend) that nothing anywhere reads the
        # row contents; get_statistics() only ever needed len(...). Kept
        # as a bare int specifically so _load_existing_coverage() below
        # can stop pulling the ENTIRE historical test_history table into a
        # Python list on every single CoverageMapper construction (i.e.
        # every run) -- see that method's docstring for why that was a
        # real, growing cost once cross-run accumulation started working.
        self._test_history_count: int = 0

        # Parameter-Registry (endpoint_id → parameter → tested)
        self.parameter_registry: Dict[str, Dict[str, bool]] = {}

        # Datenbank (optional)
        self.conn = None
        self._lock = threading.RLock()
        if db_path:
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
            self.conn = sqlite3.connect(db_path, check_same_thread=False)
            self.conn.row_factory = sqlite3.Row
            # Same WAL/NORMAL rationale as PersistentMemoryStore._init_database
            # (this project's other target-scoped, cross-run SQLite store):
            # readers (get_coverage_report(), get_statistics()) no longer
            # block behind an in-flight asyncio.to_thread-offloaded write.
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA synchronous=NORMAL")
            self._setup_database()
            self._load_existing_coverage()

    def _load_existing_coverage(self) -> None:
        """Rebuilds in-memory endpoint/graph/history state from the
        persisted DB. Without this, every new CoverageMapper instance --
        one per run, since it's constructed fresh inside CognitiveEngine
        each time -- started from an empty graph even though its DB file
        already held every route ever tested against this target: writes
        were accumulating correctly, nothing was ever reading them back.

        Note: the endpoint_coverage table doesn't persist `parameters` or
        `has_auth` (they were never part of its schema), so those two
        fields come back at their dataclass defaults for reloaded
        endpoints; everything actually used by coverage calculation and
        gap analysis (is_tested, test_count, check_types_tested,
        last_tested) round-trips fully.
        """
        for row in self.conn.execute("SELECT * FROM endpoint_coverage"):
            node = EndpointNode(
                path=row["path"],
                method=row["method"],
                is_tested=bool(row["is_tested"]),
                test_count=row["test_count"] or 0,
                last_tested=row["last_tested"],
                check_types_tested=set(json.loads(row["check_types_tested"] or "[]")),
                node_id=row["node_id"],
            )
            self.endpoints[node.node_id] = node
            self.parameter_registry.setdefault(node.node_id, {})
            if self.graph is not None:
                self.graph.add_node(
                    node.node_id,
                    path=node.path,
                    method=node.method,
                    has_auth=False,
                    is_tested=node.is_tested,
                )

        (row_count,) = self.conn.execute("SELECT COUNT(*) FROM test_history").fetchone()
        self._test_history_count = row_count
        # Deliberately NOT "SELECT * ... then append every row to a
        # Python list": nothing in this class ever reads a test_history
        # row's contents back out again (get_statistics() only ever
        # needed the count) -- verified with a repo-wide grep, not
        # assumed. That means the previous version of this method loaded
        # every row this target has EVER accumulated, deserialized each
        # into a dict, and held the whole thing in process memory, on
        # every single CoverageMapper construction (i.e. every run) --
        # purely to compute a number the DB can already give back in one
        # query without materializing a single row in Python.

    def _setup_database(self) -> None:
        """Erstellt das Datenbank-Schema."""
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS endpoint_coverage (
                node_id TEXT PRIMARY KEY,
                path TEXT,
                method TEXT,
                is_tested BOOLEAN,
                test_count INTEGER,
                check_types_tested TEXT,
                last_tested TEXT
            )
        """)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS test_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                node_id TEXT,
                check_type TEXT,
                detected BOOLEAN,
                timestamp TEXT
            )
        """)
        self.conn.commit()

    def close(self) -> None:
        if self.conn:
            self.conn.close()

    # ------------------------------------------------------------------
    # Endpunkte hinzufügen
    # ------------------------------------------------------------------

    def add_endpoint(
        self,
        path: str,
        method: str,
        parameters: Optional[List[str]] = None,
        has_auth: bool = False,
    ) -> str:
        """Fügt einen Endpunkt hinzu.

        Returns:
            Die node_id des Endpunkts.
        """
        node_id = f"{method.upper()}:{path}"

        with self._lock:
            if node_id not in self.endpoints:
                endpoint = EndpointNode(
                    path=path,
                    method=method.upper(),
                    parameters=parameters or [],
                    has_auth=has_auth,
                    node_id=node_id,
                )
                self.endpoints[node_id] = endpoint

                # Parameter-Registry initialisieren
                self.parameter_registry[node_id] = {
                    param: False for param in (parameters or [])
                }

                # Zum Graph hinzufügen
                if self.graph is not None:
                    self.graph.add_node(
                        node_id,
                        path=path,
                        method=method.upper(),
                        has_auth=has_auth,
                        is_tested=False,
                    )

        return node_id

    def add_endpoints_from_openapi(self, openapi_spec: Dict[str, Any]) -> int:
        """Fügt alle Endpunkte aus einer OpenAPI-Spezifikation hinzu.

        Returns:
            Anzahl hinzugefügter Endpunkte.
        """
        added = 0
        paths = openapi_spec.get("paths", {})

        for path, path_item in paths.items():
            for method, operation in path_item.items():
                if method.lower() not in ("get", "post", "put", "patch", "delete"):
                    continue

                # Parameter extrahieren
                parameters = []
                for param in operation.get("parameters", []):
                    parameters.append(param.get("name", ""))

                # Request-Body-Parameter falls vorhanden
                request_body = operation.get("requestBody", {})
                content = request_body.get("content", {})
                json_content = content.get("application/json", {})
                schema = json_content.get("schema", {})
                properties = schema.get("properties", {})
                parameters.extend(properties.keys())

                # Auth-Status
                has_auth = bool(operation.get("security"))

                self.add_endpoint(path, method, parameters, has_auth)
                added += 1

        return added

    def add_data_flow(
        self,
        source_path: str,
        source_method: str,
        target_path: str,
        target_method: str,
        data_type: str = "unknown",
        description: str = "",
    ) -> None:
        """Fügt einen Datenfluss zwischen Endpunkten hinzu.

        Beispiel: POST /orders → PATCH /orders/{id}/status
        (Bestellung erstellen → Status aktualisieren)
        """
        source_id = f"{source_method.upper()}:{source_path}"
        target_id = f"{target_method.upper()}:{target_path}"

        flow = DataFlow(
            source_id=source_id,
            target_id=target_id,
            data_type=data_type,
            description=description,
        )
        self.data_flows.append(flow)

        if self.graph is not None:
            self.graph.add_edge(
                source_id,
                target_id,
                data_type=data_type,
                description=description,
                is_tested=False,
            )

    # ------------------------------------------------------------------
    # Test-Ergebnisse aufzeichnen
    # ------------------------------------------------------------------

    def record_test(
        self,
        path: str,
        method: str,
        check_type: str,
        detected: bool = False,
        parameters_tested: Optional[List[str]] = None,
    ) -> None:
        """Zeichnet auf dass ein Endpunkt getestet wurde.

        Args:
            path: Der Endpunkt-Pfad.
            method: Die HTTP-Methode.
            check_type: Welche Art von Check durchgeführt wurde.
            detected: Ob eine Inkonsistenz gefunden wurde.
            parameters_tested: Welche Parameter dabei getestet wurden.
        """
        node_id = f"{method.upper()}:{path}"

        with self._lock:
            if node_id in self.endpoints:
                endpoint = self.endpoints[node_id]
                endpoint.is_tested = True
                endpoint.test_count += 1
                endpoint.last_tested = datetime.now().isoformat()
                endpoint.check_types_tested.add(check_type)

                # Parameter als getestet markieren
                if parameters_tested:
                    for param in parameters_tested:
                        if param in self.parameter_registry.get(node_id, {}):
                            self.parameter_registry[node_id][param] = True

                # Graph aktualisieren
                if self.graph is not None:
                    self.graph.nodes[node_id]["is_tested"] = True

            # Historie-Zähler (nicht die Zeilen selbst -- siehe
            # __init__/_load_existing_coverage: nichts liest die Inhalte).
            self._test_history_count += 1

            # In DB speichern falls verfügbar
            if self.conn:
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO endpoint_coverage
                    (node_id, path, method, is_tested, test_count,
                     check_types_tested, last_tested)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        node_id,
                        path,
                        method.upper(),
                        True,
                        self.endpoints[node_id].test_count if node_id in self.endpoints else 1,
                        json.dumps(list(self.endpoints[node_id].check_types_tested)) if node_id in self.endpoints else "[]",
                        datetime.now().isoformat(),
                    ),
                )
                self.conn.execute(
                    """
                    INSERT INTO test_history
                    (node_id, check_type, detected, timestamp)
                    VALUES (?, ?, ?, ?)
                    """,
                    (node_id, check_type, detected, datetime.now().isoformat()),
                )
                self.conn.commit()

    # ------------------------------------------------------------------
    # Coverage-Berechnung
    # ------------------------------------------------------------------

    def calculate_coverage(self) -> CoverageReport:
        """Berechnet die aktuelle Test-Abdeckung.

        Returns:
            CoverageReport mit allen Metriken.
        """
        report = CoverageReport()

        # Endpunkt-Abdeckung
        report.total_endpoints = len(self.endpoints)
        report.tested_endpoints = sum(
            1 for e in self.endpoints.values() if e.is_tested
        )
        report.coverage_percentage = (
            report.tested_endpoints / report.total_endpoints * 100
            if report.total_endpoints > 0 else 0.0
        )

        # Methoden-Abdeckung (GET/POST/PATCH auf verschiedenen Pfaden)
        method_path_pairs = set()
        tested_method_path_pairs = set()

        for endpoint in self.endpoints.values():
            pair = (endpoint.path, endpoint.method)
            method_path_pairs.add(pair)
            if endpoint.is_tested:
                tested_method_path_pairs.add(pair)

        report.total_methods = len(method_path_pairs)
        report.tested_methods = len(tested_method_path_pairs)
        report.method_coverage_percentage = (
            report.tested_methods / report.total_methods * 100
            if report.total_methods > 0 else 0.0
        )

        # Parameter-Abdeckung
        total_params = 0
        tested_params = 0

        for node_id, params in self.parameter_registry.items():
            for param_name, is_tested in params.items():
                total_params += 1
                if is_tested:
                    tested_params += 1

        report.total_parameters = total_params
        report.tested_parameters = tested_params
        report.parameter_coverage_percentage = (
            tested_params / total_params * 100
            if total_params > 0 else 0.0
        )

        # Graph-Dichte (falls NetworkX verfügbar)
        if self.graph is not None and self.graph.number_of_nodes() > 1:
            report.graph_density = round(nx.density(self.graph), 3)

        # Lücken identifizieren
        report.gaps = self.find_gaps()

        # Empfehlungen generieren
        report.recommendations = [
            self._recommendation_to_dict(rec)
            for rec in self.generate_test_recommendations()
        ]

        # Ungedeckte kritische Pfade finden
        report.untested_critical_paths = self._find_untested_paths()

        return report

    # ------------------------------------------------------------------
    # Lücken-Erkennung
    # ------------------------------------------------------------------

    def find_gaps(self) -> List[CoverageGap]:
        """Identifiziert alle Lücken in der Test-Abdeckung."""
        gaps: List[CoverageGap] = []

        # Lücke 1: Ungetestete Endpunkte
        for endpoint in self.endpoints.values():
            if not endpoint.is_tested:
                severity = "high" if endpoint.has_auth else "medium"
                recommended = self._get_recommended_check(endpoint.path)

                gaps.append(CoverageGap(
                    gap_type="endpoint_untested",
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    description=f"Endpoint {endpoint.method} {endpoint.path} has never been tested",
                    severity=severity,
                    recommended_check=recommended,
                ))

        # Lücke 2: Ungetestete Methoden auf getesteten Pfaden
        tested_paths = set(
            e.path for e in self.endpoints.values() if e.is_tested
        )

        for endpoint in self.endpoints.values():
            if not endpoint.is_tested and endpoint.path in tested_paths:
                gaps.append(CoverageGap(
                    gap_type="method_untested",
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    description=(
                        f"Method {endpoint.method} on {endpoint.path} untested "
                        f"while other methods on this path are tested"
                    ),
                    severity="medium",
                    recommended_check=self._get_recommended_check(endpoint.path),
                ))

        # Lücke 3: Ungetestete Parameter auf getesteten Endpunkten
        for node_id, params in self.parameter_registry.items():
            endpoint = self.endpoints.get(node_id)
            if endpoint and endpoint.is_tested:
                untested_params = [
                    p for p, tested in params.items() if not tested
                ]
                if untested_params:
                    gaps.append(CoverageGap(
                        gap_type="parameter_untested",
                        endpoint=endpoint.path,
                        method=endpoint.method,
                        parameter=", ".join(untested_params[:5]),
                        description=(
                            f"Parameters {untested_params[:5]} on {endpoint.method} "
                            f"{endpoint.path} have not been specifically tested"
                        ),
                        severity="low",
                        recommended_check="input_field_whitelisting",
                    ))

        # Lücke 4: Fehlende Check-Types auf getesteten Endpunkten
        for endpoint in self.endpoints.values():
            if endpoint.is_tested:
                expected_checks = self._get_expected_checks(endpoint.path)
                missing_checks = expected_checks - endpoint.check_types_tested

                if missing_checks:
                    for check in list(missing_checks)[:3]:  # Max 3 pro Endpunkt
                        gaps.append(CoverageGap(
                            gap_type="check_type_missing",
                            endpoint=endpoint.path,
                            method=endpoint.method,
                            description=(
                                f"Check type '{check}' has not been performed "
                                f"on {endpoint.method} {endpoint.path}"
                            ),
                            severity="medium",
                            recommended_check=check,
                        ))

        # Nach Severity sortieren
        severity_order = {"high": 3, "medium": 2, "low": 1}
        gaps.sort(key=lambda g: severity_order.get(g.severity, 0), reverse=True)

        return gaps

    def _get_recommended_check(self, path: str) -> str:
        """Empfielt einen Check-Type basierend auf dem Pfad."""
        path_lower = path.lower()

        for pattern, checks in ENDPOINT_CHECK_MATRIX.items():
            if pattern in path_lower:
                return checks[0] if checks else "response_field_filtering"

        return "response_field_filtering"  # Standard

    def _get_expected_checks(self, path: str) -> Set[str]:
        """Gibt die erwarteten Check-Types für einen Pfad zurück."""
        path_lower = path.lower()
        expected = set()

        for pattern, checks in ENDPOINT_CHECK_MATRIX.items():
            if pattern in path_lower:
                expected.update(checks)

        if not expected:
            expected = {"response_field_filtering", "error_message_disclosure"}

        return expected

    def _find_untested_paths(self) -> List[List[str]]:
        """Findet kritische Pfade im Graph die vollständig ungetestet sind.

        Ein Pfad ist kritisch wenn er von einem schreibenden Endpunkt
        zu einem lesenden Endpunkt führt und kein Endpunkt darauf getestet wurde.
        """
        if self.graph is None:
            return []

        untested_paths = []

        # Finde alle einfachen Pfade der Länge 2-3
        nodes = list(self.graph.nodes())

        for source in nodes[:20]:  # Limit für Performance
            for target in nodes[:20]:
                if source == target:
                    continue

                try:
                    paths = list(
                        nx.all_simple_paths(
                            self.graph, source, target, cutoff=3
                        )
                    )

                    for path in paths:
                        # Prüfe ob ALLE Nodes im Pfad ungetestet sind
                        all_untested = all(
                            not self.graph.nodes[n].get("is_tested", False)
                            for n in path
                        )

                        if all_untested and len(path) >= 2:
                            untested_paths.append(path)

                except (nx.NetworkXNoPath, nx.NodeNotFound):
                    continue

        # Deduplizieren und limitieren
        unique_paths = []
        seen = set()
        for path in untested_paths:
            path_key = tuple(path)
            if path_key not in seen:
                seen.add(path_key)
                unique_paths.append(path)

        return unique_paths[:10]

    # ------------------------------------------------------------------
    # Test-Empfehlungen
    # ------------------------------------------------------------------

    def generate_test_recommendations(
        self,
        max_recommendations: int = 10,
    ) -> List[TestRecommendation]:
        """Generiert priorisierte Test-Empfehlungen basierend auf Lücken.

        Returns:
            Liste von Empfehlungen sortiert nach Priorität.
        """
        gaps = self.find_gaps()
        recommendations: List[TestRecommendation] = []

        for gap in gaps[:max_recommendations]:
            # Priorität basierend auf Severity
            if gap.severity == "high":
                priority = "HIGH"
                reason = f"Critical gap: {gap.description}"
            elif gap.severity == "medium":
                priority = "MEDIUM"
                reason = f"Coverage gap: {gap.description}"
            else:
                priority = "LOW"
                reason = f"Minor gap: {gap.description}"

            # Impact basierend auf Auth-Status
            endpoint = self.endpoints.get(f"{gap.method}:{gap.endpoint}")
            if endpoint and endpoint.has_auth:
                potential_impact = "high (authenticated endpoint)"
            else:
                potential_impact = "medium"

            recommendations.append(TestRecommendation(
                priority=priority,
                check_type=gap.recommended_check,
                endpoint=gap.endpoint,
                method=gap.method or "GET",
                reason=reason,
                estimated_time_s=gap.estimated_test_time_s,
                potential_impact=potential_impact,
            ))

        # Nach Priorität sortieren
        priority_order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
        recommendations.sort(
            key=lambda r: priority_order.get(r.priority, 0),
            reverse=True,
        )

        return recommendations

    def _recommendation_to_dict(self, rec: TestRecommendation) -> Dict[str, Any]:
        """Konvertiert eine Empfehlung in ein Dict."""
        return {
            "priority": rec.priority,
            "check_type": rec.check_type,
            "endpoint": rec.endpoint,
            "method": rec.method,
            "reason": rec.reason,
            "estimated_time_s": rec.estimated_time_s,
            "potential_impact": rec.potential_impact,
        }

    # ------------------------------------------------------------------
    # Berichte
    # ------------------------------------------------------------------

    def get_coverage_summary(self) -> str:
        """Generiert einen lesbaren Abdeckungs-Bericht."""
        report = self.calculate_coverage()

        lines = []
        lines.append("=" * 60)
        lines.append("TEST COVERAGE REPORT")
        lines.append("=" * 60)
        lines.append("")

        # Endpunkt-Abdeckung
        bar_length = int(report.coverage_percentage / 5)
        bar = "█" * bar_length + "░" * (20 - bar_length)
        lines.append(f"  Endpoints:  {bar} {report.coverage_percentage:.1f}% "
                     f"({report.tested_endpoints}/{report.total_endpoints})")

        # Methoden-Abdeckung
        bar_length = int(report.method_coverage_percentage / 5)
        bar = "█" * bar_length + "░" * (20 - bar_length)
        lines.append(f"  Methods:    {bar} {report.method_coverage_percentage:.1f}% "
                     f"({report.tested_methods}/{report.total_methods})")

        # Parameter-Abdeckung
        bar_length = int(report.parameter_coverage_percentage / 5)
        bar = "█" * bar_length + "░" * (20 - bar_length)
        lines.append(f"  Parameters: {bar} {report.parameter_coverage_percentage:.1f}% "
                     f"({report.tested_parameters}/{report.total_parameters})")

        # Lücken
        lines.append(f"\n  Gaps identified: {len(report.gaps)}")
        high_gaps = [g for g in report.gaps if g.severity == "high"]
        medium_gaps = [g for g in report.gaps if g.severity == "medium"]
        low_gaps = [g for g in report.gaps if g.severity == "low"]
        lines.append(f"    High:   {len(high_gaps)}")
        lines.append(f"    Medium: {len(medium_gaps)}")
        lines.append(f"    Low:    {len(low_gaps)}")

        # Top-Empfehlungen
        if report.recommendations:
            lines.append(f"\n  Top recommendations:")
            for i, rec in enumerate(report.recommendations[:5], 1):
                lines.append(
                    f"    {i}. [{rec['priority']}] {rec['check_type']} "
                    f"on {rec['method']} {rec['endpoint']}"
                )

        lines.append("")

        return "\n".join(lines)

    def prune_test_history_older_than(self, max_age_seconds: float) -> int:
        """Deletes test_history rows older than `max_age_seconds` and
        returns the number removed. Same rationale and same "operator
        decides the window, this class doesn't decide it for them" stance
        as PersistentMemoryStore.prune_episodic_older_than -- see there.
        Endpoint coverage itself (self.endpoints / the endpoint_coverage
        table) is untouched by this: that's the current state of what has
        ever been tested, which should never shrink; test_history is only
        ever-growing raw event log on top of it.
        """
        if self.conn is None:
            return 0
        cutoff_iso = datetime.fromtimestamp(time.time() - max_age_seconds).isoformat()
        with self._lock:
            cursor = self.conn.execute("DELETE FROM test_history WHERE timestamp < ?", (cutoff_iso,))
            self.conn.commit()
            deleted = cursor.rowcount
            (remaining,) = self.conn.execute("SELECT COUNT(*) FROM test_history").fetchone()
            self._test_history_count = remaining
            return deleted

    def get_statistics(self) -> Dict[str, Any]:
        """Gibt Mapper-Statistiken zurück."""
        report = self.calculate_coverage()

        return {
            "total_endpoints": report.total_endpoints,
            "tested_endpoints": report.tested_endpoints,
            "coverage_percentage": round(report.coverage_percentage, 1),
            "total_gaps": len(report.gaps),
            "high_severity_gaps": sum(1 for g in report.gaps if g.severity == "high"),
            "total_tests_recorded": self._test_history_count,
            "total_data_flows": len(self.data_flows),
            "graph_nodes": self.graph.number_of_nodes() if self.graph else 0,
            "graph_edges": self.graph.number_of_edges() if self.graph else 0,
            "graph_density": report.graph_density,
            "networkx_available": NETWORKX_AVAILABLE,
        }


if __name__ == "__main__":
    # Echter Test mit simulierter API
    print("=" * 70)
    print("COVERAGE MAPPER — STANDALONE TEST")
    print("=" * 70)

    mapper = CoverageMapper()

    # Endpunkte hinzufügen (simuliert eine Web-API)
    print("\n1. Adding endpoints...")

    endpoints = [
        ("/api/users", "GET", ["id", "fields", "page"], True),
        ("/api/users", "POST", ["name", "email", "role"], True),
        ("/api/users", "PUT", ["name", "email", "role", "is_admin"], True),
        ("/api/orders", "GET", ["id", "status"], True),
        ("/api/orders", "POST", ["amount", "currency", "items"], True),
        ("/api/orders/{id}/status", "PATCH", ["status"], True),
        ("/api/payment/confirm", "POST", ["amount", "payment_method"], True),
        ("/api/webhook/stripe", "POST", ["event", "signature"], False),
        ("/api/search", "GET", ["query", "filter"], False),
        ("/api/upload", "POST", ["file", "content_type"], True),
        ("/api/admin/settings", "GET", [], True),
        ("/api/admin/users", "GET", [], True),
        ("/api/debug/info", "GET", [], False),
        ("/api/config", "GET", [], False),
    ]

    for path, method, params, has_auth in endpoints:
        mapper.add_endpoint(path, method, params, has_auth)

    print(f"   Added {len(mapper.endpoints)} endpoints")

    # Datenflüsse hinzufügen
    print("\n2. Adding data flows...")
    mapper.add_data_flow("/api/orders", "POST", "/api/orders/{id}/status", "PATCH",
                         data_type="order_state", description="Order creation to status update")
    mapper.add_data_flow("/api/payment/confirm", "POST", "/api/webhook/stripe", "POST",
                         data_type="payment_event", description="Payment triggers webhook")
    mapper.add_data_flow("/api/users", "POST", "/api/users", "PUT",
                         data_type="user_data", description="User creation to profile update")

    print(f"   Added {len(mapper.data_flows)} data flows")

    # Einige Tests aufzeichnen
    print("\n3. Recording test results...")

    # Nur einige Endpunkte testen (Lücken erzeugen)
    mapper.record_test("/api/users", "GET", "resource_ownership_consistency",
                       detected=False, parameters_tested=["id"])
    mapper.record_test("/api/users", "POST", "input_field_whitelisting",
                       detected=True, parameters_tested=["name", "email"])
    mapper.record_test("/api/orders", "GET", "response_field_filtering",
                       detected=False)
    mapper.record_test("/api/payment/confirm", "POST", "input_field_whitelisting",
                       detected=True, parameters_tested=["amount"])

    print(f"   Recorded {mapper._test_history_count} tests")

    # Abdeckung berechnen
    print("\n4. Calculating coverage...")
    report = mapper.calculate_coverage()

    print(f"\n{mapper.get_coverage_summary()}")

    # Lücken anzeigen
    print("\n5. Coverage gaps:")
    gaps = mapper.find_gaps()
    for gap in gaps[:8]:
        print(f"  [{gap.severity.upper():<6}] {gap.gap_type}: {gap.description[:60]}...")

    # Empfehlungen
    print("\n6. Test recommendations:")
    recommendations = mapper.generate_test_recommendations(max_recommendations=5)
    for i, rec in enumerate(recommendations, 1):
        print(f"  {i}. [{rec.priority}] {rec.check_type} on {rec.method} {rec.endpoint}")
        print(f"     Reason: {rec.reason[:60]}...")
        print(f"     Estimated time: {rec.estimated_time_s}s")

    # Ungedeckte Pfade
    if report.untested_critical_paths:
        print(f"\n7. Untested critical paths ({len(report.untested_critical_paths)}):")
        for path in report.untested_critical_paths[:3]:
            print(f"  {' → '.join(path)}")

    # Statistiken
    print("\n8. Statistics:")
    stats = mapper.get_statistics()
    for key, value in stats.items():
        print(f"  {key}: {value}")

    print("\n✅ Coverage Mapper test completed")
