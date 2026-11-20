"""The internal representation an analyzer produces, before
discovery/engine.py converts it into a TestResult for the dashboard.

Enhanced with CVSS v3.1 scoring, confidence classification (Cloudflare
six-phase methodology), vulnerability chain tracking, trust-boundary
mapping, exploitability metrics, CWE references, temporal analysis,
attack-path modeling, business-impact rating, and adversarial
verification -- every field a Big-4 auditor expects to see on a
production-grade finding, plus advanced chain composition and
reverse-engineering provenance tracking."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.testing.enums import ResultStatus


@dataclass
class Finding:
    finding_id: str
    title: str
    description: str
    status: ResultStatus
    observation: str
    standard_reference: str
    source_test_case_ids: list[str] = field(default_factory=list)
    recommendation: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)

    # --- CVSS v3.1 scoring (Full-Chain-Sentinel methodology) ---
    cvss_vector: str | None = None
    cvss_score: float | None = None
    severity_label: str | None = None

    # --- Confidence classification (Cloudflare six-phase) ---
    confidence: str = "needs_validation"
    confidence_factors: dict[str, bool] = field(default_factory=dict)

    # --- Vulnerability taxonomy (expanded 38 categories) ---
    vuln_category: str | None = None
    vuln_subcategory: str | None = None

    # --- CWE / CVE references ---
    cwe_id: str | None = None
    cwe_name: str | None = None
    related_cves: list[str] = field(default_factory=list)
    owasp_category: str | None = None

    # --- Chain tracking (sapper-v2 fact-intent graph) ---
    chain_id: str | None = None
    chain_position: int | None = None
    chain_prerequisites: list[str] = field(default_factory=list)
    chain_impact_multiplier: float = 1.0

    # --- Trust boundary classification (Cloudflare audit skill) ---
    trust_boundaries: list[str] = field(default_factory=list)
    boundary_violation: str | None = None
    boundary_crossing_direction: str | None = None

    # --- Exploitability metrics ---
    attack_complexity: str | None = None
    privileges_required: str | None = None
    user_interaction: str | None = None
    exploit_maturity: str | None = None
    exploit_code_available: bool = False
    weaponization_difficulty: str | None = None

    # --- Hunting skill provenance (BugHunter) ---
    hunting_skill_id: str | None = None
    detection_signature: str | None = None
    detection_method: str | None = None

    # --- Adversarial validation (Cloudflare) ---
    validation_status: str | None = None
    validation_notes: str | None = None
    false_positive_likelihood: str | None = None
    reproduction_steps: list[str] = field(default_factory=list)

    # --- Cross-module correlation ---
    corroborating_modules: list[str] = field(default_factory=list)
    contradicting_evidence: list[str] = field(default_factory=list)
    cross_module_confidence_boost: float = 0.0

    # --- Temporal analysis ---
    first_observed_in_run: str | None = None
    observation_count: int = 1
    temporal_pattern: str | None = None

    # --- Attack path modeling ---
    attack_path: list[str] = field(default_factory=list)
    entry_point: str | None = None
    target_asset: str | None = None
    lateral_movement_risk: bool = False

    # --- Business impact assessment ---
    business_impact: str | None = None
    data_classification: str | None = None
    affected_users_scope: str | None = None
    financial_impact_estimate: str | None = None
    compliance_implications: list[str] = field(default_factory=list)

    # --- Remediation tracking ---
    remediation_priority: str | None = None
    remediation_complexity: str | None = None
    estimated_fix_time: str | None = None
    remediation_dependencies: list[str] = field(default_factory=list)

    # --- Reverse engineering provenance ---
    re_method: str | None = None
    re_confidence: str | None = None
    inferred_from: list[str] = field(default_factory=list)
    behavioral_signature: str | None = None

    # --- Rate limit / captcha bypass specifics ---
    bypass_technique: str | None = None
    bypass_class: str | None = None
    effective_requests_per_window: int | None = None

    # --- Response differential analysis ---
    response_divergence_score: float | None = None
    baseline_response_hash: str | None = None
    anomaly_features: list[str] = field(default_factory=list)
