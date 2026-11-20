"""The internal representation an analyzer produces, before
discovery/engine.py converts it into a TestResult for the dashboard.

Enhanced with CVSS v3.1 scoring, confidence classification (Cloudflare
six-phase methodology), vulnerability chain tracking, trust-boundary
mapping, and exploitability metrics -- every field a Big-4 auditor
expects to see on a production-grade finding."""
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
    cvss_vector: str | None = None      # e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    cvss_score: float | None = None     # 0.0-10.0 base score
    severity_label: str | None = None   # none / low / medium / high / critical

    # --- Confidence classification (Cloudflare six-phase) ---
    confidence: str = "needs_validation"  # confirmed / needs_validation / low_confidence
    confidence_factors: dict[str, bool] = field(default_factory=dict)

    # --- Vulnerability taxonomy (BugHunter 24 categories) ---
    vuln_category: str | None = None    # VulnCategory enum value
    vuln_subcategory: str | None = None

    # --- Chain tracking (sapper-v2 fact-intent graph) ---
    chain_id: str | None = None         # links findings in the same exploit chain
    chain_position: int | None = None   # ordinal within the chain (0 = entry)
    chain_prerequisites: list[str] = field(default_factory=list)  # finding_ids this depends on

    # --- Trust boundary classification (Cloudflare audit skill) ---
    trust_boundaries: list[str] = field(default_factory=list)
    boundary_violation: str | None = None  # which specific boundary was crossed

    # --- Exploitability metrics ---
    attack_complexity: str | None = None  # low / medium / high
    privileges_required: str | None = None  # none / low / high
    user_interaction: str | None = None   # none / required

    # --- Hunting skill provenance (BugHunter) ---
    hunting_skill_id: str | None = None
    detection_signature: str | None = None

    # --- Adversarial validation (Cloudflare) ---
    validation_status: str | None = None  # verified / disputed / pending
    validation_notes: str | None = None

    # --- Cross-module correlation ---
    corroborating_modules: list[str] = field(default_factory=list)
    contradicting_evidence: list[str] = field(default_factory=list)
