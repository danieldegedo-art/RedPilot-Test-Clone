"""Intelligent Finding Discovery layer -- six-phase pipeline.

Runs AFTER all 10 test modules complete (see runner.py), with access to
every TestResult they collected -- every response body, status code,
timing, and request any module made this run.

Deliberate design boundary: this layer is RETROSPECTIVE ANALYSIS ONLY. It
correlates and re-examines evidence the 10 modules already gathered; it
never sends the target a request of its own. Two reasons that's the right
line, not just the cautious one:

  1. Compliance evidence has to be reproducible and reviewable. A finding
     derived from "here are the three responses that disagree" is
     something an auditor (or the engineering team fixing it) can verify
     independently. A finding from "the system decided, based on an
     inferred pattern, to send some additional requests this run" is not
     reproducible the same way and would undermine exactly the
     audit-evidence purpose this suite exists for.
  2. Every module already tests its OWN hypothesis exhaustively (ROLE-002
     already tries every mutating route it found, not a sample). An
     autonomous "try more things based on what looked interesting" layer
     would either duplicate that exhaustive coverage or extrapolate into
     attack surface no module was scoped to touch -- neither is what
     "intelligent" should mean here. Intelligence, in this layer, means
     seeing the cross-module pattern in data that already exists, which a
     single-module, single-purpose test case structurally cannot do.

Pipeline architecture (adapted from Cloudflare security-audit-skill's
six-phase methodology for retrospective analysis):

  Phase 1 -- Reconnaissance & Surface Mapping
      coverage_gaps, attack_surface_completeness, response_shapes,
      header_security
  Phase 2 -- Deep Pattern Hunting (26 independent detectors)
      sensitive_data, timing_outliers, injection_artifacts,
      trust_boundary_violations, auth_bypass_patterns, idor_indicators,
      business_logic_flaws, privilege_escalation, ssrf_indicators,
      hunting_skill_application, entitlement_drift,
      response_fingerprinting, ssti_indicators, nosql_injection,
      xxe_indicators, prototype_pollution, http_smuggling,
      cache_poisoning, advanced_rate_limit_bypass,
      webhook_security_deep, subscription_lifecycle_abuse,
      reverse_engineering_artifacts, payment_flow_deep,
      advanced_auth_deep, graphql_deep
  Phase 3 -- Cross-Module Correlation (8 correlators)
      cross_endpoint_consistency, systemic_patterns,
      route_pattern_consistency, format_consistency,
      cross_module_correlation, vulnerability_chains,
      cve_chain_correlation, impact_amplification
  Phase 4 -- Adversarial Validation
      Re-examines every finding from Phases 1-3; classifies confidence
      (confirmed / needs_validation / low_confidence)
  Phase 5 -- Severity Scoring & Chain Synthesis
      CVSS v3.1 base scores, exploit-chain matching against known
      CVE chain templates, deduplication
  Phase 6 -- Reporting
      Severity-sorted emission, chain summaries, coverage summaries

Toggle: ``RunSettings.discovery_layer_enabled`` (default True).
"""
from __future__ import annotations

import logging
import time
from collections import defaultdict
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone

from app.testing.discovery.analyzers import (
    # Phase 1 -- Reconnaissance & Surface Mapping
    analyze_coverage_gaps,
    analyze_response_shapes,
    analyze_attack_surface_completeness,
    analyze_header_security,
    # Phase 2 -- Deep Pattern Hunting (original 12)
    analyze_sensitive_data,
    analyze_timing_outliers,
    analyze_injection_artifacts,
    analyze_trust_boundary_violations,
    analyze_auth_bypass_patterns,
    analyze_idor_indicators,
    analyze_business_logic_flaws,
    analyze_privilege_escalation,
    analyze_ssrf_indicators,
    analyze_hunting_skill_application,
    analyze_entitlement_drift,
    analyze_response_fingerprinting,
    # Phase 2b -- Advanced Hunting (14 new detectors)
    analyze_ssti_indicators,
    analyze_nosql_injection_indicators,
    analyze_xxe_indicators,
    analyze_prototype_pollution,
    analyze_http_smuggling_indicators,
    analyze_cache_poisoning_indicators,
    analyze_advanced_rate_limit_bypass,
    analyze_webhook_security_deep,
    analyze_subscription_lifecycle_abuse,
    analyze_reverse_engineering_artifacts,
    analyze_payment_flow_deep,
    analyze_advanced_auth_deep,
    analyze_graphql_deep,
    # Phase 3 -- Cross-Module Correlation
    analyze_cross_endpoint_consistency,
    analyze_systemic_patterns,
    analyze_route_pattern_consistency,
    analyze_format_consistency,
    analyze_cross_module_correlation,
    analyze_vulnerability_chains,
    analyze_cve_chain_correlation,
    # Phase 3b -- Meta-analysis
    analyze_impact_amplification,
    # Phase 4 -- Adversarial Validation
    analyze_adversarial_validation,
)
from app.testing.discovery.findings import Finding
from app.testing.discovery.vuln_knowledge import (
    CATEGORY_CVSS_DEFAULTS,
    CVE_CHAIN_TEMPLATES,
    VulnCategory,
    match_cve_chains,
)
from app.testing.enums import ResultStatus, TestCategory
from app.testing.models import TestResult
from app.testing.recon.function_mapper import FunctionMap

EmitFn = Callable[[TestResult], Awaitable[None]]

logger = logging.getLogger("qa.discovery")

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 4}


class DiscoveryEngine:
    category = TestCategory.INTELLIGENT_DISCOVERY

    def __init__(self, all_results: list[TestResult], function_map: FunctionMap | None) -> None:
        self.all_results = all_results
        self.function_map = function_map
        self._analyzer_errors: list[tuple[str, str]] = []
        self._phase_timings: list[tuple[str, float, int]] = []

    # ------------------------------------------------------------------
    # phase runners
    # ------------------------------------------------------------------

    def _run_phase(
        self,
        phase_name: str,
        analyzers: list[tuple[str, Callable[[], list[Finding]]]],
    ) -> list[Finding]:
        """Run a list of analyzers with per-analyzer fault isolation.
        Returns all findings produced in the phase."""
        t0 = time.monotonic()
        findings: list[Finding] = []
        for name, analyzer in analyzers:
            try:
                findings.extend(analyzer())
            except Exception as exc:  # noqa: BLE001
                logger.exception("Discovery analyzer %r raised in %s", name, phase_name)
                self._analyzer_errors.append((name, f"{type(exc).__name__}: {exc}"))
        elapsed = time.monotonic() - t0
        self._phase_timings.append((phase_name, round(elapsed * 1000, 1), len(findings)))
        logger.info(
            "Discovery %s complete: %d finding(s) in %.1fms",
            phase_name, len(findings), elapsed * 1000,
        )
        return findings

    def _phase_1_reconnaissance(self) -> list[Finding]:
        return self._run_phase("Phase 1: Reconnaissance", [
            ("coverage_gaps", lambda: analyze_coverage_gaps(self.all_results, self.function_map)),
            ("attack_surface_completeness", lambda: analyze_attack_surface_completeness(self.all_results)),
            ("response_shapes", lambda: analyze_response_shapes(self.all_results)),
            ("header_security", lambda: analyze_header_security(self.all_results)),
        ])

    def _phase_2_hunting(self) -> list[Finding]:
        return self._run_phase("Phase 2: Deep Hunting", [
            # Original 12 detectors
            ("sensitive_data", lambda: analyze_sensitive_data(self.all_results)),
            ("timing_outliers", lambda: analyze_timing_outliers(self.all_results)),
            ("injection_artifacts", lambda: analyze_injection_artifacts(self.all_results)),
            ("trust_boundary_violations", lambda: analyze_trust_boundary_violations(self.all_results)),
            ("auth_bypass_patterns", lambda: analyze_auth_bypass_patterns(self.all_results)),
            ("idor_indicators", lambda: analyze_idor_indicators(self.all_results)),
            ("business_logic_flaws", lambda: analyze_business_logic_flaws(self.all_results)),
            ("privilege_escalation", lambda: analyze_privilege_escalation(self.all_results)),
            ("ssrf_indicators", lambda: analyze_ssrf_indicators(self.all_results)),
            ("hunting_skill_application", lambda: analyze_hunting_skill_application(self.all_results)),
            ("entitlement_drift", lambda: analyze_entitlement_drift(self.all_results)),
            ("response_fingerprinting", lambda: analyze_response_fingerprinting(self.all_results)),
            # 14 new advanced detectors
            ("ssti_indicators", lambda: analyze_ssti_indicators(self.all_results)),
            ("nosql_injection", lambda: analyze_nosql_injection_indicators(self.all_results)),
            ("xxe_indicators", lambda: analyze_xxe_indicators(self.all_results)),
            ("prototype_pollution", lambda: analyze_prototype_pollution(self.all_results)),
            ("http_smuggling", lambda: analyze_http_smuggling_indicators(self.all_results)),
            ("cache_poisoning", lambda: analyze_cache_poisoning_indicators(self.all_results)),
            ("advanced_rate_limit_bypass", lambda: analyze_advanced_rate_limit_bypass(self.all_results)),
            ("webhook_security_deep", lambda: analyze_webhook_security_deep(self.all_results)),
            ("subscription_lifecycle_abuse", lambda: analyze_subscription_lifecycle_abuse(self.all_results)),
            ("reverse_engineering_artifacts", lambda: analyze_reverse_engineering_artifacts(self.all_results)),
            ("payment_flow_deep", lambda: analyze_payment_flow_deep(self.all_results)),
            ("advanced_auth_deep", lambda: analyze_advanced_auth_deep(self.all_results)),
            ("graphql_deep", lambda: analyze_graphql_deep(self.all_results)),
        ])

    def _phase_3_correlation(self, prior_findings: list[Finding] | None = None) -> list[Finding]:
        return self._run_phase("Phase 3: Correlation", [
            ("cross_endpoint_consistency", lambda: analyze_cross_endpoint_consistency(self.all_results)),
            ("systemic_patterns", lambda: analyze_systemic_patterns(self.all_results)),
            ("route_pattern_consistency", lambda: analyze_route_pattern_consistency(self.all_results)),
            ("format_consistency", lambda: analyze_format_consistency(self.all_results)),
            ("cross_module_correlation", lambda: analyze_cross_module_correlation(self.all_results)),
            ("vulnerability_chains", lambda: analyze_vulnerability_chains(self.all_results)),
            ("cve_chain_correlation", lambda: analyze_cve_chain_correlation(self.all_results)),
            ("impact_amplification", lambda: analyze_impact_amplification(self.all_results, prior_findings)),
        ])

    def _phase_4_validation(self, all_findings: list[Finding]) -> list[Finding]:
        """Adversarial validation: re-examine every finding from Phases 1-3
        and classify confidence.  The validator is a *separate checker* from
        the finders (Cloudflare six-phase principle)."""
        t0 = time.monotonic()
        validated: list[Finding] = []
        try:
            validated = analyze_adversarial_validation(self.all_results, all_findings)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Adversarial validation raised")
            self._analyzer_errors.append(("adversarial_validation", f"{type(exc).__name__}: {exc}"))
            validated = all_findings
        elapsed = time.monotonic() - t0
        self._phase_timings.append(("Phase 4: Validation", round(elapsed * 1000, 1), len(validated)))
        logger.info(
            "Discovery Phase 4: Validation complete: %d finding(s) in %.1fms",
            len(validated), elapsed * 1000,
        )
        return validated

    def _phase_5_scoring(self, findings: list[Finding]) -> list[Finding]:
        """Assign CVSS v3.1 scores, synthesize exploit chains, and
        deduplicate overlapping findings."""
        t0 = time.monotonic()

        for finding in findings:
            if finding.cvss_score is None and finding.vuln_category:
                try:
                    cat = VulnCategory(finding.vuln_category)
                    vec = CATEGORY_CVSS_DEFAULTS.get(cat)
                    if vec:
                        finding.cvss_score = vec.base_score()
                        finding.cvss_vector = vec.vector_string()
                        finding.severity_label = vec.severity_label()
                except (ValueError, KeyError):
                    pass

            if finding.cvss_score is None:
                if finding.status == ResultStatus.FAIL:
                    finding.cvss_score = 7.0
                    finding.severity_label = "high"
                elif finding.status == ResultStatus.WARNING:
                    finding.cvss_score = 4.0
                    finding.severity_label = "medium"
                else:
                    finding.cvss_score = 2.0
                    finding.severity_label = "low"

        observed_cats: set[VulnCategory] = set()
        for f in findings:
            if f.vuln_category:
                try:
                    observed_cats.add(VulnCategory(f.vuln_category))
                except ValueError:
                    pass

        chain_findings: list[Finding] = []
        matched_chains = match_cve_chains(observed_cats)
        for chain in matched_chains:
            step_finding_ids = []
            for step_cat in chain.steps:
                for f in findings:
                    if f.vuln_category == step_cat.value:
                        step_finding_ids.append(f.finding_id)
                        break

            chain_finding = Finding(
                finding_id=f"DISCOVERY-CHAIN-{chain.chain_id}",
                title=f"Exploit chain detected: {chain.name}",
                description=chain.description,
                status=ResultStatus.FAIL,
                observation=(
                    f"All prerequisite vulnerability categories for chain "
                    f"'{chain.name}' are present in this run's findings. "
                    f"Steps: {' -> '.join(s.value for s in chain.steps)}. "
                    f"Combined CVSS: {chain.combined_cvss}."
                ),
                standard_reference=chain.reference,
                source_test_case_ids=step_finding_ids,
                recommendation=(
                    f"This exploit chain represents compounded risk exceeding "
                    f"any individual finding. Prioritize remediation of the "
                    f"chain entry point ({chain.steps[0].value}) to break "
                    f"the chain."
                ),
                evidence={
                    "chain_id": chain.chain_id,
                    "chain_steps": [s.value for s in chain.steps],
                    "combined_cvss": chain.combined_cvss,
                    "enterprise_context": chain.enterprise_context,
                    "contributing_findings": step_finding_ids,
                },
                cvss_score=chain.combined_cvss,
                cvss_vector=None,
                severity_label="critical" if chain.combined_cvss >= 9.0 else "high",
                confidence="confirmed" if len(step_finding_ids) == len(chain.steps) else "needs_validation",
                vuln_category=chain.steps[-1].value,
                chain_id=chain.chain_id,
            )

            for idx, fid in enumerate(step_finding_ids):
                for f in findings:
                    if f.finding_id == fid:
                        f.chain_id = chain.chain_id
                        f.chain_position = idx
                        break

            chain_findings.append(chain_finding)

        all_findings = findings + chain_findings

        seen_signatures: dict[str, Finding] = {}
        deduplicated: list[Finding] = []
        for f in all_findings:
            sig = (f.vuln_category or "", f.title, f.observation[:80] if f.observation else "")
            sig_key = str(sig)
            existing = seen_signatures.get(sig_key)
            if existing is None:
                seen_signatures[sig_key] = f
                deduplicated.append(f)
            else:
                existing.source_test_case_ids = list(
                    dict.fromkeys(existing.source_test_case_ids + f.source_test_case_ids)
                )
                if f.cvss_score and (existing.cvss_score is None or f.cvss_score > existing.cvss_score):
                    existing.cvss_score = f.cvss_score
                    existing.cvss_vector = f.cvss_vector
                    existing.severity_label = f.severity_label

        elapsed = time.monotonic() - t0
        self._phase_timings.append(("Phase 5: Scoring", round(elapsed * 1000, 1), len(deduplicated)))
        logger.info(
            "Discovery Phase 5: Scoring complete: %d finding(s), %d chain(s) in %.1fms",
            len(deduplicated), len(chain_findings), elapsed * 1000,
        )
        return deduplicated

    # ------------------------------------------------------------------
    # main entry point
    # ------------------------------------------------------------------

    async def run(self, emit: EmitFn) -> None:
        if not self.all_results:
            await emit(self._info_result("No test results were available to analyze this run."))
            return

        overall_t0 = time.monotonic()

        phase_1_findings = self._phase_1_reconnaissance()
        phase_2_findings = self._phase_2_hunting()
        prior = phase_1_findings + phase_2_findings
        phase_3_findings = self._phase_3_correlation(prior)

        all_raw = prior + phase_3_findings

        validated = self._phase_4_validation(all_raw)
        scored = self._phase_5_scoring(validated)

        overall_elapsed = time.monotonic() - overall_t0

        if self._analyzer_errors:
            await emit(self._analyzer_error_result())

        if not scored:
            skipped_note = ""
            if self._analyzer_errors:
                skipped_note = (
                    f" ({len(self._analyzer_errors)} analyzer(s) raised and "
                    f"were skipped -- see DISCOVERY-ANALYZER-ERROR above.)"
                )
            await emit(self._info_result(
                f"Analyzed {len(self.all_results)} result(s) from this run across "
                f"all 38 analyzers in 6 phases ({overall_elapsed * 1000:.0f}ms) "
                f"-- no additional finding surfaced beyond what the 10 modules "
                f"already reported directly.{skipped_note}"
            ))
            return

        severity_counts: dict[str, int] = defaultdict(int)
        chain_ids: set[str] = set()
        confidence_counts: dict[str, int] = defaultdict(int)
        for f in scored:
            severity_counts[f.severity_label or "none"] += 1
            confidence_counts[f.confidence] += 1
            if f.chain_id:
                chain_ids.add(f.chain_id)

        sorted_findings = sorted(
            scored,
            key=lambda f: (
                _SEVERITY_ORDER.get(f.severity_label or "none", 99),
                -(f.cvss_score or 0),
                0 if f.confidence == "confirmed" else (1 if f.confidence == "needs_validation" else 2),
            ),
        )

        for finding in sorted_findings:
            await emit(self._to_test_result(finding))

        await emit(self._summary_result(scored, severity_counts, confidence_counts, chain_ids, overall_elapsed))

    # ------------------------------------------------------------------
    # TestResult converters
    # ------------------------------------------------------------------

    def _analyzer_error_result(self) -> TestResult:
        now = datetime.now(timezone.utc)
        failed_names = [name for name, _ in self._analyzer_errors]
        details = "; ".join(f"{name}: {message}" for name, message in self._analyzer_errors)
        return TestResult(
            test_case_id="DISCOVERY-ANALYZER-ERROR",
            category=self.category,
            name="One or more discovery analyzers failed",
            description=(
                "Each of the 38 discovery analyzers runs independently and is individually "
                "fault-isolated: one raising an exception does not discard the findings the "
                "other analyzers already produced this run."
            ),
            input_parameters={"failed_analyzers": failed_names, "failed_count": len(failed_names)},
            expected="All 38 analyzers complete without raising.",
            actual=f"{len(failed_names)} analyzer(s) raised and were skipped: {details}",
            status=ResultStatus.WARNING,
            recommendation=(
                "Check backend logs for the full traceback of each failed analyzer "
                "(logger \"qa.discovery\") and fix the underlying bug."
            ),
            started_at=now,
            finished_at=now,
            duration_ms=0.0,
        )

    def _info_result(self, actual: str) -> TestResult:
        now = datetime.now(timezone.utc)
        return TestResult(
            test_case_id="DISCOVERY-000",
            category=self.category,
            name="Intelligent Finding Discovery",
            description=(
                "Six-phase retrospective analysis of every response body, status code, "
                "timing, and request the 10 test modules collected this run. Phase 1: "
                "surface mapping. Phase 2: deep pattern hunting (26 detectors). Phase 3: "
                "cross-module correlation (8 correlators). Phase 4: adversarial validation. "
                "Phase 5: CVSS scoring and exploit-chain synthesis. Phase 6: severity-ranked "
                "reporting. Sends no new requests to the target."
            ),
            input_parameters={
                "results_analyzed": len(self.all_results),
                "phase_timings": [
                    {"phase": name, "duration_ms": ms, "findings": count}
                    for name, ms, count in self._phase_timings
                ],
            },
            expected="N/A - informational.",
            actual=actual,
            status=ResultStatus.INFO,
            started_at=now,
            finished_at=now,
            duration_ms=0.0,
        )

    def _to_test_result(self, finding: Finding) -> TestResult:
        now = datetime.now(timezone.utc)

        evidence = dict(finding.evidence)
        evidence["source_test_case_ids"] = finding.source_test_case_ids

        if finding.cvss_score is not None:
            evidence["cvss_score"] = finding.cvss_score
        if finding.cvss_vector:
            evidence["cvss_vector"] = finding.cvss_vector
        if finding.severity_label:
            evidence["severity_label"] = finding.severity_label
        if finding.confidence:
            evidence["confidence"] = finding.confidence
        if finding.vuln_category:
            evidence["vuln_category"] = finding.vuln_category
        if finding.chain_id:
            evidence["chain_id"] = finding.chain_id
            if finding.chain_position is not None:
                evidence["chain_position"] = finding.chain_position
        if finding.trust_boundaries:
            evidence["trust_boundaries"] = finding.trust_boundaries
        if finding.hunting_skill_id:
            evidence["hunting_skill_id"] = finding.hunting_skill_id
        if finding.corroborating_modules:
            evidence["corroborating_modules"] = finding.corroborating_modules
        if finding.confidence_factors:
            evidence["confidence_factors"] = finding.confidence_factors
        if finding.attack_complexity:
            evidence["attack_complexity"] = finding.attack_complexity
        if finding.cwe_id:
            evidence["cwe_id"] = finding.cwe_id
        if finding.bypass_technique:
            evidence["bypass_technique"] = finding.bypass_technique
        if finding.bypass_class:
            evidence["bypass_class"] = finding.bypass_class
        if finding.re_method:
            evidence["re_method"] = finding.re_method
        if finding.business_impact:
            evidence["business_impact"] = finding.business_impact
        if finding.chain_impact_multiplier != 1.0:
            evidence["chain_impact_multiplier"] = finding.chain_impact_multiplier
        if finding.financial_impact_estimate:
            evidence["financial_impact_estimate"] = finding.financial_impact_estimate

        desc = f"{finding.description} Standard reference: {finding.standard_reference}."
        if finding.severity_label and finding.cvss_score is not None:
            desc += f" Severity: {finding.severity_label.upper()} (CVSS {finding.cvss_score:.1f})."
        if finding.confidence:
            desc += f" Confidence: {finding.confidence}."

        return TestResult(
            test_case_id=finding.finding_id,
            category=self.category,
            name=finding.title,
            description=desc,
            input_parameters=evidence,
            expected="N/A - this is a derived finding, not a pass/fail check against a single expectation.",
            actual=finding.observation,
            status=finding.status,
            recommendation=finding.recommendation,
            started_at=now,
            finished_at=now,
            duration_ms=0.0,
        )

    def _summary_result(
        self,
        findings: list[Finding],
        severity_counts: dict[str, int],
        confidence_counts: dict[str, int],
        chain_ids: set[str],
        overall_elapsed: float,
    ) -> TestResult:
        now = datetime.now(timezone.utc)

        severity_desc = ", ".join(
            f"{count} {label}"
            for label, count in sorted(
                severity_counts.items(),
                key=lambda x: _SEVERITY_ORDER.get(x[0], 99),
            )
        )

        confidence_desc = ", ".join(
            f"{count} {label}" for label, count in sorted(confidence_counts.items())
        )

        chain_desc = f"{len(chain_ids)} exploit chain(s) detected" if chain_ids else "no exploit chains"

        rollup = ResultStatus.FAIL
        if not severity_counts.get("critical") and not severity_counts.get("high"):
            rollup = ResultStatus.WARNING if severity_counts.get("medium") else ResultStatus.INFO

        return TestResult(
            test_case_id="DISCOVERY-SUMMARY",
            category=self.category,
            name="Intelligent Finding Discovery (six-phase summary)",
            description=(
                "Aggregate rollup of every finding the six-phase discovery pipeline "
                "derived this run. Phase 1: reconnaissance & surface mapping. "
                "Phase 2: deep pattern hunting. Phase 3: cross-module correlation. "
                "Phase 4: adversarial validation. Phase 5: CVSS scoring & chain "
                "synthesis. Phase 6: severity-ranked reporting."
            ),
            input_parameters={
                "finding_count": len(findings),
                "severity_distribution": dict(severity_counts),
                "confidence_distribution": dict(confidence_counts),
                "chain_count": len(chain_ids),
                "chain_ids": sorted(chain_ids),
                "total_duration_ms": round(overall_elapsed * 1000, 1),
                "phase_timings": [
                    {"phase": name, "duration_ms": ms, "findings": count}
                    for name, ms, count in self._phase_timings
                ],
            },
            expected="N/A - aggregate rollup.",
            actual=(
                f"{len(findings)} finding(s) derived from {len(self.all_results)} "
                f"result(s) in {overall_elapsed * 1000:.0f}ms. "
                f"Severity: {severity_desc}. Confidence: {confidence_desc}. "
                f"{chain_desc.capitalize()}."
            ),
            status=rollup,
            started_at=now,
            finished_at=now,
            duration_ms=round(overall_elapsed * 1000, 1),
        )
