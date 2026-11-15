"""Intelligent Finding Discovery layer.

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

Nine analyzers (see analyzers.py), each independent and individually
skippable if its preconditions aren't met (e.g. coverage-gap analysis
needs Recon's FunctionMap; timing analysis needs 4+ comparable samples):

  1. Sensitive-data / secret exposure       -- every response body, not just errors
  2. Cross-endpoint resource consistency    -- generalizes LIFECYCLE-004 to every resource
  3. Response shape anomalies               -- undocumented/inconsistent/debug fields
  4. Timing outliers                        -- same-endpoint response-time side channels
  5. Coverage gaps                          -- FunctionMap routes nothing ever tested
  6. Systemic pattern synthesis             -- aggregates OTHER modules' own per-route results
  7. Route-pattern consistency (Anforderung 1 / CC7.2)        -- ROLE-002-MATRIX grouped by structural similarity
  8. Format-dependent consistency (Anforderung 2 / ISO 25010) -- ROLE-002-MATRIX x FORMAT-MATRIX correlation
  9. Cross-module correlation (Anforderung 3)                 -- ROLE-003 weak-auth x ROLE-002 injection correlation

Toggle: `RunSettings.discovery_layer_enabled` (default True). Not part of
`enabled_modules`/`SCOPE_MODULES` since it isn't module-shaped -- it has no
scope of its own, only the union of whatever scope already ran.
"""
from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone

from app.testing.discovery.analyzers import (
    analyze_coverage_gaps,
    analyze_cross_endpoint_consistency,
    analyze_cross_module_correlation,
    analyze_format_consistency,
    analyze_response_shapes,
    analyze_route_pattern_consistency,
    analyze_sensitive_data,
    analyze_systemic_patterns,
    analyze_timing_outliers,
)
from app.testing.discovery.findings import Finding
from app.testing.enums import ResultStatus, TestCategory
from app.testing.models import TestResult
from app.testing.recon.function_mapper import FunctionMap

EmitFn = Callable[[TestResult], Awaitable[None]]

logger = logging.getLogger("qa.discovery")


class DiscoveryEngine:
    category = TestCategory.INTELLIGENT_DISCOVERY

    def __init__(self, all_results: list[TestResult], function_map: FunctionMap | None) -> None:
        self.all_results = all_results
        self.function_map = function_map
        # Populated by _run_analyzers(); read by run() to emit a summary of
        # which analyzers (if any) raised, so a bug in one doesn't just
        # silently reduce coverage with nothing in the evidence to show it.
        self._analyzer_errors: list[tuple[str, str]] = []

    def _run_analyzers(self) -> list[Finding]:
        """Each of the nine analyzers is independent by design (see this
        module's docstring: "each independent and individually skippable if
        its preconditions aren't met"). This extends that same guarantee to
        an analyzer that raises, not just one that decides to skip itself:
        one analyzer's bug must not discard the other eight's findings, and
        must not discard the ten modules' worth of evidence this engine was
        constructed with in the first place (see runner.py, which no longer
        lets an exception here escape the run either -- this is the
        belt-and-suspenders half of that same fix, isolating the individual
        analyzer, not just the layer as a whole)."""
        analyzers: list[tuple[str, Callable[[], list[Finding]]]] = [
            ("sensitive_data", lambda: analyze_sensitive_data(self.all_results)),
            ("cross_endpoint_consistency", lambda: analyze_cross_endpoint_consistency(self.all_results)),
            ("response_shapes", lambda: analyze_response_shapes(self.all_results)),
            ("timing_outliers", lambda: analyze_timing_outliers(self.all_results)),
            ("coverage_gaps", lambda: analyze_coverage_gaps(self.all_results, self.function_map)),
            ("systemic_patterns", lambda: analyze_systemic_patterns(self.all_results)),
            ("route_pattern_consistency", lambda: analyze_route_pattern_consistency(self.all_results)),
            ("format_consistency", lambda: analyze_format_consistency(self.all_results)),
            ("cross_module_correlation", lambda: analyze_cross_module_correlation(self.all_results)),
        ]
        findings: list[Finding] = []
        self._analyzer_errors = []
        for name, analyzer in analyzers:
            try:
                findings.extend(analyzer())
            except Exception as exc:  # noqa: BLE001 -- deliberately broad, see docstring above
                logger.exception("Discovery analyzer %r raised", name)
                self._analyzer_errors.append((name, f"{type(exc).__name__}: {exc}"))
        return findings

    async def run(self, emit: EmitFn) -> None:
        if not self.all_results:
            await emit(self._info_result("No test results were available to analyze this run."))
            return

        findings = self._run_analyzers()
        if self._analyzer_errors:
            await emit(self._analyzer_error_result())

        if not findings:
            skipped = f" ({len(self._analyzer_errors)} of nine analyzer(s) raised and were skipped -- see DISCOVERY-ANALYZER-ERROR above.)" if self._analyzer_errors else ""
            await emit(
                self._info_result(
                    f"Analyzed {len(self.all_results)} result(s) from this run across all nine techniques "
                    "(sensitive-data scanning, cross-endpoint consistency, response-shape anomalies, timing "
                    "outliers, coverage gaps, systemic pattern synthesis, route-pattern consistency, "
                    "format-dependent consistency, cross-module correlation) -- no additional finding surfaced "
                    f"beyond what the 10 modules already reported directly.{skipped}"
                )
            )
            return

        for finding in findings:
            await emit(self._to_test_result(finding))
        await emit(self._summary_result(findings))

    def _analyzer_error_result(self) -> TestResult:
        now = datetime.now(timezone.utc)
        failed_names = [name for name, _ in self._analyzer_errors]
        details = "; ".join(f"{name}: {message}" for name, message in self._analyzer_errors)
        return TestResult(
            test_case_id="DISCOVERY-ANALYZER-ERROR",
            category=self.category,
            name="One or more discovery analyzers failed",
            description=(
                "Each of the nine discovery analyzers runs independently and is individually "
                "fault-isolated (see _run_analyzers in discovery/engine.py): one raising an exception "
                "no longer discards the findings the other analyzers already produced this run, or the "
                "test modules' evidence this layer was analyzing."
            ),
            input_parameters={"failed_analyzers": failed_names, "failed_count": len(failed_names)},
            expected="All nine analyzers complete without raising.",
            actual=f"{len(failed_names)} of nine analyzer(s) raised and were skipped: {details}",
            status=ResultStatus.WARNING,
            recommendation=(
                "Check backend logs for the full traceback of each failed analyzer (logger \"qa.discovery\") "
                "and fix the underlying bug -- that analyzer's usual findings were not produced this run, "
                "which may mean reduced coverage for whatever it checks."
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
                "Retrospective, cross-module analysis of every response body, status code, timing, and request "
                "the 10 test modules collected this run -- correlates already-observed evidence into findings "
                "no single module's own test case was checking for. Sends no new requests to the target."
            ),
            input_parameters={"results_analyzed": len(self.all_results)},
            expected="N/A - informational.",
            actual=actual,
            status=ResultStatus.INFO,
            started_at=now,
            finished_at=now,
            duration_ms=0.0,
        )

    def _to_test_result(self, finding: Finding) -> TestResult:
        now = datetime.now(timezone.utc)
        return TestResult(
            test_case_id=finding.finding_id,
            category=self.category,
            name=finding.title,
            description=f"{finding.description} Standard reference: {finding.standard_reference}.",
            input_parameters={**finding.evidence, "source_test_case_ids": finding.source_test_case_ids},
            expected="N/A - this is a derived finding, not a pass/fail check against a single expectation.",
            actual=finding.observation,
            status=finding.status,
            recommendation=finding.recommendation,
            started_at=now,
            finished_at=now,
            duration_ms=0.0,
        )

    def _summary_result(self, findings: list[Finding]) -> TestResult:
        now = datetime.now(timezone.utc)
        counts: dict[str, int] = {}
        for finding in findings:
            key = finding.status.value if hasattr(finding.status, "value") else str(finding.status)
            counts[key] = counts.get(key, 0) + 1
        counts_desc = ", ".join(f"{count} {status}" for status, count in sorted(counts.items()))
        rollup = ResultStatus.FAIL if counts.get("FAIL") else (ResultStatus.WARNING if counts.get("WARNING") else ResultStatus.INFO)

        return TestResult(
            test_case_id="DISCOVERY-SUMMARY",
            category=self.category,
            name="Intelligent Finding Discovery (summary)",
            description=(
                "Aggregate rollup of every finding the discovery layer derived this run from the 10 modules' "
                "own collected evidence (see DISCOVERY-* above for each finding's full evidence and standard "
                "reference)."
            ),
            input_parameters={"finding_count": len(findings)},
            expected="N/A - aggregate rollup.",
            actual=f"{len(findings)} finding(s) derived from {len(self.all_results)} result(s) this run: {counts_desc}.",
            status=rollup,
            started_at=now,
            finished_at=now,
            duration_ms=0.0,
        )
