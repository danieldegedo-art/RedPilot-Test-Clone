"""Migration inventory: every target-facing component classified for the Pure Black-Box rule (machine-readable, validated by tests).

Each entry carries the mandate's fields. ``paths`` are repo-relative globs (``*`` matches across ``/``); the audit (audit.py) proves that
EVERY file of the repository is covered by at least one entry (complete-inventory gate) and that no WHITE_BOX/GREY_BOX entry has
``no_change`` (forbidden by the mandate). ``state_after_migration`` records what is true NOW for the entry.
Stdlib only. Moved to the Enterprise Controls with the audit it feeds (together with the three enums only this inventory uses).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from xml.sax.saxutils import escape


class Classification(str, Enum):
    """How a target-facing dependency relates to the Pure Black-Box rule (mandate: 'purity inventory')."""

    PURE_BLACK_BOX = "pure_black_box"
    WHITE_BOX = "white_box"
    GREY_BOX = "grey_box"
    UNKNOWN = "unknown"
    BLOCKED = "blocked"


class MigrationAction(str, Enum):
    REMOVE = "remove"
    REPLACE = "replace"
    DISABLE = "disable"
    QUARANTINE = "quarantine"
    NO_CHANGE = "no_change"


class Priority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

P, W, G, U, B = Classification.PURE_BLACK_BOX, Classification.WHITE_BOX, Classification.GREY_BOX, Classification.UNKNOWN, Classification.BLOCKED
RM, RP, DS, QR, NC = MigrationAction.REMOVE, MigrationAction.REPLACE, MigrationAction.DISABLE, MigrationAction.QUARANTINE, MigrationAction.NO_CHANGE
CR, HI, ME, LO = Priority.CRITICAL, Priority.HIGH, Priority.MEDIUM, Priority.LOW
Q = "backend/quarantine/legacy_greybox"


@dataclass(frozen=True)
class TargetAccessDependency:
    id: str
    system_component: str
    file_or_module: str
    paths: tuple[str, ...]
    current_behavior: str
    target_information_or_access_used: str
    classification: Classification
    why_it_is_not_pure_black_box: str
    impact_on_findings_or_benchmarks: str
    safe_black_box_replacement: str
    migration_action: MigrationAction
    migration_priority: Priority
    validation_method: str
    remaining_limitations: str
    state_after_migration: str = ""

    def to_xml(self) -> str:
        def tag(name: str, value: str) -> str:
            return f"  <{name}>{escape(value)}</{name}>"
        rows = [
            tag("id", self.id), tag("system_component", self.system_component), tag("file_or_module", self.file_or_module), tag("current_behavior", self.current_behavior),
            tag("target_information_or_access_used", self.target_information_or_access_used), tag("classification", self.classification.value),
            tag("why_it_is_not_pure_black_box", self.why_it_is_not_pure_black_box), tag("impact_on_findings_or_benchmarks", self.impact_on_findings_or_benchmarks),
            tag("safe_black_box_replacement", self.safe_black_box_replacement), tag("migration_action", self.migration_action.value), tag("migration_priority", self.migration_priority.value),
            tag("validation_method", self.validation_method), tag("remaining_limitations", self.remaining_limitations),
        ]
        return "<target_access_dependency>\n" + "\n".join(rows) + "\n</target_access_dependency>"


def D(id: str, comp: str, mod: str, paths: tuple[str, ...], behavior: str, info: str, cls: Classification, why: str, impact: str, repl: str, action: MigrationAction,
      prio: Priority, validation: str, limits: str, state: str = "") -> TargetAccessDependency:
    return TargetAccessDependency(id, comp, mod, paths, behavior, info, cls, why, impact, repl, action, prio, validation, limits, state)


PURE_NA = "n/a (pure black-box)"
T_PURITY = "tests/test_purity_enforcement.py"
T_ENGINE = "tests/test_pure_engine.py"
T_BENCH = "tests/verification_infrastructure/test_purity_benchmark.py"

INVENTORY: tuple[TargetAccessDependency, ...] = (
    # ------------------------------------------------------------------------------------------------ A. legacy grey-box engine
    D("TAD-001", "Payment-integrity engine", "legacy contract.webhook_secret + OracleEngine(webhook_secret=...)", (f"{Q}/app_testing_integrity/contract.py",),
      "The customer declared the target's SANDBOX webhook signing secret; the engine signed forged provider events with it.", "target secret (webhook signing key)", W,
      "A signing secret is a target-side secret; no authorised external customer obtains it through product use.", "Every P0 class behind a signature perimeter (B,C,F,G,H) was only reachable WITH the secret: those detections are grey-box claims.",
      "Customer-level experiments (return flow, sandbox payment) judged by the Protected-Feature Oracle; no secret is ever accepted (credential gate rejects webhook_secret/whsec_ values).", RM, CR,
      f"{T_PURITY}::test_brief_rejects_webhook_signing_secret, ::test_credential_gate_rejects_secret_values", "Provider-event authenticity stays BLOCKED (cannot be tested without the secret).", "removed from product; legacy source quarantined (cannot load)"),
    D("TAD-002", "Payment-integrity engine", "legacy oracle_engine.py (forged provider webhooks to /api/v1/webhooks/payment-confirmed)", (f"{Q}/app_testing_integrity/oracle_engine.py",),
      "ORC-A..I posted forged provider-origin payment events to a provider-facing route learned from a customer-declared vocabulary.", "private/provider-facing endpoint knowledge; provider-origin event channel", G,
      "The route is not a customer-facing surface and a customer cannot emit provider events; the oracle verdicts depended on that channel.", "Detection numbers of the legacy scorecard are not valid black-box claims.",
      "integrity/engine.py: PBB-U/F/H/C/G/X/R/E through customer-level flows; provider-event class reported BLOCKED by gaps.py.", RP, CR,
      f"{T_BENCH}::test_blind_matrix_matches_ground_truth", "Webhook forgery/replay/signature perimeter cannot be covered without grey-box input.", "replaced; legacy file quarantined"),
    D("TAD-003", "Payment-integrity engine", "legacy entitlement/status reads (GET /access/{user}, GET /entitlements/{user})", (f"{Q}/app_testing_integrity/oracle_engine.py", f"{Q}/tests_verification/black_box_prober.py"),
      "A backend-provided entitlement/access status was the oracle for 'access granted'.", "backend-provided entitlement status; internal entitlement record", G,
      "A status read is not proof that a paid feature can be USED; the mandate classifies backend-provided entitlement status as grey-box.", "Verdicts could be wrong in both directions (status says active, feature denied, or the reverse).",
      "integrity/oracle.py ProtectedFeatureOracle: allowed only when a server-enforced feature is actually used and the declared proof field is present.", RP, CR,
      f"{T_ENGINE}::test_oracle_requires_proof_field, ::test_ui_claims_never_confirm", "Needs a server-enforced protected feature with a proof field in the brief.", "replaced"),
    D("TAD-004", "Payment-integrity engine", "legacy POST /entitlements/grant-direct (baseline)", (f"{Q}/app_testing_integrity/oracle_engine.py", f"{Q}/tests_verification/entitlement_target.py"),
      "An internal/admin grant route created the 'clean, correctly obtained entitlement' baseline.", "hidden internal/admin route", G, "An admin/internal grant route is a hidden test route a customer cannot use.", "Baselines were built with privileged writes.",
      "Controls use a real approved sandbox payment by a synthetic identity (CTRL: legitimate payer allowed, clean identity denied).", RM, CR, f"{T_ENGINE}::test_controls_use_only_customer_level_calls", "Needs an approved sandbox payment flow.", "removed from product"),
    D("TAD-005", "Payment-integrity engine", "legacy _revoke_delay_seconds test hook (ORC-I)", (f"{Q}/app_testing_integrity/oracle_engine.py", f"{Q}/tests_verification/entitlement_target.py"),
      "A request field injected a revocation delay into the target to time-box the revocation oracle.", "internal test fixture / hidden test hook", G, "A test-only target hook is not part of any customer flow.", "The lag oracle measured the hook, not the target's behaviour.",
      "PBB-R: externally timed polling of the protected feature after a confirmed self-service refund, judged against a CUSTOMER_DECLARED tolerance.", RP, HI, f"{T_BENCH}::test_refund_scenarios", "Poll window is bounded; the measured lag is an upper bound.", "replaced"),
    D("TAD-006", "Payment-integrity engine", "legacy vocabulary_confirmed (reference route/field vocabulary)", (f"{Q}/app_testing_integrity/contract.py",),
      "The customer confirmed the target implements a reference route vocabulary, unlocking mutating probes.", "private endpoint list / internal API documentation", G, "A route/field list not learned through normal product use is a private endpoint list.", "Probing relied on target-declared internals.",
      "integrity/brief.py: every operation/feature needs observed_via in {browser trace, customer API trace, public documentation, product UI, public API reference} and must not name internal/admin/test paths.", RP, HI, f"{T_PURITY}::test_brief_rejects_internal_api_base_and_internal_paths_and_missing_provenance", "observed_via is an attestation (not cryptographically verifiable).", "replaced"),
    D("TAD-007", "Payment-integrity engine", "legacy expected_gated declaration", (f"{Q}/app_testing_integrity/contract.py",), "Customer declared which surfaces must be paid-only.", "customer-declared product policy", P,
      PURE_NA, "Policy input only (CUSTOMER_DECLARED); it never confirmed a finding on its own.", "Kept as brief.features[].requires_plan / declared_paid_features (still CUSTOMER_DECLARED, can never confirm).", RP, LO, f"{T_ENGINE}::test_open_feature_is_partial_not_confirmed",
      "Plan-gating claims are not externally verified.", "moved into the brief"),
    D("TAD-008", "Payment-integrity engine", "legacy gap register (recommended declaring the webhook signing secret)", (f"{Q}/app_testing_integrity/gaps.py",), "The gap register told customers to supply a sandbox signing secret.", "recommendation of grey-box input", G,
      "Recommending a secret hands the tester grey-box access.", "Coverage numbers assumed the secret.", "integrity/gaps.py: BLOCKED rows state the black-box capability that would unlock each class; a secret is never requested.", RP, HI, f"{T_ENGINE}::test_gap_engine_marks_unsupported_classes_blocked", "Some classes stay BLOCKED by design.", "replaced"),
    D("TAD-009", "Verification infrastructure", "legacy black_box_prober.py (baseline prober)", (f"{Q}/tests_verification/black_box_prober.py",), "Forged webhooks and read /access/{user} against the legacy vocabulary.", "private route vocabulary; entitlement status; forged provider events", G,
      "Same channels as TAD-002/003.", "Produced the 'legacy baseline' numbers.", "Superseded by the purity benchmark baseline (docs/purity/legacy_baseline.json).", QR, ME, f"{T_PURITY}::test_quarantined_modules_cannot_load", "Removal by 2026-11-30.", "quarantined (cannot load)"),
    D("TAD-010", "Benchmark fixture", "legacy entitlement_target.py (target with admin/test routes used as engine vocabulary)", (f"{Q}/tests_verification/entitlement_target.py",), "Benchmark target whose internal routes, secret and hooks were part of what the engine used.", "benchmark hints (secret, hooks, internal routes)", G,
      "The engine was given the target's secret/hooks: benchmark hint passthrough.", "Benchmark credit was earned with hints.", "purity_benchmark/customer_target.py: hints/internal routes exist but are never given to the engine (scorer counts hits).", QR, ME, f"{T_BENCH}::test_internal_routes_and_hints_are_ignored", "Removal by 2026-11-30.", "quarantined"),
    D("TAD-011", "Benchmark infrastructure", "legacy benchmark_lab.py (passed webhook_secret; truth from in-process flags)", (f"{Q}/tests_verification/benchmark_lab.py", f"{Q}/tests_verification/oracle_engine_shim.py"), "Ran the engine with the target's secret and derived truth from flags in the same process.", "benchmark hints (secret) + shared-process truth", G,
      "Violates benchmark blindness.", "Scorecard credit invalid as a black-box claim.", "purity_benchmark/lab.py: blind runner (base URL + customer-level brief only); scorer.py is the independent post-run scorer.", QR, ME, f"{T_BENCH}::test_engine_inputs_contain_no_ground_truth", "Removal by 2026-11-30.", "quarantined"),
    D("TAD-012", "Benchmark documentation", "legacy BENCHMARK_SCORECARD (17 scenarios x 10 oracles)", (f"{Q}/BENCHMARK_SCORECARD_LEGACY.md",), "Published detection rates measured with grey-box inputs.", "benchmark hints", G, "Numbers cannot be cited as black-box capability.", "Competitive/capability claims built on them are invalid.",
      "docs/BENCHMARK_SCORECARD.md (pure benchmark, measured by scripts/run_purity_benchmark.py).", QR, HI, f"{T_PURITY}::test_scorecard_has_no_legacy_claims", "Kept for audit only.", "archived with an INVALID banner"),
    D("TAD-013", "Evidence analysis", "legacy reconciliation.py (reconcile internal payment vs entitlement records)", (f"{Q}/app_testing/reconciliation.py",), "Compared the target's internal payment and entitlement records.", "internal payment records + internal entitlement records", W,
      "Input IS the target's internal records.", "Library only; no product caller, but it modelled internal truth as evidence.", "External divergence between customer-visible state and the oracle (PBB-E).", QR, HI, f"{T_PURITY}::test_quarantined_modules_cannot_load", "Removal by 2026-11-30.", "quarantined"),
    D("TAD-014", "Evidence analysis", "legacy truth_model.py (internal read paths marked AUTHORITATIVE)", (f"{Q}/app_testing/truth_model.py",), "Classified internal record reads as authoritative truth sources.", "internal architecture assumptions", W, "Encodes target-internal truth sources.", "None at runtime (no importer).", "External truth labels in purity/taxonomy.py (EXTERNALLY_OBSERVED ...).", QR, ME,
      f"{T_PURITY}::test_quarantined_modules_cannot_load", "Removal by 2026-11-30.", "quarantined"),
    D("TAD-015", "Evidence analysis", "legacy check_trust_boundary.py (claimed vs authoritative server-side status)", (f"{Q}/app_testing/check_trust_boundary.py",), "Required the target's authoritative server-side status.", "backend-provided status / internal authoritative record", W,
      "Needs target-side authoritative state as input.", "Used only by legacy tests.", "PBB-E: customer-visible claim vs protected-feature oracle.", QR, ME, f"{T_PURITY}::test_quarantined_modules_cannot_load", "Removal by 2026-11-30.", "quarantined"),
    D("TAD-016", "Legacy tests", "tests of the grey-box engine/prober/target (6 files)", (f"{Q}/tests_verification/test_*.py",), "Validated the legacy path against the legacy target.", "benchmark hints, internal records", G, "They test code that no longer loads.", "49 legacy tests are no longer part of the active suite (not deleted, not weakened: quarantined with the code under test).",
      "tests/test_pure_engine.py, tests/test_purity_enforcement.py, tests/verification_infrastructure/test_purity_benchmark.py.", QR, ME, f"{T_PURITY}::test_quarantined_modules_cannot_load", "Removal by 2026-11-30.", "quarantined"),
    D("TAD-047", "Quarantine containment", "quarantine package guards + QUARANTINE.md", (f"{Q}/__init__.py", f"{Q}/*/__init__.py", f"{Q}/QUARANTINE.md", "backend/quarantine/__init__.py"), "Import guards that always raise; removal plan.", "none", P, PURE_NA, "None: the code behind it cannot execute.", "n/a", NC, LO,
      f"{T_PURITY}::test_quarantined_modules_cannot_load", "None.", "enforced"),
    # ------------------------------------------------------------------------------------------------ B. enforcement + engine (new)
    D("TAD-040", "Pure Black-Box enforcement layer", "app/enterprise_controls/** + app/control_adapter/** + app/core/control_port/** + app/testing/purity/** + scripts", ("backend/app/enterprise_controls/*", "backend/app/control_adapter/*", "backend/app/core/control_port/*", "backend/app/testing/purity/*", "backend/scripts/*"), "Access gate, credential gate, provenance ledger, oracle gate, blindness, quarantine, inventory, audit.", "none (stdlib only)", P, PURE_NA,
      "Enforces the rule for everything else.", "n/a", NC, CR, f"{T_PURITY} (all tests)", "Enforcement is heuristic where intent cannot be proven (see TAD-018/019).", "implemented + tested"),
    D("TAD-041", "Customer-level payment-integrity engine", "app/testing/integrity/** + modules/payment_integrity.py", ("backend/app/testing/integrity/*", "backend/app/testing/modules/payment_integrity.py"),
      "Synthetic identities, approved sandbox payments, return flow, Protected-Feature Oracle, controls, experiments, gaps, regression.", "authorised external customer-level behaviour only", P, PURE_NA, "This IS the replacement capability.", "n/a", NC, CR, f"{T_ENGINE} + {T_BENCH}",
      "Provider-event authenticity, concurrency and lifecycle (renewal/expiry/coupon) classes are BLOCKED/UNKNOWN by design.", "implemented + tested"),
    D("TAD-017", "Framework core", "ScopeGuard, QAHttpClient, runner, context, base, models, registry, enums, collector, event bus ...", ("backend/app/testing/*.py",), "Single choke point for every request (host allowlist, budget, rate, kill switch) + always-on purity gate.", "none beyond the run's own configuration", P,
      PURE_NA, "Hardened: every request and redirect hop passes the purity gate.", "n/a", NC, CR, "tests/test_scope_guard.py, tests/test_runner_e2e_scope.py, " + T_PURITY, "none", "hardened (AccessGate added)"),
    D("TAD-022", "Endpoint map", "EndpointMap.stripe_webhook override", ("backend/app/testing/endpoints.py",), "Operators could declare the provider-facing webhook route.", "private endpoint list (provider-facing route)", G, "A customer cannot learn a server-to-server route through product use.", "STRIPE-002/003 and webhook_delivery_consistency probed an operator-declared private route.",
      "Operator overrides for provider-facing operations are IGNORED; only the conventional placeholder is probed; the ignore is reported.", RP, HI, f"{T_PURITY}::test_provider_facing_endpoint_override_is_ignored", "A 404 on the conventional path means 'not testable here' (UNKNOWN), never 'passed'.", "replaced"),
    D("TAD-018", "Authentication / session import", "RunSettings.session_cookies + custom_headers (merged Cookie header)", ("backend/app/schemas/settings.py", "backend/app/core/settings_store.py", "backend/app/enterprise_controls/http_perimeter.py"),
      "An operator pastes a session cookie/headers that every module then sends.", "a session of unknown principal (could be staff/admin)", U, "The system cannot prove the cookie belongs to a synthetic customer-level identity.", "A privileged session would silently widen what every module can see.",
      "credentials.check_headers refuses privileged header/cookie names, secret-looking values and JWTs asserting admin/staff/service claims, at run start (HTTP 400) and in the runner.", RP, HI,
      f"{T_PURITY}::test_run_gate_rejects_privileged_session_material", "An opaque admin cookie (neutral name, non-JWT value) cannot be detected: needs an operator attestation field (alias, role=customer, synthetic=true) in the settings UI.", "partially enforced (heuristic)"),
    D("TAD-019", "Operator-declared routes", "endpoint_overrides + manual_routes + extra_allowed_hosts", ("backend/app/api/*", "backend/app/main.py", "backend/app/__init__.py"), "Operator-declared customer-facing routes and hosts.", "customer-declared routes (provenance unverifiable)", U,
      "An operator could paste a hidden/internal route learned from internal documentation.", "Probing could reach internal surfaces.", "Run start refuses internal/admin/debug/hidden-test paths and non-customer-facing hosts; the ScopeGuard purity gate refuses them again on the wire.", RP, HI,
      f"{T_PURITY}::test_run_gate_rejects_internal_endpoint_overrides_and_hosts", "A hidden-but-customer-looking route cannot be recognised as hidden.", "partially enforced (path/host rules)"),
    D("TAD-021", "Webhook security module", "additional_webhook_providers + AdditionalWebhookSecurityModule", ("backend/app/testing/modules/additional_webhook_security.py",), "Probes operator-declared provider webhook routes with unsigned/invalid-signature requests.", "private endpoint list (provider-facing route)", G,
      "The route is learned from the operator, not from an external discovery channel.", "Would send traffic to a private route.", "Each provider needs observed_via in the allowed set; otherwise BLOCKED with no request sent.", RP, HI, f"{T_PURITY}::test_webhook_provider_without_provenance_is_blocked", "Providers with attested provenance still only yield QA findings, never CONFIRMED_P0.", "replaced"),
    D("TAD-023", "Webhook/Stripe probes", "stripe_flow STRIPE-002/003, webhook_delivery_consistency, checkout_provider_testing", ("backend/app/testing/checkout_provider_testing.py", "backend/app/testing/modules/stripe_flow.py", "backend/app/testing/modules/webhook_delivery_consistency.py"),
      "Negative probes on the conventional webhook placeholder with a FABRICATED signing secret.", "none (fabricated secret; conventional path)", P, PURE_NA, "Internal-cause claims and 'check your database' advice were rewritten to externally honest wording (UNKNOWN, protected-feature oracle).", "n/a", NC, ME,
      f"{T_PURITY}::test_no_internal_causal_claims_in_product_text", "Results are QA findings, never CONFIRMED_P0 (no protected-feature oracle in these modules).", "wording hardened"),
    D("TAD-024", "Recon", "recon/path_prober.py (system-path probes: /admin, /actuator, /.env ...)", ("backend/app/testing/recon/path_prober.py",), "Probes conventional system paths with GET to see whether they are reachable.", "none (external guess)", P, PURE_NA, "Probes are tagged negative_access_control, counted, and response bodies are withheld (size + digest only): content of an exposed internal surface is never ingested.", "n/a", RP, ME,
      f"{T_PURITY}::test_negative_access_control_probe_is_tagged_counted_and_body_withheld", "Reachability of an internal surface is reported from the status code only.", "tagged + body withheld"),
    D("TAD-025", "Business-rule module", "business_rule_consistency hidden-route probes (GraphQL introspection, batch POST, debug body read)", ("backend/app/testing/modules/business_rule_consistency.py",), "Introspected GraphQL schemas, POSTed to undocumented batch routes, read debug/actuator bodies.", "internal schema / private API specification; undocumented write routes", G,
      "Introspection asks the target for its private API specification; batch POSTs hit undocumented write routes.", "Findings relied on internal content.", "Existence/status probe only (tagged, body withheld); introspection and batch POST are DISABLED and reported not_supported_pure_black_box.", DS, HI,
      f"{T_PURITY}::test_hidden_route_module_no_longer_reads_bodies_or_writes", "Whether a debug surface leaks secrets is UNKNOWN from outside (its body is not read).", "partially disabled"),
    D("TAD-026", "Cross-version module", "cross_version_consistency legacy-version write probes", ("backend/app/testing/modules/cross_version_consistency.py",), "Sent non-standard payment fields to undocumented legacy API versions.", "undocumented endpoints (write)", G, "Write probes against undocumented endpoints are outside every approved flow.", "Could change target state through hidden routes.",
      "Exposure of a legacy version is reported from a tagged GET; the strictness comparison is DISABLED (not_supported, never 'passed').", DS, HI, f"{T_PURITY}::test_hidden_route_module_no_longer_reads_bodies_or_writes", "Strictness of legacy versions is UNKNOWN.", "partially disabled"),
    D("TAD-027", "Role-based access module", "ROLE-003 system-route access with a customer session", ("backend/app/testing/modules/role_based_access.py",), "Sends one request to a discovered admin-looking route with the customer-level session and expects a rejection.", "none", P, PURE_NA,
      "Tagged negative_access_control so the purity gate admits it; still obeys host/scheme/port rules.", "n/a", NC, ME, f"{T_PURITY}::test_negative_access_control_probe_is_tagged_counted_and_body_withheld", "none", "tagged"),
    D("TAD-028", "Generic probe modules", "functional, negative, edge_case, error_handling, integration, processing_integrity, lifecycle, state/sequence, session, format modules", ("backend/app/testing/modules/*.py",),
      "Customer-facing API probes with the run's customer-level session; response-pattern scans.", "none beyond the customer-level session", P, PURE_NA, "n/a", "n/a", NC, LO, "tests/test_*.py + modules' own e2e tests", "Results are QA findings; only payment_integrity can emit CONFIRMED_P0.", "unchanged"),
    D("TAD-029", "Webhook sink", "core/webhook_sink.py + api/v1/webhook_sink.py", ("backend/app/core/webhook_sink.py", "backend/app/api/v1/webhook_sink.py"), "Receives the target's OUTBOUND notifications addressed to the QA system's own sink URL.", "customer-visible notification channel", P, PURE_NA,
      "Evidence from the sink may only be classified external_notification.", "n/a", NC, LO, "tests/test_security_middleware.py", "The sink is unauthenticated by design (local only).", "unchanged"),
    D("TAD-031", "Cognitive layer", "app/testing/cognition/** + app/testing/discovery/** + benchmark/**", ("backend/app/testing/cognition/*", "backend/app/testing/discovery/*", "backend/benchmark/*"), "Offline reasoning over observations the modules already collected; no network.", "none", P, PURE_NA, "n/a", "n/a", NC, LO,
      "tests/cognition/*, tests/test_ambiguous_case_resolution.py, tests/test_llm_replacement_layer.py", "none", "unchanged"),
    D("TAD-032", "Cognitive layer", "self-optimisation label channel (in_ground_truth)", ("backend/app/testing/cognition/improvement_loop.py", "backend/app/testing/cognition/hyperparameter_optimizer.py"), "Metrics for self-tuning consumed per-result ground-truth labels of any origin.", "benchmark flaw labels", G,
      "A label from a benchmark's seeded flaws would steer the system under assessment.", "Could overfit tuning to seeded scenarios.", "filter_label_channel: only human_reviewer_confirmed or synthetic_selftest labels are used; everything else is stripped before metrics.", RP, HI,
      f"{T_PURITY}::test_label_channel_strips_unapproved_ground_truth", "Reviewer labels are trusted as given.", "replaced"),
    D("TAD-033", "Recon", "browser_crawler, js_endpoint_parser, stripe_detector, function_mapper, mapper", ("backend/app/testing/recon/*",), "Authorised browser behaviour and public JS/HTML analysis.", "none", P, PURE_NA, "n/a", "n/a", NC, LO, "tests/test_url_utils.py + e2e", "none", "unchanged"),
    D("TAD-035", "Reporting", "reporter, results export, run summary", ("backend/app/api/v1/*", "backend/app/schemas/*"), "Aggregates results; the payment_integrity summary now carries a black-box purity attestation.", "none", P, PURE_NA, "n/a", "n/a", NC, LO, "tests/test_redaction.py", "none", "unchanged"),
    D("TAD-036", "Redaction", "redaction.py", ("backend/app/testing/redaction.py",), "Redacts secrets/PII before persistence (incl. whsec_/sk_ patterns seen in responses).", "none", P, PURE_NA, "n/a", "n/a", NC, LO, "tests/test_redaction.py", "none", "unchanged"),
    D("TAD-037", "Tool datastore", "app/db/** + core stores", ("backend/app/db/*", "backend/app/core/*"), "The QA system's OWN PostgreSQL/SQLAlchemy storage for runs/results/settings. It has no target database connector.", "none (tool-side storage)", P, PURE_NA, "n/a", "n/a", NC, LO, "audit: no DB driver import in target-facing code", "none", "unchanged"),
    D("TAD-038", "Configuration", "env example, compose, Dockerfile, requirements, launcher", ("backend/.env.example", "backend/Dockerfile", "backend/pytest.ini", "backend/requirements*.txt", "docker-compose.yml", ".gitignore", "run-benchmark.sh"), "Tool configuration; QA_INTEGRITY_CONTRACT_PATH/MEMORY_DIR removed, QA_INTEGRITY_BRIEF_PATH added.", "none", P, PURE_NA, "n/a", "n/a", RP, ME,
      f"{T_PURITY}::test_config_no_longer_references_legacy_contract_and_secret", "none", "updated"),
    D("TAD-039", "Documentation", "README, docs/**", ("README.md", "docs/*.md"), "Single consolidated README (project overview, legal/authorization notice, capabilities, architecture, boss coverage, setup); legacy grey-box claims removed.", "claims derived from grey-box measurements", G,
      "Legacy docs advertised secret-signed oracles and grey-box scorecard numbers.", "Misleading capability claims.", "docs/PAYMENT_INTEGRITY_PLATFORM.md, docs/PURE_BLACK_BOX.md, docs/BENCHMARK_SCORECARD.md", RP, ME, f"{T_PURITY}::test_scorecard_has_no_legacy_claims", "none", "rewritten"),
    D("TAD-042", "Black-Box Purity Benchmark", "tests/verification_infrastructure/purity_benchmark/** + generated scorecard", ("backend/tests/verification_infrastructure/purity_benchmark/*", "docs/BENCHMARK_SCORECARD.md"),
      "Controlled benchmark targets (hints/internal routes present but ignored), blind runner, independent post-run scorer, scorecard.", "none given to the engine", P, PURE_NA, "n/a", "n/a", NC, CR, T_BENCH, "Author of engine and targets is the same (shared-authorship bias).", "implemented + executed"),
    D("TAD-043", "Unit/e2e tests", "tests/test_*.py, tests/cognition/**", ("backend/tests/test_*.py", "backend/tests/__init__.py", "backend/tests/cognition/*"), "Tests of the QA system itself.", "none", P, PURE_NA, "n/a", "n/a", NC, LO, "executed with the offline mini_pytest stand-in", "Real pytest could not be installed in the sandbox.", "unchanged + new"),
    D("TAD-044", "Offline test harness + controlled targets", "mini_pytest, shims, reference/provider_b targets and their e2e tests", ("backend/tests/verification_infrastructure/mini_pytest.py", "backend/tests/verification_infrastructure/shims/*", "backend/tests/verification_infrastructure/reference_target.py",
      "backend/tests/verification_infrastructure/provider_b_target.py", "backend/tests/verification_infrastructure/test_*.py"), "Controlled benchmark targets for resilience/fault-injection tests; they are assessed as black boxes.", "none given to the system", P, PURE_NA, "n/a", "n/a", NC, LO, "executed", "none", "unchanged"),
    D("TAD-045", "Hardened purity benchmark", "tests/verification_infrastructure/hardened_benchmark/** (independent prober, randomized population, generalization probe, generated results)",
      ("backend/tests/verification_infrastructure/hardened_benchmark/*",),
      "Independent ground-truth prober, randomized/adversarial target population, and a generalization/recon-breadth probe; truth is derived from each target's public-API behaviour only and nothing is given to the engine.",
      "none given to the engine", P, PURE_NA, "n/a", "n/a", NC, LO,
      "executed with the offline mini_pytest stand-in and direct asyncio runners (validate_prober.py, run_hardened.py, generalization_probe.py)",
      "Loopback only; flaw mechanisms reuse the base fixture (mechanism-variant and surface-vocabulary randomization are the next hardening step).", "new"),
    D("TAD-051", "RP-001 terminal console", "backend/app/cli/** (theme/model/render/commands/app)",
      ("backend/app/cli/*",),
      "Terminal-first CLI/TUI in the exact RedPilot website palette; renders engine/orchestration/roster state in a terminal-native layout. No target access of its own.",
      "none", P, PURE_NA, "n/a", "n/a", NC, LO,
      "tests/test_cli_theme.py, tests/test_cli_model.py, tests/test_cli_render.py, tests/test_cli_commands.py (+ an executed demo render)",
      "The interactive raw-terminal event loop needs a real TTY; the non-TTY demo path is exercised in tests and run directly.", "implemented + executed"),
)
BY_ID = {d.id: d for d in INVENTORY}


def inventory_xml() -> str:
    return "\n".join(d.to_xml() for d in INVENTORY)


def counts() -> dict[str, int]:
    out: dict[str, int] = {c.value: 0 for c in Classification}
    for d in INVENTORY:
        out[d.classification.value] += 1
    return out


def forbidden_no_change() -> list[str]:
    """Entries that violate 'WHITE_BOX/GREY_BOX with no_change is forbidden'."""
    return [d.id for d in INVENTORY if d.classification in (W, G) and d.migration_action == NC]

