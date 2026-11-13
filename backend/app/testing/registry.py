"""Central registry of test modules.

MODULE_REGISTRY holds the modules implemented so far. SCOPE_MODULES declares
the full intended module set per test scope, including modules not yet
implemented -- the TestRunner emits an INFO result for any scoped module
that isn't in MODULE_REGISTRY yet, so adding a new module is a two-line
change here with no other code to touch.

MODULE_EXECUTION_ORDER pins "recon" first: when enabled, it discovers real
endpoints (and third-party integrations like Stripe -- see
recon/stripe_detector.py) and merges them into the shared EndpointMap /
context.shared_state before the other modules run in the same pass, so
their requests target the discovered routes and "stripe_flow" knows
whether to run its Stripe-specific cases at all. Recon also builds the
categorized FunctionMap (see recon/function_mapper.py) that
"role_based_access" and "lifecycle_consistency" depend on. "role_based_access"
runs right after everything else and stashes its route x attribute matrix
into shared_state for "input_format_consistency" (Module 12), which runs
immediately after it for the same reason -- it re-tests exactly the
routes/attributes ROLE-002 already confirmed blocking, as alternate wire
formats. "webhook_delivery_consistency" runs after all payment-flow modules
so it can observe the complete set of webhook interactions. "state_transition_consistency"
runs after webhook tests to verify state integrity across all observed transitions.
"cross_version_consistency" runs after state tests to compare version-specific behavior.
"advanced_input_format" runs after cross-version to stress-test input handling.
"session_consistency" runs after all request-based tests to verify session integrity.
"business_rule_consistency" runs near the end, verifying business workflow rules.
"lifecycle_consistency" is pinned truly last: it's the only
module that deliberately drives the test account's subscription to a
real, terminal cancelled state, so nothing else in the same pass should
run after it and be surprised by that. The remaining modules run in a
sensible QA order (happy path, then negative/edge/error, then multi-step
flows last); any future module id not listed falls back to alphabetical
order at the end.

Current build: every module referenced in SCOPE_MODULES is implemented --
recon, functional, negative, edge_case, error_handling, integration,
stripe_flow, role_based_access, processing_integrity, lifecycle_consistency,
input_format_consistency, webhook_delivery_consistency,
state_transition_consistency, cross_version_consistency,
advanced_input_format, session_consistency, business_rule_consistency,
state_machine_exploration, additional_webhook_security, payment_integrity.

"payment_integrity" (app/testing/modules/payment_integrity.py, the pure black-box Protected-Feature Oracle engine)
runs immediately BEFORE lifecycle_consistency, never after it: lifecycle_consistency
drives the shared test account to a terminal cancelled state, after which every
authenticated request of the same pass may behave differently and the oracles'
baselines would be measuring that, not the target's controls. It is deliberately not
in PARALLEL_SAFE_MODULES (it creates and refunds its own synthetic payments). It is
SAFE BY DEFAULT: without a valid, authorised, customer-level ExecutionBrief
(app/testing/integrity/brief.py) it sends ZERO requests and emits one WARNING that
lists the P0 classes left untested. It is PURE BLACK-BOX: synthetic identities, the
approved sandbox payment flow and server-enforced protected-feature use are its only
sources of truth (no target secrets, logs, databases, dashboards or internal routes).
"""
from __future__ import annotations

from app.testing.base import BaseTestModule
from app.testing.enums import TestScope
from app.testing.modules.additional_webhook_security import AdditionalWebhookSecurityModule
from app.testing.modules.edge_case import EdgeCaseTestModule
from app.testing.modules.error_handling import ErrorHandlingTestModule
from app.testing.modules.functional import FunctionalTestModule
from app.testing.modules.input_format_consistency import InputFormatConsistencyModule
from app.testing.modules.integration import IntegrationTestModule
from app.testing.modules.lifecycle_consistency import LifecycleConsistencyModule
from app.testing.modules.negative import NegativeTestModule
from app.testing.modules.payment_integrity import PaymentIntegrityModule
from app.testing.modules.processing_integrity import ProcessingIntegrityModule
from app.testing.modules.recon import ReconModule
from app.testing.modules.role_based_access import RoleBasedAccessModule
from app.testing.modules.stripe_flow import StripeFlowTestModule
from app.testing.modules.webhook_delivery_consistency import WebhookDeliveryConsistencyModule
from app.testing.modules.state_transition_consistency import StateTransitionConsistencyModule
from app.testing.modules.cross_version_consistency import CrossVersionConsistencyModule
from app.testing.modules.advanced_input_format import AdvancedInputFormatModule
from app.testing.modules.session_consistency import SessionConsistencyModule
from app.testing.modules.business_rule_consistency import BusinessRuleConsistencyModule
from app.testing.modules.state_machine_exploration import StateMachineExplorationModule

MODULE_REGISTRY: dict[str, type[BaseTestModule]] = {
    ReconModule.module_id: ReconModule,
    FunctionalTestModule.module_id: FunctionalTestModule,
    NegativeTestModule.module_id: NegativeTestModule,
    EdgeCaseTestModule.module_id: EdgeCaseTestModule,
    IntegrationTestModule.module_id: IntegrationTestModule,
    ErrorHandlingTestModule.module_id: ErrorHandlingTestModule,
    StripeFlowTestModule.module_id: StripeFlowTestModule,
    AdditionalWebhookSecurityModule.module_id: AdditionalWebhookSecurityModule,
    RoleBasedAccessModule.module_id: RoleBasedAccessModule,
    ProcessingIntegrityModule.module_id: ProcessingIntegrityModule,
    LifecycleConsistencyModule.module_id: LifecycleConsistencyModule,
    InputFormatConsistencyModule.module_id: InputFormatConsistencyModule,
    WebhookDeliveryConsistencyModule.module_id: WebhookDeliveryConsistencyModule,
    StateTransitionConsistencyModule.module_id: StateTransitionConsistencyModule,
    CrossVersionConsistencyModule.module_id: CrossVersionConsistencyModule,
    AdvancedInputFormatModule.module_id: AdvancedInputFormatModule,
    SessionConsistencyModule.module_id: SessionConsistencyModule,
    BusinessRuleConsistencyModule.module_id: BusinessRuleConsistencyModule,
    StateMachineExplorationModule.module_id: StateMachineExplorationModule,
    PaymentIntegrityModule.module_id: PaymentIntegrityModule,
}

SCOPE_MODULES: dict[TestScope, set[str]] = {
    TestScope.SMOKE: {"functional", "negative"},
    TestScope.STANDARD: {"functional", "negative", "error_handling", "recon", "stripe_flow"},
    TestScope.COMPREHENSIVE: {
        "functional", "negative", "error_handling", "edge_case", "recon", "stripe_flow",
        "additional_webhook_security", "role_based_access",
        "processing_integrity", "lifecycle_consistency", "input_format_consistency",
        "webhook_delivery_consistency", "state_transition_consistency", "state_machine_exploration",
        "advanced_input_format", "session_consistency", "business_rule_consistency", "payment_integrity",
    },
    TestScope.FULL_REGRESSION: {
        "functional", "negative", "error_handling", "edge_case", "integration", "recon", "stripe_flow",
        "additional_webhook_security",
        "role_based_access", "processing_integrity", "lifecycle_consistency", "input_format_consistency",
        "webhook_delivery_consistency", "state_transition_consistency", "state_machine_exploration",
        "cross_version_consistency",
        "advanced_input_format", "session_consistency", "business_rule_consistency", "payment_integrity",
    },
}

MODULE_EXECUTION_ORDER: tuple[str, ...] = (
    "recon", "functional", "negative", "error_handling", "edge_case", "integration", "processing_integrity",
    "stripe_flow", "additional_webhook_security", "role_based_access", "input_format_consistency",
    "webhook_delivery_consistency", "state_transition_consistency", "state_machine_exploration",
    "cross_version_consistency",
    "advanced_input_format", "session_consistency", "business_rule_consistency", "payment_integrity", "lifecycle_consistency",
)


def resolve_execution_order(module_ids: set[str]) -> list[str]:
    """Orders a set of module ids per MODULE_EXECUTION_ORDER, appending any
    unlisted id alphabetically at the end."""
    ordered = [module_id for module_id in MODULE_EXECUTION_ORDER if module_id in module_ids]
    remaining = sorted(module_ids - set(MODULE_EXECUTION_ORDER))
    return ordered + remaining


# Modules verified safe to run CONCURRENTLY with each other (see runner.py's
# batched execution, added alongside this set). Two independent checks, both
# evidence-based rather than assumed, gate membership here:
#
#  1. No cross-module data dependency through context.shared_state. Verified
#     by grepping every module for shared_state reads/writes (not by
#     inspection alone -- assuming independence from a docstring, when a
#     module could have grown an undocumented read later, is exactly the
#     kind of unverified claim this project's own culture rejects). Ground
#     truth: only `recon` (writes function_map / stripe_detection /
#     discovered_values) and `role_based_access` (writes role_002_matrix,
#     consumed only by input_format_consistency) write to shared_state at
#     all. Every module below only ever reads recon's output -- never each
#     other's -- which is already satisfied once recon's own (necessarily
#     solo, always-first) phase completes.
#  2. No shared, mutable TARGET-side state. functional / negative /
#     edge_case / error_handling / integration / processing_integrity /
#     stripe_flow / additional_webhook_security each create and act on
#     THEIR OWN payment/checkout/refund/webhook-event resources per case
#     (see each module's own docstring), not a single long-lived account
#     record. This is what specifically EXCLUDES role_based_access and
#     input_format_consistency from this set despite also having no
#     shared_state conflict with it: both perform payment-attribute
#     injection against the shared "test account" with an explicit
#     rollback/restore step (see role_based_access.py's own "restored on
#     the test account" language) -- concurrent mutation of the same
#     account fields from a sibling module risks exactly the kind of race
#     a payment-integrity tool must not itself introduce. Both stay
#     sequential, in their existing relative position in
#     MODULE_EXECUTION_ORDER, unchanged by this set's existence.
#     additional_webhook_security (added alongside this comment, see the
#     efficiency/extensibility pass) sends the same kind of synthetic,
#     self-contained webhook POSTs stripe_flow already does -- no
#     shared_state, no shared test-account mutation, same safety profile.
#
# lifecycle_consistency, and the observational-tail modules (webhook/state/
# cross-version/session/business-rule), are excluded for the reasons
# already documented at the top of this file (each depends on having
# observed the complete, settled set of effects everything before it
# produced) -- this set does not revisit those, only formalizes the
# no-shared-state cluster that was already sitting consecutively in
# MODULE_EXECUTION_ORDER.
PARALLEL_SAFE_MODULES: frozenset[str] = frozenset(
    {
        "functional",
        "negative",
        "edge_case",
        "error_handling",
        "integration",
        "processing_integrity",
        "stripe_flow",
        "additional_webhook_security",
        # Added alongside state_machine_exploration.py itself: every
        # scenario it runs creates and drives its own fresh payment (see
        # that module's _drive_to_state) and never touches shared_state or
        # discovered_values -- the same no-shared-mutable-state property
        # that qualified the eight modules above. Not adjacent to them in
        # MODULE_EXECUTION_ORDER (kept next to state_transition_consistency
        # instead, its conceptual sibling), so this currently forms its
        # own single-module batch rather than joining the larger one --
        # correct and safe, just not yet claiming a parallelism benefit
        # against that specific cluster; see the project's before/after
        # report for the real, measured batch this produces today.
        "state_machine_exploration",
    }
)


def batch_execution_order(module_ids: set[str]) -> list[list[str]]:
    """Like resolve_execution_order, but grouped into batches: consecutive
    runs of PARALLEL_SAFE_MODULES members collapse into one batch (meant to
    be executed concurrently -- see runner.py), while anything else keeps
    its own single-element batch (executed alone, blocking the next batch).
    Ordering is otherwise identical to resolve_execution_order -- this
    changes HOW consecutive safe modules run, never their relative order or
    what set of modules is included."""
    ordered = resolve_execution_order(module_ids)
    batches: list[list[str]] = []
    current: list[str] = []
    for module_id in ordered:
        if module_id in PARALLEL_SAFE_MODULES:
            current.append(module_id)
            continue
        if current:
            batches.append(current)
            current = []
        batches.append([module_id])
    if current:
        batches.append(current)
    return batches
