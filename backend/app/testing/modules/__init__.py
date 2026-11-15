"""Test Module Package.

Re-exports all test module classes for convenient access.

Original modules (11):
- functional: Positive testing — valid requests should succeed
- negative: Parameter validation — invalid input should be rejected
- edge_case: Overflow, precision, unicode, race conditions
- error_handling: Error codes, response consistency
- integration: End-to-end checkout and refund flows
- recon: Endpoint discovery (browser + JS parsing + path probing)
- stripe_flow: Stripe-specific payment flow validation
- role_based_access: Account isolation and payment-attribute checks
- processing_integrity: Idempotency, round-trip fidelity
- lifecycle_consistency: Cross-endpoint subscription status
- input_format_consistency: Alternate wire format validation

Extended modules (6):
- webhook_delivery_consistency: Webhook duplicate detection, timing,
  signature validation, delayed repeat safety
- state_transition_consistency: Concurrent modification, unusual
  transition rejection, cross-endpoint state agreement, refund sync
- cross_version_consistency: API version validation consistency,
  legacy version discovery
- advanced_input_format: Duplicate parameters, content-type variants,
  charset variants, type confusion, structure keys, source priority
- session_consistency: Authentication consistency, CSRF enforcement,
  middleware integrity, session renewal privilege stability
- business_rule_consistency: Trial parameter validation, completion
  verification, currency consistency, balance floors, undocumented routes
"""
from app.testing.modules.functional import FunctionalTestModule
from app.testing.modules.negative import NegativeTestModule
from app.testing.modules.edge_case import EdgeCaseTestModule
from app.testing.modules.error_handling import ErrorHandlingTestModule
from app.testing.modules.integration import IntegrationTestModule
from app.testing.modules.recon import ReconModule
from app.testing.modules.stripe_flow import StripeFlowTestModule
from app.testing.modules.role_based_access import RoleBasedAccessModule
from app.testing.modules.processing_integrity import ProcessingIntegrityModule
from app.testing.modules.lifecycle_consistency import LifecycleConsistencyModule
from app.testing.modules.input_format_consistency import InputFormatConsistencyModule

# Extended modules (14-19)
from app.testing.modules.webhook_delivery_consistency import WebhookDeliveryConsistencyModule
from app.testing.modules.state_transition_consistency import StateTransitionConsistencyModule
from app.testing.modules.cross_version_consistency import CrossVersionConsistencyModule
from app.testing.modules.advanced_input_format import AdvancedInputFormatModule
from app.testing.modules.session_consistency import SessionConsistencyModule
from app.testing.modules.business_rule_consistency import BusinessRuleConsistencyModule

__all__ = [
    # Original modules
    "FunctionalTestModule",
    "NegativeTestModule",
    "EdgeCaseTestModule",
    "ErrorHandlingTestModule",
    "IntegrationTestModule",
    "ReconModule",
    "StripeFlowTestModule",
    "RoleBasedAccessModule",
    "ProcessingIntegrityModule",
    "LifecycleConsistencyModule",
    "InputFormatConsistencyModule",

    # Extended modules
    "WebhookDeliveryConsistencyModule",
    "StateTransitionConsistencyModule",
    "CrossVersionConsistencyModule",
    "AdvancedInputFormatModule",
    "SessionConsistencyModule",
    "BusinessRuleConsistencyModule",
]
