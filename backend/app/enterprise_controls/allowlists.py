"""Allowlists and provider-route rules of the Enterprise Controls. Stdlib only, no I/O.

Moved unchanged from purity/taxonomy.py (INTERNAL_PROVENANCE_MARKERS, ALLOWED_OBSERVED_VIA, PURE_MODE_ENV) and testing/endpoints.py
(PROVIDER_FACING_OPERATIONS).
"""
from __future__ import annotations

# Provenance classifications that are named explicitly so a rejection can say WHY (internal vs merely unknown).
INTERNAL_PROVENANCE_MARKERS = frozenset({
    "internal", "privileged", "admin", "staff", "database", "db", "log", "logs", "dashboard", "provider_dashboard",
    "webhook_log", "source_code", "repository", "entitlement_record", "internal_state", "benchmark_label", "ground_truth",
    "unknown", "unverified",
})

# observed_via values a brief may attest for a customer-facing operation/feature. Anything else (internal docs, source
# code, admin panel, private API spec, staff instructions ...) is a grey-box origin and is rejected.
ALLOWED_OBSERVED_VIA = frozenset({
    "authorized_browser_trace", "authorized_customer_api_trace", "public_documentation", "product_ui", "public_api_reference",
})

PURE_MODE_ENV = "QA_PURE_BLACK_BOX"  # informational constant: no code reads it and there is no switch for the mode (see quarantine.py)

# Operations the provider calls (not the customer): an operator override for them is ignored (EndpointMap.resolve)
PROVIDER_FACING_OPERATIONS = frozenset({"stripe_webhook"})
