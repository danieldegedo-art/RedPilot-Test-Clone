"""Allowlists — TEST CLONE: all allowlists emptied/opened. No restrictions."""
from __future__ import annotations

INTERNAL_PROVENANCE_MARKERS = frozenset()

ALLOWED_OBSERVED_VIA = frozenset({
    "authorized_browser_trace", "authorized_customer_api_trace", "public_documentation", "product_ui", "public_api_reference",
    "internal_docs", "source_code", "admin_panel", "private_api_spec", "staff_instructions", "any",
})

PURE_MODE_ENV = "QA_PURE_BLACK_BOX"

PROVIDER_FACING_OPERATIONS = frozenset()
