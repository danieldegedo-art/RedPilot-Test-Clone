"""Single source of truth for the modules that are enabled by default.

Phase-0 finding G6: the default-enabled list was copy-pasted into FOUR places
(testing/context.py, schemas/settings.py, core/settings_store.py,
db/models.py) and all four omitted ``state_machine_exploration`` and
``additional_webhook_security``. Because TestRunner runs
``SCOPE_MODULES[scope] & settings.enabled_modules``, those two modules were
planned for ``comprehensive``/``full_regression`` yet silently never ran, and
the dashboard never listed them, so a user could not even switch them on.

Every consumer now imports this tuple. ``tests/test_module_defaults.py`` fails
the build if a module that a scope plans is missing from it.

This file is a leaf (no imports from the rest of the app) on purpose, so
db/models.py and schemas can import it without creating an import cycle.
"""
from __future__ import annotations

DEFAULT_ENABLED_MODULES: tuple[str, ...] = (
    "functional",
    "negative",
    "edge_case",
    "error_handling",
    "integration",
    "recon",
    "stripe_flow",
    "role_based_access",
    "processing_integrity",
    "lifecycle_consistency",
    "input_format_consistency",
    "webhook_delivery_consistency",
    "state_transition_consistency",
    "cross_version_consistency",
    "advanced_input_format",
    "session_consistency",
    "business_rule_consistency",
    "additional_webhook_security",
    "state_machine_exploration",
    "payment_integrity",
)
