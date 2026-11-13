"""Quarantine guard: keeps White-/Grey-Box code that was moved out of the product from EVER loading (mandate: 'quarantine').

Quarantine is temporary technical containment, never an operating mode. There is deliberately NO opt-in, no environment variable
and no context manager that lets a quarantined module load: ``refuse_in_pure_mode`` raises ``QuarantinedModuleError`` unconditionally.
Consequences, each pinned by tests/test_purity_enforcement.py:
  * quarantined code cannot receive target credentials or target data (it cannot even be imported),
  * it cannot influence planning, execution, evidence, benchmarks, findings or reports (nothing under app/ may import it),
  * a legacy baseline can only be re-measured by checking out the pre-migration tree -- a deliberate act, not a runtime toggle.
Removal plan: see backend/quarantine/legacy_greybox/QUARANTINE.md (scheduled removal date is machine-readable below).
"""
from __future__ import annotations

from app.core.control_port.contract import QuarantinedModuleError

QUARANTINE_REMOVAL_DEADLINE = "2026-11-30"
QUARANTINE_REASON = "White-/Grey-Box dependency (target secret, provider-facing webhook forgery, internal entitlement records, admin/test-hook routes, benchmark internals)"


def refuse_in_pure_mode(module_name: str) -> None:
    raise QuarantinedModuleError(
        "quarantined_module_load_refused",
        f"DEPRECATED + QUARANTINED: {module_name!r} depends on target-side information ({QUARANTINE_REASON}). "
        f"The Payment QA System is 100% Pure Black-Box; this module never loads. Scheduled for removal by {QUARANTINE_REMOVAL_DEADLINE}. "
        f"Use app.testing.integrity (customer-level Protected-Feature Oracle engine) instead.",
    )
