"""Core vocabulary of the Payment QA System (verdicts, truth labels, coverage). Stdlib only, no I/O.

Everything the customer-level oracle engine, the findings/gaps/regression models and the benchmark scorer have to agree on lives
here, so a verdict, a truth label or a coverage status can never silently mean two different things in two modules.

Moved out of this module by the Enterprise-Control isolation (see app/core/control_port and app/enterprise_controls):
  * EvidenceClass                                  -> app.core.control_port.contract (K4)
  * INTERNAL_PROVENANCE_MARKERS, ALLOWED_OBSERVED_VIA, PURE_MODE_ENV -> app.enterprise_controls.allowlists
  * Classification, MigrationAction, Priority      -> app.enterprise_controls.inventory (only the purity inventory uses them)
"""
from __future__ import annotations

from enum import Enum


class TruthLabel(str, Enum):
    EXTERNALLY_OBSERVED = "EXTERNALLY_OBSERVED"
    EXTERNALLY_REPRODUCED = "EXTERNALLY_REPRODUCED"
    CUSTOMER_DECLARED = "CUSTOMER_DECLARED"
    INFERRED = "INFERRED"
    UNKNOWN = "UNKNOWN"
    BLOCKED = "BLOCKED"


class Verdict(str, Enum):
    """Finding-level outcomes. CONFIRMED_P0 is unreachable without a ConfirmationToken (see oracle_gate.py)."""

    CONFIRMED_P0 = "CONFIRMED_P0"
    SUSPECTED_PAYMENT_INTEGRITY_ISSUE = "SUSPECTED_PAYMENT_INTEGRITY_ISSUE"
    PARTIALLY_VALIDATED_PAYMENT_INTEGRITY_ISSUE = "PARTIALLY_VALIDATED_PAYMENT_INTEGRITY_ISSUE"
    RULED_OUT = "RULED_OUT"
    UNKNOWN = "UNKNOWN"
    BLOCKED = "BLOCKED"


class Coverage(str, Enum):
    COVERED = "COVERED"
    PARTIALLY_COVERED = "PARTIALLY_COVERED"
    UNKNOWN = "UNKNOWN"
    BLOCKED = "BLOCKED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
