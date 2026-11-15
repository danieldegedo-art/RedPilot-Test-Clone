"""B19: Shadow-Ledger Cross-Check -- the comparison, labelled explicitly.

The ledger-side source of truth already exists: `oracle_calibration.
make_ledger_cross_check_verifier` answers 'allowed'/'denied' from PESM's
independently-recorded entitlement state, deliberately WITHOUT comparing it to the
target's own HTTP answer. The comparison -- the actual shadow-ledger cross-check of
Section 14.1 ("the sandbox provider ledger shows no charge, yet the application grants
paid access") -- was left to each calling experiment and never packaged. This module
packages exactly that comparison as B19, reusing the existing verifier's output rather
than duplicating any ledger logic.

It compares two outcomes for the SAME session -- the independent LEDGER outcome and
the APPLICATION's outcome -- and classifies the (in)consistency:
  * ledger denied (no charge) but application allowed -> INCONSISTENT_GRANT: access
    without a backing charge, the strongest shadow-ledger fraud signal.
  * ledger allowed but application denied -> INCONSISTENT_DENY: a paid-but-denied
    billing/availability inconsistency.
  * agree -> CONSISTENT; either side indeterminate -> INDETERMINATE (never guessed).

An INCONSISTENT_GRANT is a strong LEAD; it is still confirmed through the oracle gate
(ZR-017), never a standalone verdict. Stdlib only; pure.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

MODULE_VERSION = "shadow-ledger/1.0"
_OUTCOMES = ("allowed", "denied", "indeterminate")


class ShadowLedgerStatus(str, Enum):
    CONSISTENT = "CONSISTENT"
    INCONSISTENT_GRANT = "INCONSISTENT_GRANT"   # ledger: no charge, app: access -> strongest signal
    INCONSISTENT_DENY = "INCONSISTENT_DENY"     # ledger: charged, app: denied
    INDETERMINATE = "INDETERMINATE"             # at least one side unknown


@dataclass(frozen=True)
class ShadowLedgerResult:
    status: ShadowLedgerStatus
    ledger: str
    application: str
    note: str

    @property
    def is_lead(self) -> bool:
        return self.status in (ShadowLedgerStatus.INCONSISTENT_GRANT, ShadowLedgerStatus.INCONSISTENT_DENY)

    def to_dict(self) -> dict[str, Any]:
        return {"status": self.status.value, "ledger": self.ledger, "application": self.application,
                "is_lead": self.is_lead, "note": self.note}


def cross_check(ledger_outcome: str, application_outcome: str) -> ShadowLedgerResult:
    """Compare the independent ledger outcome against the application outcome for the
    same session. Both must be one of 'allowed' | 'denied' | 'indeterminate'."""
    if ledger_outcome not in _OUTCOMES or application_outcome not in _OUTCOMES:
        raise ValueError(f"outcomes must each be one of {_OUTCOMES}")

    if ledger_outcome == "indeterminate" or application_outcome == "indeterminate":
        return ShadowLedgerResult(ShadowLedgerStatus.INDETERMINATE, ledger_outcome, application_outcome,
                                  "at least one side is indeterminate -> no cross-check conclusion (never guessed)")
    if ledger_outcome == application_outcome:
        return ShadowLedgerResult(ShadowLedgerStatus.CONSISTENT, ledger_outcome, application_outcome,
                                  "ledger and application agree")
    if ledger_outcome == "denied" and application_outcome == "allowed":
        return ShadowLedgerResult(ShadowLedgerStatus.INCONSISTENT_GRANT, ledger_outcome, application_outcome,
                                  "LEAD: the application grants access the ledger has no charge for (Section 14.1); "
                                  "a strong shadow-ledger signal, still confirmed via the oracle gate (ZR-017), never "
                                  "a standalone verdict")
    return ShadowLedgerResult(ShadowLedgerStatus.INCONSISTENT_DENY, ledger_outcome, application_outcome,
                              "LEAD: the ledger shows a charge the application denies access for (paid-but-denied)")


def cross_check_payload(ledger_outcome: str, application_outcome: str) -> dict[str, Any]:
    res = cross_check(ledger_outcome, application_outcome)
    return {"module_version": MODULE_VERSION, **res.to_dict(),
            "note": "B19 shadow-ledger cross-check: compares the independent ledger outcome (from "
                    "oracle_calibration.make_ledger_cross_check_verifier) with the application outcome; an "
                    "inconsistency is a lead, confirmed via the oracle gate (ZR-017), never a standalone verdict."}
