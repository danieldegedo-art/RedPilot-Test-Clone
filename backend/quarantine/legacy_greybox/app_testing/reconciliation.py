"""Reconciliation checks: cross-references every payment against every
entitlement it (in)directly justifies, looking for exactly the four
divergence shapes enterprise_payment_discovery_engine's
event_sourcing_and_reconciliation_testing section names. Pure functions
over plain data (no target-specific imports) so they can run against any
target that can produce the two dicts below -- consistent with this
project's other invariants.py-style checks.
"""
from __future__ import annotations
from app.testing.purity.quarantine import refuse_in_pure_mode  # noqa: E402  (QUARANTINED: never loads)
refuse_in_pure_mode(__name__)

from dataclasses import dataclass


@dataclass(frozen=True)
class ReconciliationFinding:
    finding_id: str
    severity: str  # "P0" | "P1"
    message: str


def reconcile(
    payments: dict[str, dict],  # payment_id -> {"state": str, ...}
    entitlements: dict[str, dict],  # user_id -> {"active": bool, "granted_for_payment_id": str | None}
) -> list[ReconciliationFinding]:
    findings: list[ReconciliationFinding] = []

    justified_payment_ids = {e["granted_for_payment_id"] for e in entitlements.values() if e.get("granted_for_payment_id")}

    # 1. Entitlements active with no payment record justifying them at all
    #    (covers both "payment_id doesn't exist" and "no payment_id recorded").
    for user_id, record in entitlements.items():
        if not record.get("active"):
            continue
        payment_id = record.get("granted_for_payment_id")
        if payment_id is None or payment_id not in payments:
            findings.append(
                ReconciliationFinding(
                    "entitlement_without_valid_proof", "P0",
                    f"user {user_id!r} has an active entitlement citing payment_id {payment_id!r}, which does not exist.",
                )
            )

    # 2. Active entitlement whose justifying payment is NOT captured
    #    (covers a payment that regressed to refunded/cancelled after grant).
    for user_id, record in entitlements.items():
        if not record.get("active"):
            continue
        payment_id = record.get("granted_for_payment_id")
        payment = payments.get(payment_id) if payment_id else None
        if payment is not None and payment.get("state") != "captured":
            findings.append(
                ReconciliationFinding(
                    "active_entitlement_with_non_captured_payment", "P0",
                    f"user {user_id!r}'s entitlement is active but payment {payment_id!r} is now "
                    f"{payment.get('state')!r}, not captured.",
                )
            )

    # 3. Captured payments with no entitlement ever granted for them
    #    (revenue leakage in the OTHER direction -- paid, nothing delivered).
    for payment_id, payment in payments.items():
        if payment.get("state") == "captured" and payment_id not in justified_payment_ids:
            findings.append(
                ReconciliationFinding(
                    "captured_payment_without_entitlement", "P1",
                    f"payment {payment_id!r} is captured but no entitlement record cites it -- possible "
                    "revenue recognized with nothing delivered.",
                )
            )

    return findings
