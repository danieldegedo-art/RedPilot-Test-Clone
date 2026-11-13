"""Capability-gap register: what the Oracle Engine can and cannot test under a given contract.

"Not externally testable" must become a documented UNKNOWN/BLOCKED critical exposure,
never a claim of safety. Every row that is not COVERED states, in the mandated form,
WHICH barrier blocks it, of WHICH kind (SYSTEM_LIMIT / ASSESSMENT_LIMIT / TARGET_LIMIT /
SAFETY_LIMIT), the smallest safe improvement, and how that improvement would be measured.
Stdlib-only.
"""
from __future__ import annotations
from app.testing.purity.quarantine import refuse_in_pure_mode  # noqa: E402  (QUARANTINED: never loads)
refuse_in_pure_mode(__name__)

from dataclasses import dataclass


@dataclass(frozen=True)
class GapRow:
    p0_class: str
    status: str  # COVERED | PARTIALLY_COVERED | BLOCKED | MISSING
    barrier_type: str | None
    barrier: str
    improvement: str
    success_metric: str

    def statement(self) -> str:
        if self.status == "COVERED":
            return f"{self.p0_class}: COVERED by the Oracle Engine under the declared contract."
        return (
            f"This P0 class ({self.p0_class}) remains {self.status} because {self.barrier}. "
            f"The smallest safe improvement with the highest expected critical discovery value is {self.improvement}. "
            f"Its success metric is {self.success_metric}."
        )


def capability_gaps(*, has_contract: bool, has_secret: bool) -> list[GapRow]:
    no_contract = "no integrity contract is declared (authorization attestation, sandbox scope, allowed hosts), so the engine is not permitted to send a single request"
    declare = "declaring a sandbox integrity contract (see docs/PAYMENT_INTEGRITY_PLATFORM.md, 'Integrity contract')"

    def engine_row(name: str, metric: str) -> GapRow:
        if has_contract:
            return GapRow(name, "COVERED", None, "", "", "")
        return GapRow(name, "BLOCKED", "ASSESSMENT_LIMIT", no_contract, declare, metric)

    rows = [
        engine_row("payment-to-entitlement timing: an unconfirmed payment event yields a usable benefit (ORC-B)", "ORC-B ends CONFIRMED_P0 or RULED_OUT on the customer sandbox"),
        engine_row("webhook authentication perimeter (ORC-A)", "ORC-A ends CONFIRMED_P0 or RULED_OUT on the customer sandbox"),
        engine_row("duplicate delivery of the same payment event, sequential (ORC-C)", "ORC-C ends CONFIRMED_P0 or RULED_OUT on the customer sandbox"),
        engine_row("amount/tier binding (ORC-F) and currency binding (ORC-H)", "ORC-F and ORC-H end CONFIRMED_P0 or RULED_OUT on the customer sandbox"),
        engine_row("tenant binding of a payment (ORC-G)", "ORC-G ends CONFIRMED_P0 or RULED_OUT on the customer sandbox"),
        engine_row("refund -> access retention, cross-view truth divergence, revocation lag (ORC-D/E/I)", "ORC-D/E/I end in a definite verdict on the customer sandbox"),
    ]
    if not has_contract:
        rows.append(GapRow("business-logic controls behind the webhook signature perimeter", "BLOCKED", "ASSESSMENT_LIMIT", no_contract, declare, "ORC-B/C/F/G/H leave UNKNOWN"))
    elif has_secret:
        rows.append(GapRow("business-logic controls behind the webhook signature perimeter", "COVERED", None, "", "", ""))
    else:
        rows.append(GapRow(
            "business-logic controls behind the webhook signature perimeter", "BLOCKED", "TARGET_LIMIT",
            "no sandbox webhook signing secret is declared, so every event the engine sends is stopped at the signature perimeter and the controls behind it (status, amount, tenant, currency, de-duplication) are never exercised",
            "declaring the provider's SANDBOX webhook signing secret in the contract (webhook_secret + webhook_secret_is_sandbox: true)",
            "ORC-B/C/F/G/H change from UNKNOWN to CONFIRMED_P0 or RULED_OUT on the perimeter-fixed benchmark scenario",
        ))
    rows += [
        GapRow("concurrent duplicate deliveries / parallel redemption (race)", "PARTIALLY_COVERED", "SYSTEM_LIMIT",
               "the engine replays sequentially only; simultaneous delivery of the same event is not exercised", "a bounded (max 3 in flight) concurrent-delivery oracle behind the same scope guard",
               "a seeded racy-de-duplication target flips from RULED_OUT to CONFIRMED_P0"),
        GapRow("return/redirect-flow entitlement (a success URL reached without payment)", "MISSING", "SYSTEM_LIMIT",
               "the engine has no return-flow oracle", "a return-flow oracle plus a seeded target with a cosmetic and a granting success page",
               "the granting variant is CONFIRMED_P0 and the cosmetic variant OBSERVED_DIVERGENCE"),
        GapRow("alternate public paths (coupon, trial, billing portal, recovery)", "MISSING", "SYSTEM_LIMIT",
               "no oracle exists for these paths", "one oracle per path, each reusing the paid-vs-unpaid access discriminator",
               "each seeded alternate-path bypass is CONFIRMED_P0 with zero false positives on the decoys"),
        GapRow("cross-client truth divergence (web vs mobile vs API vs SDK)", "MISSING", "SYSTEM_LIMIT",
               "the engine drives one HTTP client identity; there is no browser/mobile/SDK driver", "a second driver (isolated browser context) exposing the same access probe",
               "a seeded target that grants on web but not on API is reported as OBSERVED_DIVERGENCE or CONFIRMED_P0 as appropriate"),
        GapRow("customer APIs that do not implement the reference vocabulary", "BLOCKED", "SYSTEM_LIMIT",
               "route/field mapping for arbitrary customer APIs is not implemented; only the reference vocabulary is supported", "a declarative route/field mapping layer in the contract",
               "the seeded benchmark passes unchanged when the reference target is exposed through a renamed-route mapping"),
    ]
    return rows


def unknown_exposures(rows: list[GapRow]) -> list[GapRow]:
    return [r for r in rows if r.status != "COVERED"]
