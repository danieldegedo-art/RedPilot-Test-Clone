"""Trust-boundary invariant: a status CLAIM (from a webhook payload, a
client-supplied field, a redirect query parameter -- anything this
project does not independently control) must never be trusted in place
of the AUTHORITATIVE status this project's own server-side record
reports. Directly operationalizes the payment-integrity mission's
Invariant 2 ("Client-Daten... dürfen niemals allein eine Zahlung oder ein
Entitlement bestätigen") as a composable, reusable check in the same
style as app.testing.invariants -- kept in its own module rather than
added to invariants.py because it needs status_vocabulary.py
(invariants.py is deliberately free of that dependency, and every
existing invariant there compares AttemptRecord facts to each other, not
an untrusted claim to an authoritative source).
"""
from __future__ import annotations
from app.testing.purity.quarantine import refuse_in_pure_mode  # noqa: E402  (QUARANTINED: never loads)
refuse_in_pure_mode(__name__)

from dataclasses import dataclass

from app.testing.status_vocabulary import IDENTITY, StatusVocabulary


@dataclass(frozen=True)
class TrustBoundaryViolation:
    check_id: str
    message: str


def check_claimed_status_matches_authoritative(
    claimed_status: str | None,
    authoritative_status: str | None,
    *,
    resource_type: str = "payment",
    vocabulary: StatusVocabulary = IDENTITY,
    claim_source: str = "unspecified",
) -> list[TrustBoundaryViolation]:
    """`claimed_status`: whatever an untrusted source (webhook body,
    client field, redirect param) says the status is. `authoritative_status`:
    what THIS project's own server-side record independently reports for
    the SAME resource, queried through a path the claim source does not
    control. A mismatch is reported regardless of which direction it goes
    (claim is more advanced than reality, or less) -- both are the same
    class of bug: something is granting significance to the claim instead
    of the authoritative source.
    """
    if authoritative_status is None:
        return [
            TrustBoundaryViolation(
                "trust_boundary_no_authoritative_check",
                f"A status claim ({claim_source}: {claimed_status!r}) was evaluated with no authoritative "
                "status queried at all -- this is the more dangerous case (Invariant 2's exact violation: "
                "the claim was trusted alone), not a milder version of a mismatch.",
            )
        ]
    canonical_claimed = vocabulary.canonicalize(claimed_status, resource_type)
    canonical_authoritative = vocabulary.canonicalize(authoritative_status, resource_type)
    if canonical_claimed != canonical_authoritative:
        return [
            TrustBoundaryViolation(
                "trust_boundary_status_mismatch",
                f"Claim from {claim_source} says {claimed_status!r} (canonical: {canonical_claimed!r}) but the "
                f"authoritative record says {authoritative_status!r} (canonical: {canonical_authoritative!r}).",
            )
        ]
    return []


def check_entitlement_requires_authoritative_final_state(
    entitlement_granted: bool,
    authoritative_status: str | None,
    *,
    resource_type: str = "payment",
    vocabulary: StatusVocabulary = IDENTITY,
    final_states: frozenset[str] = frozenset({"captured"}),
) -> list[TrustBoundaryViolation]:
    """Invariant 1 ("ein Entitlement darf nur nach finaler, serverseitig
    verifizierter Zahlung gewährt werden"): an entitlement must never be
    True while the authoritative status is not one of `final_states`
    (default: only "captured" counts as final for a payment -- adjust per
    resource type/business rule when calling this for subscriptions
    etc.)."""
    if not entitlement_granted:
        return []
    canonical = vocabulary.canonicalize(authoritative_status, resource_type)
    if canonical not in final_states:
        return [
            TrustBoundaryViolation(
                "entitlement_granted_without_final_payment",
                f"Entitlement was granted while the authoritative status is {authoritative_status!r} "
                f"(canonical: {canonical!r}), which is not in the required final-state set {sorted(final_states)}.",
            )
        ]
    return []


def check_amount_matches_product_tier(
    paid_amount: float,
    granted_tier: str,
    product_catalog: dict[str, float],
    *,
    tolerance: float = 0.0,
) -> list[TrustBoundaryViolation]:
    """Mission invariant ("ein niedrigerer Betrag darf niemals ein
    höherwertiges Produkt aktivieren"): the amount AUTHORITATIVELY paid
    (from the payment record, never from a claim) must be >= the granted
    tier's catalog price. Deliberately >=, not ==: overpaying is not a
    security problem this check cares about (a promo/rounding credit
    might legitimately leave a few cents of slack the other direction is
    a business decision, not an integrity one) -- underpaying for the
    granted tier is the only direction that represents unauthorized
    value. `tolerance` exists for the same reason invariants.py's money
    comparisons go through Decimal rather than raw floats -- pass a small
    positive value if legitimate rounding could otherwise trip this by a
    cent; defaults to zero (exact-or-better required)."""
    if granted_tier not in product_catalog:
        return [
            TrustBoundaryViolation(
                "amount_check_unknown_tier",
                f"Cannot verify amount against an unknown tier {granted_tier!r} -- not in the product catalog "
                f"{sorted(product_catalog)}. Treat as UNKNOWN, not as passing.",
            )
        ]
    required = product_catalog[granted_tier]
    if paid_amount + tolerance < required:
        return [
            TrustBoundaryViolation(
                "amount_below_granted_tier",
                f"Granted tier {granted_tier!r} requires {required}, but the authoritative paid amount was "
                f"only {paid_amount} -- underpaid by {required - paid_amount}.",
            )
        ]
    return []


def check_currency_matches_catalog(
    paid_currency: str | None,
    catalog_currency: str,
) -> list[TrustBoundaryViolation]:
    """The CURRENCY half of amount/currency integrity, deliberately its
    own check rather than folded into check_amount_matches_product_tier:
    a payment of 99.99 JPY numerically satisfies a 99.99 USD price, so an
    amount-only comparison passes it -- the two checks fail independently
    and must be able to be verified independently (a system can have one
    without the other, which is exactly the bug this exists to expose).
    An unknown/missing currency is a violation, not a pass: absence of
    evidence about the currency is not evidence the currency is correct."""
    if paid_currency != catalog_currency:
        return [
            TrustBoundaryViolation(
                "currency_mismatch",
                f"Authoritative paid currency is {paid_currency!r} but the product catalog is priced in "
                f"{catalog_currency!r}; comparing the bare amounts across currencies is meaningless.",
            )
        ]
    return []
