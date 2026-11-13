"""The Truth Model, as actual code: every source of "what is the payment/
entitlement state" this project's own reference infrastructure has is
classified into exactly one of three categories, and
check_trust_boundary.py's checks are re-expressed in terms of it.

Why code, not documentation: a classification that only exists in prose
can drift silently from what the code actually does (a new read path can
start trusting a DERIVED or UNTRUSTED source without anyone updating a
document). TruthSource below is attached to the actual read functions in
entitlement_target.py, so `AUTHORITATIVE_SOURCES`/`classify_read_path` are
checkable facts about the running code, not a diagram.
"""
from __future__ import annotations
from app.testing.purity.quarantine import refuse_in_pure_mode  # noqa: E402  (QUARANTINED: never loads)
refuse_in_pure_mode(__name__)

from enum import Enum


class TruthCategory(Enum):
    AUTHORITATIVE = "authoritative"  # a server-side, verified source that MAY justify a payment/entitlement decision
    DERIVED = "derived"              # an internal projection/cache that must never CONTRADICT an authoritative source
    UNTRUSTED = "untrusted"          # client input, webhook claims, redirect params -- never sufficient alone


# Every read path this project's own reference/entitlement targets expose,
# classified once, in one place. A new read path added later without an
# entry here is exactly the kind of silent drift this file exists to make
# impossible to miss -- test_truth_model.py's
# test_every_known_read_path_is_classified pins the current, complete set.
READ_PATH_CLASSIFICATION: dict[str, TruthCategory] = {
    "ReferenceTarget.payments[id]['state']": TruthCategory.AUTHORITATIVE,
    "EntitlementTarget.authoritative_status()": TruthCategory.AUTHORITATIVE,
    "EntitlementTarget.entitlements[user_id]": TruthCategory.AUTHORITATIVE,  # the entitlement record ITSELF is authoritative for "what did we grant"
    "EntitlementTarget.access_cache[user_id]": TruthCategory.DERIVED,  # a projection of entitlements, may go stale -- see check_access()
    "webhook body['status']": TruthCategory.UNTRUSTED,
    "webhook body['payment_id']/['user_id']": TruthCategory.UNTRUSTED,
    "client redirect / query parameters": TruthCategory.UNTRUSTED,
}


def is_sufficient_alone_for_a_payment_decision(category: TruthCategory) -> bool:
    """The one-line rule the whole Truth Model exists to enforce: only
    AUTHORITATIVE sources may justify a decision by themselves. DERIVED
    sources may inform a decision only insofar as they agree with an
    AUTHORITATIVE one queried in the same check (see
    check_access_does_not_diverge_from_authoritative below); UNTRUSTED
    sources never justify anything alone, ever."""
    return category is TruthCategory.AUTHORITATIVE
