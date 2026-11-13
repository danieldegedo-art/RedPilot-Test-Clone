"""The frozen DEV/TEST manifest for the Real-Glue-Code Recall Gauntlet.

Each INSTANCE is (family, seed). The engine runs BLIND -- it is handed only the brief + URL
and never sees anything in this file (a-priori expectation, provenance, class, split). This
file is scorer-side metadata only.

Split discipline:
  * DEV  -- studyable. Phase-2 engine upgrades may be developed against DEV misses.
  * TEST -- SEALED. Run only to MEASURE, never to tune. TEST deliberately contains BOTH
            unseen instances of DEV-present classes (tests surface/name overfit) AND
            held-out classes absent from DEV (tests the vocabulary ceiling).

Scope:
  * in_scope -- a real business-logic flaw inside RedPilot's RoE (black-box, no signature/
                auth bypass, no id guessing). Counts toward RECALL.
  * ceiling  -- a real flaw that is OUT of RedPilot's authorised method (requires forging a
                provider signature / auth bypass). The correct engine behavior is to ABSTAIN.
                Reported separately; NOT in the recall denominator.

Every family maps to a real, independently-authored public advisory WITH a public fix
(see ``PROVENANCE``). Reconstructions are faithful to the advisory's missing/incorrect check;
surface strings are anonymised per seed (see surface.py).
"""
from __future__ import annotations

# family -> (advisory id, ecosystem/package, one-line mechanism, public fix, engine-class, in-RoE a-priori)
PROVENANCE: dict[str, dict] = {
    "amount_binding": {
        "advisory": "GHSA-c2fq-w6qj-3hj4", "package": "Solidus (Ruby/Rails)",
        "mechanism": "server trusts a client-supplied payment amount -> underpayment",
        "fix": "Solidus 4.7.1 / 4.6.3 made the server authoritative for the charged amount",
        "engine_class": "PBB-F plan_or_price_binding", "aprior": "find"},
    "unconfirmed_payment": {
        "advisory": "GHSA-8r29-2mp2-pmrw", "package": "@payloadcms/plugin-ecommerce (npm)",
        "mechanism": "order treated as paid without a valid captured payment",
        "fix": "verify the payment actually succeeded before confirming the order",
        "engine_class": "PBB-U unconfirmed_payment_grants_access", "aprior": "find"},
    "cross_tenant_grant": {
        "advisory": "GHSA-h3rm-78g3-j7cp", "package": "@better-auth/stripe (npm)",
        "mechanism": "subscription action trusts a client-named beneficiary org (cross-org billing tampering)",
        "fix": "authorize the reference/org id against the caller",
        "engine_class": "PBB-G cross_tenant_binding", "aprior": "find"},
    "cross_identity_redeem": {
        "advisory": "GHSA-vgwx-9pm9-8qvj", "package": "Solidus (Ruby/Rails)",
        "mechanism": "a payment/profile is redeemable by a non-owning identity",
        "fix": "bind the payment object to its owning identity",
        "engine_class": "PBB-X cross_identity_binding", "aprior": "find"},
    "coupon_reuse": {
        "advisory": "GHSA-3p9j-442x-hjp7", "package": "microweber (PHP)",
        "mechanism": "a single-use coupon can be redeemed repeatedly",
        "fix": "microweber 1.2.11 enforces single-use consumption",
        "engine_class": "glue: coupon/promo lifecycle (outside the fixed 10)", "aprior": "miss"},
    "discount_disabled_api": {
        "advisory": "GHSA-qjfx-fvx7-3wvw", "package": "microweber (PHP)",
        "mechanism": "a disabled coupon is still honored via the API path",
        "fix": "the API path consults the enabled flag",
        "engine_class": "glue: coupon lifecycle (outside the fixed 10)", "aprior": "miss"},
    "alt_flow_entitlement": {
        "advisory": "GHSA-xm43-3m56-w3wf", "package": "Ghost (npm)",
        "mechanism": "a paid entitlement is obtainable via a cheap alternate (donation) flow",
        "fix": "the donation flow no longer grants a paid membership",
        "engine_class": "glue: alternate-flow entitlement (outside the fixed 10)", "aprior": "miss"},
    "completed_order_mutate": {
        "advisory": "GHSA-5597-7rmh-97q5", "package": "Sylius (PHP)",
        "mechanism": "an already-completed order can still be mutated (plan upgraded without charge)",
        "fix": "a terminal-state order is immutable",
        "engine_class": "glue: order state-machine integrity (outside the fixed 10)", "aprior": "miss"},
    "credit_balance_race": {
        "advisory": "GHSA-pgcq-8grm-5rx9 (+ GHSA-5gmm-hjfj-8ff7)", "package": "paymenter (PHP)",
        "mechanism": "non-atomic credit-balance check lets concurrent spends double-spend",
        "fix": "paymenter 1.5.5 wraps the lock/check in a real transaction",
        "engine_class": "near PBB-C but a concurrency race on an undeclared credit route", "aprior": "miss"},
    "proof_of_control": {
        "advisory": "GHSA-jg6q-3qfh-r9f8", "package": "@insumermodel/mppx-condition-gate (npm)",
        "mechanism": "grants access from a claimed ownership with no proof of control",
        "fix": "require a server-issued proof tied to a real purchase",
        "engine_class": "near PBB-OPEN/U but via an undeclared claim route", "aprior": "miss"},
    "webhook_forgery": {
        "advisory": "GHSA-xff3-5c9p-2mr4 / CVE-2026-41432", "package": "New API (Go)",
        "mechanism": "empty webhook secret lets anyone forge provider events -> fraudulent grant",
        "fix": "require a non-empty secret and verify payment_status",
        "engine_class": "CEILING: provider-event authenticity (out of RoE: no signature forgery)",
        "aprior": "abstain"},
}

# (family, seed, split, scope)
DEV: list[tuple] = [
    ("amount_binding", 101, "dev", "in_scope"),
    ("cross_tenant_grant", 102, "dev", "in_scope"),
    ("unconfirmed_payment", 106, "dev", "in_scope"),
    ("coupon_reuse", 103, "dev", "in_scope"),
    ("alt_flow_entitlement", 104, "dev", "in_scope"),
    ("credit_balance_race", 105, "dev", "in_scope"),
    ("completed_order_mutate", 107, "dev", "in_scope"),
    ("webhook_forgery", 108, "dev", "ceiling"),
]

TEST: list[tuple] = [
    # seen-class, unseen-instance (surface/name-overfit stress)
    ("amount_binding", 201, "test", "in_scope"),
    ("unconfirmed_payment", 202, "test", "in_scope"),
    ("cross_tenant_grant", 203, "test", "in_scope"),
    ("coupon_reuse", 205, "test", "in_scope"),
    ("alt_flow_entitlement", 207, "test", "in_scope"),
    ("completed_order_mutate", 208, "test", "in_scope"),
    ("credit_balance_race", 209, "test", "in_scope"),
    # held-out classes (absent from DEV): vocabulary-ceiling stress
    ("cross_identity_redeem", 204, "test", "in_scope"),
    ("discount_disabled_api", 206, "test", "in_scope"),
    ("proof_of_control", 210, "test", "in_scope"),
    # ceiling (reported separately)
    ("webhook_forgery", 302, "test", "ceiling"),
]

ALL = DEV + TEST
