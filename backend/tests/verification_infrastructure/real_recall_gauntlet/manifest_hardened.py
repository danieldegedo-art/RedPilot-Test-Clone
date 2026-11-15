"""Frozen manifest for the ENTERPRISE-HARDENED GREY-BOX tranche (DEV / sealed TEST).

Separate from the legacy ``manifest.py`` (which stays byte-identical). Same discipline: each
INSTANCE is (family, seed); the engine runs BLIND; this file is scorer-side metadata only. Every
family maps to a real, independently-disclosed advisory with a public fix (see ``PROVENANCE`` and
``docs/HARDENED_CORPUS_PLAN.md`` for links + mechanism + fix). Each flaw target flips exactly ONE
check behind the six enterprise defenses; its patched twin flips nothing and is itself a hardened
DECOY (scary surface, fully correct) that must stay RULED_OUT (0 FP).

The generalized critical class under test is forbidden cross-subject/role/tenant/state access,
confirmed by a non-destructive grey-box differential within the four-rule hard floor.
``kind`` tags each family: payment (access-without-payment) or authz (grey-box authorization).
"""
from __future__ import annotations

PROVENANCE: dict[str, dict] = {
    "h_async_auth": {
        "advisory": "GHSA-v4g2-cm5v-cxv7", "package": "Aimeos ai-client-html (Composer/PHP)",
        "mechanism": "an authorized/non-settled payment state is treated as a completed payment",
        "fix": "fulfil only after the payment is verified to have really succeeded (terminal capture)",
        "engine_class": "PBB-U (access without payment; non-settled state treated as paid)",
        "kind": "payment", "aprior": "miss", "real_code": False},
    "h_replay_regrant": {
        "advisory": "GHSA-8mhj-rffc-rcvw / CVE-2026-34210", "package": "mppx (npm)",
        "mechanism": "idempotency-key reuse re-grants (pay once, replay the credential -> extra entitlement)",
        "fix": "mppx 0.4.11 detects the replayed response and rejects the reuse",
        "engine_class": "PBB-U / PBB-C (replay / over-limit re-grant)",
        "kind": "payment", "aprior": "miss", "real_code": False},
    "h_state_skip": {
        "advisory": "GHSA-qwqm-3jx5-rr8m", "package": "Solidus (RubyGems)",
        "mechanism": "client-supplied target state jumps the order to 'complete'/entitled, skipping pay",
        "fix": "only accept a state already reached or passed; forward jumps -> 422",
        "engine_class": "PBB-U (state-machine skip to entitled)",
        "kind": "payment", "aprior": "miss", "real_code": False},
    "h_federated_skip": {
        "advisory": "GHSA-7wwh-c3v9-fc55", "package": "OwnPay (PHP)",
        "mechanism": "entitlement side trusts a well-formed payment reference as completed without gateway verification",
        "fix": "the gateway verify fails closed; never trust a bare non-empty reference",
        "engine_class": "PBB-U (federated/cross-service confirm skipped)",
        "kind": "payment", "aprior": "uncertain", "real_code": False},
    "h_claim_stepup": {
        "advisory": "GHSA-jg6q-3qfh-r9f8 (+ Ghost GHSA-xm43-3m56-w3wf)", "package": "mppx-condition-gate (npm)",
        "mechanism": "a claim route behind a real step-up still grants on an unproven ownership claim",
        "fix": "require a server-issued proof tied to a real purchase; a bare claim is never enough",
        "engine_class": "PBB-U (alternate-flow / claim grant)",
        "kind": "payment", "aprior": "miss", "real_code": False},
    "gb_bola_object": {
        "advisory": "GHSA-x287-5c68-36wp", "package": "OpenWISP IPAM (PyPI/Django)",
        "mechanism": "a member of one tenant can read another tenant's object (missing ownership check)",
        "fix": "add org/ownership validation at the data-access layer",
        "engine_class": "BOLA (forbidden cross-tenant object access)",
        "kind": "authz", "aprior": "miss", "real_code": False},
    "gb_bopla_massassign": {
        "advisory": "GHSA-5448-v74m-7mv7", "package": "Snipe-IT (Composer/PHP)",
        "mechanism": "mass assignment lets an ordinary caller set a privileged field (the plan) on update",
        "fix": "allow-list writable fields; reject privileged fields from the caller",
        "engine_class": "BOPLA / mass-assignment (forbidden property write == access without payment)",
        "kind": "authz", "aprior": "miss", "real_code": False},
    "gb_shadow_api": {
        "advisory": "GHSA-9jr7-2hgp-vhp8", "package": "DefectDojo (PyPI/Django)",
        "mechanism": "a deprecated/shadow route to a resource omits the authorization check the current route enforces",
        "fix": "apply the same authorization check on every route; retire the uncontrolled path",
        "engine_class": "improper inventory / shadow API (forbidden access == access without payment)",
        "kind": "authz", "aprior": "miss", "real_code": False},
    # Ceiling control carried into the hardened set so correct abstention is proven here too.
    "webhook_forgery": {
        "advisory": "GHSA-xff3-5c9p-2mr4 / CVE-2026-41432", "package": "New API (Go)",
        "mechanism": "empty webhook secret lets anyone forge provider events -> fraudulent grant",
        "fix": "require a non-empty secret and verify payment_status",
        "engine_class": "CEILING: provider-event authenticity (out of RoE: signature forgery)",
        "kind": "ceiling", "aprior": "abstain", "real_code": False},
}

# (family, seed, split, scope)
DEV: list[tuple] = [
    ("h_async_auth", 401, "dev", "in_scope"),
    ("h_replay_regrant", 402, "dev", "in_scope"),
    ("h_state_skip", 403, "dev", "in_scope"),
    ("h_federated_skip", 404, "dev", "in_scope"),
    ("h_claim_stepup", 405, "dev", "in_scope"),
    ("gb_bola_object", 406, "dev", "in_scope"),
    ("gb_bopla_massassign", 407, "dev", "in_scope"),
    ("gb_shadow_api", 408, "dev", "in_scope"),
]

TEST: list[tuple] = [
    # the eight hardened mechanisms, different (sealed) seeds
    ("h_async_auth", 501, "test", "in_scope"),
    ("h_replay_regrant", 502, "test", "in_scope"),
    ("h_state_skip", 503, "test", "in_scope"),
    ("h_federated_skip", 504, "test", "in_scope"),
    ("h_claim_stepup", 505, "test", "in_scope"),
    ("gb_bola_object", 506, "test", "in_scope"),
    ("gb_bopla_massassign", 507, "test", "in_scope"),
    ("gb_shadow_api", 508, "test", "in_scope"),
    # seen-mechanism / unseen-instance (surface-overfit stress)
    ("h_async_auth", 509, "test", "in_scope"),
    ("gb_bopla_massassign", 510, "test", "in_scope"),
    # ceiling control (reported separately; correct behaviour = ABSTAIN)
    ("webhook_forgery", 590, "test", "ceiling"),
]

ALL = DEV + TEST
