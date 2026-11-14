"""AUTHOR-BLIND HOLDOUT manifest for OPERATION COLD CROWN.

Authored by a SEPARATE session from the one that built and tuned the cold engine. Every target is a
fresh, hardened reconstruction of an ALREADY-PROVENANCE-PROVEN advisory mechanism (see
``manifest_hardened.py`` and ``docs/HARDENED_CORPUS_PLAN.md §2``), but with its OWN single flipped
check, its OWN glue-route shapes/field vocabularies, and its OWN seeds (701-720) -- so the specifics
are BLIND to the engine's author and the engine cannot have overfit to them.

Same discipline as the hardened manifest: each INSTANCE is (family, seed); the engine runs BLIND;
this file is scorer-side metadata only. Each flaw target flips exactly ONE check behind the six
enterprise defenses; its patched twin flips nothing and is a hardened DECOY (scary surface, fully
correct) that must stay RULED_OUT (0 FP). The whole corpus is the holdout, so DEV is empty and every
target lives in TEST. ``kind`` tags each family: payment (access-without-payment), authz (grey-box
authorization), or ceiling (correct-abstention control).
"""
from __future__ import annotations

PROVENANCE: dict[str, dict] = {
    "hd_hold_settle": {
        "advisory": "GHSA-v4g2-cm5v-cxv7", "package": "Aimeos ai-client-html (Composer/PHP)",
        "mechanism": "a held / authorized non-settled payment state is treated as a completed payment",
        "fix": "fulfil only after the payment is verified to have really succeeded (terminal capture)",
        "engine_class": "PBB-U (access without payment; non-settled state treated as paid)",
        "kind": "payment", "aprior": "miss", "real_code": False},
    "hd_key_reuse": {
        "advisory": "GHSA-8mhj-rffc-rcvw / CVE-2026-34210", "package": "mppx (npm)",
        "mechanism": "idempotency-key reuse re-grants (pay once, replay the credential -> extra entitlement)",
        "fix": "mppx 0.4.11 detects the replayed response and rejects the reuse",
        "engine_class": "PBB-U / PBB-C (replay / over-limit re-grant)",
        "kind": "payment", "aprior": "miss", "real_code": False},
    "hd_phase_jump": {
        "advisory": "GHSA-qwqm-3jx5-rr8m", "package": "Solidus (RubyGems)",
        "mechanism": "client-supplied target phase jumps the order to fulfilled/entitled, skipping pay",
        "fix": "only accept a phase already reached or passed; forward jumps -> 422",
        "engine_class": "PBB-U (state-machine skip to entitled)",
        "kind": "payment", "aprior": "miss", "real_code": False},
    "hd_ref_trust": {
        "advisory": "GHSA-7wwh-c3v9-fc55", "package": "OwnPay (PHP)",
        "mechanism": "entitlement side trusts a well-formed payment reference as completed without gateway verification",
        "fix": "the gateway verify fails closed; never trust a bare non-empty reference",
        "engine_class": "PBB-U (federated/cross-service confirm skipped)",
        "kind": "payment", "aprior": "miss", "real_code": False},
    "hd_claim_unlock": {
        "advisory": "GHSA-jg6q-3qfh-r9f8 (+ Ghost GHSA-xm43-3m56-w3wf)", "package": "mppx-condition-gate (npm)",
        "mechanism": "a claim route behind a real step-up still grants on an unproven ownership claim",
        "fix": "require a server-issued proof tied to a real purchase; a bare claim is never enough",
        "engine_class": "PBB-U (alternate-flow / claim grant)",
        "kind": "payment", "aprior": "miss", "real_code": False},
    "hd_prop_write": {
        "advisory": "GHSA-5448-v74m-7mv7", "package": "Snipe-IT (Composer/PHP)",
        "mechanism": "mass assignment lets an ordinary caller set a privileged field (the plan) on update",
        "fix": "allow-list writable fields; reject privileged fields from the caller",
        "engine_class": "BOPLA / mass-assignment (forbidden property write == access without payment)",
        "kind": "authz", "aprior": "miss", "real_code": False},
    "hd_legacy_path": {
        "advisory": "GHSA-9jr7-2hgp-vhp8", "package": "DefectDojo (PyPI/Django)",
        "mechanism": "a deprecated/shadow route to a resource omits the authorization check the current route enforces",
        "fix": "apply the same authorization check on every route; retire the uncontrolled path",
        "engine_class": "improper inventory / shadow API (forbidden access == access without payment)",
        "kind": "authz", "aprior": "miss", "real_code": False},
    # Ceiling control carried into the holdout set so correct abstention is proven here too.
    "hd_webhook_ceiling": {
        "advisory": "GHSA-xff3-5c9p-2mr4 / CVE-2026-41432", "package": "New API (Go)",
        "mechanism": "empty webhook secret lets anyone forge provider events -> fraudulent grant",
        "fix": "require a non-empty secret and verify payment_status",
        "engine_class": "CEILING: provider-event authenticity (out of RoE: signature forgery)",
        "kind": "ceiling", "aprior": "abstain", "real_code": False},
}

# The whole corpus is the holdout -> no DEV split.
DEV: list[tuple] = []

# (family, seed, split, scope)
TEST: list[tuple] = [
    # the seven hardened mechanisms, fresh author-blind reconstructions, own seeds
    ("hd_hold_settle", 701, "test", "in_scope"),
    ("hd_key_reuse", 702, "test", "in_scope"),
    ("hd_phase_jump", 703, "test", "in_scope"),
    ("hd_ref_trust", 704, "test", "in_scope"),
    ("hd_claim_unlock", 705, "test", "in_scope"),
    ("hd_prop_write", 706, "test", "in_scope"),
    ("hd_legacy_path", 707, "test", "in_scope"),
    # seen-mechanism / unseen-instance stress (same mechanism, different sealed seed + surface)
    ("hd_hold_settle", 708, "test", "in_scope"),
    ("hd_prop_write", 709, "test", "in_scope"),
    # ceiling control (reported separately; correct behaviour = ABSTAIN)
    ("hd_webhook_ceiling", 720, "test", "ceiling"),
]

ALL = DEV + TEST
