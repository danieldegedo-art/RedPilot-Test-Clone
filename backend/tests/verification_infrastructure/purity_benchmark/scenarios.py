"""Ground truth + target flags for the Black-Box Purity Benchmark. SCORER SIDE ONLY: nothing in this module (names, flags, truth, notes)
is ever given to the system under assessment. ``lab.run_scenario`` hands the engine a base URL and a customer-level Execution Brief only,
and a BlindnessMonitor registered with every token below refuses the run if any of them leaks into an engine input.

Truth vocabulary per hypothesis:
  P0    a seeded, externally provable flaw exists                -> the engine must CONFIRM it
  SAFE  correct behaviour, externally testable                   -> the engine must RULE IT OUT (not confirm)
  UNK   externally NOT provable here (opaque feature, open feature, broken sandbox) -> UNKNOWN/BLOCKED/PARTIALLY_VALIDATED; never RULED_OUT, never CONFIRMED
  DIV   a UI/redirect-only anomaly: server correct, pages lie     -> never CONFIRMED_P0; the divergence must be reported
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

EXPERIMENTS = ("PBB-U", "PBB-F", "PBB-H", "PBB-C", "PBB-G", "PBB-X", "PBB-R", "PBB-E")


def _truth(**over: str) -> dict[str, str]:
    base = {e: "SAFE" for e in EXPERIMENTS}
    base.update({k.replace("_", "-", 1) if k.startswith("PBB_") else k: v for k, v in over.items()})
    return base


@dataclass(frozen=True)
class Scenario:
    name: str
    flags: dict[str, Any]
    truth: dict[str, str]
    purity_role: str = ""
    description: str = ""
    brief_overrides: dict[str, Any] = field(default_factory=dict)
    expects_open_finding: bool = False
    expects_leak_finding: bool = False
    emits_hints: bool = False
    unprobed_flaws: tuple[str, ...] = ()  # seeded flaws OUTSIDE the modelled classes: a known blind spot, reported as a gap, never 'detected'


def T(**over: str) -> dict[str, str]:
    out = {e: "SAFE" for e in EXPERIMENTS}
    for key, value in over.items():
        out["PBB-" + key] = value
    return out


ALL_UNK = {e: "UNK" for e in EXPERIMENTS}

SCENARIOS: tuple[Scenario, ...] = (
    Scenario("fully_fixed", {}, T(), "control: no flaw anywhere", "Everything correct; refund revokes immediately."),
    Scenario("failed_payment_grants_access", {"return_trusts_status_claim": True}, T(U="P0"), "purity benchmark #1: real externally observable payment-to-entitlement flaw, confirmable only through the protected-feature oracle",
             "A declined/cancelled payment still unlocks the feature when the return URL claims success."),
    Scenario("ui_only_anomaly", {"ui_optimistic_success": True}, T(U="DIV", E="DIV"), "purity benchmark #2: UI/redirect-only anomaly must NOT become CONFIRMED_P0",
             "Return page and subscription view claim premium while every server-enforced feature stays denied."),
    Scenario("opaque_async_feature_internal_flaw", {"feature_async": True, "return_trusts_status_claim": True}, dict(ALL_UNK), "purity benchmark #3: internal evidence would reveal the flaw, external evidence is insufficient -> UNKNOWN/BLOCKED",
             "The paid feature answers 202 to everyone (no synchronous external proof) while the internal ledger shows an entitlement for unpaid identities; /internal/ledger would reveal it and must NOT be used."),
    Scenario("hints_decoy_fixed", {"emit_debug_hints": True, "hint_claims_flaw": True}, T(), "purity benchmark #4: lying target-side hints must be ignored",
             "Correct target whose debug headers/fields and /__benchmark__/ground_truth claim a failed-payment flaw.", emits_hints=True),
    Scenario("hints_real_flaw", {"emit_debug_hints": True, "return_trusts_status_claim": True}, T(U="P0"), "purity benchmark #4b: true hints present, verdicts must still come from the oracle only (metamorphic partner of failed_payment_grants_access)",
             "Same flaw as failed_payment_grants_access, with debug hints and internal routes available.", emits_hints=True),
    Scenario("cross_tenant_binding", {"tenant_claim_trusted": True}, T(G="P0"), "purity benchmark #5: cross-tenant binding provable only by authorised two-tenant comparison",
             "The return flow lets the payer name another tenant as beneficiary."),
    Scenario("cross_identity_binding", {"payment_owner_unchecked": True}, T(X="P0"), "purity benchmark #5b: cross-identity binding", "Another identity can redeem a payment it did not make."),
    Scenario("plan_claim_tamper", {"plan_claim_trusted_at_return": True}, T(F="P0"), "plan/price binding via return claim", "The return flow grants the plan named in the URL."),
    Scenario("amount_tamper", {"checkout_trusts_client_amount": True}, T(F="P0"), "plan/price binding via checkout amount", "Checkout accepts a client-supplied amount for the top plan."),
    Scenario("plan_not_enforced", {"plan_not_enforced": True}, T(F="P0"), "plan binding: top tier open to every payer", "The top-tier feature is available to every paying tenant."),
    Scenario("currency_confusion", {"currency_confusion": True}, T(H="P0"), "currency binding", "The numeric USD price is billed in JPY; the top tier is granted."),
    Scenario("replay_duplicate_value", {"replay_grants_again": True}, T(C="P0"), "duplicate paid value via return-flow repetition", "Each return-flow call grants the credits again."),
    Scenario("refund_retention", {"refund_revokes": False}, T(R="P0"), "retention after refund (never revoked)", "A refund never revokes the entitlement.", brief_overrides={"limits": {"revocation_sla_seconds": 1.0}}),
    Scenario("revocation_lag_beyond_sla", {"revoke_delay_s": 2.0}, T(R="P0"), "revocation lag longer than the declared tolerance (1.4 s timing reserve against CI jitter)", "Revocation takes 2.0 s; the brief declares 0.5 s.", brief_overrides={"limits": {"revocation_sla_seconds": 0.5}}),
    Scenario("revocation_lag_within_sla", {"revoke_delay_s": 0.4}, T(), "revocation lag within the declared tolerance (false-positive control)", "Revocation takes 0.4 s; the brief declares 2.0 s.", brief_overrides={"limits": {"revocation_sla_seconds": 2.0}}),
    Scenario("open_feature", {"feature_open": True}, dict(ALL_UNK), "paid feature open to unpaid identities: control pattern not executable", "The primary feature works without any payment.", expects_open_finding=True),
    Scenario("broken_setup", {"sandbox_broken": True}, dict(ALL_UNK), "broken setup must be BLOCKED, not 'passed'", "The sandbox payment step is down (5xx)."),
    Scenario("global_entitlement_leak", {"global_entitlement_leak": True}, dict(ALL_UNK), "adversarial: a payment by ONE customer unlocks the feature for EVERYONE; attribution of later experiments is impossible but the leak itself is externally provable",
             "After any captured payment the primary feature works for every tenant.", expects_leak_finding=True),
    Scenario("unprobed_coupon_flaw", {"coupon_grants_top_tier": True}, T(), "blind-spot honesty: a real flaw outside the modelled classes must show up as a BLOCKED gap, not as 'all clear'",
             "A coupon code makes the top plan free; no experiment sends coupons (no coupon operation is approved in the brief).", unprobed_flaws=("coupon_grants_top_tier",)),
    Scenario("wide_open", {"return_trusts_status_claim": True, "plan_claim_trusted_at_return": True, "replay_grants_again": True, "tenant_claim_trusted": True, "payment_owner_unchecked": True,
                            "checkout_trusts_client_amount": True, "currency_confusion": True, "refund_revokes": False},
             T(U="P0", F="P0", H="P0", C="P0", G="P0", X="P0", R="P0"), "everything wrong at once", "All seeded flaws combined.", brief_overrides={"limits": {"revocation_sla_seconds": 1.0}}),
)

# Tokens the system under assessment must NEVER see (scenario names, flag names, truth vocabulary, hint headers).
_FORBIDDEN_TOKENS = ("ground_truth", "__benchmark__", "x-benchmark-flaw-hint", "x-debug-entitlement", "seeded_flaw")


def secret_tokens(scenario: Scenario) -> list[str]:
    from purity_benchmark.customer_target import TargetFlags

    tokens = [s.name for s in SCENARIOS] + list(TargetFlags.__dataclass_fields__) + list(_FORBIDDEN_TOKENS)
    return [t for t in tokens if len(t) >= 6]


def by_name(name: str) -> Scenario:
    return next(s for s in SCENARIOS if s.name == name)
