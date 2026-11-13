"""B29: Synthetic Twin.

A deterministic, in-memory model of how a correct paywall is SUPPOSED to behave,
so a probe can be rehearsed and sanity-checked offline before any real request is
made. It encodes the spec-correct entitlement rules (a qualifying, un-refunded
payment entitles ONLY its own payer; a non-qualifying payment entitles no one; a
refund revokes; naming another beneficiary grants nothing) and answers "what
SHOULD happen here?".

Two properties keep it safe and honest:

  * Synthetic only. Identities are opaque caller tokens; the twin stores nothing
    but those tokens and booleans, performs no I/O, and never touches a real
    system or real payment/PII data. It is deterministic (no time, no randomness).
  * NON-AUTHORITATIVE. A twin outcome is an EXPECTATION for planning/rehearsal,
    never a finding. A real P0 still requires the real server-enforced oracle
    chain and the confirmation gate (ZR-017); a twin/real mismatch is only a LEAD
    to investigate with the real oracle, exactly like B6's non-authoritative
    surfaces. Nothing here can confirm anything.

Stdlib only; pure.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

MODULE_VERSION = "synthetic-twin/1.0"


@dataclass(frozen=True)
class PaymentRecord:
    qualifying: bool
    refunded: bool = False


@dataclass(frozen=True)
class TwinComparison:
    identity: str
    expected: bool          # what the correct model says SHOULD happen
    observed: bool          # what the real target actually did (passed in)
    diverges: bool
    note: str

    def to_dict(self) -> dict[str, Any]:
        return {"identity": self.identity, "expected": self.expected, "observed": self.observed,
                "diverges": self.diverges, "note": self.note}


class SyntheticTwin:
    """An offline model of correct paywall behaviour. Not authoritative."""

    def __init__(self) -> None:
        self._payments: dict[str, PaymentRecord] = {}
        self._beneficiary_claims: list[tuple[str, str]] = []  # (payer, named_beneficiary) -- recorded, never granted

    @staticmethod
    def _check_identity(identity: str) -> None:
        if not isinstance(identity, str) or not identity:
            raise ValueError("identity must be a non-empty synthetic token")

    def pay(self, identity: str, *, qualifying: bool = True) -> None:
        self._check_identity(identity)
        self._payments[identity] = PaymentRecord(qualifying=qualifying, refunded=False)

    def refund(self, identity: str) -> None:
        self._check_identity(identity)
        rec = self._payments.get(identity)
        if rec is not None:
            self._payments[identity] = PaymentRecord(qualifying=rec.qualifying, refunded=True)

    def name_beneficiary(self, payer: str, beneficiary: str) -> None:
        """Model a return-flow claim naming another beneficiary. Correct behaviour
        grants the beneficiary NOTHING (cross-identity/tenant binding holds); the
        claim is only recorded for inspection."""
        self._check_identity(payer)
        self._check_identity(beneficiary)
        self._beneficiary_claims.append((payer, beneficiary))

    def expected(self, identity: str) -> bool:
        """The spec-correct expectation: entitled iff this identity has its OWN
        qualifying, un-refunded payment."""
        self._check_identity(identity)
        rec = self._payments.get(identity)
        return bool(rec and rec.qualifying and not rec.refunded)

    def use(self, identity: str) -> bool:
        """Rehearse USING the feature as `identity`. Returns the EXPECTED outcome
        (not an authoritative result)."""
        return self.expected(identity)

    def compare(self, identity: str, observed_entitled: bool) -> TwinComparison:
        """Compare a real observed outcome against the correct expectation. A
        divergence is a LEAD only -- the real oracle still governs (ZR-017)."""
        exp = self.expected(identity)
        diverges = exp != observed_entitled
        if not diverges:
            note = "matches the correct expectation"
        elif observed_entitled and not exp:
            note = ("observed access the correct model does NOT expect -- a LEAD for the real oracle "
                    "(never a finding on its own; the twin is not authoritative)")
        else:
            note = ("observed denial where the correct model expects access -- a reliability/availability LEAD "
                    "for the real oracle, not an entitlement finding")
        return TwinComparison(identity, exp, observed_entitled, diverges, note)

    def snapshot(self) -> dict[str, Any]:
        return {"module_version": MODULE_VERSION,
                "payments": {k: {"qualifying": v.qualifying, "refunded": v.refunded}
                             for k, v in sorted(self._payments.items())},
                "beneficiary_claims": [list(c) for c in self._beneficiary_claims],
                "note": "Synthetic, deterministic, offline model of CORRECT behaviour. A twin outcome is an "
                        "expectation for rehearsal/planning, never a finding; real P0s require the real oracle "
                        "chain (ZR-017)."}
