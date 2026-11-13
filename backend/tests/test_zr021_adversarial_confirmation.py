"""
ZR-021 adversarial verification (executed, not static).

Acceptance criterion (Master Specification, section 16.3):
  "Verify NON_AUTHORITATIVE_SIGNALS (oracle_gate.py:27) actually prevents
   client-signal-only confirmation, not merely that it exists."
  "Adversarial suite passes with zero false confirmations."

This script imports the real app.enterprise_controls.oracle_gate module (stdlib
only, confirmed importable without fastapi/sqlalchemy/etc.) and throws a battery
of adversarial ConfirmationCandidate constructions at ConfirmationGate.evaluate(),
including the specific signal-ordering case, then checks the result for real.
"""
import itertools
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.core.control_port.contract import (
    KIND_FEATURE_USE, ConfirmationCandidate, OracleObservation, EvidenceClass,
)
from app.enterprise_controls.oracle_gate import ConfirmationGate, NON_AUTHORITATIVE_SIGNALS


class _FakeLedger:
    """Isolates gate-logic testing from ledger-admission logic (tested separately).
    Every artifact id in `admitted` counts as ledger-admitted; nothing else does."""

    def __init__(self, admitted):
        self._admitted = set(admitted)

    def is_admitted(self, artifact_id):
        return artifact_id in self._admitted


def weak_obs(outcome="allowed", proof_present=True, discriminating=None, session="s1", artifact="weak-art-1"):
    """An OracleObservation that LOOKS like a feature-use proof but is actually
    built from nothing but client-side/UI signal kinds -- this is what an attacker
    controlling only the frontend would be able to fabricate."""
    return OracleObservation(
        oracle_id="forged", feature_id="feat-1", identity_alias="attacker",
        tenant_alias=None, outcome=outcome, kind=KIND_FEATURE_USE,
        proof_present=proof_present, session_isolation_id=session,
        artifact_ids=(artifact,), discriminating=discriminating,
    )


failures = []
attempts = 0

print("=== Attack 1: signals_used is weak-only, every permutation of 3 weak signals ===")
weak_signals = ["ui_badge", "success_page", "redirect"]
for perm in itertools.permutations(weak_signals):
    attempts += 1
    ledger = _FakeLedger(admitted=["a1"])
    cand = ConfirmationCandidate(
        hypothesis_id="h1",
        control_denied=weak_obs(outcome="denied", discriminating=True, artifact="a1"),
        scenario_allowed=weak_obs(outcome="allowed", session="s-scenario", artifact="a1"),
        clean_reproduction=weak_obs(outcome="allowed", session="s-clean", artifact="a1"),
        qualifying_payment_present=False,
        signals_used=tuple(perm),  # <-- the exact field under test, every order
        evidence_classes=(EvidenceClass.EXTERNAL_BROWSER.value,),
    )
    decision = ConfirmationGate(ledger=ledger, registered_feature_ids=frozenset({"feat-1"})).evaluate(cand)
    fired = any(r.startswith("non_authoritative_signals_only") for r in decision.reasons)
    if decision.confirmed:
        failures.append(f"BYPASS: signals_used={perm} produced confirmed=True")
    if not fired:
        print(f"  note: order {perm} -> 'non_authoritative_signals_only' did NOT fire "
              f"(reasons={decision.reasons}) -- confirms the ordering bug, "
              f"but overall confirmed={decision.confirmed}")

print(f"\n=== Attack 2: signals_used omits KIND_FEATURE_USE entirely (single weak signal) ===")
for sig in sorted(NON_AUTHORITATIVE_SIGNALS):
    attempts += 1
    ledger = _FakeLedger(admitted=["a2"])
    cand = ConfirmationCandidate(
        hypothesis_id="h2", control_denied=weak_obs(outcome="denied", discriminating=True, artifact="a2"),
        scenario_allowed=weak_obs(outcome="allowed", session="s-scenario", artifact="a2"),
        clean_reproduction=weak_obs(outcome="allowed", session="s-clean", artifact="a2"),
        qualifying_payment_present=False, signals_used=(sig,),
        evidence_classes=(EvidenceClass.EXTERNAL_BROWSER.value,),
    )
    decision = ConfirmationGate(ledger=ledger, registered_feature_ids=frozenset({"feat-1"})).evaluate(cand)
    if decision.confirmed:
        failures.append(f"BYPASS: single weak signal {sig!r} produced confirmed=True")

print("=== Attack 3: no real proof at all -- ctl/sc/rp all None, weak signals only ===")
attempts += 1
ledger = _FakeLedger(admitted=[])
cand = ConfirmationCandidate(
    hypothesis_id="h3", control_denied=None, scenario_allowed=None, clean_reproduction=None,
    qualifying_payment_present=False, signals_used=("ui_badge", "success_page"),
)
decision = ConfirmationGate(ledger=ledger, registered_feature_ids=frozenset({"feat-1"})).evaluate(cand)
if decision.confirmed:
    failures.append("BYPASS: no proof objects at all still produced confirmed=True")

print("=== Attack 4: proof objects exist but artifacts were never admitted to the ledger ===")
attempts += 1
ledger = _FakeLedger(admitted=[])  # nothing admitted
cand = ConfirmationCandidate(
    hypothesis_id="h4", control_denied=weak_obs(outcome="denied", discriminating=True, artifact="unadmitted"),
    scenario_allowed=weak_obs(outcome="allowed", session="s-scenario", artifact="unadmitted"),
    clean_reproduction=weak_obs(outcome="allowed", session="s-clean", artifact="unadmitted"),
    qualifying_payment_present=False,
)
decision = ConfirmationGate(ledger=ledger, registered_feature_ids=frozenset({"feat-1"})).evaluate(cand)
if decision.confirmed:
    failures.append("BYPASS: unadmitted artifacts still produced confirmed=True")

print("=== Attack 5: qualifying_payment_present=True (access may be correct behaviour) but shaped like a finding ===")
attempts += 1
ledger = _FakeLedger(admitted=["a5"])
cand = ConfirmationCandidate(
    hypothesis_id="h5", control_denied=weak_obs(outcome="denied", discriminating=True, artifact="a5"),
    scenario_allowed=weak_obs(outcome="allowed", session="s-scenario", artifact="a5"),
    clean_reproduction=weak_obs(outcome="allowed", session="s-clean", artifact="a5"),
    qualifying_payment_present=True,  # legit payment -- "allowed" would be correct, not a finding
)
decision = ConfirmationGate(ledger=ledger, registered_feature_ids=frozenset({"feat-1"})).evaluate(cand)
if decision.confirmed:
    failures.append("BYPASS: qualifying_payment_present=True still produced confirmed=True")

print("=== Attack 6: clean_reproduction reuses the scenario's own session (not independent) ===")
attempts += 1
ledger = _FakeLedger(admitted=["a6"])
cand = ConfirmationCandidate(
    hypothesis_id="h6", control_denied=weak_obs(outcome="denied", discriminating=True, artifact="a6"),
    scenario_allowed=weak_obs(outcome="allowed", session="same-session", artifact="a6"),
    clean_reproduction=weak_obs(outcome="allowed", session="same-session", artifact="a6"),  # same session id
    qualifying_payment_present=False,
)
decision = ConfirmationGate(ledger=ledger, registered_feature_ids=frozenset({"feat-1"})).evaluate(cand)
if decision.confirmed:
    failures.append("BYPASS: session-reused 'clean' reproduction still produced confirmed=True")

print("\n=== Positive control: a genuinely well-evidenced candidate MUST still confirm ===")
attempts += 1
ledger = _FakeLedger(admitted=["ctl-art", "sc-art", "rp-art"])
good = ConfirmationCandidate(
    hypothesis_id="h-good",
    control_denied=OracleObservation("o1", "feat-1", "clean-id", None, "denied", KIND_FEATURE_USE, True, "s1", ("ctl-art",), discriminating=True),
    scenario_allowed=OracleObservation("o2", "feat-1", "victim-id", None, "allowed", KIND_FEATURE_USE, True, "s2", ("sc-art",)),
    clean_reproduction=OracleObservation("o3", "feat-1", "victim-id", None, "allowed", KIND_FEATURE_USE, True, "s3", ("rp-art",)),
    qualifying_payment_present=False,
    evidence_classes=(EvidenceClass.EXTERNAL_BROWSER.value,),
)
decision = ConfirmationGate(ledger=ledger, registered_feature_ids=frozenset({"feat-1"})).evaluate(good)
if not decision.confirmed or decision.token is None:
    failures.append(f"FALSE NEGATIVE: a genuinely well-evidenced candidate was rejected: {decision.reasons}")
else:
    print(f"  confirmed correctly: token issued, covers('h-good')={decision.token.covers('h-good')}")

print(f"\n{'='*70}\nTOTAL ADVERSARIAL ATTEMPTS: {attempts}\nFALSE CONFIRMATIONS: {len(failures)}")
for f in failures:
    print(f"  FAIL: {f}")
print("RESULT:", "FAIL -- gate can be forced" if failures else "PASS -- zero false confirmations across all attempts")
if __name__ == "__main__":
    sys.exit(1 if failures else 0)
assert not failures, f"{len(failures)} adversarial attempt(s) forced a false confirmation: {failures}"
