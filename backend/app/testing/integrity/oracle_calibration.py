"""ZR-004 / B3: typed, per-target-configured oracle verifiers, each required
to pass calibration before being trusted on a real hypothesis.

Section 14.1's exact taxonomy (five tiers, in descending confidence):

    Ledger/billing cross-check (B19)    -- highest; needs ledger/sandbox access
    Durable state-change verifier       -- the default, expected tier
    External side-effect verifier       -- a side effect outside req/resp
    Resource/data-delta verifier        -- medium-high, depends on specificity
    Non-authoritative signal (ZR-024)   -- zero; never contributes

This is NOT a replacement for app/testing/integrity/oracle.py's
ProtectedFeatureOracle, which already does one real thing well (an
HTTP-response proof-field check, closest in spirit to DURABLE_STATE_CHANGE)
and is wired into every PBB experiment today. Restructuring that working,
tested code into this framework in one pass was judged higher-risk than the
benefit justified this session; what's built here is the framework itself --
the tier taxonomy, calibration, and two new concrete verifiers this
project's own data already supports (LEDGER_BILLING_CROSS_CHECK against
PESM, RESOURCE_DATA_DELTA) -- ready to have ProtectedFeatureOracle's
existing check wrapped as a DURABLE_STATE_CHANGE verifier, and to have the
calibration gate below applied to it, as the next increment. See HANDOFF.md.

THE H4 FIX (ZR-004's acceptance criterion: "H4-class false clearance
specifically re-tested")
-------------------------------------------------------------------------
H4 is a false RULED_OUT: the oracle reports "denied" not because the target
actually denied it, but because the verifier itself can't tell the
difference (wrong field checked, wrong tier for what the target exposes).
Calibration is the fix: `ruled_out_is_trustworthy()` below is a hard gate --
a RULED_OUT verdict is trustworthy only if the oracle that produced it has
ALREADY passed both probes (correctly confirms a known-positive case,
correctly denies a known-negative one). An uncalibrated oracle's "denied"
proves nothing; this makes that an explicit, checked precondition rather
than an implicit assumption (Section 14.1's own framing).

Stdlib only.
"""
from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any

from app.testing.pesm import EntitlementStatus, PESMStore


class OracleTier(str, Enum):
    LEDGER_BILLING_CROSS_CHECK = "ledger_billing_cross_check"
    DURABLE_STATE_CHANGE = "durable_state_change"
    EXTERNAL_SIDE_EFFECT = "external_side_effect"
    RESOURCE_DATA_DELTA = "resource_data_delta"
    NON_AUTHORITATIVE = "non_authoritative"


# Section 14.1's table, verbatim in spirit: "Medium-high" for RESOURCE_DATA_DELTA
# ("depending on delta specificity") is given its stated low end here -- a
# specific delta can score higher by construction (see the verifier below),
# never by just asserting a nicer number for this tier as a whole.
CONFIDENCE_WEIGHT: dict[OracleTier, float] = {
    OracleTier.LEDGER_BILLING_CROSS_CHECK: 1.0,
    OracleTier.DURABLE_STATE_CHANGE: 0.8,
    OracleTier.EXTERNAL_SIDE_EFFECT: 0.8,
    OracleTier.RESOURCE_DATA_DELTA: 0.6,
    OracleTier.NON_AUTHORITATIVE: 0.0,
}

# "allowed" | "denied" | "indeterminate" -- matches oracle.py's existing vocabulary
OracleOutcome = str
VerifierFn = Callable[[Any], Awaitable[OracleOutcome]]


class OracleNotCalibrated(Exception):
    """Raised by CalibratedOracle.check() if asked to run before calibration,
    or after calibration failed. Mirrors ConfirmationRefused's shape
    (contract.py) -- a typed exception for a structural precondition, not a
    generic RuntimeError, so a caller can't mistake it for a transient fault."""


@dataclass(frozen=True)
class CalibrationResult:
    tier: OracleTier
    known_positive_outcome: OracleOutcome
    known_negative_outcome: OracleOutcome
    reason: str | None = None  # populated iff not calibrated

    @property
    def calibrated(self) -> bool:
        return self.known_positive_outcome == "allowed" and self.known_negative_outcome == "denied"


async def calibrate(tier: OracleTier, verifier: VerifierFn, known_positive: Any, known_negative: Any) -> CalibrationResult:
    """Section 14.1: "each configured oracle must pass a known-positive probe
    ... and a known-negative probe ... before it is trusted on real
    hypotheses." Runs both, unconditionally -- a verifier that gets the
    positive probe right and the negative probe wrong (or vice versa) is
    exactly as uncalibrated as one that fails both; this never short-circuits
    after the first probe."""
    pos = await verifier(known_positive)
    neg = await verifier(known_negative)
    return CalibrationResult(tier, pos, neg, _calibration_reason(pos, neg))


def _calibration_reason(pos: OracleOutcome, neg: OracleOutcome) -> str | None:
    """Single source of the calibrated/uncalibrated reason string, shared by
    `calibrate` (which runs the probes) and `calibration_from_outcomes` (handed
    outcomes already observed elsewhere). A positive-probe failure is named
    before a negative one only for a stable message -- the negative probe is
    never skipped by the caller that produced these outcomes."""
    if pos != "allowed":
        return f"known-positive probe returned {pos!r}, expected 'allowed'"
    if neg != "denied":
        return f"known-negative probe returned {neg!r}, expected 'denied'"
    return None


def calibration_from_outcomes(tier: OracleTier, known_positive_outcome: OracleOutcome,
                              known_negative_outcome: OracleOutcome) -> CalibrationResult:
    """Build a CalibrationResult directly from control outcomes already observed
    elsewhere -- e.g. the engine's own positive (legit-payer) and negative
    (clean-identity) control probes -- without re-issuing any traffic. Same
    calibrated/reason semantics as `calibrate()`; this is what lets the live
    engine gate a RULED_OUT on the calibration it already established during its
    control phase instead of paying for a second round of probes."""
    return CalibrationResult(tier, known_positive_outcome, known_negative_outcome,
                             _calibration_reason(known_positive_outcome, known_negative_outcome))


@dataclass
class CalibratedOracle:
    """A verifier bound to its own calibration result. The only way to get a
    `check()` that will actually run is through `calibrate_oracle()` below --
    there is no public constructor that skips calibration."""

    tier: OracleTier
    _verifier: VerifierFn
    _calibration: CalibrationResult

    @property
    def calibration(self) -> CalibrationResult:
        return self._calibration

    @property
    def confidence_weight(self) -> float:
        return CONFIDENCE_WEIGHT[self.tier] if self._calibration.calibrated else 0.0

    async def check(self, session: Any) -> OracleOutcome:
        if not self._calibration.calibrated:
            raise OracleNotCalibrated(f"{self.tier.value}: {self._calibration.reason}")
        return await self._verifier(session)


async def calibrate_oracle(tier: OracleTier, verifier: VerifierFn, known_positive: Any, known_negative: Any) -> CalibratedOracle:
    """The one supported way to get a CalibratedOracle. Always returns one --
    even an uncalibrated verifier gets wrapped (its .check() just raises;
    .calibration.calibrated says why before anything is attempted), so a
    caller can report *which* tier failed and *why* instead of only knowing
    "no oracle was configured"."""
    result = await calibrate(tier, verifier, known_positive, known_negative)
    return CalibratedOracle(tier, verifier, result)


def ruled_out_result_is_trustworthy(calibration: CalibrationResult) -> tuple[bool, str | None]:
    """ZR-004's H4 fix, expressed directly over a CalibrationResult so a caller
    that already holds the calibration outcome (e.g. the engine's control phase)
    can gate a RULED_OUT without reconstructing a CalibratedOracle. (True, None)
    means a RULED_OUT built on this oracle's "denied" may stand; otherwise the
    second element is the reason to surface instead -- map it through
    UncertaintyStatus.BLOCKED_BY_MISSING_ORACLE (oracle_gate.py), never a silent
    acceptance of an uncalibrated "denied" as fact (Section 14.1: a target with
    no qualifying verifier yields exactly that status, never a guess)."""
    if not calibration.calibrated:
        return False, f"oracle not calibrated for tier {calibration.tier.value}: {calibration.reason}"
    return True, None


def ruled_out_is_trustworthy(oracle: CalibratedOracle) -> tuple[bool, str | None]:
    """ZR-004's H4 fix over a CalibratedOracle -- a thin wrapper over
    `ruled_out_result_is_trustworthy`, which holds the single implementation."""
    return ruled_out_result_is_trustworthy(oracle.calibration)


def make_feature_use_verifier(oracle: Any, feature: Any, *, oracle_id: str) -> VerifierFn:
    """Wrap app/testing/integrity/oracle.py's ProtectedFeatureOracle (or any
    object exposing the same async ``check(session, feature, *, oracle_id) ->
    OracleObservation`` contract) as a DURABLE_STATE_CHANGE VerifierFn that runs
    the real server-enforced feature-use check and returns its ``.outcome``
    ("allowed"/"denied"/"indeterminate"). This is the concrete "wrap the existing
    ProtectedFeatureOracle as a DURABLE_STATE_CHANGE verifier" step the module
    docstring describes, so the live oracle can be driven through
    `calibrate_oracle` and gated by `ruled_out_is_trustworthy`. Duck-typed on
    purpose (no import of the engine's oracle module) so this module stays
    dependency-light and import-cycle-free."""
    async def verify(session: Any) -> OracleOutcome:
        obs = await oracle.check(session, feature, oracle_id=oracle_id)
        return obs.outcome
    return verify


### Two concrete verifiers this project's own data already supports.
### DURABLE_STATE_CHANGE and EXTERNAL_SIDE_EFFECT need a real target to
### build a verifier for (what gets independently re-read, or which side
### effect, is specific to each target's surface) -- not implemented here,
### and not fabricated as a generic stand-in either.


@dataclass(frozen=True)
class LedgerLookup:
    feature_id: str
    identity_alias: str
    tenant_alias: str | None
    as_of: datetime


def make_ledger_cross_check_verifier(store: PESMStore) -> VerifierFn:
    """LEDGER_BILLING_CROSS_CHECK, closed over a PESMStore (ZR-002). Answers
    'allowed'/'denied' using PESM's independently-recorded entitlement state
    as the source of truth -- NOT the target's own HTTP response, which is
    exactly the point of this tier.

    This function only answers the ledger's own view of one session.
    Comparing it against a DURABLE_STATE_CHANGE verifier's answer for the
    SAME session is what surfaces a genuine billing-side inconsistency
    (Section 14.1's example: "sandbox provider ledger shows no charge, yet
    application grants paid access") -- that comparison belongs to the
    calling experiment, which has both verifiers' answers to compare; this
    function deliberately doesn't do it internally, so it stays a true
    single-source-of-truth check rather than a hidden two-tier merge.
    """
    async def verify(lookup: LedgerLookup) -> OracleOutcome:
        state = await store.latest_state(lookup.feature_id, lookup.identity_alias, lookup.tenant_alias, before=lookup.as_of)
        if state is None:
            return "indeterminate"  # no ledger record at all -- genuinely unknown, not "denied"
        return "allowed" if state.status == EntitlementStatus.ACTIVE else "denied"
    return verify


@dataclass(frozen=True)
class ResourceDelta:
    before: float
    after: float
    expected_min_delta: float  # smallest delta explainable only by the operation having executed


async def _resource_delta_verify(reading: ResourceDelta) -> OracleOutcome:
    delta = reading.after - reading.before
    if delta <= 0:
        return "denied"
    if delta >= reading.expected_min_delta:
        return "allowed"
    return "indeterminate"  # positive but below the declared minimum -- ambiguous, not a guess either way


resource_delta_verifier: VerifierFn = _resource_delta_verify
"""RESOURCE_DATA_DELTA. Pure arithmetic over a before/after reading -- no
external dependency, confidence genuinely does depend on delta specificity
(a tight expected_min_delta is more informative than a loose one), matching
Section 14.1's "Medium-high, depending on delta specificity" directly rather
than asserting one fixed number for the whole tier."""


def select_tier(available_evidence_kinds: frozenset[str]) -> OracleTier | None:
    """Section 14.1: "the verifier type is chosen from the library based on
    the target's recon data (which durable state changes, side effects, or
    deltas the target's surfaces actually expose)". `available_evidence_kinds`
    names what recon found exposed for this target (its own vocabulary, e.g.
    {"ledger_access", "independent_read", "quota_counter"} -- deliberately not
    pinned to a closed enum here, since what recon can discover is exactly
    the open-ended thing B1/A3 are responsible for, not this module).
    Highest-confidence tier whose required evidence kind is present wins;
    None means no qualifying verifier exists for this target -- the caller's
    job is then Section 2.7's BLOCKED BY MISSING SERVER-SIDE ORACLE, not a
    guess at a lower tier."""
    by_confidence = sorted(
        (t for t in OracleTier if t != OracleTier.NON_AUTHORITATIVE),
        key=lambda t: -CONFIDENCE_WEIGHT[t],
    )
    requires = {
        OracleTier.LEDGER_BILLING_CROSS_CHECK: "ledger_access",
        OracleTier.DURABLE_STATE_CHANGE: "independent_read",
        OracleTier.EXTERNAL_SIDE_EFFECT: "side_effect_channel",
        OracleTier.RESOURCE_DATA_DELTA: "quota_counter",
    }
    for tier in by_confidence:
        if requires[tier] in available_evidence_kinds:
            return tier
    return None
