"""The external Protected-Feature Oracle requirement, enforced by construction (mandate: 'Oracle enforcement').

A CONFIRMED_P0 decision needs the full external chain:
  1. control   -- a clean identity/tenant WITHOUT a qualifying payment is DENIED by the same server-enforced feature
                  (so the feature demonstrably discriminates and frontend state cannot explain the later 'allowed');
  2. scenario  -- after the commercial scenario the feature is actually USED successfully (proof present, not just HTTP 200);
  3. clean reproduction -- the same result under an independent clean session/identity;
  4. every artifact admitted by the EvidenceLedger, with an external classification;
  5. no qualifying payment for the identity/tenant/plan that got the access (otherwise 'allowed' is correct behaviour).
Internal state, logs, DB rows, provider dashboards, benchmark labels, UI badges, redirects, bare HTTP statuses, browser
cache/local storage and client-side state are NOT oracle evidence and can never satisfy this gate.

``ConfirmationGate.evaluate`` is the only producer of a ``ConfirmationToken``; a Finding with verdict CONFIRMED_P0 cannot be
constructed without one. (A guard against accidental misuse by code in this project, not a defence against a malicious
in-process caller.) Stdlib only.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.core.control_port.contract import (  # K3 data types live in the contract; re-exported here for the control layer's own tests
    KIND_FEATURE_USE, ConfirmationCandidate, ConfirmationRefused, EvidenceClass, GateDecision, OracleObservation,
    UncertaintyStatus,
)
from app.enterprise_controls.provenance import EvidenceLedger

__all__ = ["KIND_FEATURE_USE", "NON_AUTHORITATIVE_SIGNALS", "OracleObservation", "ConfirmationCandidate", "ConfirmationToken", "GateDecision", "ConfirmationGate"]
NON_AUTHORITATIVE_SIGNALS = frozenset({
    "ui_badge", "success_page", "failure_page", "redirect", "http_status_only", "invoice_looking_page", "browser_cache", "local_storage",
    "client_side_state", "frontend_feature_flag", "optimistic_message", "provider_callback_page", "status_read", "subscription_view",
    "internal_state", "log", "database", "provider_dashboard", "benchmark_label",
})
_MINT = object()
_ISSUED: set[int] = set()


class ConfirmationToken:
    """Proof that ConfirmationGate.evaluate approved ``hypothesis_id``. Cannot be constructed directly."""

    __slots__ = ("hypothesis_id", "artifact_ids")

    def __init__(self, hypothesis_id: str, artifact_ids: tuple[str, ...], *, _key: object = None) -> None:
        if _key is not _MINT:
            raise ConfirmationRefused("confirmation_token_forged", "a ConfirmationToken can only be issued by ConfirmationGate.evaluate")
        object.__setattr__(self, "hypothesis_id", hypothesis_id)
        object.__setattr__(self, "artifact_ids", artifact_ids)
        _ISSUED.add(id(self))

    def __setattr__(self, name: str, value: Any) -> None:  # immutable
        raise AttributeError("ConfirmationToken is immutable")

    def covers(self, hypothesis_id: str) -> bool:
        return id(self) in _ISSUED and self.hypothesis_id == hypothesis_id


def _classify_uncertainty(reasons: tuple[str, ...]) -> UncertaintyStatus | None:
    """ZR-024. Exactly one of the four labels per non-confirmed decision, chosen
    in priority order (most fundamental/structural blocker first) rather than
    by reason-list position, so a candidate missing both the oracle AND the
    reproduction is reported as missing the oracle -- fix that first, the rest
    may resolve once it's there. See each reason string's own producing check
    in evaluate() just above for what triggers it.
    """
    def has(prefix: str) -> bool:
        return any(r.startswith(prefix) for r in reasons)

    if has("qualifying_payment_present"):
        return None  # a conclusively-determined non-finding, not an unproven suspicion
    if has("feature_not_registered"):
        return UncertaintyStatus.UNCONFIRMED  # ZR-025 condition 1: nothing else is worth investigating yet
    if has("control_missing"):
        return UncertaintyStatus.BLOCKED_BY_MISSING_ORACLE
    if has("clean_reproduction_missing") or has("clean_reproduction_not_independent"):
        return UncertaintyStatus.NOT_SUFFICIENTLY_PROVABLE
    if has("scenario_not_proven") or has("no_evidence_artifacts") or has("artifact_not_admitted") or has("evidence_class_not_external"):
        return UncertaintyStatus.PARTIALLY_VERIFIED
    if has("oracle_requirement_not_met") or has("non_authoritative_signals_only"):
        return UncertaintyStatus.UNCONFIRMED
    # Defensive: evaluate() only calls this with a non-empty reasons tuple
    # (it only runs `if reasons:`), and every reason string it can produce is
    # handled above -- reachable only if a future reason is added here without
    # updating this classifier, which the exhaustiveness test below catches.
    return UncertaintyStatus.UNCONFIRMED


@dataclass
class ConfirmationGate:
    ledger: EvidenceLedger
    registered_feature_ids: frozenset[str] | None = None  # ZR-002/ZR-025 condition 1; None = not wired up yet (fails OPEN on this condition only -- see evaluate()); a real frozenset is a hard AND-gate condition
    _decisions: list[GateDecision] = field(default_factory=list)

    def evaluate(self, c: ConfirmationCandidate) -> GateDecision:
        reasons: list[str] = []
        ctl, sc, rp = c.control_denied, c.scenario_allowed, c.clean_reproduction
        feature_ids = {o.feature_id for o in (ctl, sc, rp) if o is not None}
        if len(feature_ids) > 1:
            # Internal inconsistency on the candidate itself -- flagged regardless of
            # whether a registry is configured; this isn't a PESM question at all.
            reasons.append(f"feature_not_registered: observations disagree on feature_id: {sorted(feature_ids)}")
        elif self.registered_feature_ids is not None and (not feature_ids or next(iter(feature_ids)) not in self.registered_feature_ids):
            # ZR-025 condition 1, enforced only once a caller actually wires PESM in
            # (control_adapter/adapter.py's new_confirmation_gate doesn't yet -- nothing
            # populates PESM until A3/A5-A7 exist, so this stays fail-open until then;
            # see this field's definition above). Hard block once configured.
            reasons.append("feature_not_registered: target is not a confirmed registered paid/protected feature")
        if KIND_FEATURE_USE not in c.signals_used:
            reasons.append("oracle_requirement_not_met: no protected-feature-use observation among the signals")
        weak = sorted(s for s in c.signals_used if s in NON_AUTHORITATIVE_SIGNALS)
        if c.signals_used and all(s in NON_AUTHORITATIVE_SIGNALS for s in c.signals_used):
            reasons.append(f"non_authoritative_signals_only: {weak}")
        if ctl is None or ctl.outcome != "denied" or ctl.kind != KIND_FEATURE_USE or ctl.discriminating is not True:
            reasons.append("control_missing: a clean identity/tenant without a qualifying payment must be DENIED by the same feature (discriminating oracle)")
        if sc is None or sc.outcome != "allowed" or sc.kind != KIND_FEATURE_USE or not sc.proof_present:
            reasons.append("scenario_not_proven: the protected feature was not actually used successfully (proof of use missing)")
        if rp is None or rp.outcome != "allowed" or rp.kind != KIND_FEATURE_USE or not rp.proof_present:
            reasons.append("clean_reproduction_missing: no independent clean-session reproduction of the access")
        elif sc is not None and rp.session_isolation_id == sc.session_isolation_id:
            reasons.append("clean_reproduction_not_independent: reproduction reused the scenario's session")
        if c.qualifying_payment_present:
            reasons.append("qualifying_payment_present: the access may be correct behaviour")
        ids = tuple(a for o in (ctl, sc, rp) if o is not None for a in o.artifact_ids) + tuple(c.extra_artifact_ids)
        if not ids:
            reasons.append("no_evidence_artifacts")
        for artifact_id in ids:
            if not self.ledger.is_admitted(artifact_id):
                reasons.append(f"artifact_not_admitted: {artifact_id}")
        valid_classes = {e.value for e in EvidenceClass}
        for cls in c.evidence_classes:
            if cls not in valid_classes:
                reasons.append(f"evidence_class_not_external: {cls}")
        if reasons:
            frozen_reasons = tuple(reasons)
            decision = GateDecision(False, frozen_reasons, uncertainty_status=_classify_uncertainty(frozen_reasons))
        else:
            decision = GateDecision(True, (), ConfirmationToken(c.hypothesis_id, ids, _key=_MINT))
        self._decisions.append(decision)
        return decision
