"""The external Protected-Feature Oracle: USE the server-enforced paid feature as an authorised customer-level identity.

Outcomes (deterministic, from the identity's own response only):
  allowed        2xx AND the declared proof field is present and non-empty  (the feature was actually used; a bare 200 is NOT enough)
  denied         one of the feature's declared denial statuses (401/402/403 by default)
  indeterminate  anything else: transport error, 5xx, 404, 2xx without proof, a rejected (non-admitted) artifact, a non-JSON answer
UI badges, success/failure pages, redirects, subscription views, status reads, caches and client state are never consulted here -- they cannot
produce an ``allowed``. Whether the oracle DISCRIMINATES (denies a clean identity AND allows a qualifying payer) is established by the engine's
controls, not assumed. Stdlib only.
"""
from __future__ import annotations

from dataclasses import replace

from app.testing.integrity.brief import FeatureSpec
from app.testing.integrity.session import CustomerSession
from app.core.control_port import KIND_FEATURE_USE, OracleObservation, now_iso


class ProtectedFeatureOracle:
    def __init__(self) -> None:
        self.observations: list[OracleObservation] = []

    async def check(self, session: CustomerSession, feature: FeatureSpec, *, oracle_id: str,
                    extra_headers: dict[str, str] | None = None, extra_params: dict | None = None) -> OracleObservation:
        if extra_headers is None and extra_params is None:
            res = await session.feature_call(feature, label=oracle_id)  # unchanged default path (keeps stub/mocked sessions working)
        else:
            res = await session.feature_call(feature, label=oracle_id, extra_headers=extra_headers, extra_params=extra_params)
        proof = isinstance(res.body, dict) and bool(res.body.get(feature.proof_field))
        if not res.admitted or res.error is not None or res.status is None:
            outcome = "indeterminate"
        elif res.status in feature.allowed_statuses:
            outcome = "allowed" if proof else "indeterminate"
        elif res.status in feature.denied_statuses:
            outcome = "denied"
        else:
            outcome = "indeterminate"
        obs = OracleObservation(
            oracle_id=oracle_id, feature_id=feature.feature_id, identity_alias=session.identity_alias, tenant_alias=session.tenant_alias, outcome=outcome, kind=KIND_FEATURE_USE,
            proof_present=bool(proof and outcome == "allowed"), session_isolation_id=session.session_id, artifact_ids=(res.artifact_id,) if res.artifact_id else (), observed_at=now_iso(),
        )
        self.observations.append(obs)
        return obs

    @staticmethod
    def with_discrimination(obs: OracleObservation, discriminating: bool) -> OracleObservation:
        return replace(obs, discriminating=discriminating)
