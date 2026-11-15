"""ZR-015 / B20 (reproduction half): tests for app/testing/integrity/replay.py. Stdlib only."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.core.control_port.contract import (  # noqa: E402
    EvidenceClass, KIND_FEATURE_USE, OracleObservation, build_artifact,
)
from app.testing.integrity.replay import (  # noqa: E402
    BUNDLE_VERSION, ReplayBundle, attach_replay_bundles, build_replay_bundle,
)
from app.testing.purity.taxonomy import Verdict  # noqa: E402


class _Finding:
    """Duck-typed stand-in for integrity.findings.Finding (replay only reads
    hypothesis_id / p0_class / verdict.value / artifact_ids and writes
    reproduction_steps)."""

    def __init__(self, hypothesis_id, artifact_ids, verdict, p0_class="demo_class"):
        self.hypothesis_id = hypothesis_id
        self.artifact_ids = list(artifact_ids)
        self.verdict = verdict
        self.p0_class = p0_class
        self.reproduction_steps = None


def _art(seq, target, payload):
    return build_artifact(
        payload=payload, source_type="customer_api_call", classification=EvidenceClass.EXTERNAL_CUSTOMER_API,
        identity_alias="S", tenant_alias="tenant_s", target=target, session_isolation_id=f"sess-{seq:02d}",
        authorization_ref="AUTH-123", sequence=seq,
    )


def _obs(oracle_id, artifact_ids, outcome="allowed"):
    return OracleObservation(
        oracle_id=oracle_id, feature_id="premium_export", identity_alias="S", tenant_alias="tenant_s",
        outcome=outcome, kind=KIND_FEATURE_USE, proof_present=True, session_isolation_id="sess-oracle",
        artifact_ids=tuple(artifact_ids),
    )


def _fixture():
    a1 = _art(1, "https://shop.example.test/checkout", {"method": "POST", "path": "/checkout", "amount": 0, "status": 200})
    a2 = _art(2, "https://shop.example.test/use-feature", {"method": "GET", "path": "/use-feature", "status": 200})
    ledger = {a1.artifact_id: a1, a2.artifact_id: a2}
    obs = _obs("oracle-use-1", (a1.artifact_id, a2.artifact_id))
    return a1, a2, ledger, obs


def _build(finding_ids, ledger, obs, verdict=Verdict.RULED_OUT):
    finding = _Finding("H-U", finding_ids, verdict)
    return build_replay_bundle(
        finding, ledger_accepted=ledger, observations=[obs], admission_order=list(ledger),
        brief_fingerprint="bf-001", authorization_ref="AUTH-123", engine_version="pbb/1.0",
    )


# ---- construction --------------------------------------------------------------

def test_artifacts_are_bundled_in_topological_order_with_the_cited_observation():
    a1, a2, ledger, obs = _fixture()
    bundle = _build([a1.artifact_id, a2.artifact_id], ledger, obs)
    assert [a["artifact_id"] for a in bundle.artifacts] == [a1.artifact_id, a2.artifact_id]
    assert bundle.missing_artifact_ids == []
    assert [o["oracle_id"] for o in bundle.observations] == ["oracle-use-1"]
    assert bundle.graph["hypothesis_id"] == "H-U"
    # the oracle node is in the DAG order, after both request/response nodes
    order = bundle.graph["order"]
    assert order.index("rr:" + a1.artifact_id) < order.index("or:oracle-use-1")
    assert order.index("rr:" + a2.artifact_id) < order.index("or:oracle-use-1")


def test_only_observations_citing_the_finding_are_included():
    a1, a2, ledger, obs = _fixture()
    unrelated = _obs("oracle-other", ("ev-9999-aaaaaaaaaa",))
    finding = _Finding("H-U", [a1.artifact_id, a2.artifact_id], Verdict.RULED_OUT)
    bundle = build_replay_bundle(
        finding, ledger_accepted=ledger, observations=[obs, unrelated], admission_order=list(ledger),
        brief_fingerprint="bf-001", authorization_ref="AUTH-123", engine_version="pbb/1.0",
    )
    assert [o["oracle_id"] for o in bundle.observations] == ["oracle-use-1"]  # 'oracle-other' cites no finding artifact


# ---- portability ---------------------------------------------------------------

def test_to_dict_from_dict_round_trip_is_stable():
    a1, a2, ledger, obs = _fixture()
    bundle = _build([a1.artifact_id, a2.artifact_id], ledger, obs)
    d = bundle.to_dict()
    again = ReplayBundle.from_dict(d).to_dict()
    assert again == d
    assert d["version"] == BUNDLE_VERSION


def test_building_twice_from_the_same_inputs_is_deterministic():
    a1, a2, ledger, obs = _fixture()
    assert _build([a1.artifact_id, a2.artifact_id], ledger, obs).to_dict() == _build([a1.artifact_id, a2.artifact_id], ledger, obs).to_dict()


# ---- integrity -----------------------------------------------------------------

def test_verify_passes_for_an_intact_bundle():
    a1, a2, ledger, obs = _fixture()
    bundle = _build([a1.artifact_id, a2.artifact_id], ledger, obs)
    assert bundle.verify() == [] and bundle.integrity_ok()


def test_verify_flags_a_tampered_payload():
    a1, a2, ledger, obs = _fixture()
    d = _build([a1.artifact_id, a2.artifact_id], ledger, obs).to_dict()
    d["artifacts"][0]["payload"]["amount"] = 999999  # tamper: change a stored value, leave the hash as-is
    tampered = ReplayBundle.from_dict(d)
    problems = tampered.verify()
    assert problems and "integrity hash mismatch" in problems[0] and not tampered.integrity_ok()


# ---- reproduction steps (ZR-019 field) -----------------------------------------

def test_reproduction_steps_are_derived_from_stored_evidence():
    a1, a2, ledger, obs = _fixture()
    bundle = _build([a1.artifact_id, a2.artifact_id], ledger, obs)
    steps = bundle.reproduction_steps()
    assert steps[0].startswith("Authorized black-box replay of H-U")
    assert sum(1 for s in steps if "payload fields:" in s) == 2  # one replay step per bundled artifact
    assert any(s.startswith("observed: feature premium_export") for s in steps)
    assert any(s.startswith("evidence DAG:") for s in steps)
    assert bundle.reproduction_text() == "\n".join(steps)


# ---- purity: never fabricate missing evidence ----------------------------------

def test_a_cited_but_unadmitted_artifact_is_recorded_not_reconstructed():
    a1, a2, ledger, _ = _fixture()
    obs = _obs("oracle-use-1", (a1.artifact_id,))  # observation backed only by a1, so a2 is not pulled into the chain
    ghost = "ev-9999-deadbeef00"
    finding = _Finding("H-U", [a1.artifact_id, ghost], Verdict.RULED_OUT)
    bundle = build_replay_bundle(
        finding, ledger_accepted=ledger, observations=[obs], admission_order=list(ledger),
        brief_fingerprint="bf-001", authorization_ref="AUTH-123", engine_version="pbb/1.0",
    )
    assert bundle.missing_artifact_ids == [ghost]
    present = [a["artifact_id"] for a in bundle.artifacts]
    assert present == [a1.artifact_id] and ghost not in present  # the ghost has no admitted body to bundle
    assert all(aid in ledger for aid in present)  # nothing bundled that the ledger did not admit
    assert any("could not be bundled" in s for s in bundle.reproduction_steps())


# ---- attach_replay_bundles -----------------------------------------------------

def test_attach_sets_reproduction_steps_and_skips_evidence_free_findings():
    a1, a2, ledger, obs = _fixture()
    with_evidence = _Finding("H-U", [a1.artifact_id, a2.artifact_id], Verdict.CONFIRMED_P0)
    no_evidence = _Finding("H-OPEN", [], Verdict.BLOCKED)
    bundles = attach_replay_bundles(
        [with_evidence, no_evidence], ledger_accepted=ledger, observations=[obs], admission_order=list(ledger),
        brief_fingerprint="bf-001", authorization_ref="AUTH-123", engine_version="pbb/1.0",
    )
    assert set(bundles) == {"H-U"}
    assert with_evidence.reproduction_steps is not None and "H-U" in with_evidence.reproduction_steps
    assert no_evidence.reproduction_steps is None  # nothing to reproduce -> stays None, not a fabricated step list


def test_attach_is_best_effort_a_single_bad_finding_does_not_sink_the_batch():
    a1, a2, ledger, obs = _fixture()
    bad = _Finding("H-BAD", [a1.artifact_id], verdict=None)  # None.value -> AttributeError inside build
    good = _Finding("H-U", [a1.artifact_id], Verdict.RULED_OUT)
    bundles = attach_replay_bundles(
        [bad, good], ledger_accepted=ledger, observations=[obs], admission_order=list(ledger),
        brief_fingerprint="bf-001", authorization_ref="AUTH-123", engine_version="pbb/1.0",
    )
    assert "H-U" in bundles and "H-BAD" not in bundles
    assert good.reproduction_steps is not None
