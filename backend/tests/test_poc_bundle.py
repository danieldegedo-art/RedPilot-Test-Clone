"""PoC Bundle (app/testing/integrity/poc_bundle.py).

Duck-typed on the finding, so these tests drive it with a lightweight stand-in
(SimpleNamespace + a schema_completeness callable) and a hand-built replay-bundle
dict -- no engine/httpx import required.

Stdlib only.
"""
from __future__ import annotations

import json
import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.testing.integrity.poc_bundle import (  # noqa: E402
    build_poc_bundle, build_poc_bundles, poc_bundles_markdown,
)
from app.testing.purity.taxonomy import Verdict  # noqa: E402


def _finding(**over):
    base = dict(
        hypothesis_id="PBB-F", p0_class="failed_payment_bypass", title="Failed payment bypass",
        verdict=Verdict.RULED_OUT, confidence="high", artifact_ids=["a1", "a2"], token=None,
        reproduction_status="independently reproduced", reproduction_steps=None, impact=None,
        server_side_oracle="o: outcome=denied, discriminating=True", expected_state="denied",
        actual_state="denied", payment_state="declined", entitlement_state="none",
        divergences=[], metrics={}, recommended_fix=None, affected_flow="checkout",
        precondition=(), effect=(), regression_test_reference="REG-PBB-F",
    )
    base.update(over)
    ns = types.SimpleNamespace(**base)
    ns.schema_completeness = lambda: 0.875
    return ns


_REPLAY = {
    "reproduction_steps": ["step one", "step two"],
    "graph": {"completeness": 1.0},
    "missing_artifact_ids": [],
    "artifacts": [
        {"artifact_id": "a1",
         "provenance": {"source_type": "customer_api_response", "classification": "pure_black_box",
                        "target": "https://staging.example/checkout", "redaction_status": "redacted",
                        "integrity_hash": "abcdef0123456789"},
         # a secret-looking VALUE that must NOT leak into the PoC path:
         "payload": {"card_number": "4242424242424242", "plan": "pro"}},
    ],
}


def test_non_confirmed_finding_asserts_no_impact():
    b = build_poc_bundle(_finding(verdict=Verdict.RULED_OUT, token=None, impact=None))
    pi = b.proof_of_impact
    assert pi["impact"] is None
    assert pi["independently_reproduced"] is False
    assert "Not a confirmed P0" in pi["note"]


def test_confirmed_finding_surfaces_impact_and_reproduction():
    b = build_poc_bundle(_finding(
        verdict=Verdict.CONFIRMED_P0, token=object(),
        impact="Unauthorized use of a paid feature without a valid payment, independently reproduced.",
    ))
    assert b.evidence["confirmation_token_present"] is True
    assert b.proof_of_impact["independently_reproduced"] is True
    assert "Unauthorized use" in b.proof_of_impact["impact"]
    assert "independently reproduced" in b.proof_of_impact["note"]


def test_request_response_path_surfaces_field_names_not_values():
    b = build_poc_bundle(_finding(), replay_bundle=_REPLAY)
    path = b.replayable_path["request_response_path"]
    assert len(path) == 1
    assert path[0]["payload_fields"] == ["card_number", "plan"]  # NAMES, sorted
    # the secret VALUE must never appear anywhere in the serialized bundle
    assert "4242424242424242" not in json.dumps(b.to_dict())


def test_replay_steps_fall_back_to_bundle_when_finding_has_none():
    b = build_poc_bundle(_finding(reproduction_steps=None), replay_bundle=_REPLAY)
    assert b.replayable_path["steps"] == ["step one", "step two"]


def test_no_replay_bundle_is_honest_not_fabricated():
    b = build_poc_bundle(_finding(reproduction_steps=None), replay_bundle=None)
    assert b.replayable_path["request_response_path"] == []
    assert b.replayable_path["steps"] == []


def test_remediation_absence_is_explicit():
    assert build_poc_bundle(_finding(recommended_fix=None)).remediation["available"] is False
    assert build_poc_bundle(_finding(recommended_fix="Re-check entitlement at point of use.")).remediation["available"] is True


def test_markdown_has_the_four_poc_sections():
    md = build_poc_bundle(_finding(), replay_bundle=_REPLAY).to_markdown()
    for section in ("### 1. Evidence", "### 2. Replayable request/response path",
                    "### 3. Proof of impact", "### 4. Remediation"):
        assert section in md
    assert "4242424242424242" not in md  # secrets never rendered


def test_build_poc_bundles_keys_by_hypothesis_and_pairs_replay():
    result = types.SimpleNamespace(
        findings=[_finding(hypothesis_id="PBB-F"), _finding(hypothesis_id="PBB-U", artifact_ids=[])],
        replay_bundles={"PBB-F": _REPLAY},
    )
    out = build_poc_bundles(result)
    assert set(out) == {"PBB-F", "PBB-U"}
    assert out["PBB-F"]["replayable_path"]["request_response_path"]  # paired with its replay bundle
    assert out["PBB-U"]["replayable_path"]["request_response_path"] == []  # no bundle -> honest empty
    assert "# Proof-of-Concept Bundles" in poc_bundles_markdown(result)


if __name__ == "__main__":
    import traceback
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = failed = 0
    for t in tests:
        try:
            t()
            print(f"PASS {t.__name__}")
            passed += 1
        except Exception:
            print(f"FAIL {t.__name__}")
            traceback.print_exc()
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
