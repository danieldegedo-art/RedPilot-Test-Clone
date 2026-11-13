"""B40: tests for app/testing/integrity/payment_fingerprint.py. Stdlib only."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.testing.integrity.payment_fingerprint import (  # noqa: E402
    SCOPE_EXCLUDED, SIGNATURES, Confidence, fingerprint, fingerprint_payload,
)

STRIPE_ALL = {"header:stripe-version", "path:/v1/payment_intents", "field:client_secret", "script:js.stripe.com"}


def test_full_signature_is_a_high_confidence_match():
    r = fingerprint(STRIPE_ALL)
    assert r.best == "stripe" and r.matches[0].confidence == Confidence.HIGH and r.matches[0].score == 1.0


def test_partial_match_lowers_confidence():
    two = fingerprint({"header:stripe-version", "path:/v1/payment_intents"})
    assert two.best == "stripe" and two.matches[0].confidence == Confidence.MEDIUM   # 2/4
    one = fingerprint({"header:stripe-version"})
    assert one.best == "stripe" and one.matches[0].confidence == Confidence.LOW      # 1/4


def test_no_known_signal_is_unknown():
    r = fingerprint({"something:unrelated"})
    assert r.best is None and r.matches == ()


def test_matches_are_ranked_by_score():
    r = fingerprint(STRIPE_ALL | {"domain:adyen.com"})   # stripe 1.0, adyen 0.33
    assert [m.provider for m in r.matches][:2] == ["stripe", "adyen"] and r.best == "stripe"


def test_signatures_contain_no_server_secret_tokens():
    secret_markers = ("sk_live", "sk_test", "rk_live", "secret_key", "private_key", "password", "bearer ", "authorization:")
    for sig in SIGNATURES:
        for token in sig.signals:
            low = token.lower()
            assert not any(m in low for m in secret_markers), (sig.provider, token)


def test_scope_excluded_is_documented_and_surfaced():
    assert "credential/secret-structure inventory" in SCOPE_EXCLUDED
    assert "bypass-pattern weaponization" in SCOPE_EXCLUDED
    assert set(fingerprint(STRIPE_ALL).to_dict()["scope_excluded"]) == set(SCOPE_EXCLUDED)


def test_payload_json_safe():
    payload = fingerprint_payload(STRIPE_ALL)
    assert payload["best"] == "stripe"
    assert json.loads(json.dumps(payload)) == payload
