"""Secret redaction + identifier hygiene for persisted/exported evidence."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.testing.redaction import (  # noqa: E402
    find_live_credentials, is_sensitive_key, normalize_result_for_persistence, redact_headers,
    redact_json, redact_text, safe_test_case_id,
)


def test_sensitive_key_classification() -> None:
    for key in ("password", "Authorization", "Set-Cookie", "x-api-key", "csrf_token", "access_token", "client_secret",
                "stripe_secret_key", "webhook_signature", "card_number", "cvv", "PAN", "new_password"):
        assert is_sensitive_key(key), key
    for key in ("tokens_used", "max_tokens", "token_type", "session_id", "payment_id", "amount", "currency", "status", "user_id"):
        assert not is_sensitive_key(key), key


def test_redact_json_masks_secrets_keeps_structure_and_correlates() -> None:
    doc = {
        "user_id": "u_1", "tokens_used": 12, "nested": {"api_key": "sk_test_abcdefghijkl", "items": [{"password": "hunter2", "n": 1}]},
        "note": "call with Bearer abcdefghijklmnop please", "empty_password": "", "password": "",
        "cookie": "session=abc123", "retry": "https://x.io/cb?token=s3cr3t&ok=1",
    }
    out = redact_json(doc)
    text = json.dumps(out)
    for leaked in ("hunter2", "sk_test_abcdefghijkl", "abcdefghijklmnop", "abc123", "s3cr3t"):
        assert leaked not in text, f"leaked {leaked}"
    assert out["user_id"] == "u_1" and out["tokens_used"] == 12 and out["nested"]["items"][0]["n"] == 1
    assert out["password"] == "" , "an EMPTY secret field carries no secret and stays visible as empty"
    assert "ok=1" in out["retry"], "non-secret query parameters survive"
    a = redact_json({"token": "same"})["token"]
    b = redact_json({"token": "same"})["token"]
    c = redact_json({"token": "different"})["token"]
    assert a == b != c and a.startswith("[REDACTED:"), "same secret => same marker within a process, different secret => different"
    assert doc["nested"]["api_key"] == "sk_test_abcdefghijkl", "input must not be mutated"


def test_redact_text_patterns_and_luhn() -> None:
    assert "4242424242424242" not in redact_text("card 4242 4242 4242 4242 charged")
    assert "[REDACTED:pan]" in redact_text("pan=4242424242424242")
    assert "4242424242424241" in redact_text("order 4242424242424241"), "non-Luhn digit runs (order numbers) are kept"
    assert "whsec_" not in redact_text("secret whsec_abcdefgh12345678")
    assert "eyJ" not in redact_text("jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijk")
    assert "-----BEGIN" not in redact_text("-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----")
    assert redact_text("") == ""


def test_redact_headers() -> None:
    out = redact_headers({"Set-Cookie": "sid=deadbeef; HttpOnly", "Content-Type": "application/json", "Authorization": "Bearer abcdefghijkl", "Location": "/cb?token=zzz"})
    assert "deadbeef" not in json.dumps(out) and "zzz" not in json.dumps(out) and out["Content-Type"] == "application/json"


def test_long_ids_are_shortened_deterministically_and_references_stay_consistent() -> None:
    long_id = "ROLE-002-ROLLBACK-01-API-V1-ACCOUNT-SUBSCRIPTION-UPDATE-PLAN"
    short = safe_test_case_id(long_id)
    assert len(short) <= 48 and short == safe_test_case_id(long_id) and short.startswith(long_id[:39])
    assert safe_test_case_id(long_id + "X") != short, "distinct long IDs must stay distinct"
    assert safe_test_case_id("ROLE-001-01-PAYMENTS") == "ROLE-001-01-PAYMENTS", "short IDs are untouched"
    fields = {
        "test_case_id": long_id,
        "input_parameters": {"matrix": [{"test_case_id": long_id, "verdict": "blocked"}], "source_test_case_ids": [long_id, "SHORT-1"]},
        "status": "pass",
    }
    out = normalize_result_for_persistence(fields)
    assert out["test_case_id"] == short
    assert out["input_parameters"]["matrix"][0]["test_case_id"] == short, "matrix cell must still point at the persisted ID"
    assert out["input_parameters"]["source_test_case_ids"] == [short, "SHORT-1"]
    assert out["status"] == "pass"


def test_persistence_normalizer_never_leaks_evidence_secrets() -> None:
    fields = {
        "test_case_id": "PROC-001",
        "request_json": {"method": "POST", "url": "https://t/pay?api_key=live_k3y", "headers": {"Cookie": "s=1234567890"}, "body": {"card_number": "4242424242424242"}},
        "response_json": {"status_code": 200, "headers": {"Set-Cookie": "sid=abcdef123456"}, "body": {"access_token": "tok_123456789", "ok": True}},
        "actual": "server echoed Bearer abcdefghijklmnop",
    }
    out = normalize_result_for_persistence(fields)
    blob = json.dumps(out)
    for leaked in ("live_k3y", "1234567890", "4242424242424242", "abcdef123456", "tok_123456789", "abcdefghijklmnop"):
        assert leaked not in blob, f"persisted evidence leaked {leaked}"
    assert out["response_json"]["body"]["ok"] is True


def test_live_credential_detection_returns_fingerprints_not_values() -> None:
    found = find_live_credentials({"a": ["x", {"k": "use sk_live_ABCDEFGH12345678 here"}]})
    assert len(found) == 1 and "sk_live" not in found[0]
    assert find_live_credentials({"k": "sk_test_ABCDEFGH12345678"}) == []


if __name__ == "__main__":
    import inspect
    import traceback

    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and inspect.isfunction(fn):
            try:
                fn()
                print(f"PASS {name}")
            except Exception:
                failures += 1
                print(f"FAIL {name}")
                traceback.print_exc()
    print(f"\n{'ALL PASSED' if not failures else str(failures) + ' FAILED'}")
    sys.exit(1 if failures else 0)
