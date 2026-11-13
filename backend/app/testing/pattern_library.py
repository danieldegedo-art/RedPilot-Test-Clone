"""Dependency-free pattern-matching primitives for spotting leaked
secrets, credential-shaped tokens, and payment-card numbers in response
bodies.

Deliberately has NO imports beyond the stdlib (re, json, typing): this is
a leaf module two different parts of the codebase build on --
app.testing.discovery.analyzers' retrospective sensitive-data scan, and
benchmark.llm_replacement_layer's zero-shot pass -- and the second of
those exists specifically to be fast and offline. Before this was split
out, benchmark/ importing these patterns from discovery/analyzers.py
transitively pulled in the ENTIRE test-module registry (httpx,
SQLAlchemy-backed modules, the whole app.testing.modules package) just to
reach a few regexes with zero actual relationship to any of that. One
canonical definition, two lightweight importers.
"""
from __future__ import annotations

import json
import re
from typing import Any

SECRET_PATTERNS: list[tuple[str, re.Pattern[str], bool]] = [
    # (name, pattern, is_critical)
    ("stripe_live_secret_key", re.compile(r"sk_live_[A-Za-z0-9]{10,}"), True),
    ("stripe_live_restricted_key", re.compile(r"rk_live_[A-Za-z0-9]{10,}"), True),
    ("aws_access_key_id", re.compile(r"AKIA[0-9A-Z]{16}"), True),
    ("pem_private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), True),
    ("jwt_shaped_token", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), False),
]

SENSITIVE_FIELD_NAME_RE = re.compile(
    r"(password|passwd|secret|private_key|api_key|apikey|cvv|cvc|ssn|social_security)", re.IGNORECASE
)
KNOWN_TEST_VALUES = {"tok_test_visa_valid"}  # this suite's own inputs -- echoed back is noise, not a finding

CARD_NUMBER_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")


def luhn_valid(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(digits[::-1]):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def body_as_text(body: Any) -> str:
    if isinstance(body, str):
        return body
    try:
        return json.dumps(body, default=str)
    except (TypeError, ValueError):
        return str(body)


def scan_field_names(body: Any, path: str = "") -> list[tuple[str, str, Any]]:
    """Recursively finds sensitively-named fields (password, api_key,
    cvv, ...) carrying a real (non-empty, non-redacted, non-test) value.
    Returns (field_path, key, value) tuples."""
    hits: list[tuple[str, str, Any]] = []
    if isinstance(body, dict):
        for key, value in body.items():
            field_path = f"{path}.{key}" if path else key
            if SENSITIVE_FIELD_NAME_RE.search(key) and value not in (None, "", "***", "REDACTED") and value not in KNOWN_TEST_VALUES:
                hits.append((field_path, key, value))
            hits.extend(scan_field_names(value, field_path))
    elif isinstance(body, list):
        for index, item in enumerate(body):
            hits.extend(scan_field_names(item, f"{path}[{index}]"))
    return hits
