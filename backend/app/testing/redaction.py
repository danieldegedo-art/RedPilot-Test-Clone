"""Secret redaction and identifier hygiene for everything the suite PERSISTS or EXPORTS.

WHY (Phase-0 finding G3/G5):
  * Evidence was stored verbatim: response headers including ``Set-Cookie``,
    request/response bodies that can carry tokens, card numbers or API keys,
    in Postgres and in every export. The session cookies the user configured
    were already stored in clear text; the evidence must not multiply that.
  * ``test_case_id`` is ``VARCHAR(48)`` in the schema but modules build IDs with
    slugs of up to 60 characters. SQLite ignores the limit, PostgreSQL raises,
    which loses the whole run's persistence step.

DESIGN DECISIONS
  * Redaction happens at PERSIST/EXPORT time, not at collection time. The
    discovery/cognition analyzers look for leaked secrets in the raw evidence
    (that is their job); redacting earlier would blind them. What is stored
    and exported never contains the raw value.
  * A redacted value is replaced by ``[REDACTED:<8 hex>]`` where the hex is an
    HMAC of the value under a per-process random salt: the same secret can be
    correlated across evidence inside one process, but the marker cannot be
    brute-forced or compared across runs.
  * Over-redaction is the safe failure mode (Luhn-valid digit runs are masked
    even if they were an order number); under-redaction is not.

Stdlib-only.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
from collections.abc import Mapping
from typing import Any

_SALT = os.urandom(16)

_SENSITIVE_EXACT = frozenset({
    "authorization", "proxyauthorization", "cookie", "setcookie", "password", "passwd", "pwd",
    "secret", "token", "apikey", "cvv", "cvv2", "cvc", "pan", "signature", "privatekey",
    "clientsecret", "xapikey", "xauthtoken", "xcsrftoken", "sessiontoken", "sessioncookie",
    "accesstoken", "refreshtoken", "idtoken", "cardnumber", "cardno", "creditcard",
})
_SENSITIVE_SUFFIXES = (
    "password", "passwd", "secret", "secretkey", "apikey", "token", "cookie",
    "authorization", "signature", "privatekey", "cardnumber",
)

_TEXT_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), "[REDACTED:private_key]"),
    (re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{8,}\b"), "[REDACTED:api_key]"),
    (re.compile(r"\bwhsec_[A-Za-z0-9]{8,}\b"), "[REDACTED:webhook_secret]"),
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}"), "Bearer [REDACTED]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b"), "[REDACTED:jwt]"),
    (
        re.compile(r"(?i)([?&](?:access_token|refresh_token|id_token|token|api_key|apikey|key|signature|sig|secret|password)=)[^&#\s\"']+"),
        r"\1[REDACTED]",
    ),
)
_CARD_RE = re.compile(r"(?<![\dA-Za-z])(?:\d[ -]?){12,18}\d(?![\dA-Za-z])")

LIVE_CREDENTIAL_RE = re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{8,}\b")


def _norm_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(key).lower())


def is_sensitive_key(key: str) -> bool:
    n = _norm_key(key)
    if not n:
        return False
    return n in _SENSITIVE_EXACT or n.endswith(_SENSITIVE_SUFFIXES)


def _fingerprint(value: Any) -> str:
    return hmac.new(_SALT, str(value).encode("utf-8", "replace"), hashlib.sha256).hexdigest()[:8]


def _mark(value: Any) -> str:
    return f"[REDACTED:{_fingerprint(value)}]"


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _redact_cards(text: str) -> str:
    def repl(match: re.Match[str]) -> str:
        digits = re.sub(r"\D", "", match.group(0))
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            return "[REDACTED:pan]"
        return match.group(0)

    return _CARD_RE.sub(repl, text)


def redact_text(text: str) -> str:
    """Mask secret-shaped substrings of a string (keys, bearer tokens, JWTs, PANs, token query params)."""
    if not text:
        return text
    for pattern, replacement in _TEXT_PATTERNS:
        text = pattern.sub(replacement, text)
    return _redact_cards(text)


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return f"{text[:limit]}...[truncated {len(text) - limit} chars]"


def redact_json(obj: Any, *, max_depth: int = 12, max_string: int = 20_000, max_items: int = 500, _depth: int = 0) -> Any:
    """Deep, non-mutating redaction of a JSON-like structure."""
    if _depth > max_depth:
        return "[TRUNCATED:depth]"
    if isinstance(obj, Mapping):
        out: dict[str, Any] = {}
        for index, (key, value) in enumerate(obj.items()):
            if index >= max_items:
                out["..."] = f"[TRUNCATED:{len(obj) - max_items} more keys]"
                break
            key_s = str(key)
            if is_sensitive_key(key_s) and value not in (None, "", [], {}):
                out[key_s] = _mark(value)
            else:
                out[key_s] = redact_json(value, max_depth=max_depth, max_string=max_string, max_items=max_items, _depth=_depth + 1)
        return out
    if isinstance(obj, (list, tuple)):
        items = [redact_json(v, max_depth=max_depth, max_string=max_string, max_items=max_items, _depth=_depth + 1) for v in list(obj)[:max_items]]
        if len(obj) > max_items:
            items.append(f"[TRUNCATED:{len(obj) - max_items} more items]")
        return items
    if isinstance(obj, str):
        return _truncate(redact_text(obj), max_string)
    return obj


def redact_headers(headers: Mapping[str, Any] | None) -> dict[str, str]:
    out: dict[str, str] = {}
    for name, value in (headers or {}).items():
        if is_sensitive_key(str(name)) and value not in (None, ""):
            out[str(name)] = _mark(value)
        else:
            out[str(name)] = redact_text(str(value))
    return out


def find_live_credentials(obj: Any) -> list[str]:
    """Return fingerprints (never values) of live-mode API credentials found anywhere in ``obj``."""
    found: list[str] = []

    def walk(node: Any) -> None:
        if isinstance(node, Mapping):
            for k, v in node.items():
                walk(k)
                walk(v)
        elif isinstance(node, (list, tuple)):
            for v in node:
                walk(v)
        elif isinstance(node, str):
            for match in LIVE_CREDENTIAL_RE.finditer(node):
                found.append(_fingerprint(match.group(0)))

    walk(obj)
    return found


# -- identifier hygiene ---------------------------------------------------------
def safe_test_case_id(test_case_id: str, max_len: int = 48) -> str:
    """Deterministically shorten an over-long ID: prefix + '~' + 8 hex of its SHA-256 (unique, stable)."""
    if len(test_case_id) <= max_len:
        return test_case_id
    digest = hashlib.sha256(test_case_id.encode("utf-8")).hexdigest()[:8]
    return f"{test_case_id[: max_len - 9]}~{digest}"


def _shorten_refs(obj: Any, max_len: int) -> Any:
    """Keep intra-result references (matrix cells, correlation lists) consistent with shortened IDs."""
    if isinstance(obj, dict):
        for key, value in list(obj.items()):
            if key == "test_case_id" and isinstance(value, str):
                obj[key] = safe_test_case_id(value, max_len)
            elif key in ("source_test_case_ids", "test_case_ids") and isinstance(value, list):
                obj[key] = [safe_test_case_id(v, max_len) if isinstance(v, str) else v for v in value]
            else:
                obj[key] = _shorten_refs(value, max_len)
    elif isinstance(obj, list):
        for i, value in enumerate(obj):
            obj[i] = _shorten_refs(value, max_len)
    return obj


_JSON_FIELDS = ("request_json", "response_json", "input_parameters", "request", "response")
_TEXT_FIELDS = ("actual", "expected", "recommendation", "description", "name")


def normalize_result_for_persistence(fields: Mapping[str, Any], *, max_id_len: int = 48) -> dict[str, Any]:
    """Redact secrets and shorten IDs in the fields of one test result about to be stored/exported.

    Only known evidence/text fields are touched; every other key (datetimes,
    status, category, ...) passes through unchanged.
    """
    out = dict(fields)
    for key in _JSON_FIELDS:
        if out.get(key) is not None:
            out[key] = _shorten_refs(redact_json(out[key]), max_id_len)
    for key in _TEXT_FIELDS:
        if isinstance(out.get(key), str):
            out[key] = redact_text(out[key])
    if isinstance(out.get("test_case_id"), str):
        out["test_case_id"] = safe_test_case_id(out["test_case_id"], max_id_len)
    return out
