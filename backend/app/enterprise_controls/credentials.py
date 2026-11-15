"""Target credential allowlist (mandate: 'Target credential allowlist').

Only CUSTOMER-LEVEL SYNTHETIC test credentials explicitly approved in the Execution Brief may reach a target. This module
refuses everything else BEFORE any request is sent:

  * administrator / staff / service-account / infrastructure / database / provider-dashboard credentials
  * provider secrets (Stripe sk_/rk_/whsec_ keys, cloud keys, private keys, VCS/chat tokens)
  * JWTs whose own (customer-readable) claims say admin / staff / service / internal
  * configuration keys that name target internals (internal API bases, log connectors, DB URLs, source paths) or
    benchmark ground truth (flaw hints, scenario names, expected results, fixtures)

Messages name the key PATH and the matched RULE only -- never the offending value, which may itself be a secret.
Stdlib only.
"""
from __future__ import annotations

import base64
import json
import re
from typing import Any, Iterable, Mapping

from app.core.control_port.contract import CredentialRejected, Reason

ALLOWED_ROLES = frozenset({"customer", "member", "user", "tenant_member", "tenant_owner"})
_ALIAS_RE = re.compile(r"^[a-z][a-z0-9_]{1,39}$")

_PRIVILEGED_WORDS = frozenset({"admin", "administrator", "superuser", "superadmin", "root", "staff", "support", "internal", "service", "service_account", "system", "platform_admin", "site_admin", "ops", "operator", "employee"})
_PRIVILEGED_BOOL_CLAIMS = frozenset({"is_admin", "is_staff", "is_superuser", "admin", "superuser", "staff", "is_service", "is_internal", "is_root"})
_CLAIM_CONTAINERS = ("role", "roles", "scope", "scopes", "scp", "groups", "permissions", "authorities", "cognito:groups", "realm_access", "resource_access")

# --- forbidden configuration KEY names (normalised: lowercase, '-' and ' ' -> '_') --------------------------------------------
_SECRET_KEYS = re.compile(
    r"(webhook_?secret|signing_?secret|whsec|client_?secret|api_?secret|secret_?key|private_?key|service_?key|master_?key|encryption_?key|"
    r"admin_?(token|password|key|credential)s?|root_?(password|token)|db_?(password|user|url|dsn|host|uri)|"
    r"database_?(url|password|uri|dsn)|connection_?string|^dsn$|redis_?url|aws_?(secret|access)|kube_?config|service_?account)"
)
_INTERNAL_KEYS = re.compile(
    r"(internal_?(api|base|url|endpoint|host|doc)\w*|private_?(api|endpoint|spec)\w*|log_?(path|url|file|reader|connector)\w*|server_?log\w*|"
    r"trace_?(url|endpoint)\w*|provider_?dashboard\w*|dashboard_?(url|token|login)\w*|admin_?(url|panel|host|api|base)\w*|cloud_?console\w*|"
    r"source_?(code|path|repo)\w*|^repo(sitory)?(_url|_path)?$|git_?(url|repo)\w*|schema_?(dump|file)\w*|migrations?$|entitlement_?(db|record|table)\w*)"
)
_BENCHMARK_KEYS = re.compile(
    r"(ground_?truth|flaw\w*|seeded\w*|hints?$|\w*_hints?$|expected_?(verdict|result|outcome)s?|scenarios?$|scenario_?name\w*|fixtures?$|"
    r"vuln(erability)?_?(label|id|location)s?|truth_?from_?flags|bug_?(class|flag)s?)"
)

_VALUE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("database_url", re.compile(r"^\s*(postgres(ql)?|mysql|mariadb|mongodb(\+srv)?|redis|rediss|amqps?|mssql|oracle|jdbc:[a-z]+)(\+\w+)?://", re.I)),
    ("provider_secret_key", re.compile(r"\b(sk|rk)_(live|test)_[A-Za-z0-9]{8,}\b")),
    ("webhook_signing_secret", re.compile(r"\bwhsec_[A-Za-z0-9]{8,}\b")),
    ("cloud_access_key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("private_key_material", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("vcs_or_chat_token", re.compile(r"\b(ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})\b")),
)

_PRIVILEGED_HEADER = re.compile(r"^x-(admin|internal|service|staff|debug|impersonat\w*|override\w*|bypass\w*|forwarded-user|remote-user|original-user|auth-user|authenticated-user|trusted-\w+)")
_PRIVILEGED_COOKIE = re.compile(r"(admin|staff|internal|superuser|root|service)[_-]?(session|token|auth|sid|jwt)", re.I)
_ENV_NAME_FORBIDDEN = re.compile(r"(ADMIN|ROOT|STAFF|SERVICE|SUPERUSER|INTERNAL|DB_|DATABASE|PASSWORD|SECRET|PRIVATE|SIGNING)", re.I)


def _norm_key(key: str) -> str:
    return re.sub(r"[\s\-]+", "_", str(key).strip().lower())


def _b64url_json(segment: str) -> dict[str, Any] | None:
    try:
        raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
        data = json.loads(raw.decode("utf-8"))
        return data if isinstance(data, dict) else None
    except Exception:  # noqa: BLE001 - any decode problem simply means "not a readable JWT"
        return None


def _flatten_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield from (p.strip().lower() for p in re.split(r"[\s,]+", value) if p.strip())
    elif isinstance(value, (list, tuple, set)):
        for v in value:
            yield from _flatten_strings(v)
    elif isinstance(value, dict):
        for k, v in value.items():
            yield str(k).lower()
            yield from _flatten_strings(v)


def jwt_privileged_claims(token: str) -> list[str]:
    """Names of privileged claims a (customer-readable) JWT payload asserts. Empty for non-JWTs and customer tokens."""
    parts = (token or "").strip().split(".")
    if len(parts) != 3:
        return []
    payload = _b64url_json(parts[1])
    if payload is None:
        return []
    found: list[str] = []
    for name in _PRIVILEGED_BOOL_CLAIMS:
        if payload.get(name) is True:
            found.append(name)
    for name, value in payload.items():
        lowered = str(name).lower()
        if lowered in _CLAIM_CONTAINERS or lowered.endswith("/roles") or lowered.endswith("/role"):
            if any(w in _PRIVILEGED_WORDS for w in _flatten_strings(value)):
                found.append(f"{lowered}:privileged")
    return found


def scan_string(value: str, location: str) -> list[Reason]:
    out: list[Reason] = []
    for name, pattern in _VALUE_PATTERNS:
        if pattern.search(value):
            out.append(Reason(f"credential_{name}", location, f"value matches the {name.replace('_', ' ')} pattern (value not shown)"))
    token = value.split()[-1] if value.lower().startswith("bearer ") else value
    claims = jwt_privileged_claims(token)
    if claims:
        out.append(Reason("credential_privileged_jwt", location, f"JWT asserts privileged claim(s) {sorted(set(claims))}"))
    return out


def scan_for_forbidden(obj: Any, *, location: str = "$", _depth: int = 0) -> list[Reason]:
    """Recursively scan a config/brief/request mapping for forbidden KEYS and forbidden VALUES."""
    reasons: list[Reason] = []
    if _depth > 12:
        return reasons
    if isinstance(obj, Mapping):
        for key, value in obj.items():
            nk, loc = _norm_key(key), f"{location}.{key}"
            if _SECRET_KEYS.search(nk):
                reasons.append(Reason("config_secret_key", loc, "key names a target/provider secret or privileged credential"))
            elif _INTERNAL_KEYS.search(nk):
                reasons.append(Reason("config_internal_key", loc, "key names a target-internal resource (internal API, log connector, dashboard, source, DB record)"))
            elif _BENCHMARK_KEYS.search(nk):
                reasons.append(Reason("config_benchmark_key", loc, "key names benchmark ground truth / flaw hint / scenario metadata"))
            reasons.extend(scan_for_forbidden(value, location=loc, _depth=_depth + 1))
    elif isinstance(obj, (list, tuple)):
        for i, item in enumerate(obj):
            reasons.extend(scan_for_forbidden(item, location=f"{location}[{i}]", _depth=_depth + 1))
    elif isinstance(obj, str):
        reasons.extend(scan_string(obj, location))
    return reasons


def check_headers(headers: Mapping[str, str] | None, cookies: Mapping[str, str] | None = None) -> list[Reason]:
    """Reject privileged/impersonation headers and cookies and secret-looking values (custom_headers + session cookies)."""
    reasons: list[Reason] = []
    for name, value in (headers or {}).items():
        lowered = str(name).strip().lower()
        loc = f"header:{name}"
        if _PRIVILEGED_HEADER.match(lowered):
            reasons.append(Reason("header_privileged", loc, "header is an admin/internal/service/impersonation/bypass header"))
        if lowered == "cookie":
            for pair in str(value).split(";"):
                cname, _, cvalue = pair.strip().partition("=")
                if cname and _PRIVILEGED_COOKIE.search(cname):
                    reasons.append(Reason("cookie_privileged", f"cookie:{cname}", "cookie name indicates an admin/staff/service session"))
                reasons.extend(scan_string(cvalue, f"cookie:{cname or '?'}"))
        else:
            reasons.extend(scan_string(str(value), loc))
    for cname, cvalue in (cookies or {}).items():
        if _PRIVILEGED_COOKIE.search(str(cname)):
            reasons.append(Reason("cookie_privileged", f"cookie:{cname}", "cookie name indicates an admin/staff/service session"))
        reasons.extend(scan_string(str(cvalue), f"cookie:{cname}"))
    return reasons


def validate_identity_spec(alias: str, spec: Mapping[str, Any]) -> list[Reason]:
    """An identity in the Execution Brief must be a synthetic, customer-level, role-allowlisted principal."""
    reasons: list[Reason] = []
    loc = f"identities.{alias}"
    if not isinstance(alias, str) or not _ALIAS_RE.match(alias):
        reasons.append(Reason("identity_alias_invalid", loc, "alias must match ^[a-z][a-z0-9_]{1,39}$"))
    role = str(spec.get("role", "")).strip().lower()
    if role not in ALLOWED_ROLES:
        reasons.append(Reason("identity_role_not_customer_level", f"{loc}.role", f"role must be one of {sorted(ALLOWED_ROLES)} (admin/staff/service/infrastructure principals are never permitted)"))
    if spec.get("synthetic") is not True:
        reasons.append(Reason("identity_not_attested_synthetic", f"{loc}.synthetic", "identity must be attested synthetic (synthetic: true)"))
    env_name = spec.get("token_env")
    if env_name is not None and (not isinstance(env_name, str) or not re.match(r"^[A-Z][A-Z0-9_]{2,63}$", env_name) or _ENV_NAME_FORBIDDEN.search(env_name)):
        reasons.append(Reason("identity_token_env_invalid", f"{loc}.token_env", "token_env must name an environment variable holding a customer-level token (no ADMIN/ROOT/SERVICE/DB/SECRET/PASSWORD names)"))
    if "token" in spec:
        reasons.append(Reason("identity_inline_token", f"{loc}.token", "tokens are never stored in the brief; reference an environment variable via token_env"))
    reasons.extend(scan_for_forbidden(dict(spec), location=loc))
    return reasons


def assert_clean(reasons: list[Reason]) -> None:
    if reasons:
        raise CredentialRejected(reasons)
