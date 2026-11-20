"""Dependency-free pattern-matching primitives for spotting leaked
secrets, credential-shaped tokens, payment-card numbers, injection
artifacts, and security misconfigurations in response bodies.

Deliberately has NO imports beyond the stdlib (re, json, typing): this is
a leaf module two different parts of the codebase build on --
app.testing.discovery.analyzers' retrospective sensitive-data scan, and
benchmark.llm_replacement_layer's zero-shot pass -- and the second of
those exists specifically to be fast and offline.

Massively expanded with detection patterns from PayloadsAllTheThings,
BugHunter, Cloudflare security-audit-skill, Shannon, and sapper-v2.
"""
from __future__ import annotations

import json
import re
from typing import Any

# ---------------------------------------------------------------------------
# 1. SECRET / CREDENTIAL PATTERNS
# ---------------------------------------------------------------------------

SECRET_PATTERNS: list[tuple[str, re.Pattern[str], bool]] = [
    # Payment / Stripe
    ("stripe_live_secret_key", re.compile(r"sk_live_[A-Za-z0-9]{10,}"), True),
    ("stripe_live_restricted_key", re.compile(r"rk_live_[A-Za-z0-9]{10,}"), True),
    ("stripe_live_publishable_key", re.compile(r"pk_live_[A-Za-z0-9]{10,}"), False),
    ("stripe_webhook_secret", re.compile(r"whsec_[A-Za-z0-9]{10,}"), True),
    # AWS
    ("aws_access_key_id", re.compile(r"AKIA[0-9A-Z]{16}"), True),
    ("aws_secret_access_key", re.compile(r"(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*[A-Za-z0-9/+=]{40}"), True),
    ("aws_session_token", re.compile(r"(?:aws_session_token|AWS_SESSION_TOKEN)\s*[=:]\s*[A-Za-z0-9/+=]{100,}"), True),
    # Private keys
    ("pem_private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"), True),
    ("pgp_private_key", re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"), True),
    # Tokens
    ("jwt_shaped_token", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), False),
    ("bearer_token_in_body", re.compile(r'["\']?(?:bearer|token|authorization)["\']?\s*[:=]\s*["\']?[A-Za-z0-9._-]{20,}', re.I), False),
    # Google / GCP
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z_-]{35}"), True),
    ("google_oauth_client_secret", re.compile(r'"client_secret"\s*:\s*"[A-Za-z0-9_-]{24}"'), True),
    ("gcp_service_account", re.compile(r'"type"\s*:\s*"service_account"'), True),
    # GitHub
    ("github_personal_token", re.compile(r"ghp_[A-Za-z0-9]{36}"), True),
    ("github_oauth_token", re.compile(r"gho_[A-Za-z0-9]{36}"), True),
    ("github_app_token", re.compile(r"ghu_[A-Za-z0-9]{36}"), True),
    ("github_fine_grained", re.compile(r"github_pat_[A-Za-z0-9_]{22,}"), True),
    # Slack
    ("slack_bot_token", re.compile(r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}"), True),
    ("slack_user_token", re.compile(r"xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-z0-9]{32}"), True),
    ("slack_webhook_url", re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"), True),
    # Azure / Microsoft
    ("azure_storage_key", re.compile(r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{86,}"), True),
    ("azure_connection_string", re.compile(r"(?:AccountKey|SharedAccessKey)=[A-Za-z0-9+/=]{40,}"), True),
    # Database
    ("database_url_with_password", re.compile(r"(?:postgres|mysql|mongodb|redis|amqp)(?:ql)?://[^:]+:[^@]+@[^/\s]+", re.I), True),
    ("connection_string_password", re.compile(r"(?:password|pwd)\s*=\s*[^\s;]{8,}", re.I), True),
    # Twilio / SendGrid / Mailgun
    ("twilio_api_key", re.compile(r"SK[0-9a-fA-F]{32}"), False),
    ("sendgrid_api_key", re.compile(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"), True),
    ("mailgun_api_key", re.compile(r"key-[A-Za-z0-9]{32}"), True),
    # Heroku / Vercel / Netlify
    ("heroku_api_key", re.compile(r"(?:heroku_api_key|HEROKU_API_KEY)\s*[=:]\s*[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I), True),
    # SSH
    ("ssh_private_key_content", re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"), True),
    # Generic high-entropy secrets
    ("generic_api_key_assignment", re.compile(r'(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token)\s*[=:]\s*["\']?[A-Za-z0-9+/=_-]{20,}', re.I), False),
]


# ---------------------------------------------------------------------------
# 2. SENSITIVE FIELD NAMES
# ---------------------------------------------------------------------------

SENSITIVE_FIELD_NAME_RE = re.compile(
    r"(password|passwd|secret|private_key|api_key|apikey|access_key|"
    r"secret_key|auth_token|refresh_token|session_token|"
    r"cvv|cvc|card_number|credit_card|ssn|social_security|"
    r"pin_code|security_code|tax_id|bank_account|routing_number|"
    r"private_key|encryption_key|master_key|signing_key)",
    re.IGNORECASE,
)
KNOWN_TEST_VALUES = {"tok_test_visa_valid"}


# ---------------------------------------------------------------------------
# 3. CARD NUMBER DETECTION
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# 4. INJECTION ARTIFACT PATTERNS (PayloadsAllTheThings)
#
# These detect REFLECTED / ECHOED payload artifacts in already-collected
# response bodies -- NOT actual payloads. Finding these in a response
# means the target processed user input unsafely.
# ---------------------------------------------------------------------------

SQL_INJECTION_ARTIFACTS: list[tuple[str, re.Pattern[str]]] = [
    ("sql_error_generic", re.compile(r"(?:SQL\s*syntax|mysql_fetch|pg_query|sqlite3?\.|ORA-\d{5})", re.I)),
    ("sql_error_mssql", re.compile(r"(?:Unclosed quotation mark|quoted string not properly terminated|Microsoft.*ODBC|SQL\s*Server)", re.I)),
    ("sql_error_postgres", re.compile(r"(?:ERROR:\s+syntax error at or near|PSQLException|invalid input syntax for)", re.I)),
    ("sql_error_mysql", re.compile(r"(?:You have an error in your SQL syntax|mysql_num_rows|mysql_result|mysql_connect)", re.I)),
    ("sql_error_sqlite", re.compile(r"(?:SQLITE_ERROR|sqlite3\.OperationalError|near \"[^\"]+\": syntax error)", re.I)),
    ("sql_error_oracle", re.compile(r"(?:ORA-\d{5}|quoted identifier|PLS-\d{5})", re.I)),
    ("union_select_echo", re.compile(r"UNION\s+(?:ALL\s+)?SELECT\s", re.I)),
    ("stacked_query_echo", re.compile(r";\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\s", re.I)),
    ("boolean_blind_indicator", re.compile(r"'\s*(?:AND|OR)\s+(?:'?\d+'?\s*=\s*'?\d+'?)", re.I)),
    ("time_blind_indicator", re.compile(r"(?:SLEEP\s*\(\s*\d+|WAITFOR\s+DELAY|pg_sleep|BENCHMARK\s*\()", re.I)),
    ("orm_error", re.compile(r"(?:ActiveRecord|Sequelize|Prisma|TypeORM|Hibernate|SQLAlchemy|Doctrine).*(?:Error|Exception)", re.I)),
]

XSS_ARTIFACTS: list[tuple[str, re.Pattern[str]]] = [
    ("script_tag_echo", re.compile(r"<script[^>]*>[^<]*(?:alert|prompt|confirm|document\.|window\.)", re.I)),
    ("event_handler_echo", re.compile(r"(?:on(?:error|load|click|mouseover|focus|blur|mouseout|change|submit|keyup|keydown))\s*=", re.I)),
    ("svg_xss_echo", re.compile(r"<svg[^>]*\s+on\w+\s*=", re.I)),
    ("img_xss_echo", re.compile(r"<img[^>]*\s+(?:onerror|onload)\s*=", re.I)),
    ("javascript_uri_echo", re.compile(r"javascript\s*:", re.I)),
    ("dom_clobbering", re.compile(r'(?:id|name)\s*=\s*["\']?(?:__proto__|constructor|toString|valueOf)', re.I)),
    ("template_injection", re.compile(r"(?:\$\{[^}]*\}|\{\{[^}]*\}\}|<%[^%]*%>)", re.I)),
]

COMMAND_INJECTION_ARTIFACTS: list[tuple[str, re.Pattern[str]]] = [
    ("shell_output", re.compile(r"(?:uid=\d+\(\w+\)|root:x:0:0:|/bin/(?:bash|sh)|total\s+\d+\s+drwx)", re.I)),
    ("backtick_echo", re.compile(r"`[^`]+`")),
    ("pipe_chain_echo", re.compile(r"\|\s*(?:cat|ls|id|whoami|curl|wget|nc|ncat|base64|python|perl|ruby)\b")),
    ("env_var_echo", re.compile(r"\$\{?(?:HOME|PATH|USER|SHELL|IFS|PWD)\}?")),
    ("os_command_echo", re.compile(r"(?:exec\s*\(|system\s*\(|popen\s*\(|proc_open|passthru)\s*\(", re.I)),
]

PATH_TRAVERSAL_ARTIFACTS: list[tuple[str, re.Pattern[str]]] = [
    ("dot_dot_echo", re.compile(r"(?:\.\./){2,}|(?:%2e%2e(?:%2f|/))+|(?:\.\.\\){2,}", re.I)),
    ("etc_passwd_content", re.compile(r"root:.*:0:0:|nobody:.*:65534:")),
    ("windows_system_file", re.compile(r"(?:\[boot loader\]|\[operating systems\]|boot\.ini|\[extensions\])", re.I)),
    ("web_config_content", re.compile(r"<(?:web-app|configuration|connectionStrings)", re.I)),
    ("null_byte_echo", re.compile(r"%00|\\x00")),
]

SSRF_ARTIFACTS: list[tuple[str, re.Pattern[str]]] = [
    ("internal_ip_echo", re.compile(r"(?:127\.0\.0\.1|0\.0\.0\.0|localhost|::1|169\.254\.169\.254)", re.I)),
    ("cloud_metadata_echo", re.compile(r"(?:ami-[0-9a-f]+|i-[0-9a-f]+|arn:aws|instance-id|availability-zone|meta-data|computeMetadata)", re.I)),
    ("internal_network_echo", re.compile(r"http://(?:10\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+|192\.168\.\d+)\.\d+", re.I)),
    ("gopher_echo", re.compile(r"gopher://", re.I)),
    ("file_scheme_echo", re.compile(r"file://(?:/etc/|/proc/|C:\\)", re.I)),
    ("dns_rebinding_indicator", re.compile(r"(?:1u\.ms|nip\.io|sslip\.io|xip\.io|localtest\.me)", re.I)),
]

DESERIALIZATION_ARTIFACTS: list[tuple[str, re.Pattern[str]]] = [
    ("java_deser_magic", re.compile(r"(?:rO0AB|ACED0005)", re.I)),
    ("java_gadget_class", re.compile(r"(?:InvokerTransformer|CommonsCollections|ChainedTransformer|ConstantTransformer|Runtime\.getRuntime)", re.I)),
    ("php_deser_magic", re.compile(r'(?:O:\d+:"[^"]+"|a:\d+:\{|s:\d+:")', re.I)),
    ("python_pickle_magic", re.compile(r"(?:__reduce__|pickle\.loads|cPickle|_reconstructor|gASV)", re.I)),
    ("dotnet_viewstate", re.compile(r"(?:__VIEWSTATE|__EVENTVALIDATION)\s*(?:=|value=)", re.I)),
    ("yaml_deser", re.compile(r"(?:!!python/object|!!ruby/object|!!java\.)", re.I)),
    ("ruby_marshal", re.compile(r"(?:Marshal\.load|ERB\.new|YAML\.load)", re.I)),
]

FILE_UPLOAD_ARTIFACTS: list[tuple[str, re.Pattern[str]]] = [
    ("php_shell_indicator", re.compile(r"(?:<\?php|<\?=|\beval\s*\(|\bsystem\s*\(|\bexec\s*\(|\bpassthru\s*\()", re.I)),
    ("webshell_indicator", re.compile(r"(?:c99shell|r57shell|webshell|cmdshell|FilesMan|WSO\s)", re.I)),
    ("htaccess_injection", re.compile(r"(?:AddType\s+application/x-httpd-php|SetHandler\s+application/x-httpd-php)", re.I)),
    ("polyglot_header", re.compile(r"(?:GIF89a|GIF87a|\x89PNG|JFIF)", re.I)),
    ("svg_script_injection", re.compile(r"<svg[^>]*>.*?<script", re.I | re.S)),
    ("exif_injection", re.compile(r"(?:DocumentName|ImageDescription|UserComment)\s*=\s*.*(?:<script|on\w+=)", re.I)),
]

OPEN_REDIRECT_ARTIFACTS: list[tuple[str, re.Pattern[str]]] = [
    ("redirect_param_echo", re.compile(r"(?:redirect_uri|return_url|next|continue|goto|dest|destination|redir|return_to|callback_url|forward|target_url)\s*[=:]\s*[\"']?https?://", re.I)),
    ("protocol_relative_echo", re.compile(r"(?:redirect|location|url)\s*[=:]\s*[\"']?//[^/]", re.I)),
    ("javascript_redirect", re.compile(r"(?:window\.location|document\.location|location\.href)\s*=", re.I)),
]

GRAPHQL_ABUSE_ARTIFACTS: list[tuple[str, re.Pattern[str]]] = [
    ("introspection_result", re.compile(r"(?:__schema|__type|queryType|mutationType|subscriptionType)", re.I)),
    ("graphql_error_verbose", re.compile(r"(?:GraphQL\s+(?:error|validation)|Cannot query field|Did you mean)", re.I)),
    ("batch_query_echo", re.compile(r"\[\s*\{.*?\"query\".*?\{.*?\"query\"", re.I | re.S)),
]

CORS_ARTIFACTS: list[tuple[str, re.Pattern[str]]] = [
    ("wildcard_origin", re.compile(r"access-control-allow-origin:\s*\*", re.I)),
    ("null_origin", re.compile(r"access-control-allow-origin:\s*null", re.I)),
    ("reflected_origin", re.compile(r"access-control-allow-origin:\s*https?://", re.I)),
    ("credentials_with_cors", re.compile(r"access-control-allow-credentials:\s*true", re.I)),
]

JWT_ABUSE_ARTIFACTS: list[tuple[str, re.Pattern[str]]] = [
    ("alg_none", re.compile(r'"alg"\s*:\s*"(?:none|None|NONE|nOnE)"')),
    ("hs256_confusion", re.compile(r'"alg"\s*:\s*"HS256".*?"(?:kty|n|e)"\s*:', re.I | re.S)),
    ("expired_token_accepted", re.compile(r'"exp"\s*:\s*(\d{10})')),
    ("jwt_secret_weak", re.compile(r'"(?:kid|jku|x5u)"\s*:\s*"', re.I)),
]

RACE_CONDITION_ARTIFACTS: list[tuple[str, re.Pattern[str]]] = [
    ("duplicate_creation", re.compile(r"(?:duplicate|already exists|unique constraint|conflict)", re.I)),
    ("stale_read", re.compile(r"(?:stale|outdated|version conflict|optimistic lock)", re.I)),
    ("double_charge", re.compile(r"(?:already (?:paid|charged|processed)|duplicate (?:payment|transaction|charge))", re.I)),
]

BUSINESS_LOGIC_ARTIFACTS: list[tuple[str, re.Pattern[str]]] = [
    ("negative_value_accepted", re.compile(r'"(?:amount|price|total|quantity|balance)":\s*-\d+')),
    ("zero_price_accepted", re.compile(r'"(?:amount|price|total|cost)":\s*(?:0(?:\.0+)?)\b')),
    ("state_bypass", re.compile(r"(?:invalid state|illegal transition|state machine|workflow violation)", re.I)),
    ("discount_overflow", re.compile(r'"(?:discount|percent_off)":\s*(?:1\d\d|[2-9]\d\d|\d{4,})')),
    ("free_premium_feature", re.compile(r'"(?:plan|tier|subscription)":\s*"(?:premium|enterprise|pro|unlimited)".*?"(?:amount|price)":\s*0', re.I | re.S)),
]

HEADER_SECURITY_PATTERNS: list[tuple[str, str]] = [
    ("missing_csp", "content-security-policy"),
    ("missing_hsts", "strict-transport-security"),
    ("missing_x_frame_options", "x-frame-options"),
    ("missing_x_content_type", "x-content-type-options"),
    ("missing_referrer_policy", "referrer-policy"),
    ("missing_permissions_policy", "permissions-policy"),
]


# ---------------------------------------------------------------------------
# 5. INFO DISCLOSURE PATTERNS (enhanced from security_scan.py)
# ---------------------------------------------------------------------------

INFO_DISCLOSURE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("stack_trace_python", re.compile(r"Traceback \(most recent call last\)", re.I)),
    ("stack_trace_java", re.compile(r"^\s*at\s+[\w.$]+\s*\([^)]*\)", re.MULTILINE)),
    ("stack_trace_node", re.compile(r"at\s+(?:Object\.|Module\.|Function\.)?[\w.]+\s+\([^)]*\.js:\d+:\d+\)")),
    ("stack_trace_dotnet", re.compile(r"(?:System\.Exception|NullReferenceException|ArgumentException).*at\s+\w+", re.I | re.S)),
    ("file_path_unix", re.compile(r"(?:/usr/|/home/[\w-]+/|/var/www|/opt/[\w./-]+|/etc/[\w./-]+|/proc/self)")),
    ("file_path_windows", re.compile(r"[A-Za-z]:\\(?:Users|Windows|Program Files|inetpub)\\", re.I)),
    ("debug_mode_indicator", re.compile(r"(?:DEBUG\s*=\s*True|FLASK_DEBUG|NODE_ENV\s*[=:]\s*development|WP_DEBUG)", re.I)),
    ("database_error_detail", re.compile(r"\b(?:SQLSTATE|duplicate key value violates|syntax error at or near|near \"\w+\": syntax error)\b", re.I)),
    ("framework_debug_page", re.compile(r"\b(?:Django Version|Werkzeug Debugger|WSGIRequest|Whoops|Laravel\\|Symfony\\|__CakePHP)\b")),
    ("internal_ip_leak", re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b")),
    ("aws_internal_hostname", re.compile(r"\bip-10-\d{1,3}-\d{1,3}-\d{1,3}\b|\.(?:internal|local|corp|intra)\b(?!\w)")),
    ("git_exposure", re.compile(r"(?:\.git/config|\.git/HEAD|refs/heads/|commit [0-9a-f]{40})", re.I)),
    ("env_file_exposure", re.compile(r"(?:DB_PASSWORD|DATABASE_URL|SECRET_KEY|STRIPE_SECRET_KEY|AWS_ACCESS_KEY_ID)\s*=", re.I)),
    ("docker_exposure", re.compile(r"(?:docker(?:file|compose)|\.dockerignore|container_name|DOCKER_HOST)", re.I)),
    ("kubernetes_exposure", re.compile(r"(?:apiVersion:\s*v\d+|kind:\s*(?:Pod|Service|Deployment)|kubectl|kube-system)", re.I)),
    ("version_disclosure", re.compile(r"(?:(?:nginx|apache|php|node|express|django|flask|rails|spring|tomcat|gunicorn)[/\s]*v?[\d.]+)", re.I)),
]


# ---------------------------------------------------------------------------
# 6. HELPER FUNCTIONS
# ---------------------------------------------------------------------------

def body_as_text(body: Any) -> str:
    if isinstance(body, str):
        return body
    try:
        return json.dumps(body, default=str)
    except (TypeError, ValueError):
        return str(body)


def scan_field_names(body: Any, path: str = "") -> list[tuple[str, str, Any]]:
    """Recursively finds sensitively-named fields (password, api_key,
    cvv, ...) carrying a real (non-empty, non-redacted, non-test) value."""
    hits: list[tuple[str, str, Any]] = []
    if isinstance(body, dict):
        for key, value in body.items():
            field_path = f"{path}.{key}" if path else key
            if SENSITIVE_FIELD_NAME_RE.search(key) and value not in (None, "", "***", "REDACTED", "[FILTERED]", "********") and value not in KNOWN_TEST_VALUES:
                hits.append((field_path, key, value))
            hits.extend(scan_field_names(value, field_path))
    elif isinstance(body, list):
        for index, item in enumerate(body):
            hits.extend(scan_field_names(item, f"{path}[{index}]"))
    return hits


def scan_injection_artifacts(text: str) -> list[tuple[str, str, str]]:
    """Scans text for injection artifact reflections across all categories.
    Returns (category, pattern_name, matched_snippet) tuples."""
    all_patterns = [
        ("sqli", SQL_INJECTION_ARTIFACTS),
        ("xss", XSS_ARTIFACTS),
        ("cmd_injection", COMMAND_INJECTION_ARTIFACTS),
        ("path_traversal", PATH_TRAVERSAL_ARTIFACTS),
        ("ssrf", SSRF_ARTIFACTS),
        ("deserialization", DESERIALIZATION_ARTIFACTS),
        ("file_upload", FILE_UPLOAD_ARTIFACTS),
        ("open_redirect", OPEN_REDIRECT_ARTIFACTS),
        ("graphql_abuse", GRAPHQL_ABUSE_ARTIFACTS),
        ("jwt_abuse", JWT_ABUSE_ARTIFACTS),
        ("race_condition", RACE_CONDITION_ARTIFACTS),
        ("business_logic", BUSINESS_LOGIC_ARTIFACTS),
    ]
    findings: list[tuple[str, str, str]] = []
    for category, patterns in all_patterns:
        for name, pattern in patterns:
            match = pattern.search(text)
            if match:
                start = max(0, match.start() - 20)
                end = min(len(text), match.end() + 40)
                findings.append((category, name, text[start:end].strip()))
    return findings


def scan_header_security(headers: dict[str, str]) -> list[tuple[str, str]]:
    """Checks response headers for missing security headers.
    Returns (issue_name, missing_header) tuples."""
    issues: list[tuple[str, str]] = []
    lower_headers = {k.lower(): v for k, v in headers.items()}
    for issue_name, header_name in HEADER_SECURITY_PATTERNS:
        if header_name not in lower_headers:
            issues.append((issue_name, header_name))
    return issues


def headers_as_text(headers: dict[str, str]) -> str:
    """Converts a header dict to a text representation for pattern matching."""
    return "\n".join(f"{k}: {v}" for k, v in headers.items())
