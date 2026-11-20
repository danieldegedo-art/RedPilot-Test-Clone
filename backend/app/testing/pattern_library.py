"""Dependency-free pattern-matching primitives for spotting leaked
secrets, credential-shaped tokens, payment-card numbers, injection
artifacts, and security misconfigurations in response bodies.

Deliberately has NO imports beyond the stdlib (re, json, typing, math):
this is a leaf module two different parts of the codebase build on --
app.testing.discovery.analyzers' retrospective sensitive-data scan, and
benchmark.llm_replacement_layer's zero-shot pass -- and the second of
those exists specifically to be fast and offline.

Massively expanded with detection patterns from PayloadsAllTheThings,
BugHunter, Cloudflare security-audit-skill, Shannon, sapper-v2,
Awesome-Hacking, SecLists, and HackTricks.

Pattern categories:
  1.  Secret / credential patterns (55+)
  2.  Sensitive field names
  3.  Card number detection
  4.  Injection artifact patterns (12 original + 13 new categories)
  5.  Info disclosure patterns
  6.  Reverse engineering artifacts
  7.  Rate limit bypass indicators
  8.  Subscription / payment abuse artifacts
  9.  Webhook security artifacts
  10. Captcha bypass indicators
  11. Helper functions (original + 6 new)
"""
from __future__ import annotations

import json
import math
import re
from typing import Any


# ===================================================================
# 1. SECRET / CREDENTIAL PATTERNS
#
# Tuple: (name, compiled_pattern, is_critical)
# "critical" means the secret could directly grant access to production
# resources; non-critical are informational / lower-risk.
# ===================================================================

SECRET_PATTERNS: list[tuple[str, re.Pattern[str], bool]] = [
    # ---------------------------------------------------------------
    # Payment / Stripe
    # ---------------------------------------------------------------
    ("stripe_live_secret_key", re.compile(r"sk_live_[A-Za-z0-9]{10,}"), True),
    ("stripe_live_restricted_key", re.compile(r"rk_live_[A-Za-z0-9]{10,}"), True),
    ("stripe_live_publishable_key", re.compile(r"pk_live_[A-Za-z0-9]{10,}"), False),
    ("stripe_webhook_secret", re.compile(r"whsec_[A-Za-z0-9]{10,}"), True),
    ("stripe_test_secret_key", re.compile(r"sk_test_[A-Za-z0-9]{10,}"), False),
    ("stripe_test_publishable_key", re.compile(r"pk_test_[A-Za-z0-9]{10,}"), False),
    ("stripe_test_webhook_secret", re.compile(r"whsec_test_[A-Za-z0-9]{10,}"), False),
    ("stripe_connect_account", re.compile(r"acct_[A-Za-z0-9]{16,}"), False),
    # PayPal
    ("paypal_access_token", re.compile(r"access_token\$(?:production|sandbox)\$[A-Za-z0-9]{16,}"), True),
    ("paypal_client_secret", re.compile(r"(?:paypal[_-]?(?:client[_-]?)?secret|PAYPAL_SECRET)\s*[=:]\s*[A-Za-z0-9_-]{20,}", re.I), True),
    # Square
    ("square_access_token", re.compile(r"sq0atp-[A-Za-z0-9_-]{22,}"), True),
    ("square_oauth_secret", re.compile(r"sq0csp-[A-Za-z0-9_-]{40,}"), True),
    # Braintree
    ("braintree_access_token", re.compile(r"access_token\$production\$[a-z0-9]{16}"), True),
    # Adyen
    ("adyen_api_key", re.compile(r"AQE[a-z0-9]{5,}\.[A-Za-z0-9_-]{30,}"), True),
    # Shopify
    ("shopify_private_app_token", re.compile(r"shppa_[A-Fa-f0-9]{32}"), True),
    ("shopify_access_token", re.compile(r"shpat_[A-Fa-f0-9]{32}"), True),
    ("shopify_custom_app_token", re.compile(r"shpca_[A-Fa-f0-9]{32}"), True),
    ("shopify_shared_secret", re.compile(r"shpss_[A-Fa-f0-9]{32}"), True),
    # Plaid
    ("plaid_client_id", re.compile(r"(?:plaid[_-]?client[_-]?id|PLAID_CLIENT_ID)\s*[=:]\s*[a-z0-9]{24}", re.I), True),
    ("plaid_secret", re.compile(r"(?:plaid[_-]?secret|PLAID_SECRET)\s*[=:]\s*[a-z0-9]{30}", re.I), True),
    # Coinbase
    ("coinbase_api_key", re.compile(r"(?:coinbase[_-]?api[_-]?(?:key|secret)|COINBASE_API_)\s*[=:]\s*[A-Za-z0-9]{16,}", re.I), True),

    # ---------------------------------------------------------------
    # Cloud / Infrastructure
    # ---------------------------------------------------------------
    # AWS
    ("aws_access_key_id", re.compile(r"AKIA[0-9A-Z]{16}"), True),
    ("aws_secret_access_key", re.compile(r"(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*[A-Za-z0-9/+=]{40}"), True),
    ("aws_session_token", re.compile(r"(?:aws_session_token|AWS_SESSION_TOKEN)\s*[=:]\s*[A-Za-z0-9/+=]{100,}"), True),
    # Google / GCP
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z_-]{35}"), True),
    ("google_oauth_client_secret", re.compile(r'"client_secret"\s*:\s*"[A-Za-z0-9_-]{24}"'), True),
    ("gcp_service_account", re.compile(r'"type"\s*:\s*"service_account"'), True),
    ("firebase_config_key", re.compile(r"(?:firebase|FIREBASE)[_-]?(?:API_KEY|apiKey)\s*[=:]\s*AIza[0-9A-Za-z_-]{35}", re.I), True),
    # Azure / Microsoft
    ("azure_storage_key", re.compile(r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{86,}"), True),
    ("azure_connection_string", re.compile(r"(?:AccountKey|SharedAccessKey)=[A-Za-z0-9+/=]{40,}"), True),
    ("azure_client_secret", re.compile(r"(?:AZURE_CLIENT_SECRET|azure[_-]client[_-]secret)\s*[=:]\s*[A-Za-z0-9~._-]{34,}", re.I), True),
    # DigitalOcean
    ("digitalocean_token", re.compile(r"dop_v1_[a-f0-9]{64}"), True),
    ("digitalocean_oauth", re.compile(r"doo_v1_[a-f0-9]{64}"), True),
    # Cloudflare
    ("cloudflare_api_token", re.compile(r"(?:cloudflare[_-]?api[_-]?token|CF_API_TOKEN)\s*[=:]\s*[A-Za-z0-9_-]{40}", re.I), True),
    ("cloudflare_global_key", re.compile(r"(?:cloudflare[_-]?api[_-]?key|CF_API_KEY)\s*[=:]\s*[a-f0-9]{37}", re.I), True),

    # ---------------------------------------------------------------
    # Private keys / Certificates
    # ---------------------------------------------------------------
    ("pem_private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"), True),
    ("pgp_private_key", re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"), True),
    ("ssh_private_key_content", re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"), True),
    ("pkcs12_base64", re.compile(r"MII[A-Za-z0-9+/]{60,}={0,2}"), False),

    # ---------------------------------------------------------------
    # Tokens / Auth
    # ---------------------------------------------------------------
    ("jwt_shaped_token", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), False),
    ("bearer_token_in_body", re.compile(r'["\']?(?:bearer|token|authorization)["\']?\s*[:=]\s*["\']?[A-Za-z0-9._-]{20,}', re.I), False),
    ("oauth2_refresh_token", re.compile(r'"refresh_token"\s*:\s*"[A-Za-z0-9._/-]{20,}"'), True),
    ("oauth2_access_token_response", re.compile(r'"access_token"\s*:\s*"[A-Za-z0-9._/-]{20,}"'), False),

    # ---------------------------------------------------------------
    # GitHub
    # ---------------------------------------------------------------
    ("github_personal_token", re.compile(r"ghp_[A-Za-z0-9]{36}"), True),
    ("github_oauth_token", re.compile(r"gho_[A-Za-z0-9]{36}"), True),
    ("github_app_token", re.compile(r"ghu_[A-Za-z0-9]{36}"), True),
    ("github_fine_grained", re.compile(r"github_pat_[A-Za-z0-9_]{22,}"), True),
    ("github_app_install_token", re.compile(r"ghs_[A-Za-z0-9]{36}"), True),

    # ---------------------------------------------------------------
    # Slack
    # ---------------------------------------------------------------
    ("slack_bot_token", re.compile(r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}"), True),
    ("slack_user_token", re.compile(r"xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-z0-9]{32}"), True),
    ("slack_webhook_url", re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"), True),
    ("slack_app_token", re.compile(r"xapp-[0-9]+-[A-Za-z0-9]+-[0-9]+-[a-z0-9]+"), True),

    # ---------------------------------------------------------------
    # Package registries
    # ---------------------------------------------------------------
    ("npm_token", re.compile(r"npm_[A-Za-z0-9]{36}"), True),
    ("pypi_token", re.compile(r"pypi-[A-Za-z0-9_-]{50,}"), True),
    ("docker_registry_token", re.compile(r"(?:docker[_-]?(?:auth|token|password)|DOCKER_(?:AUTH_CONFIG|PASSWORD))\s*[=:]\s*[A-Za-z0-9+/=_-]{20,}", re.I), True),
    ("rubygems_api_key", re.compile(r"rubygems_[a-f0-9]{48}"), True),

    # ---------------------------------------------------------------
    # Comms / Email
    # ---------------------------------------------------------------
    ("twilio_api_key", re.compile(r"SK[0-9a-fA-F]{32}"), False),
    ("sendgrid_api_key", re.compile(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"), True),
    ("mailgun_api_key", re.compile(r"key-[A-Za-z0-9]{32}"), True),

    # ---------------------------------------------------------------
    # Hosting / DevOps
    # ---------------------------------------------------------------
    ("heroku_api_key", re.compile(r"(?:heroku_api_key|HEROKU_API_KEY)\s*[=:]\s*[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I), True),
    ("vercel_token", re.compile(r"(?:vercel[_-]?token|VERCEL_TOKEN)\s*[=:]\s*[A-Za-z0-9]{24}", re.I), True),
    ("railway_token", re.compile(r"(?:railway[_-]?token|RAILWAY_TOKEN)\s*[=:]\s*[A-Za-z0-9_-]{36,}", re.I), True),
    ("terraform_cloud_token", re.compile(r"(?:TFE_TOKEN|terraform_cloud_token|atlasv1)\s*[=:]\s*[A-Za-z0-9._-]{14,}", re.I), True),

    # ---------------------------------------------------------------
    # Secrets managers
    # ---------------------------------------------------------------
    ("vault_token_service", re.compile(r"hvs\.[A-Za-z0-9_-]{24,}"), True),
    ("vault_token_batch", re.compile(r"hvb\.[A-Za-z0-9_-]{24,}"), True),
    ("vault_token_recovery", re.compile(r"hvr\.[A-Za-z0-9_-]{24,}"), True),

    # ---------------------------------------------------------------
    # Observability / Analytics
    # ---------------------------------------------------------------
    ("datadog_api_key", re.compile(r"(?:datadog[_-]?api[_-]?key|DD_API_KEY)\s*[=:]\s*[a-f0-9]{32}", re.I), True),
    ("datadog_app_key", re.compile(r"(?:datadog[_-]?app[_-]?key|DD_APP_KEY)\s*[=:]\s*[a-f0-9]{40}", re.I), True),
    ("newrelic_license_key", re.compile(r"(?:new_relic_license_key|NEWRELIC_LICENSE|NEW_RELIC_LICENSE_KEY)\s*[=:]\s*[a-f0-9]{40}", re.I), True),
    ("sentry_dsn", re.compile(r"https://[a-f0-9]{32}@(?:o\d+\.)?(?:sentry\.io|[^/]+)/\d+"), True),
    ("algolia_api_key", re.compile(r"(?:algolia[_-]?(?:api[_-]?key|admin[_-]?key)|ALGOLIA_)\s*[=:]\s*[a-f0-9]{32}", re.I), True),

    # ---------------------------------------------------------------
    # SaaS APIs
    # ---------------------------------------------------------------
    ("linear_api_key", re.compile(r"lin_api_[A-Za-z0-9]{40,}"), True),
    ("supabase_key", re.compile(r"sbp_[a-f0-9]{40,}"), True),
    ("supabase_service_role", re.compile(r"(?:SUPABASE_SERVICE_ROLE_KEY|supabase[_-]service[_-]role)\s*[=:]\s*eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", re.I), True),
    ("planetscale_token", re.compile(r"pscale_tkn_[A-Za-z0-9_-]{40,}"), True),
    ("planetscale_oauth", re.compile(r"pscale_oauth_[A-Za-z0-9_-]{40,}"), True),

    # ---------------------------------------------------------------
    # Database
    # ---------------------------------------------------------------
    ("database_url_with_password", re.compile(r"(?:postgres|mysql|mongodb|redis|amqp|cockroachdb|couchdb)(?:ql)?://[^:]+:[^@]+@[^/\s]+", re.I), True),
    ("connection_string_password", re.compile(r"(?:password|pwd)\s*=\s*[^\s;]{8,}", re.I), True),

    # ---------------------------------------------------------------
    # Generic high-entropy secrets
    # ---------------------------------------------------------------
    ("generic_api_key_assignment", re.compile(r'(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token)\s*[=:]\s*["\']?[A-Za-z0-9+/=_-]{20,}', re.I), False),
    ("generic_private_key_env", re.compile(r"(?:PRIVATE_KEY|SIGNING_KEY|ENCRYPTION_KEY|MASTER_KEY)\s*[=:]", re.I), False),
]


# ===================================================================
# 2. SENSITIVE FIELD NAMES
# ===================================================================

SENSITIVE_FIELD_NAME_RE = re.compile(
    r"(password|passwd|secret|private_key|api_key|apikey|access_key|"
    r"secret_key|auth_token|refresh_token|session_token|"
    r"cvv|cvc|card_number|credit_card|ssn|social_security|"
    r"pin_code|security_code|tax_id|bank_account|routing_number|"
    r"private_key|encryption_key|master_key|signing_key|"
    r"client_secret|webhook_secret|mfa_secret|totp_secret|"
    r"recovery_code|backup_code|passphrase|credential|"
    r"account_number|iban|swift_code|bic_code|"
    r"stripe_key|payment_token|billing_token)",
    re.IGNORECASE,
)
KNOWN_TEST_VALUES = {"tok_test_visa_valid"}


# ===================================================================
# 3. CARD NUMBER DETECTION
# ===================================================================

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


# ===================================================================
# 4. INJECTION ARTIFACT PATTERNS (PayloadsAllTheThings + HackTricks)
#
# These detect REFLECTED / ECHOED payload artifacts in already-collected
# response bodies -- NOT actual payloads.  Finding these in a response
# means the target processed user input unsafely.
# ===================================================================

# --- 4a. SQL Injection ---

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
    # --- expanded: Cassandra / CQL injection ---
    ("cql_error", re.compile(r"(?:SyntaxException|InvalidRequestException|com\.datastax\.driver)", re.I)),
    # --- expanded: GraphQL injection via query ---
    ("graphql_injection_error", re.compile(r"(?:Syntax Error.*GraphQL|Expected Name, found|Cannot query field .* on type)", re.I)),
    # --- expanded: HQL / JPQL injection ---
    ("hql_injection_error", re.compile(r"(?:org\.hibernate\.hql|unexpected token|QuerySyntaxException)", re.I)),
]

# --- 4b. XSS ---

XSS_ARTIFACTS: list[tuple[str, re.Pattern[str]]] = [
    ("script_tag_echo", re.compile(r"<script[^>]*>[^<]*(?:alert|prompt|confirm|document\.|window\.)", re.I)),
    ("event_handler_echo", re.compile(r"(?:on(?:error|load|click|mouseover|focus|blur|mouseout|change|submit|keyup|keydown))\s*=", re.I)),
    ("svg_xss_echo", re.compile(r"<svg[^>]*\s+on\w+\s*=", re.I)),
    ("img_xss_echo", re.compile(r"<img[^>]*\s+(?:onerror|onload)\s*=", re.I)),
    ("javascript_uri_echo", re.compile(r"javascript\s*:", re.I)),
    ("dom_clobbering", re.compile(r'(?:id|name)\s*=\s*["\']?(?:__proto__|constructor|toString|valueOf)', re.I)),
    ("template_injection", re.compile(r"(?:\$\{[^}]*\}|\{\{[^}]*\}\}|<%[^%]*%>)", re.I)),
    # --- expanded: mutation XSS ---
    ("mutation_xss_noscript", re.compile(r"<noscript>.*?<img", re.I | re.S)),
    ("mutation_xss_table", re.compile(r"<table[^>]*>.*?<img[^>]*on\w+=", re.I | re.S)),
    ("mutation_xss_math", re.compile(r"<math>.*?<m(?:text|annotation)", re.I | re.S)),
    # --- expanded: CSS injection ---
    ("css_injection_import", re.compile(r"@import\s+(?:url\s*\(|['\"])", re.I)),
    ("css_injection_expression", re.compile(r"(?:expression|behavior|moz-binding)\s*\(", re.I)),
    # --- expanded: dangling markup ---
    ("dangling_markup", re.compile(r"""<[a-z]+[^>]+(?:href|src|action|formaction)\s*=\s*['"]?\s*(?:$|[^>]*$)""", re.I)),
    # --- expanded: data URI XSS ---
    ("data_uri_xss", re.compile(r"data:\s*(?:text/html|application/xhtml\+xml)[;,]", re.I)),
]

# --- 4c. Command Injection ---

COMMAND_INJECTION_ARTIFACTS: list[tuple[str, re.Pattern[str]]] = [
    ("shell_output", re.compile(r"(?:uid=\d+\(\w+\)|root:x:0:0:|/bin/(?:bash|sh)|total\s+\d+\s+drwx)", re.I)),
    ("backtick_echo", re.compile(r"`[^`]+`")),
    ("pipe_chain_echo", re.compile(r"\|\s*(?:cat|ls|id|whoami|curl|wget|nc|ncat|base64|python|perl|ruby)\b")),
    ("env_var_echo", re.compile(r"\$\{?(?:HOME|PATH|USER|SHELL|IFS|PWD)\}?")),
    ("os_command_echo", re.compile(r"(?:exec\s*\(|system\s*\(|popen\s*\(|proc_open|passthru)\s*\(", re.I)),
    # --- expanded: PowerShell ---
    ("powershell_echo", re.compile(r"(?:Invoke-Expression|IEX|New-Object\s+System|Start-Process|Get-ChildItem|Set-ExecutionPolicy)", re.I)),
    ("powershell_encoded", re.compile(r"-(?:enc|EncodedCommand)\s+[A-Za-z0-9+/=]{20,}", re.I)),
    # --- expanded: Windows cmd ---
    ("windows_cmd_echo", re.compile(r"(?:Directory of [A-Z]:\\|Volume Serial Number|Microsoft Windows \[Version)", re.I)),
    ("windows_cmd_chain", re.compile(r"(?:cmd\.exe|command\.com|%comspec%|&\s*(?:dir|type|net\s+user|tasklist))", re.I)),
]

# --- 4d. Path Traversal ---

PATH_TRAVERSAL_ARTIFACTS: list[tuple[str, re.Pattern[str]]] = [
    ("dot_dot_echo", re.compile(r"(?:\.\./){2,}|(?:%2e%2e(?:%2f|/))+|(?:\.\.\\){2,}", re.I)),
    ("etc_passwd_content", re.compile(r"root:.*:0:0:|nobody:.*:65534:")),
    ("windows_system_file", re.compile(r"(?:\[boot loader\]|\[operating systems\]|boot\.ini|\[extensions\])", re.I)),
    ("web_config_content", re.compile(r"<(?:web-app|configuration|connectionStrings)", re.I)),
    ("null_byte_echo", re.compile(r"%00|\\x00")),
    # --- expanded: deep encoding variants ---
    ("double_url_encoded_traversal", re.compile(r"(?:%252e%252e|%252f|%255c)", re.I)),
    ("utf8_overlong_traversal", re.compile(r"(?:%c0%ae|%c0%af|%e0%80%ae)", re.I)),
    ("proc_self_leak", re.compile(r"/proc/self/(?:environ|cmdline|status|maps|cwd|fd)", re.I)),
]

# --- 4e. SSRF ---

SSRF_ARTIFACTS: list[tuple[str, re.Pattern[str]]] = [
    ("internal_ip_echo", re.compile(r"(?:127\.0\.0\.1|0\.0\.0\.0|localhost|::1|169\.254\.169\.254)", re.I)),
    ("cloud_metadata_echo", re.compile(r"(?:ami-[0-9a-f]+|i-[0-9a-f]+|arn:aws|instance-id|availability-zone|meta-data|computeMetadata)", re.I)),
    ("internal_network_echo", re.compile(r"http://(?:10\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+|192\.168\.\d+)\.\d+", re.I)),
    ("gopher_echo", re.compile(r"gopher://", re.I)),
    ("file_scheme_echo", re.compile(r"file://(?:/etc/|/proc/|C:\\)", re.I)),
    ("dns_rebinding_indicator", re.compile(r"(?:1u\.ms|nip\.io|sslip\.io|xip\.io|localtest\.me)", re.I)),
    # --- expanded: IPv6 bypasses ---
    ("ipv6_loopback_echo", re.compile(r"(?:\[::1\]|\[0:0:0:0:0:0:0:1\]|\[::ffff:127\.0\.0\.1\])", re.I)),
    ("ipv6_mapped_internal", re.compile(r"\[::ffff:(?:10\.\d|172\.(?:1[6-9]|2\d|3[01])|192\.168\.)", re.I)),
    # --- expanded: Azure IMDS ---
    ("azure_metadata_echo", re.compile(r"(?:169\.254\.169\.254/metadata|Metadata:\s*true|azure-instance-metadata)", re.I)),
    # --- expanded: GCP metadata ---
    ("gcp_metadata_echo", re.compile(r"(?:metadata\.google\.internal|computeMetadata/v1|X-Google-Metadata-Request)", re.I)),
    # --- expanded: URL parser differential ---
    ("url_parser_confusion", re.compile(r"(?:http://[^/]*@|http://[^/]*#.*@|\\\\[^/]+)", re.I)),
    # --- expanded: redirect-based SSRF ---
    ("redirect_ssrf_indicator", re.compile(r"(?:Location:\s*https?://(?:127\.|10\.|172\.(1[6-9]|2\d|3[01])|192\.168\.|localhost))", re.I)),
]

# --- 4f. Deserialization ---

DESERIALIZATION_ARTIFACTS: list[tuple[str, re.Pattern[str]]] = [
    ("java_deser_magic", re.compile(r"(?:rO0AB|ACED0005)", re.I)),
    ("java_gadget_class", re.compile(r"(?:InvokerTransformer|CommonsCollections|ChainedTransformer|ConstantTransformer|Runtime\.getRuntime)", re.I)),
    ("php_deser_magic", re.compile(r'(?:O:\d+:"[^"]+"|a:\d+:\{|s:\d+:")', re.I)),
    ("python_pickle_magic", re.compile(r"(?:__reduce__|pickle\.loads|cPickle|_reconstructor|gASV)", re.I)),
    ("dotnet_viewstate", re.compile(r"(?:__VIEWSTATE|__EVENTVALIDATION)\s*(?:=|value=)", re.I)),
    ("yaml_deser", re.compile(r"(?:!!python/object|!!ruby/object|!!java\.)", re.I)),
    ("ruby_marshal", re.compile(r"(?:Marshal\.load|ERB\.new|YAML\.load)", re.I)),
    # --- expanded: .NET BinaryFormatter ---
    ("dotnet_binary_formatter", re.compile(r"(?:BinaryFormatter|ObjectStateFormatter|LosFormatter|SoapFormatter)", re.I)),
    ("dotnet_gadget", re.compile(r"(?:TypeConfuseDelegate|TextFormattingRunProperties|PSObject)", re.I)),
]

# --- 4g. File Upload ---

FILE_UPLOAD_ARTIFACTS: list[tuple[str, re.Pattern[str]]] = [
    ("php_shell_indicator", re.compile(r"(?:<\?php|<\?=|\beval\s*\(|\bsystem\s*\(|\bexec\s*\(|\bpassthru\s*\()", re.I)),
    ("webshell_indicator", re.compile(r"(?:c99shell|r57shell|webshell|cmdshell|FilesMan|WSO\s)", re.I)),
    ("htaccess_injection", re.compile(r"(?:AddType\s+application/x-httpd-php|SetHandler\s+application/x-httpd-php)", re.I)),
    ("polyglot_header", re.compile(r"(?:GIF89a|GIF87a|\x89PNG|JFIF)", re.I)),
    ("svg_script_injection", re.compile(r"<svg[^>]*>.*?<script", re.I | re.S)),
    ("exif_injection", re.compile(r"(?:DocumentName|ImageDescription|UserComment)\s*=\s*.*(?:<script|on\w+=)", re.I)),
    # --- expanded: double extension ---
    ("double_extension", re.compile(r"\.\w+\.(?:php|jsp|asp|aspx|cgi|pl|py|rb|sh|exe|bat|cmd)", re.I)),
    ("content_type_mismatch", re.compile(r"Content-Type:\s*(?:image|text)/.*?\.(?:php|jsp|asp|exe)", re.I)),
]

# --- 4h. Open Redirect ---

OPEN_REDIRECT_ARTIFACTS: list[tuple[str, re.Pattern[str]]] = [
    ("redirect_param_echo", re.compile(r"(?:redirect_uri|return_url|next|continue|goto|dest|destination|redir|return_to|callback_url|forward|target_url)\s*[=:]\s*[\"']?https?://", re.I)),
    ("protocol_relative_echo", re.compile(r"(?:redirect|location|url)\s*[=:]\s*[\"']?//[^/]", re.I)),
    ("javascript_redirect", re.compile(r"(?:window\.location|document\.location|location\.href)\s*=", re.I)),
    # --- expanded: backslash trick ---
    ("backslash_redirect", re.compile(r"(?:redirect|location|url)\s*[=:]\s*[\"']?/\\\\", re.I)),
    ("encoded_redirect", re.compile(r"(?:redirect|location|url)\s*[=:]\s*[\"']?%2f%2f", re.I)),
]

# --- 4i. GraphQL Abuse ---

GRAPHQL_ABUSE_ARTIFACTS: list[tuple[str, re.Pattern[str]]] = [
    ("introspection_result", re.compile(r"(?:__schema|__type|queryType|mutationType|subscriptionType)", re.I)),
    ("graphql_error_verbose", re.compile(r"(?:GraphQL\s+(?:error|validation)|Cannot query field|Did you mean)", re.I)),
    ("batch_query_echo", re.compile(r"\[\s*\{.*?\"query\".*?\{.*?\"query\"", re.I | re.S)),
    # --- expanded: alias-based batching ---
    ("graphql_alias_batching", re.compile(r'"(?:alias_?\d+|a\d+|q\d+)":\s*\{', re.I)),
    ("graphql_depth_exceeded", re.compile(r"(?:maximum query depth|query complexity|max.*depth.*exceeded)", re.I)),
    ("graphql_field_suggestion", re.compile(r"Did you mean.*?\"(\w+)\"", re.I)),
]

# --- 4j. CORS ---

CORS_ARTIFACTS: list[tuple[str, re.Pattern[str]]] = [
    ("wildcard_origin", re.compile(r"access-control-allow-origin:\s*\*", re.I)),
    ("null_origin", re.compile(r"access-control-allow-origin:\s*null", re.I)),
    ("reflected_origin", re.compile(r"access-control-allow-origin:\s*https?://", re.I)),
    ("credentials_with_cors", re.compile(r"access-control-allow-credentials:\s*true", re.I)),
    # --- expanded ---
    ("cors_vary_missing", re.compile(r"access-control-allow-origin:(?!.*Vary:\s*Origin)", re.I | re.S)),
    ("cors_preflight_cache_long", re.compile(r"access-control-max-age:\s*(?:[1-9]\d{5,}|86[5-9]\d{2})", re.I)),
]

# --- 4k. JWT Abuse ---

JWT_ABUSE_ARTIFACTS: list[tuple[str, re.Pattern[str]]] = [
    ("alg_none", re.compile(r'"alg"\s*:\s*"(?:none|None|NONE|nOnE)"')),
    ("hs256_confusion", re.compile(r'"alg"\s*:\s*"HS256".*?"(?:kty|n|e)"\s*:', re.I | re.S)),
    ("expired_token_accepted", re.compile(r'"exp"\s*:\s*(\d{10})')),
    ("jwt_secret_weak", re.compile(r'"(?:kid|jku|x5u)"\s*:\s*"', re.I)),
    # --- expanded ---
    ("jwt_missing_signature", re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.\s*$")),
    ("jwt_jwk_injection", re.compile(r'"jwk"\s*:\s*\{', re.I)),
    ("jwt_embedded_key", re.compile(r'"(?:x5c|x5u)"\s*:\s*[\["]', re.I)),
]

# --- 4l. Race Condition ---

RACE_CONDITION_ARTIFACTS: list[tuple[str, re.Pattern[str]]] = [
    ("duplicate_creation", re.compile(r"(?:duplicate|already exists|unique constraint|conflict)", re.I)),
    ("stale_read", re.compile(r"(?:stale|outdated|version conflict|optimistic lock)", re.I)),
    ("double_charge", re.compile(r"(?:already (?:paid|charged|processed)|duplicate (?:payment|transaction|charge))", re.I)),
    # --- expanded ---
    ("toctou_indicator", re.compile(r"(?:resource changed|concurrent modification|retry.*conflict|CAS.*failed)", re.I)),
    ("counter_overflow", re.compile(r"(?:counter.*(?:overflow|underflow|negative)|balance.*negative|insufficient.*after)", re.I)),
]

# --- 4m. Business Logic ---

BUSINESS_LOGIC_ARTIFACTS: list[tuple[str, re.Pattern[str]]] = [
    ("negative_value_accepted", re.compile(r'"(?:amount|price|total|quantity|balance)":\s*-\d+')),
    ("zero_price_accepted", re.compile(r'"(?:amount|price|total|cost)":\s*(?:0(?:\.0+)?)\b')),
    ("state_bypass", re.compile(r"(?:invalid state|illegal transition|state machine|workflow violation)", re.I)),
    ("discount_overflow", re.compile(r'"(?:discount|percent_off)":\s*(?:1\d\d|[2-9]\d\d|\d{4,})')),
    ("free_premium_feature", re.compile(r'"(?:plan|tier|subscription)":\s*"(?:premium|enterprise|pro|unlimited)".*?"(?:amount|price)":\s*0', re.I | re.S)),
    # --- expanded ---
    ("coupon_stack_indicator", re.compile(r'"(?:coupons?|promotions?|discounts?)":\s*\[.*?,.*?\]', re.I | re.S)),
    ("negative_quantity", re.compile(r'"(?:quantity|qty|count)":\s*-\d+')),
    ("exceeds_limit", re.compile(r'"(?:quantity|qty|count)":\s*(?:\d{6,}|99999)', re.I)),
    ("currency_mismatch", re.compile(r'"currency":\s*"(\w{3})".*?"(?:settlement_currency|presentment_currency)":\s*"(?!\1)\w{3}"', re.S)),
    ("refund_exceeds_charge", re.compile(r'"(?:amount_refunded|refund_amount)":\s*(\d+).*?"(?:amount|total)":\s*(\d+)', re.S)),
]


# ===================================================================
# 4-NEW. ADDITIONAL INJECTION / ARTIFACT CATEGORIES
# ===================================================================

# --- SSTI (Server-Side Template Injection) ---

SSTI_ARTIFACTS: list[tuple[str, re.Pattern[str]]] = [
    ("ssti_jinja2_config", re.compile(r"\{\{\s*config\s*\}\}", re.I)),
    ("ssti_jinja2_class", re.compile(r"\{\{\s*['\"][\s\S]*?\.__class__", re.I)),
    ("ssti_jinja2_mro", re.compile(r"__mro__|__subclasses__|__globals__|__builtins__", re.I)),
    ("ssti_jinja2_math", re.compile(r"\{\{\s*\d+\s*\*\s*\d+\s*\}\}")),
    ("ssti_twig_self", re.compile(r"\{\{\s*_self\.env", re.I)),
    ("ssti_twig_filter", re.compile(r"\{\{\s*['\"].*?\|.*?filter", re.I)),
    ("ssti_freemarker_assign", re.compile(r"<#assign\s+\w+\s*=", re.I)),
    ("ssti_freemarker_exec", re.compile(r'<#assign\s+.*?exec\(', re.I)),
    ("ssti_pebble_exec", re.compile(r"\{\{\s*['\"].*?\.java\.lang\.", re.I)),
    ("ssti_thymeleaf_exec", re.compile(r"\$\{T\(java\.lang\.Runtime\)", re.I)),
    ("ssti_erb_exec", re.compile(r"<%=\s*`[^`]+`\s*%>", re.I)),
    ("ssti_smarty_php", re.compile(r"\{\$smarty\.", re.I)),
    ("ssti_velocity", re.compile(r"#set\s*\(\s*\$\w+\s*=", re.I)),
    ("ssti_49_indicator", re.compile(r"\b49\b.*?\{\{.*?7\s*\*\s*7")),
]

# --- NoSQL Injection ---

NOSQL_INJECTION_ARTIFACTS: list[tuple[str, re.Pattern[str]]] = [
    ("nosql_mongo_operator", re.compile(r'\$(?:gt|gte|lt|lte|ne|in|nin|regex|where|exists|type|size|all|elemMatch)\b', re.I)),
    ("nosql_mongo_where", re.compile(r"\$where\s*:\s*[\"'].*?(?:function|this\.|return)", re.I)),
    ("nosql_mongo_js", re.compile(r'"\$where"\s*:\s*".*(?:sleep|db\.|tojsononeline)', re.I)),
    ("nosql_mongo_error", re.compile(r"(?:MongoError|MongoServerError|BSONTypeError|CastError)", re.I)),
    ("nosql_couchdb_error", re.compile(r"(?:couchdb|CouchDB|badarg|case_clause)", re.I)),
    ("nosql_redis_command", re.compile(r"(?:WRONGTYPE|ERR unknown command|MOVED \d+|CLUSTERDOWN)", re.I)),
    ("nosql_elasticsearch_error", re.compile(r"(?:SearchParseException|QueryShardException|query_shard_exception|search_phase_execution)", re.I)),
    ("nosql_elasticsearch_query", re.compile(r'"query"\s*:\s*\{\s*"(?:bool|match|term|range|script)', re.I)),
]

# --- XXE (XML External Entity) ---

XXE_ARTIFACTS: list[tuple[str, re.Pattern[str]]] = [
    ("xxe_doctype_entity", re.compile(r"<!DOCTYPE\s+\w+\s+\[.*?<!ENTITY", re.I | re.S)),
    ("xxe_external_entity", re.compile(r'<!ENTITY\s+\w+\s+SYSTEM\s+"', re.I)),
    ("xxe_parameter_entity", re.compile(r"<!ENTITY\s+%\s+\w+\s+SYSTEM", re.I)),
    ("xxe_file_scheme", re.compile(r'SYSTEM\s+"file:///', re.I)),
    ("xxe_php_expect", re.compile(r'SYSTEM\s+"expect://', re.I)),
    ("xxe_php_filter", re.compile(r'SYSTEM\s+"php://filter', re.I)),
    ("xxe_data_uri", re.compile(r'SYSTEM\s+"data://', re.I)),
    ("xxe_xinclude", re.compile(r"<xi:include\s+.*?parse=", re.I)),
    ("xxe_svg_in_response", re.compile(r"<svg[^>]*>.*?<!ENTITY", re.I | re.S)),
    ("xxe_error_disclosure", re.compile(r"(?:SAXParseException|XMLSyntaxError|XMLParserError|lxml\.etree)", re.I)),
]

# --- Prototype Pollution ---

PROTOTYPE_POLLUTION_ARTIFACTS: list[tuple[str, re.Pattern[str]]] = [
    ("proto_in_body", re.compile(r'"__proto__"\s*:', re.I)),
    ("constructor_prototype", re.compile(r'"constructor"\s*:\s*\{\s*"prototype"', re.I)),
    ("proto_pollution_merge", re.compile(r"(?:Object\.assign|merge|deepMerge|extend|defaultsDeep)\s*\([^)]*__proto__", re.I)),
    ("proto_json_parse", re.compile(r'JSON\.parse\s*\([^)]*__proto__', re.I)),
    ("proto_lodash_set", re.compile(r"(?:lodash|_)\.(?:set|merge|defaultsDeep|assign)\s*\(", re.I)),
    ("proto_pollution_indicator", re.compile(r'"(?:polluted|isAdmin|isAuthenticated)"\s*:\s*true', re.I)),
]

# --- HTTP Request Smuggling ---

HTTP_SMUGGLING_ARTIFACTS: list[tuple[str, re.Pattern[str]]] = [
    ("smuggling_cl_te", re.compile(r"Content-Length:\s*\d+.*?Transfer-Encoding:\s*chunked", re.I | re.S)),
    ("smuggling_te_cl", re.compile(r"Transfer-Encoding:\s*chunked.*?Content-Length:\s*\d+", re.I | re.S)),
    ("smuggling_te_obfuscation", re.compile(r"Transfer-Encoding\s*:\s*(?:chunked\s*,\s*identity|identity\s*,\s*chunked|[\t ]*chunked[\t ]*)", re.I)),
    ("smuggling_te_variants", re.compile(r"Transfer-Encoding:\s*(?:xchunked|chunked\x00|chu\x00nked|\x09chunked)", re.I)),
    ("smuggling_h2_to_h1", re.compile(r"(?:HTTP/2.*?Host:.*?Host:|:method.*?:method)", re.I | re.S)),
    ("smuggling_response_split", re.compile(r"(?:\\r\\n|%0d%0a)(?:HTTP/|Set-Cookie|Location)", re.I)),
]

# --- Cache Poisoning ---

CACHE_POISONING_ARTIFACTS: list[tuple[str, re.Pattern[str]]] = [
    ("cache_xfh_reflected", re.compile(r"X-Forwarded-Host:\s*[^\r\n]+.*?(?:href|src|action|url)\s*=\s*[\"']?https?://", re.I | re.S)),
    ("cache_x_original_url", re.compile(r"X-Original-URL:\s*|X-Rewrite-URL:\s*", re.I)),
    ("cache_unkeyed_header_reflected", re.compile(r"(?:X-Forwarded-(?:Scheme|Proto|Port|Prefix)|X-Host|X-Original-Host):\s*", re.I)),
    ("cache_key_normalization", re.compile(r"(?:X-Cache:\s*HIT|cf-cache-status:\s*HIT|Age:\s*[1-9])", re.I)),
    ("cache_poisoning_indicator", re.compile(r"(?:X-Cache-Key:|Surrogate-Key:|Fastly-Debug-|x-amz-cf-id)", re.I)),
    ("web_cache_deception", re.compile(r"/(?:account|profile|settings|dashboard)\.\w+(?:\?|$)", re.I)),
]

# --- HTTP Parameter Pollution ---

PARAMETER_POLLUTION_ARTIFACTS: list[tuple[str, re.Pattern[str]]] = [
    ("hpp_duplicate_param", re.compile(r"(\w+=\w+).*?\1", re.I)),
    ("hpp_array_param", re.compile(r"\w+\[\]=.*?\w+\[\]=", re.I)),
    ("hpp_param_override", re.compile(r"(?:role|admin|is_admin|user_type|access_level)=.*?&.*?(?:role|admin|is_admin|user_type|access_level)=", re.I)),
]

# --- Type Confusion ---

TYPE_CONFUSION_ARTIFACTS: list[tuple[str, re.Pattern[str]]] = [
    ("type_coercion_error", re.compile(r"(?:Cannot (?:read|convert|cast)|TypeError|type mismatch|expected (?:string|number|boolean|array|object))", re.I)),
    ("implicit_conversion", re.compile(r"(?:NaN|Infinity|-Infinity|undefined|null)\s*(?:was|is|became|converted)", re.I)),
    ("schema_validation_bypass", re.compile(r"(?:additionalProperties|not allowed|does not match|required property|schema validation|oneOf|anyOf)", re.I)),
    ("json_type_confusion", re.compile(r'"(?:amount|price|quantity|count)":\s*"(?:0|true|false|null)"', re.I)),
]

# --- Captcha Bypass Indicators ---

CAPTCHA_BYPASS_ARTIFACTS: list[tuple[str, re.Pattern[str]]] = [
    ("captcha_token_in_response", re.compile(r'"(?:captcha_token|captcha_response|g-recaptcha-response|h-captcha-response|turnstile-response)"\s*:', re.I)),
    ("captcha_missing_validation", re.compile(r'"(?:captcha_required|captcha_enabled|requires_captcha)"\s*:\s*false', re.I)),
    ("captcha_static_solution", re.compile(r'"(?:captcha_solution|captcha_answer)"\s*:\s*"[^"]{1,20}"', re.I)),
    ("captcha_bypass_header", re.compile(r"X-(?:Bypass-Captcha|No-Captcha|Skip-Captcha|Captcha-Exempt):\s*", re.I)),
    ("captcha_score_leaked", re.compile(r'"(?:captcha_score|risk_score|bot_score|recaptcha_score)"\s*:\s*[\d.]', re.I)),
    ("captcha_debug_mode", re.compile(r"(?:captcha.*?(?:debug|test|bypass|disabled|mock)|recaptcha.*?sitekey.*?test)", re.I)),
]

# --- Rate Limit Bypass Indicators ---

RATE_LIMIT_BYPASS_ARTIFACTS: list[tuple[str, re.Pattern[str]]] = [
    ("ratelimit_xff_accepted", re.compile(r"X-Forwarded-For:\s*(?:127\.\d|10\.\d|172\.\d|192\.168\.)", re.I)),
    ("ratelimit_path_normalization", re.compile(r"(?:/api/login/|/api//login|/api/\./login|/api/%6c%6f%67%69%6e)", re.I)),
    ("ratelimit_method_override", re.compile(r"X-HTTP-Method-Override:\s*(?:POST|PUT|PATCH|DELETE)", re.I)),
    ("ratelimit_graphql_batch", re.compile(r"\[\s*\{.*?\"query\".*?\}.*?,.*?\{.*?\"query\"", re.I | re.S)),
    ("ratelimit_retry_after", re.compile(r"Retry-After:\s*(\d+)", re.I)),
    ("ratelimit_remaining_zero", re.compile(r"X-RateLimit-Remaining:\s*0\b", re.I)),
    ("ratelimit_header_exposed", re.compile(r"X-RateLimit-(?:Limit|Remaining|Reset|Window):\s*\d+", re.I)),
    ("ratelimit_429_response", re.compile(r'"(?:rate_limit|rate.limited|too_many_requests|throttled|slow_down)"', re.I)),
    ("ratelimit_window_boundary", re.compile(r"X-RateLimit-Reset:\s*(\d{10})", re.I)),
]

# --- Webhook Security ---

WEBHOOK_SECURITY_ARTIFACTS: list[tuple[str, re.Pattern[str]]] = [
    ("webhook_missing_signature", re.compile(r'"(?:webhook_secret|signing_secret|endpoint_secret)"\s*:\s*(?:null|"")', re.I)),
    ("webhook_timestamp_drift", re.compile(r'"(?:webhook_tolerance|timestamp_tolerance|max_age)"\s*:\s*(?:\d{4,}|null)', re.I)),
    ("webhook_replay_indicator", re.compile(r'"(?:idempotency_key|event_id|delivery_id)"\s*:\s*"[^"]*".*?(?:already|duplicate|replayed)', re.I | re.S)),
    ("webhook_type_confusion", re.compile(r'"type"\s*:\s*"(?:customer|charge|invoice|payment_intent)\.\w+".*?"object"\s*:\s*"(?!event)', re.I | re.S)),
    ("webhook_url_ssrf", re.compile(r'"(?:webhook_url|callback_url|notification_url)"\s*:\s*"https?://(?:127\.|10\.|172\.(1[6-9]|2\d|3[01])|192\.168\.|localhost)', re.I)),
    ("webhook_no_tls_verification", re.compile(r'"(?:verify_ssl|ssl_verify|tls_verify)"\s*:\s*false', re.I)),
]

# --- Subscription / Payment Abuse ---

SUBSCRIPTION_ABUSE_ARTIFACTS: list[tuple[str, re.Pattern[str]]] = [
    ("trial_extension", re.compile(r'"trial_end"\s*:\s*(?:null|\d{10,}).*?"(?:status|trial_status)"\s*:\s*"trialing"', re.I | re.S)),
    ("downgrade_retention", re.compile(r'"(?:plan|tier)"\s*:\s*"(?:free|basic|starter)".*?"(?:features?|entitlements?|capabilities?)"\s*:\s*[\[{].*?"(?:premium|enterprise|pro)', re.I | re.S)),
    ("grace_period_exploit", re.compile(r'"(?:status|subscription_status)"\s*:\s*"(?:past_due|unpaid)".*?"(?:access|active|entitled)"\s*:\s*true', re.I | re.S)),
    ("proration_manipulation", re.compile(r'"(?:proration|prorate|prorated_amount)"\s*:\s*-?\d+.*?"(?:amount|total)":\s*0', re.I | re.S)),
    ("dunning_bypass", re.compile(r'"(?:dunning_status|retry_status|collection_method)"\s*:\s*"(?:exhausted|failed|none)".*?"(?:status|active)"\s*:\s*"?(?:true|active)', re.I | re.S)),
    ("metered_undercount", re.compile(r'"(?:quantity|usage_quantity|metered_usage)"\s*:\s*0\b.*?"(?:status)"\s*:\s*"active"', re.I | re.S)),
    ("usage_record_manipulation", re.compile(r'"(?:action|usage_action)"\s*:\s*"(?:set|decrement)".*?"(?:quantity|usage)":\s*(?:0|-\d+)', re.I | re.S)),
    ("plan_override_accepted", re.compile(r'"(?:plan_id|price_id|product_id)"\s*:\s*"[^"]+_(?:override|custom|internal)', re.I)),
    ("free_trial_restart", re.compile(r'"(?:trial_start|trial_period_days)"\s*:\s*\d+.*?"(?:previous_plan|cancel_at|canceled_at)"', re.I | re.S)),
    ("billing_anchor_manipulation", re.compile(r'"(?:billing_cycle_anchor|billing_anchor)"\s*:\s*\d{10,}', re.I)),
]


# ===================================================================
# 4-RE. REVERSE ENGINEERING ARTIFACTS
# ===================================================================

REVERSE_ENGINEERING_ARTIFACTS: list[tuple[str, re.Pattern[str]]] = [
    # API documentation exposure
    ("swagger_exposure", re.compile(r'"swagger"\s*:\s*"2\.\d"|"openapi"\s*:\s*"3\.\d', re.I)),
    ("openapi_spec_exposed", re.compile(r'"(?:paths|components|schemas|securityDefinitions|definitions)"\s*:\s*\{', re.I)),
    ("wsdl_exposure", re.compile(r"<(?:wsdl:)?definitions\s|<(?:wsdl:)?service\s|<(?:wsdl:)?portType\s", re.I)),
    ("graphql_schema_full", re.compile(r'"(?:__schema)"\s*:\s*\{.*?"(?:types|queryType|mutationType)"', re.I | re.S)),
    # Source map exposure
    ("source_map_reference", re.compile(r"//[#@]\s*sourceMappingURL\s*=\s*\S+\.map", re.I)),
    ("source_map_content", re.compile(r'"(?:sources|sourcesContent|mappings)"\s*:\s*[\["]', re.I)),
    # Obfuscated code indicators
    ("eval_chain", re.compile(r"eval\s*\(\s*(?:atob|unescape|decodeURIComponent|String\.fromCharCode)\s*\(", re.I)),
    ("fromcharcode_chain", re.compile(r"String\.fromCharCode\s*\(\s*\d+(?:\s*,\s*\d+){5,}", re.I)),
    ("base64_decode_chain", re.compile(r"(?:atob|Buffer\.from|base64\.b64decode)\s*\(\s*['\"][A-Za-z0-9+/=]{20,}", re.I)),
    # Internal routing / architecture
    ("internal_routing_info", re.compile(r'"(?:upstream|backend|service_name|cluster|namespace|pod)"\s*:\s*"', re.I)),
    ("internal_service_mesh", re.compile(r"(?:x-envoy-|x-b3-|x-request-id|x-datadog-|baggage)", re.I)),
    # Debug headers
    ("debug_header_exposure", re.compile(r"(?:X-Debug-Token|X-Debug-Info|X-Symfony-|Server-Timing|X-Request-Id|X-Correlation-Id):\s*", re.I)),
    ("trace_id_exposure", re.compile(r"(?:X-Trace-Id|X-Span-Id|X-Parent-Id|traceparent|tracestate):\s*", re.I)),
    # Binary / serialization format
    ("protobuf_indicator", re.compile(r"(?:application/(?:x-)?protobuf|application/grpc|google\.protobuf)", re.I)),
    ("msgpack_indicator", re.compile(r"(?:application/(?:x-)?msgpack|application/vnd\.msgpack)", re.I)),
    ("avro_indicator", re.compile(r"(?:application/avro|avro\.schema|\"type\"\s*:\s*\"record\".*?\"fields\")", re.I | re.S)),
    # Anti-reverse-engineering markers
    ("anti_debug_js", re.compile(r"(?:debugger\s*;|Function\(\"debugger\"\)|setInterval.*?debugger)", re.I)),
    ("anti_tamper_check", re.compile(r"(?:integrity\s*check|tamper\s*detect|checksum\s*mismatch|signature\s*invalid)", re.I)),
    ("obfuscation_layer", re.compile(r"(?:_0x[a-f0-9]{4,}|\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){5,})", re.I)),
]


# ===================================================================
# 5. HEADER SECURITY PATTERNS
# ===================================================================

HEADER_SECURITY_PATTERNS: list[tuple[str, str]] = [
    ("missing_csp", "content-security-policy"),
    ("missing_hsts", "strict-transport-security"),
    ("missing_x_frame_options", "x-frame-options"),
    ("missing_x_content_type", "x-content-type-options"),
    ("missing_referrer_policy", "referrer-policy"),
    ("missing_permissions_policy", "permissions-policy"),
    # --- expanded ---
    ("missing_cache_control", "cache-control"),
    ("missing_x_xss_protection", "x-xss-protection"),
    ("missing_cross_origin_opener", "cross-origin-opener-policy"),
    ("missing_cross_origin_embedder", "cross-origin-embedder-policy"),
    ("missing_cross_origin_resource", "cross-origin-resource-policy"),
]


# ===================================================================
# 6. INFO DISCLOSURE PATTERNS (enhanced from security_scan.py)
# ===================================================================

INFO_DISCLOSURE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("stack_trace_python", re.compile(r"Traceback \(most recent call last\)", re.I)),
    ("stack_trace_java", re.compile(r"^\s*at\s+[\w.$]+\s*\([^)]*\)", re.MULTILINE)),
    ("stack_trace_node", re.compile(r"at\s+(?:Object\.|Module\.|Function\.)?[\w.]+\s+\([^)]*\.js:\d+:\d+\)")),
    ("stack_trace_dotnet", re.compile(r"(?:System\.Exception|NullReferenceException|ArgumentException).*at\s+\w+", re.I | re.S)),
    ("stack_trace_go", re.compile(r"goroutine\s+\d+\s+\[(?:running|chan receive)\]:", re.I)),
    ("stack_trace_ruby", re.compile(r"(?:NoMethodError|NameError|ArgumentError).*?from\s+\S+:\d+:in\s+`", re.I | re.S)),
    ("stack_trace_php", re.compile(r"(?:Fatal error|Parse error|Warning):\s*.*?\s+in\s+\S+\.php\s+on\s+line\s+\d+", re.I)),
    ("file_path_unix", re.compile(r"(?:/usr/|/home/[\w-]+/|/var/www|/opt/[\w./-]+|/etc/[\w./-]+|/proc/self)")),
    ("file_path_windows", re.compile(r"[A-Za-z]:\\(?:Users|Windows|Program Files|inetpub)\\", re.I)),
    ("debug_mode_indicator", re.compile(r"(?:DEBUG\s*=\s*True|FLASK_DEBUG|NODE_ENV\s*[=:]\s*development|WP_DEBUG|RAILS_ENV.*?development)", re.I)),
    ("database_error_detail", re.compile(r"\b(?:SQLSTATE|duplicate key value violates|syntax error at or near|near \"\w+\": syntax error)\b", re.I)),
    ("framework_debug_page", re.compile(r"\b(?:Django Version|Werkzeug Debugger|WSGIRequest|Whoops|Laravel\\|Symfony\\|__CakePHP|Yii\\|Spring Boot Actuator)\b")),
    ("internal_ip_leak", re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b")),
    ("aws_internal_hostname", re.compile(r"\bip-10-\d{1,3}-\d{1,3}-\d{1,3}\b|\.(?:internal|local|corp|intra)\b(?!\w)")),
    ("git_exposure", re.compile(r"(?:\.git/config|\.git/HEAD|refs/heads/|commit [0-9a-f]{40})", re.I)),
    ("env_file_exposure", re.compile(r"(?:DB_PASSWORD|DATABASE_URL|SECRET_KEY|STRIPE_SECRET_KEY|AWS_ACCESS_KEY_ID)\s*=", re.I)),
    ("docker_exposure", re.compile(r"(?:docker(?:file|compose)|\.dockerignore|container_name|DOCKER_HOST)", re.I)),
    ("kubernetes_exposure", re.compile(r"(?:apiVersion:\s*v\d+|kind:\s*(?:Pod|Service|Deployment)|kubectl|kube-system)", re.I)),
    ("version_disclosure", re.compile(r"(?:(?:nginx|apache|php|node|express|django|flask|rails|spring|tomcat|gunicorn)[/\s]*v?[\d.]+)", re.I)),
    # --- expanded ---
    ("terraform_state_leak", re.compile(r'"(?:terraform_version|serial|lineage|backend)"\s*:', re.I)),
    ("ci_cd_exposure", re.compile(r"(?:GITHUB_TOKEN|CIRCLE_TOKEN|GITLAB_TOKEN|JENKINS_URL|CI_JOB_TOKEN|BUILDKITE_)\s*[=:]", re.I)),
    ("actuator_exposure", re.compile(r"/actuator/(?:health|info|env|beans|mappings|configprops|metrics)", re.I)),
    ("graphql_playground_exposed", re.compile(r"(?:GraphQL Playground|graphiql|altair|voyager)\b.*?(?:endpoint|path)", re.I | re.S)),
]


# ===================================================================
# 7. HELPER FUNCTIONS — original
# ===================================================================

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
    """Scans text for injection artifact reflections across ALL categories
    (original 12 + 13 new). Returns (category, pattern_name, snippet)."""
    all_patterns: list[tuple[str, list[tuple[str, re.Pattern[str]]]]] = [
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
        # --- new categories ---
        ("ssti", SSTI_ARTIFACTS),
        ("nosql_injection", NOSQL_INJECTION_ARTIFACTS),
        ("xxe", XXE_ARTIFACTS),
        ("prototype_pollution", PROTOTYPE_POLLUTION_ARTIFACTS),
        ("http_smuggling", HTTP_SMUGGLING_ARTIFACTS),
        ("cache_poisoning", CACHE_POISONING_ARTIFACTS),
        ("parameter_pollution", PARAMETER_POLLUTION_ARTIFACTS),
        ("type_confusion", TYPE_CONFUSION_ARTIFACTS),
        ("captcha_bypass", CAPTCHA_BYPASS_ARTIFACTS),
        ("rate_limit_bypass", RATE_LIMIT_BYPASS_ARTIFACTS),
        ("webhook_security", WEBHOOK_SECURITY_ARTIFACTS),
        ("subscription_abuse", SUBSCRIPTION_ABUSE_ARTIFACTS),
        ("reverse_engineering", REVERSE_ENGINEERING_ARTIFACTS),
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


# ===================================================================
# 8. NEW HELPER FUNCTIONS
# ===================================================================

def scan_rate_limit_bypass_indicators(
    headers: dict[str, str],
    status_code: int | None,
    body: Any,
) -> list[tuple[str, str, str]]:
    """Scans response headers and body for rate-limit bypass indicators.
    Returns (class, indicator_name, detail) tuples.

    Covers all advanced bypass classes:
      - Identity-key confusion (header spoofing)
      - Edge/origin mismatch
      - Request-shape equivalence (path normalization)
      - Batching / fan-out
      - Window boundary timing
      - Distributed identity abuse
    """
    findings: list[tuple[str, str, str]] = []
    lower_headers = {k.lower(): v for k, v in headers.items()}
    text = body_as_text(body) if body is not None else ""
    header_text = headers_as_text(headers)

    # Identity-key confusion: spoofable forwarding headers trusted
    spoofable = ["x-forwarded-for", "x-real-ip", "true-client-ip",
                 "x-originating-ip", "x-remote-ip", "x-client-ip",
                 "forwarded", "cf-connecting-ip"]
    for hdr in spoofable:
        if hdr in lower_headers:
            findings.append(("identity_key_confusion", f"trusts_{hdr.replace('-', '_')}",
                             f"Header '{hdr}' present in response (may be reflected/trusted)"))

    # Rate limit header exposure (reveals window/limit info)
    for rl_hdr in ["x-ratelimit-limit", "x-ratelimit-remaining",
                    "x-ratelimit-reset", "ratelimit-limit",
                    "ratelimit-remaining", "ratelimit-reset",
                    "retry-after"]:
        if rl_hdr in lower_headers:
            findings.append(("window_boundary", f"rate_header_{rl_hdr.replace('-', '_')}",
                             f"{rl_hdr}: {lower_headers[rl_hdr]}"))

    # 429 status but not on the expected endpoint shape
    if status_code == 429:
        findings.append(("rate_enforcement", "429_received",
                         "Rate limit enforced (HTTP 429)"))
    elif status_code == 200 and "retry-after" in lower_headers:
        findings.append(("rate_bypass_possible", "200_with_retry_after",
                         "HTTP 200 returned alongside Retry-After header -- limiter may be advisory only"))

    # Method override headers
    for override_hdr in ["x-http-method-override", "x-http-method",
                         "x-method-override"]:
        if override_hdr in lower_headers:
            findings.append(("method_override", f"accepts_{override_hdr.replace('-', '_')}",
                             f"Server honors {override_hdr} header"))

    # GraphQL batching indicators in body
    for pat_name, pat_re in RATE_LIMIT_BYPASS_ARTIFACTS:
        m = pat_re.search(text) or pat_re.search(header_text)
        if m:
            findings.append(("rate_limit_bypass", pat_name, m.group()[:120]))

    return findings


def scan_subscription_abuse_indicators(body: Any) -> list[tuple[str, str, str]]:
    """Scans a response body for subscription / payment abuse indicators.
    Returns (abuse_class, indicator_name, detail) tuples."""
    findings: list[tuple[str, str, str]] = []
    text = body_as_text(body) if body is not None else ""
    if not text:
        return findings

    for pat_name, pat_re in SUBSCRIPTION_ABUSE_ARTIFACTS:
        m = pat_re.search(text)
        if m:
            start = max(0, m.start() - 15)
            end = min(len(text), m.end() + 40)
            findings.append(("subscription_abuse", pat_name,
                             text[start:end].strip()[:200]))

    for pat_name, pat_re in BUSINESS_LOGIC_ARTIFACTS:
        m = pat_re.search(text)
        if m:
            start = max(0, m.start() - 15)
            end = min(len(text), m.end() + 40)
            findings.append(("business_logic", pat_name,
                             text[start:end].strip()[:200]))

    return findings


def scan_reverse_engineering_artifacts(
    body: Any,
    headers: dict[str, str] | None = None,
) -> list[tuple[str, str, str]]:
    """Scans response body and headers for reverse-engineering artifacts:
    exposed API docs, source maps, obfuscation, internal routing info,
    debug headers, binary protocol markers, and anti-RE defences.
    Returns (artifact_class, name, snippet) tuples."""
    findings: list[tuple[str, str, str]] = []
    text = body_as_text(body) if body is not None else ""

    for pat_name, pat_re in REVERSE_ENGINEERING_ARTIFACTS:
        m = pat_re.search(text)
        if m:
            start = max(0, m.start() - 15)
            end = min(len(text), m.end() + 40)
            findings.append(("reverse_engineering", pat_name,
                             text[start:end].strip()[:200]))

    if headers:
        header_text = headers_as_text(headers)
        header_patterns = [p for p in REVERSE_ENGINEERING_ARTIFACTS
                           if any(kw in p[0] for kw in ("header", "trace", "debug", "mesh", "protobuf", "msgpack"))]
        for pat_name, pat_re in header_patterns:
            m = pat_re.search(header_text)
            if m:
                findings.append(("reverse_engineering", pat_name,
                                 m.group().strip()[:200]))

    return findings


def compute_response_entropy(text: str) -> float:
    """Compute Shannon entropy of a response body. Higher entropy may
    indicate encrypted, compressed, or binary content in an unexpected
    text response -- useful for anomaly detection.

    Returns bits-per-character (0.0 for empty, up to ~8.0 for uniformly
    random bytes)."""
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(text)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


_API_ENDPOINT_RE = re.compile(
    r'(?:"(?:url|href|endpoint|path|uri|api_url|base_url|callback_url|webhook_url)"'
    r'\s*:\s*")((?:/[^"]*|https?://[^"]+))"',
    re.I,
)
_PATH_LIKE_RE = re.compile(r'"(/(?:api|v\d+|graphql|rest|auth|admin|internal|webhook)[^"]{2,})"')


def extract_api_endpoints_from_response(body: Any) -> list[str]:
    """Extracts API endpoint references found in a response body.
    Useful for attack-surface discovery from already-collected traffic."""
    text = body_as_text(body) if body is not None else ""
    if not text:
        return []
    endpoints: set[str] = set()
    for m in _API_ENDPOINT_RE.finditer(text):
        endpoints.add(m.group(1))
    for m in _PATH_LIKE_RE.finditer(text):
        endpoints.add(m.group(1))
    return sorted(endpoints)


_FORMAT_SIGNATURES: list[tuple[str, re.Pattern[str]]] = [
    ("json", re.compile(r"^\s*[\[{]")),
    ("xml", re.compile(r"^\s*<\?xml|^\s*<\w+[: >]", re.I)),
    ("html", re.compile(r"^\s*<!DOCTYPE|^\s*<html", re.I)),
    ("yaml", re.compile(r"^---\s*$|^\w+:\s", re.MULTILINE)),
    ("protobuf_base64", re.compile(r"^[A-Za-z0-9+/]{50,}={0,2}$")),
    ("msgpack_hex", re.compile(r"^(?:[0-9a-f]{2}){10,}$", re.I)),
    ("csv", re.compile(r'^[^,\n]+(?:,[^,\n]+){2,}(?:\n[^,\n]+(?:,[^,\n]+){2,})+', re.MULTILINE)),
    ("jwt", re.compile(r"^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+")),
    ("multipart", re.compile(r"^--[A-Za-z0-9_-]+\r?\n", re.MULTILINE)),
    ("url_encoded", re.compile(r"^[A-Za-z0-9_]+=[^&]+(?:&[A-Za-z0-9_]+=[^&]+)+")),
]


def detect_serialization_format(body: Any) -> str:
    """Identify the serialization format of a response body.
    Returns one of: json, xml, html, yaml, protobuf_base64, msgpack_hex,
    csv, jwt, multipart, url_encoded, or 'unknown'."""
    text = body_as_text(body) if body is not None else ""
    if not text:
        return "unknown"
    for fmt_name, fmt_re in _FORMAT_SIGNATURES:
        if fmt_re.search(text[:500]):
            return fmt_name
    return "unknown"


def scan_captcha_bypass_indicators(
    headers: dict[str, str],
    body: Any,
) -> list[tuple[str, str, str]]:
    """Scans response headers and body for captcha-bypass indicators.
    Returns (bypass_class, indicator_name, detail) tuples."""
    findings: list[tuple[str, str, str]] = []
    text = body_as_text(body) if body is not None else ""
    header_text = headers_as_text(headers) if headers else ""
    combined = text + "\n" + header_text

    for pat_name, pat_re in CAPTCHA_BYPASS_ARTIFACTS:
        m = pat_re.search(combined)
        if m:
            start = max(0, m.start() - 15)
            end = min(len(combined), m.end() + 40)
            findings.append(("captcha_bypass", pat_name,
                             combined[start:end].strip()[:200]))

    return findings


def scan_webhook_security(
    headers: dict[str, str],
    body: Any,
) -> list[tuple[str, str, str]]:
    """Scans response body and request headers for webhook security issues.
    Returns (issue_class, indicator_name, detail) tuples."""
    findings: list[tuple[str, str, str]] = []
    text = body_as_text(body) if body is not None else ""

    for pat_name, pat_re in WEBHOOK_SECURITY_ARTIFACTS:
        m = pat_re.search(text)
        if m:
            start = max(0, m.start() - 15)
            end = min(len(text), m.end() + 40)
            findings.append(("webhook_security", pat_name,
                             text[start:end].strip()[:200]))

    if headers:
        lower_headers = {k.lower(): v for k, v in headers.items()}
        sig_headers = ["stripe-signature", "x-hub-signature", "x-hub-signature-256",
                       "x-webhook-signature", "x-shopify-hmac-sha256",
                       "x-square-hmacsha256-signature", "x-paypal-cert-url"]
        has_sig = any(h in lower_headers for h in sig_headers)
        if not has_sig and any(kw in str(body).lower() for kw in ("webhook", "event", "callback")):
            findings.append(("webhook_security", "missing_signature_header",
                             "Webhook-shaped request/response with no signature validation header"))

    return findings
