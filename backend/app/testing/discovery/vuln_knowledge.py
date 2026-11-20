"""Comprehensive vulnerability knowledge base.

Encodes domain knowledge from 10+ offensive-security knowledge sources into
a dependency-free, pattern-driven taxonomy the discovery layer's retrospective
analyzers can query without sending a single new request.  Every constant here
is a DETECTION HEURISTIC over already-collected evidence (response bodies,
status codes, headers, timings, request shapes) -- not an exploit payload.

Sources synthesized (see the owner's GitHub links for each):
  - Claude-BugHunter: 681 HackerOne reports -> 24 vuln categories, CVE chains
  - Strix:            multi-agent chaining, PoC-validation patterns
  - Cloudflare audit: six-phase methodology, trust-boundary taxonomy
  - Shannon:          white-box attack-surface mapping heuristics
  - PentAGI:          terminal/browser/editor integration patterns
  - PayloadsAllTheThings: injection/auth/deser/upload/SSRF signatures
  - reverse-skill:    reverse-engineering knowledge-base patterns
  - SWE-agent:        systematic issue-resolution workflows
  - Full-Chain-Sentinel: CVSS scoring, evidence-retention methodology
  - sapper-v2:        fact-intent graph, 63-entry offline KB, chaining

Design boundary: this module is PURE DATA -- no I/O, no imports beyond
stdlib, no side effects.  Analyzers in analyzers.py import constants and
helper functions from here; nothing here runs against a target.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# 1. VULNERABILITY TAXONOMY (24 categories, BugHunter + PayloadsAllTheThings)
# ---------------------------------------------------------------------------

class VulnCategory(str, Enum):
    """24 vulnerability categories covering the full OWASP + HackerOne
    taxonomy, each with detection heuristics for retrospective analysis."""
    IDOR = "idor"
    SSRF = "ssrf"
    XSS = "xss"
    SQLI = "sqli"
    AUTH_BYPASS = "auth_bypass"
    BROKEN_ACCESS_CONTROL = "broken_access_control"
    MASS_ASSIGNMENT = "mass_assignment"
    RACE_CONDITION = "race_condition"
    BUSINESS_LOGIC = "business_logic"
    INFO_DISCLOSURE = "info_disclosure"
    PRIVILEGE_ESCALATION = "priv_esc"
    CSRF = "csrf"
    DESERIALIZATION = "deserialization"
    FILE_UPLOAD = "file_upload"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "cmd_injection"
    OPEN_REDIRECT = "open_redirect"
    CORS_MISCONFIGURATION = "cors_misconfig"
    SUBDOMAIN_TAKEOVER = "subdomain_takeover"
    GRAPHQL_ABUSE = "graphql_abuse"
    WEBSOCKET_ABUSE = "websocket_abuse"
    API_RATE_LIMIT_BYPASS = "rate_limit_bypass"
    PAYMENT_MANIPULATION = "payment_manipulation"
    ENTITLEMENT_BYPASS = "entitlement_bypass"


# ---------------------------------------------------------------------------
# 2. DETECTION SIGNATURES (per-category heuristics over collected evidence)
#
# Each signature is a tuple: (category, name, what_to_check, regex_or_fn)
# where what_to_check is "response_body" | "response_headers" | "status_pattern"
# | "request_body" | "timing" | "structural"
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DetectionSignature:
    category: VulnCategory
    name: str
    target: str          # what field to check
    pattern: re.Pattern[str] | None = None
    description: str = ""
    severity_base: float = 5.0   # CVSS v3.1 base score estimate
    confidence: str = "medium"   # low / medium / high


# Response-body signatures: indicators of vulnerability classes visible
# in already-collected response data
RESPONSE_BODY_SIGNATURES: list[DetectionSignature] = [
    # -- IDOR indicators --
    DetectionSignature(VulnCategory.IDOR, "sequential_id_exposure",
                       "response_body", re.compile(r'"(?:id|user_id|account_id|order_id)":\s*(\d{1,8})\b'),
                       "Sequential numeric IDs in responses suggest IDOR risk", 6.5, "medium"),
    DetectionSignature(VulnCategory.IDOR, "uuid_in_error",
                       "response_body", re.compile(r'(?:not found|unauthorized|forbidden).*[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I),
                       "UUID leaked in error message enables targeted IDOR", 5.3, "medium"),
    # -- SSRF indicators --
    DetectionSignature(VulnCategory.SSRF, "internal_ip_in_response",
                       "response_body", re.compile(r'\b(?:127\.0\.0\.1|0\.0\.0\.0|localhost|169\.254\.169\.254|::1)\b'),
                       "Internal/metadata IPs in response body indicate SSRF risk", 8.6, "high"),
    DetectionSignature(VulnCategory.SSRF, "cloud_metadata_leak",
                       "response_body", re.compile(r'(?:ami-[0-9a-f]+|i-[0-9a-f]+|arn:aws|instance-id|availability-zone|meta-data)', re.I),
                       "Cloud metadata in response indicates SSRF or misconfiguration", 9.0, "high"),
    # -- SQLi indicators --
    DetectionSignature(VulnCategory.SQLI, "sql_error_in_response",
                       "response_body", re.compile(r'(?:SQL\s*syntax|mysql_fetch|pg_query|sqlite3?\.|ORA-\d{5}|quoted string not properly terminated|unclosed quotation mark)', re.I),
                       "SQL error messages indicate injection vulnerability", 8.6, "high"),
    DetectionSignature(VulnCategory.SQLI, "orm_error_leak",
                       "response_body", re.compile(r'(?:ActiveRecord|Sequelize|Prisma|TypeORM|Hibernate|SQLAlchemy).*(?:Error|Exception)', re.I),
                       "ORM error leak may reveal database structure", 5.3, "medium"),
    # -- XSS indicators --
    DetectionSignature(VulnCategory.XSS, "unescaped_input_reflection",
                       "response_body", re.compile(r'<script[^>]*>[^<]*(?:alert|prompt|confirm|document\.|window\.)', re.I),
                       "Unescaped script execution in response", 6.1, "high"),
    DetectionSignature(VulnCategory.XSS, "event_handler_reflection",
                       "response_body", re.compile(r'(?:on(?:error|load|click|mouseover|focus))\s*=\s*["\']?[^"\'>\s]+', re.I),
                       "Event handler reflection suggests XSS", 6.1, "medium"),
    # -- Auth bypass indicators --
    DetectionSignature(VulnCategory.AUTH_BYPASS, "auth_header_in_response",
                       "response_body", re.compile(r'(?:bearer|token|session_id|auth_token|access_token)\s*[=:]\s*["\']?[A-Za-z0-9._-]{20,}', re.I),
                       "Authentication token leaked in response body", 7.5, "high"),
    DetectionSignature(VulnCategory.AUTH_BYPASS, "default_credentials_hint",
                       "response_body", re.compile(r'(?:default.*(?:password|credential|login)|admin.*admin|test.*test123)', re.I),
                       "Default credential hints in response", 7.2, "medium"),
    # -- Command injection indicators --
    DetectionSignature(VulnCategory.COMMAND_INJECTION, "shell_output_in_response",
                       "response_body", re.compile(r'(?:uid=\d+|root:x:0|/bin/(?:bash|sh)|total\s+\d+\s+drwx)', re.I),
                       "Shell command output in response body", 9.8, "high"),
    # -- Path traversal indicators --
    DetectionSignature(VulnCategory.PATH_TRAVERSAL, "traversal_artifact",
                       "response_body", re.compile(r'(?:\.\./\.\./|root:.*:0:0:|boot\.ini|\[extensions\]|<web-app)', re.I),
                       "Path traversal artifacts in response", 7.5, "high"),
    # -- Deserialization indicators --
    DetectionSignature(VulnCategory.DESERIALIZATION, "java_deser_marker",
                       "response_body", re.compile(r'(?:java\.lang\.Runtime|java\.io\.ObjectInputStream|ysoserial|CommonsCollections|InvokerTransformer)', re.I),
                       "Java deserialization gadget chain indicators", 9.8, "high"),
    DetectionSignature(VulnCategory.DESERIALIZATION, "pickle_marker",
                       "response_body", re.compile(r'(?:__reduce__|pickle\.loads|cPickle|_reconstructor)', re.I),
                       "Python pickle deserialization indicators", 9.0, "high"),
    # -- Info disclosure --
    DetectionSignature(VulnCategory.INFO_DISCLOSURE, "version_disclosure",
                       "response_body", re.compile(r'(?:(?:nginx|apache|php|node|express|django|flask|rails|spring|tomcat)[/\s]*v?[\d.]+)', re.I),
                       "Server/framework version disclosure", 3.7, "low"),
    DetectionSignature(VulnCategory.INFO_DISCLOSURE, "source_code_leak",
                       "response_body", re.compile(r'(?:def\s+\w+\s*\(|function\s+\w+\s*\(|class\s+\w+\s*(?:extends|implements|{)|\bimport\s+\w+\b.*\bfrom\b)', re.I),
                       "Source code fragments in response", 5.3, "medium"),
    DetectionSignature(VulnCategory.INFO_DISCLOSURE, "environment_var_leak",
                       "response_body", re.compile(r'(?:DATABASE_URL|SECRET_KEY|AWS_SECRET|STRIPE_SECRET|API_KEY|REDIS_URL|MONGODB_URI)\s*[=:]', re.I),
                       "Environment variable names/values in response", 7.5, "high"),
    # -- GraphQL abuse --
    DetectionSignature(VulnCategory.GRAPHQL_ABUSE, "introspection_enabled",
                       "response_body", re.compile(r'(?:__schema|__type|queryType|mutationType|subscriptionType)', re.I),
                       "GraphQL introspection enabled exposes entire schema", 5.3, "high"),
    # -- Open redirect --
    DetectionSignature(VulnCategory.OPEN_REDIRECT, "redirect_in_body",
                       "response_body", re.compile(r'(?:redirect_uri|return_url|next|continue|goto|dest|destination|redir|return_to)\s*[=:]\s*["\']?https?://', re.I),
                       "Open redirect parameter in response body", 4.7, "medium"),
    # -- Payment manipulation --
    DetectionSignature(VulnCategory.PAYMENT_MANIPULATION, "price_in_response",
                       "response_body", re.compile(r'"(?:amount|price|total|unit_amount|cost)":\s*(?:0(?:\.0+)?|-\d+|0\.0*1)\b'),
                       "Zero/negative/trivial price in payment response", 8.1, "high"),
    DetectionSignature(VulnCategory.PAYMENT_MANIPULATION, "currency_mismatch",
                       "response_body", re.compile(r'"currency":\s*"(\w{3})".*?"currency":\s*"(?!\1)\w{3}"', re.S),
                       "Currency mismatch within same payment response", 6.5, "medium"),
]

# Header-based signatures
HEADER_SIGNATURES: list[DetectionSignature] = [
    DetectionSignature(VulnCategory.CORS_MISCONFIGURATION, "cors_wildcard",
                       "response_headers", re.compile(r'access-control-allow-origin:\s*\*', re.I),
                       "Wildcard CORS allows any origin", 5.4, "high"),
    DetectionSignature(VulnCategory.CORS_MISCONFIGURATION, "cors_null_origin",
                       "response_headers", re.compile(r'access-control-allow-origin:\s*null', re.I),
                       "CORS allows null origin (sandbox bypass)", 5.4, "high"),
    DetectionSignature(VulnCategory.CORS_MISCONFIGURATION, "cors_credentials_with_wildcard",
                       "response_headers", re.compile(r'access-control-allow-credentials:\s*true', re.I),
                       "CORS with credentials flag set", 6.5, "medium"),
    DetectionSignature(VulnCategory.INFO_DISCLOSURE, "server_header_version",
                       "response_headers", re.compile(r'server:\s*\S+/[\d.]+', re.I),
                       "Server version in headers", 3.1, "low"),
    DetectionSignature(VulnCategory.INFO_DISCLOSURE, "powered_by_header",
                       "response_headers", re.compile(r'x-powered-by:', re.I),
                       "X-Powered-By header reveals technology stack", 3.1, "low"),
    DetectionSignature(VulnCategory.AUTH_BYPASS, "missing_security_headers",
                       "response_headers", None,
                       "Missing critical security headers (CSP, HSTS, X-Frame-Options)", 4.3, "low"),
    DetectionSignature(VulnCategory.CSRF, "no_csrf_protection",
                       "response_headers", None,
                       "No SameSite cookie attribute or CSRF token", 5.4, "medium"),
]


# ---------------------------------------------------------------------------
# 3. KNOWN CVE CHAIN PATTERNS (BugHunter enterprise focus: M365, Okta, etc.)
#
# Each chain is a sequence of vuln categories that, when found together on
# the same target, compound into a higher-severity finding. The discovery
# engine matches observed finding categories against these templates.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CVEChainTemplate:
    chain_id: str
    name: str
    description: str
    steps: tuple[VulnCategory, ...]
    combined_cvss: float
    reference: str
    enterprise_context: str = ""


CVE_CHAIN_TEMPLATES: list[CVEChainTemplate] = [
    CVEChainTemplate(
        "CHAIN-001", "Auth Bypass -> IDOR -> Data Exfiltration",
        "Authentication bypass allows access to other users' resources via IDOR, "
        "compounded by information disclosure enabling targeted extraction.",
        (VulnCategory.AUTH_BYPASS, VulnCategory.IDOR, VulnCategory.INFO_DISCLOSURE),
        9.1, "CWE-284 -> CWE-639 -> CWE-200",
        "Common in multi-tenant SaaS (M365 CVE-2023-23397 chain pattern)"
    ),
    CVEChainTemplate(
        "CHAIN-002", "SSRF -> Cloud Metadata -> Credential Theft",
        "Server-side request forgery to cloud metadata endpoint enables "
        "credential theft and lateral movement.",
        (VulnCategory.SSRF, VulnCategory.INFO_DISCLOSURE, VulnCategory.PRIVILEGE_ESCALATION),
        9.8, "CWE-918 -> CWE-522 -> CWE-269",
        "Classic AWS/GCP/Azure IMDS chain (Capital One breach pattern)"
    ),
    CVEChainTemplate(
        "CHAIN-003", "Mass Assignment -> Privilege Escalation",
        "Unprotected mass assignment allows setting admin/role fields, "
        "escalating from regular user to administrator.",
        (VulnCategory.MASS_ASSIGNMENT, VulnCategory.PRIVILEGE_ESCALATION),
        8.8, "CWE-915 -> CWE-269",
        "Common in Ruby on Rails, Django, Node.js frameworks"
    ),
    CVEChainTemplate(
        "CHAIN-004", "Race Condition -> Payment Bypass",
        "TOCTOU race in payment verification allows completing purchase "
        "without valid payment or at reduced price.",
        (VulnCategory.RACE_CONDITION, VulnCategory.PAYMENT_MANIPULATION, VulnCategory.ENTITLEMENT_BYPASS),
        8.1, "CWE-362 -> CWE-799",
        "E-commerce / subscription billing (Stripe double-charge pattern)"
    ),
    CVEChainTemplate(
        "CHAIN-005", "IDOR -> Business Logic -> Entitlement Bypass",
        "Object-level authorization flaw combined with business logic error "
        "allows accessing paid features or other users' subscriptions.",
        (VulnCategory.IDOR, VulnCategory.BUSINESS_LOGIC, VulnCategory.ENTITLEMENT_BYPASS),
        8.6, "CWE-639 -> CWE-840 -> CWE-862",
        "Subscription SaaS (Okta CVE-2023-20933 pattern)"
    ),
    CVEChainTemplate(
        "CHAIN-006", "XSS -> CSRF -> Account Takeover",
        "Stored XSS enables CSRF token theft, allowing full account takeover "
        "of any user who visits the poisoned page.",
        (VulnCategory.XSS, VulnCategory.CSRF, VulnCategory.AUTH_BYPASS),
        8.8, "CWE-79 -> CWE-352 -> CWE-287",
    ),
    CVEChainTemplate(
        "CHAIN-007", "GraphQL Introspection -> IDOR -> Data Exfiltration",
        "Schema introspection reveals hidden queries/mutations, enabling "
        "targeted IDOR attacks against internal resources.",
        (VulnCategory.GRAPHQL_ABUSE, VulnCategory.IDOR, VulnCategory.INFO_DISCLOSURE),
        7.5, "CWE-200 -> CWE-639",
    ),
    CVEChainTemplate(
        "CHAIN-008", "Deserialization -> Command Execution -> Lateral Movement",
        "Unsafe deserialization enables remote code execution, followed by "
        "lateral movement through internal network.",
        (VulnCategory.DESERIALIZATION, VulnCategory.COMMAND_INJECTION, VulnCategory.SSRF),
        10.0, "CWE-502 -> CWE-78 -> CWE-918",
    ),
    CVEChainTemplate(
        "CHAIN-009", "Open Redirect -> Phishing -> Token Theft",
        "Open redirect abused for OAuth token theft via authorization code "
        "interception through the redirect chain.",
        (VulnCategory.OPEN_REDIRECT, VulnCategory.AUTH_BYPASS),
        7.4, "CWE-601 -> CWE-287",
        "OAuth/OIDC implementations"
    ),
    CVEChainTemplate(
        "CHAIN-010", "Rate Limit Bypass -> Brute Force -> Account Takeover",
        "Missing or bypassable rate limiting enables credential brute force "
        "attacks against authentication endpoints.",
        (VulnCategory.API_RATE_LIMIT_BYPASS, VulnCategory.AUTH_BYPASS),
        7.5, "CWE-307 -> CWE-287",
    ),
    CVEChainTemplate(
        "CHAIN-011", "Payment Manipulation -> Entitlement Bypass -> Business Impact",
        "Client-side price manipulation combined with insufficient server-side "
        "validation enables access to premium features without payment.",
        (VulnCategory.PAYMENT_MANIPULATION, VulnCategory.ENTITLEMENT_BYPASS, VulnCategory.BUSINESS_LOGIC),
        9.1, "CWE-799 -> CWE-862 -> CWE-840",
        "THE core access-without-payment chain this engine exists to find"
    ),
    CVEChainTemplate(
        "CHAIN-012", "Broken Access Control -> Mass Assignment -> Admin Escalation",
        "Broken function-level auth combined with mass assignment allows "
        "normal users to escalate to admin by modifying role fields.",
        (VulnCategory.BROKEN_ACCESS_CONTROL, VulnCategory.MASS_ASSIGNMENT, VulnCategory.PRIVILEGE_ESCALATION),
        9.1, "CWE-285 -> CWE-915 -> CWE-269",
    ),
]


# ---------------------------------------------------------------------------
# 4. TRUST BOUNDARY TAXONOMY (Cloudflare security-audit-skill six-phase)
#
# Trust boundaries for the retrospective analyzer: when a request crosses
# one of these boundaries and the response indicates the check was weak
# or absent, that's a finding.
# ---------------------------------------------------------------------------

class TrustBoundary(str, Enum):
    PUBLIC_TO_AUTHENTICATED = "public_to_authenticated"
    AUTHENTICATED_TO_ADMIN = "authenticated_to_admin"
    USER_TO_USER = "user_to_user"
    API_TO_INTERNAL = "api_to_internal"
    CLIENT_TO_SERVER = "client_to_server"
    PAYMENT_TO_ENTITLEMENT = "payment_to_entitlement"
    WEBHOOK_TO_INTERNAL = "webhook_to_internal"
    FRONTEND_TO_BACKEND = "frontend_to_backend"


TRUST_BOUNDARY_INDICATORS: dict[TrustBoundary, list[re.Pattern[str]]] = {
    TrustBoundary.PUBLIC_TO_AUTHENTICATED: [
        re.compile(r'/(?:login|signin|auth|oauth|token|register|signup)', re.I),
    ],
    TrustBoundary.AUTHENTICATED_TO_ADMIN: [
        re.compile(r'/(?:admin|dashboard|manage|internal|system|config|settings)', re.I),
    ],
    TrustBoundary.USER_TO_USER: [
        re.compile(r'/(?:users?|profiles?|accounts?)/(?:\d+|[a-f0-9-]{20,})', re.I),
    ],
    TrustBoundary.PAYMENT_TO_ENTITLEMENT: [
        re.compile(r'/(?:pay|checkout|subscribe|billing|invoice|charge|purchase|order)', re.I),
    ],
    TrustBoundary.WEBHOOK_TO_INTERNAL: [
        re.compile(r'/(?:webhook|callback|hook|notify|ipn|event)', re.I),
    ],
}


# ---------------------------------------------------------------------------
# 5. CVSS v3.1 SCORING ENGINE (Full-Chain-Sentinel methodology)
#
# Automated CVSS base-score computation from finding attributes. This is
# a simplified but standards-compliant implementation: the official CVSS
# v3.1 specification defines the exact formula.
# ---------------------------------------------------------------------------

class AttackVector(str, Enum):
    NETWORK = "N"
    ADJACENT = "A"
    LOCAL = "L"
    PHYSICAL = "P"

class AttackComplexity(str, Enum):
    LOW = "L"
    HIGH = "H"

class PrivilegesRequired(str, Enum):
    NONE = "N"
    LOW = "L"
    HIGH = "H"

class UserInteraction(str, Enum):
    NONE = "N"
    REQUIRED = "R"

class Scope(str, Enum):
    UNCHANGED = "U"
    CHANGED = "C"

class Impact(str, Enum):
    NONE = "N"
    LOW = "L"
    HIGH = "H"


@dataclass(frozen=True)
class CVSSVector:
    attack_vector: AttackVector = AttackVector.NETWORK
    attack_complexity: AttackComplexity = AttackComplexity.LOW
    privileges_required: PrivilegesRequired = PrivilegesRequired.NONE
    user_interaction: UserInteraction = UserInteraction.NONE
    scope: Scope = Scope.UNCHANGED
    confidentiality: Impact = Impact.NONE
    integrity: Impact = Impact.NONE
    availability: Impact = Impact.NONE

    def base_score(self) -> float:
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}[self.attack_vector.value]
        ac = {"L": 0.77, "H": 0.44}[self.attack_complexity.value]
        sc = self.scope == Scope.CHANGED
        pr_map = {"N": 0.85, "L": 0.68 if sc else 0.62, "H": 0.50 if sc else 0.27}
        pr = pr_map[self.privileges_required.value]
        ui = {"N": 0.85, "R": 0.62}[self.user_interaction.value]
        exploitability = 8.22 * av * ac * pr * ui
        c = {"N": 0, "L": 0.22, "H": 0.56}[self.confidentiality.value]
        i = {"N": 0, "L": 0.22, "H": 0.56}[self.integrity.value]
        a_val = {"N": 0, "L": 0.22, "H": 0.56}[self.availability.value]
        isc_base = 1 - (1 - c) * (1 - i) * (1 - a_val)
        if isc_base <= 0:
            return 0.0
        if sc:
            impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
        else:
            impact = 6.42 * isc_base
        if impact <= 0:
            return 0.0
        raw = impact + exploitability
        if sc:
            raw = min(raw, 10.0)
        score = _roundup(min(raw, 10.0))
        return score

    def vector_string(self) -> str:
        return (f"CVSS:3.1/AV:{self.attack_vector.value}/AC:{self.attack_complexity.value}"
                f"/PR:{self.privileges_required.value}/UI:{self.user_interaction.value}"
                f"/S:{self.scope.value}/C:{self.confidentiality.value}"
                f"/I:{self.integrity.value}/A:{self.availability.value}")

    def severity_label(self) -> str:
        s = self.base_score()
        if s == 0:
            return "none"
        if s < 4.0:
            return "low"
        if s < 7.0:
            return "medium"
        if s < 9.0:
            return "high"
        return "critical"


def _roundup(x: float) -> float:
    """CVSS v3.1 roundup function (spec: round UP to 1 decimal)."""
    import math
    return math.ceil(x * 10) / 10


# Default CVSS vectors for common vulnerability categories
CATEGORY_CVSS_DEFAULTS: dict[VulnCategory, CVSSVector] = {
    VulnCategory.IDOR: CVSSVector(
        confidentiality=Impact.HIGH, integrity=Impact.LOW,
        privileges_required=PrivilegesRequired.LOW),
    VulnCategory.SSRF: CVSSVector(
        confidentiality=Impact.HIGH, integrity=Impact.LOW, availability=Impact.LOW,
        scope=Scope.CHANGED),
    VulnCategory.SQLI: CVSSVector(
        confidentiality=Impact.HIGH, integrity=Impact.HIGH, availability=Impact.HIGH),
    VulnCategory.XSS: CVSSVector(
        confidentiality=Impact.LOW, integrity=Impact.LOW,
        user_interaction=UserInteraction.REQUIRED, scope=Scope.CHANGED),
    VulnCategory.AUTH_BYPASS: CVSSVector(
        confidentiality=Impact.HIGH, integrity=Impact.HIGH,
        privileges_required=PrivilegesRequired.NONE),
    VulnCategory.MASS_ASSIGNMENT: CVSSVector(
        confidentiality=Impact.LOW, integrity=Impact.HIGH,
        privileges_required=PrivilegesRequired.LOW),
    VulnCategory.RACE_CONDITION: CVSSVector(
        integrity=Impact.HIGH, attack_complexity=AttackComplexity.HIGH,
        privileges_required=PrivilegesRequired.LOW),
    VulnCategory.BUSINESS_LOGIC: CVSSVector(
        confidentiality=Impact.LOW, integrity=Impact.HIGH,
        privileges_required=PrivilegesRequired.LOW),
    VulnCategory.PRIVILEGE_ESCALATION: CVSSVector(
        confidentiality=Impact.HIGH, integrity=Impact.HIGH, availability=Impact.HIGH,
        privileges_required=PrivilegesRequired.LOW),
    VulnCategory.DESERIALIZATION: CVSSVector(
        confidentiality=Impact.HIGH, integrity=Impact.HIGH, availability=Impact.HIGH),
    VulnCategory.COMMAND_INJECTION: CVSSVector(
        confidentiality=Impact.HIGH, integrity=Impact.HIGH, availability=Impact.HIGH),
    VulnCategory.PAYMENT_MANIPULATION: CVSSVector(
        integrity=Impact.HIGH, confidentiality=Impact.LOW,
        privileges_required=PrivilegesRequired.LOW),
    VulnCategory.ENTITLEMENT_BYPASS: CVSSVector(
        integrity=Impact.HIGH, confidentiality=Impact.HIGH,
        privileges_required=PrivilegesRequired.LOW),
    VulnCategory.CORS_MISCONFIGURATION: CVSSVector(
        confidentiality=Impact.LOW, integrity=Impact.LOW,
        user_interaction=UserInteraction.REQUIRED),
    VulnCategory.CSRF: CVSSVector(
        integrity=Impact.HIGH, user_interaction=UserInteraction.REQUIRED),
    VulnCategory.OPEN_REDIRECT: CVSSVector(
        confidentiality=Impact.LOW, user_interaction=UserInteraction.REQUIRED,
        scope=Scope.CHANGED),
    VulnCategory.GRAPHQL_ABUSE: CVSSVector(
        confidentiality=Impact.HIGH, integrity=Impact.LOW,
        privileges_required=PrivilegesRequired.LOW),
    VulnCategory.PATH_TRAVERSAL: CVSSVector(
        confidentiality=Impact.HIGH, integrity=Impact.LOW),
    VulnCategory.INFO_DISCLOSURE: CVSSVector(
        confidentiality=Impact.LOW),
    VulnCategory.API_RATE_LIMIT_BYPASS: CVSSVector(
        availability=Impact.LOW, integrity=Impact.LOW,
        attack_complexity=AttackComplexity.LOW),
}


# ---------------------------------------------------------------------------
# 6. PAYLOAD SIGNATURE PATTERNS (PayloadsAllTheThings detection heuristics)
#
# NOT actual payloads -- these detect ECHOED/REFLECTED payload artifacts in
# already-collected response bodies, indicating the target processed user
# input unsafely.
# ---------------------------------------------------------------------------

PAYLOAD_REFLECTION_PATTERNS: list[tuple[VulnCategory, str, re.Pattern[str]]] = [
    # SQL injection reflections
    (VulnCategory.SQLI, "union_select_reflection", re.compile(r'(?:UNION\s+(?:ALL\s+)?SELECT|ORDER\s+BY\s+\d+--)', re.I)),
    (VulnCategory.SQLI, "boolean_blind_indicator", re.compile(r"(?:'\s*(?:AND|OR)\s+(?:'?\d+'?\s*=\s*'?\d+'?|SLEEP|WAITFOR|BENCHMARK))", re.I)),
    (VulnCategory.SQLI, "time_blind_indicator", re.compile(r'(?:SLEEP\s*\(\s*\d+|WAITFOR\s+DELAY|pg_sleep|BENCHMARK\s*\()', re.I)),
    # XSS reflections
    (VulnCategory.XSS, "svg_xss_reflection", re.compile(r'<svg[^>]*\s+on\w+\s*=', re.I)),
    (VulnCategory.XSS, "img_xss_reflection", re.compile(r'<img[^>]*\s+(?:onerror|onload)\s*=', re.I)),
    (VulnCategory.XSS, "javascript_uri_reflection", re.compile(r'javascript\s*:', re.I)),
    # Command injection reflections
    (VulnCategory.COMMAND_INJECTION, "backtick_reflection", re.compile(r'`[^`]+`')),
    (VulnCategory.COMMAND_INJECTION, "pipe_chain_reflection", re.compile(r'\|\s*(?:cat|ls|id|whoami|curl|wget|nc|ncat)\b')),
    # Path traversal reflections
    (VulnCategory.PATH_TRAVERSAL, "traversal_reflection", re.compile(r'(?:\.\./){2,}|(?:%2e%2e%2f){2,}|(?:\.\.\\){2,}', re.I)),
    # SSRF reflections
    (VulnCategory.SSRF, "internal_url_reflection", re.compile(r'(?:http://(?:127\.0\.0\.1|localhost|0\.0\.0\.0|169\.254\.169\.254|10\.\d|172\.(?:1[6-9]|2\d|3[01])|192\.168\.))', re.I)),
    # SSTI (Server-Side Template Injection)
    (VulnCategory.COMMAND_INJECTION, "ssti_reflection", re.compile(r'(?:\$\{[^}]*\}|\{\{[^}]*\}\}|<%[^%]*%>|#\{[^}]*\})', re.I)),
    # LDAP injection
    (VulnCategory.SQLI, "ldap_injection_reflection", re.compile(r'(?:\)\(&|\)\(|\*\)\(|objectClass=\*)', re.I)),
    # NoSQL injection
    (VulnCategory.SQLI, "nosql_injection_indicator", re.compile(r'(?:\$(?:gt|gte|lt|lte|ne|in|nin|regex|where|exists)\b|\$(?:or|and|not)\s*:)', re.I)),
]


# ---------------------------------------------------------------------------
# 7. HUNTING SKILLS (BugHunter's 58 skills distilled into pattern sets)
#
# Each skill is a focused detection strategy an analyzer can apply to a
# specific subset of collected evidence.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class HuntingSkill:
    skill_id: str
    name: str
    category: VulnCategory
    description: str
    indicators: list[str]  # field names or structural patterns to look for
    severity_weight: float  # 0.0-1.0 multiplier on base CVSS


HUNTING_SKILLS: list[HuntingSkill] = [
    HuntingSkill("HUNT-001", "Price Parameter Tampering", VulnCategory.PAYMENT_MANIPULATION,
                 "Detect when price/amount fields in responses differ from expected values or show signs of client-side manipulation acceptance",
                 ["amount", "price", "total", "unit_amount", "subtotal", "cost", "fee"], 1.0),
    HuntingSkill("HUNT-002", "Subscription Tier Confusion", VulnCategory.ENTITLEMENT_BYPASS,
                 "Detect responses that return higher-tier features to lower-tier sessions",
                 ["plan", "tier", "subscription", "entitlement", "feature_flags", "plan_id"], 0.9),
    HuntingSkill("HUNT-003", "Coupon/Promo Stack Abuse", VulnCategory.BUSINESS_LOGIC,
                 "Detect when discount codes stack or when total goes below zero",
                 ["coupon", "discount", "promo", "voucher", "promotion_code", "percent_off", "amount_off"], 0.8),
    HuntingSkill("HUNT-004", "Trial Extension Abuse", VulnCategory.ENTITLEMENT_BYPASS,
                 "Detect when trial period can be extended or restarted improperly",
                 ["trial", "trial_end", "trial_start", "trial_period_days", "trial_status"], 0.7),
    HuntingSkill("HUNT-005", "Webhook Replay Acceptance", VulnCategory.BUSINESS_LOGIC,
                 "Detect when webhooks are accepted without proper idempotency checks",
                 ["webhook", "event_id", "idempotency_key", "created", "livemode"], 0.9),
    HuntingSkill("HUNT-006", "Currency Arbitrage", VulnCategory.PAYMENT_MANIPULATION,
                 "Detect when currency mismatches between request and response indicate arbitrage opportunity",
                 ["currency", "exchange_rate", "converted_amount", "settlement_currency"], 0.8),
    HuntingSkill("HUNT-007", "Quantity Manipulation", VulnCategory.PAYMENT_MANIPULATION,
                 "Detect negative quantities or zero-quantity orders that bypass validation",
                 ["quantity", "qty", "count", "items", "line_items"], 0.9),
    HuntingSkill("HUNT-008", "Refund Excess", VulnCategory.PAYMENT_MANIPULATION,
                 "Detect refund amounts exceeding original payment",
                 ["refund", "refund_amount", "amount_refunded", "refund_status"], 1.0),
    HuntingSkill("HUNT-009", "Idempotency Key Reuse", VulnCategory.RACE_CONDITION,
                 "Detect when idempotency keys are reusable across different resources",
                 ["idempotency_key", "idempotency-key", "request_id"], 0.7),
    HuntingSkill("HUNT-010", "Object Reference Enumeration", VulnCategory.IDOR,
                 "Detect sequential or predictable resource identifiers enabling enumeration",
                 ["id", "user_id", "account_id", "order_id", "invoice_id", "ref"], 0.8),
    HuntingSkill("HUNT-011", "Role Confusion in JWT", VulnCategory.AUTH_BYPASS,
                 "Detect JWT payloads with role/scope fields that differ from expected authorization",
                 ["role", "scope", "permissions", "groups", "is_admin", "admin"], 0.9),
    HuntingSkill("HUNT-012", "Webhook Signature Bypass", VulnCategory.AUTH_BYPASS,
                 "Detect webhooks accepted without proper signature validation",
                 ["stripe-signature", "x-hub-signature", "x-webhook-signature", "sig"], 1.0),
    HuntingSkill("HUNT-013", "API Version Downgrade", VulnCategory.BROKEN_ACCESS_CONTROL,
                 "Detect when older API versions have weaker security controls",
                 ["api-version", "version", "api_version", "v1", "v2"], 0.7),
    HuntingSkill("HUNT-014", "Batch Operation Abuse", VulnCategory.BUSINESS_LOGIC,
                 "Detect batch endpoints that bypass per-item validation",
                 ["batch", "bulk", "items", "operations", "requests"], 0.8),
    HuntingSkill("HUNT-015", "State Machine Violation", VulnCategory.BUSINESS_LOGIC,
                 "Detect responses indicating illegal state transitions were accepted",
                 ["status", "state", "phase", "stage", "lifecycle_status"], 0.9),
    HuntingSkill("HUNT-016", "Feature Flag Leakage", VulnCategory.INFO_DISCLOSURE,
                 "Detect internal feature flags exposed in API responses",
                 ["feature_flags", "features", "flags", "experiments", "ab_test", "feature_enabled"], 0.6),
    HuntingSkill("HUNT-017", "Debug Endpoint Exposure", VulnCategory.INFO_DISCLOSURE,
                 "Detect debug/admin endpoints accessible in production",
                 ["debug", "trace", "profiler", "metrics", "health", "info", "env"], 0.7),
    HuntingSkill("HUNT-018", "Session Fixation Opportunity", VulnCategory.AUTH_BYPASS,
                 "Detect session tokens that survive authentication state changes",
                 ["session_id", "session_token", "sid", "jsessionid", "phpsessid"], 0.8),
    HuntingSkill("HUNT-019", "Metadata Injection", VulnCategory.MASS_ASSIGNMENT,
                 "Detect when metadata/custom fields can be used to inject controlled values",
                 ["metadata", "custom_fields", "extra", "attributes", "properties", "tags"], 0.7),
    HuntingSkill("HUNT-020", "Timing-Based Enumeration", VulnCategory.INFO_DISCLOSURE,
                 "Detect timing differences that reveal existence of resources",
                 [], 0.6),
    HuntingSkill("HUNT-021", "Invoice Manipulation", VulnCategory.PAYMENT_MANIPULATION,
                 "Detect when invoice amounts can be modified after creation",
                 ["invoice", "invoice_id", "amount_due", "amount_paid", "amount_remaining"], 0.9),
    HuntingSkill("HUNT-022", "Subscription Downgrade Retention", VulnCategory.ENTITLEMENT_BYPASS,
                 "Detect when downgraded subscriptions retain higher-tier features",
                 ["plan", "product", "features", "entitlements", "access_level"], 0.8),
    HuntingSkill("HUNT-023", "Webhook Event Type Confusion", VulnCategory.BUSINESS_LOGIC,
                 "Detect when webhook handlers process events they shouldn't accept",
                 ["type", "event_type", "event", "action", "event_name"], 0.7),
    HuntingSkill("HUNT-024", "Multi-Currency Exploit", VulnCategory.PAYMENT_MANIPULATION,
                 "Detect when switching currencies mid-flow yields incorrect conversion",
                 ["currency", "amount", "exchange_rate", "presentment_currency"], 0.8),
]


# ---------------------------------------------------------------------------
# 8. ATTACK SURFACE COMPLETENESS MAP (Shannon + sapper-v2)
#
# Categories of endpoints that a complete security assessment must cover.
# The analyzer checks which of these categories have zero test coverage.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SurfaceCategory:
    category_id: str
    name: str
    path_patterns: list[re.Pattern[str]]
    critical: bool  # must have coverage for a complete assessment
    vuln_categories: list[VulnCategory]  # most relevant vulns for this surface


ATTACK_SURFACE_MAP: list[SurfaceCategory] = [
    SurfaceCategory("SURF-AUTH", "Authentication Surface",
                    [re.compile(r'/(?:login|signin|auth|token|oauth|saml|sso|mfa|2fa|verify)', re.I)],
                    True, [VulnCategory.AUTH_BYPASS, VulnCategory.BROKEN_ACCESS_CONTROL]),
    SurfaceCategory("SURF-PAYMENT", "Payment Surface",
                    [re.compile(r'/(?:pay|checkout|charge|subscribe|billing|invoice|purchase|order|cart)', re.I)],
                    True, [VulnCategory.PAYMENT_MANIPULATION, VulnCategory.ENTITLEMENT_BYPASS, VulnCategory.RACE_CONDITION]),
    SurfaceCategory("SURF-USER", "User Management Surface",
                    [re.compile(r'/(?:user|account|profile|register|signup|password|reset|invite)', re.I)],
                    True, [VulnCategory.IDOR, VulnCategory.PRIVILEGE_ESCALATION, VulnCategory.MASS_ASSIGNMENT]),
    SurfaceCategory("SURF-ADMIN", "Administrative Surface",
                    [re.compile(r'/(?:admin|dashboard|manage|system|config|settings|internal)', re.I)],
                    True, [VulnCategory.BROKEN_ACCESS_CONTROL, VulnCategory.PRIVILEGE_ESCALATION]),
    SurfaceCategory("SURF-WEBHOOK", "Webhook Surface",
                    [re.compile(r'/(?:webhook|callback|hook|notify|ipn|event|listen)', re.I)],
                    True, [VulnCategory.AUTH_BYPASS, VulnCategory.BUSINESS_LOGIC]),
    SurfaceCategory("SURF-API", "API Surface",
                    [re.compile(r'/(?:api|graphql|rest|v\d+)', re.I)],
                    True, [VulnCategory.IDOR, VulnCategory.MASS_ASSIGNMENT, VulnCategory.INFO_DISCLOSURE]),
    SurfaceCategory("SURF-FILE", "File Handling Surface",
                    [re.compile(r'/(?:upload|download|file|attachment|media|asset|image|document)', re.I)],
                    False, [VulnCategory.FILE_UPLOAD, VulnCategory.PATH_TRAVERSAL]),
    SurfaceCategory("SURF-SEARCH", "Search/Query Surface",
                    [re.compile(r'/(?:search|query|find|filter|lookup|suggest|autocomplete)', re.I)],
                    False, [VulnCategory.SQLI, VulnCategory.XSS, VulnCategory.INFO_DISCLOSURE]),
    SurfaceCategory("SURF-EXPORT", "Export/Report Surface",
                    [re.compile(r'/(?:export|report|download|csv|pdf|generate)', re.I)],
                    False, [VulnCategory.SSRF, VulnCategory.PATH_TRAVERSAL, VulnCategory.INFO_DISCLOSURE]),
]


# ---------------------------------------------------------------------------
# 9. ADVERSARIAL VALIDATION RULES (Cloudflare six-phase methodology)
#
# Rules for adversarial thinking about whether a finding is real, a false
# positive, or needs additional evidence. Each rule provides a reason to
# upgrade, downgrade, or confirm a finding's confidence.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ValidationRule:
    rule_id: str
    name: str
    upgrade_condition: str    # when to increase confidence
    downgrade_condition: str  # when to decrease confidence
    weight: float             # influence on final confidence


ADVERSARIAL_VALIDATION_RULES: list[ValidationRule] = [
    ValidationRule("VAL-001", "Cross-Module Corroboration",
                   "Same finding type observed by 2+ independent modules",
                   "Finding observed by only one test case in one module", 0.3),
    ValidationRule("VAL-002", "Temporal Consistency",
                   "Finding reproduces across multiple request timings",
                   "Finding appears only in one timing window (may be transient)", 0.2),
    ValidationRule("VAL-003", "Input Sensitivity",
                   "Finding triggers on multiple different inputs",
                   "Finding triggers on exactly one specific input (may be test artifact)", 0.2),
    ValidationRule("VAL-004", "Status Code Alignment",
                   "Response status code confirms the vulnerability type (e.g. 200 for auth bypass when 401/403 expected)",
                   "Status code is ambiguous or expected for the endpoint", 0.15),
    ValidationRule("VAL-005", "Evidence Completeness",
                   "Full request/response evidence captured with clear causal chain",
                   "Missing request or response evidence; causal chain unclear", 0.15),
]


# ---------------------------------------------------------------------------
# 10. HELPER FUNCTIONS
# ---------------------------------------------------------------------------

def classify_finding_confidence(
    source_count: int,
    cross_module: bool,
    status_code_aligned: bool,
    evidence_complete: bool,
) -> str:
    """Classify a finding as confirmed / needs_validation / rejected based on
    adversarial validation rules (Cloudflare six-phase methodology)."""
    score = 0.0
    if cross_module:
        score += 0.3
    if source_count >= 3:
        score += 0.2
    elif source_count >= 2:
        score += 0.1
    if status_code_aligned:
        score += 0.25
    if evidence_complete:
        score += 0.25
    if score >= 0.6:
        return "confirmed"
    if score >= 0.3:
        return "needs_validation"
    return "low_confidence"


def match_cve_chains(observed_categories: set[VulnCategory]) -> list[CVEChainTemplate]:
    """Matches observed vulnerability categories against known CVE chain
    templates.  Returns chains where ALL steps are present in the observed
    set (a chain is only relevant when every prerequisite is already found)."""
    matches = []
    for chain in CVE_CHAIN_TEMPLATES:
        if all(step in observed_categories for step in chain.steps):
            matches.append(chain)
    return sorted(matches, key=lambda c: c.combined_cvss, reverse=True)


def classify_trust_boundary(path: str) -> list[TrustBoundary]:
    """Classifies a request path into trust boundaries it crosses."""
    boundaries = []
    for boundary, patterns in TRUST_BOUNDARY_INDICATORS.items():
        for pattern in patterns:
            if pattern.search(path):
                boundaries.append(boundary)
                break
    return boundaries


def compute_cvss_for_category(category: VulnCategory) -> CVSSVector:
    """Returns the default CVSS vector for a vulnerability category."""
    return CATEGORY_CVSS_DEFAULTS.get(category, CVSSVector())


def get_hunting_skills_for_category(category: VulnCategory) -> list[HuntingSkill]:
    """Returns all hunting skills relevant to a vulnerability category."""
    return [s for s in HUNTING_SKILLS if s.category == category]


def get_surface_categories_for_path(path: str) -> list[SurfaceCategory]:
    """Returns all attack surface categories a path belongs to."""
    matches = []
    for surface in ATTACK_SURFACE_MAP:
        for pattern in surface.path_patterns:
            if pattern.search(path):
                matches.append(surface)
                break
    return matches
