"""Comprehensive vulnerability knowledge base.

Encodes domain knowledge from 15+ offensive-security knowledge sources into
a dependency-free, pattern-driven taxonomy the discovery layer's retrospective
analyzers can query without sending a single new request.  Every constant here
is a DETECTION HEURISTIC over already-collected evidence (response bodies,
status codes, headers, timings, request shapes) -- not an exploit payload.

Sources synthesized (see the owner's GitHub links for each):
  - Claude-BugHunter: 681 HackerOne reports -> 38 vuln categories, CVE chains
  - Strix:            multi-agent chaining, PoC-validation patterns
  - Cloudflare audit: six-phase methodology, trust-boundary taxonomy
  - Shannon:          white-box attack-surface mapping heuristics
  - PentAGI:          terminal/browser/editor integration patterns
  - PayloadsAllTheThings: injection/auth/deser/upload/SSRF signatures
  - reverse-skill:    reverse-engineering knowledge-base patterns
  - SWE-agent:        systematic issue-resolution workflows
  - Full-Chain-Sentinel: CVSS scoring, evidence-retention methodology
  - sapper-v2:        fact-intent graph, 63-entry offline KB, chaining
  - Awesome-Hacking:  community aggregation of offensive-security toolchains
  - HackTricks:       advanced bypass classes (rate-limit, CAPTCHA, WAF)
  - SecureLayer7:     edge-to-origin parsing discrepancy research
  - OWASP Testing Guide v4.2: systematic web-app testing heuristics
  - PortSwigger Research: HTTP smuggling, cache poisoning, prototype pollution

Design boundary: this module is PURE DATA -- no I/O, no imports beyond
stdlib, no side effects.  Analyzers in analyzers.py import constants and
helper functions from here; nothing here runs against a target.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# 1. VULNERABILITY TAXONOMY (38 categories -- expanded from 24)
# ---------------------------------------------------------------------------

class VulnCategory(str, Enum):
    """38 vulnerability categories covering the full OWASP + HackerOne +
    PortSwigger + HackTricks taxonomy, each with detection heuristics for
    retrospective analysis."""
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
    # --- 14 new categories ---
    SSTI = "ssti"
    NOSQL_INJECTION = "nosql_injection"
    XXE = "xxe"
    JWT_ABUSE = "jwt_abuse"
    PROTOTYPE_POLLUTION = "prototype_pollution"
    CACHE_POISONING = "cache_poisoning"
    HTTP_SMUGGLING = "http_smuggling"
    PARAMETER_POLLUTION = "parameter_pollution"
    TYPE_CONFUSION = "type_confusion"
    INSECURE_DESERIALIZATION_ACTIVE = "insecure_deser_active"
    CAPTCHA_BYPASS = "captcha_bypass"
    RATE_LIMIT_BYPASS_ADVANCED = "rate_limit_bypass_advanced"
    SESSION_FIXATION = "session_fixation"
    WEBHOOK_ABUSE = "webhook_abuse"
    # --- v8: 8 new categories for enterprise attack classes ---
    GRAPHQL_ALIAS_BATCHING = "graphql_alias_batching"
    DEVICE_CODE_FLOW = "device_code_flow"
    OAUTH_CONSENT_PHISHING = "oauth_consent_phishing"
    LOG_TO_LEAK = "log_to_leak"
    AGENTIC_BROWSER_HIJACK = "agentic_browser_hijack"
    WAF_BYPASS = "waf_bypass"
    MCP_TOOL_POISONING = "mcp_tool_poisoning"
    WEBHOOK_FORGERY = "webhook_forgery"


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
    cwe_id: str = ""


RESPONSE_BODY_SIGNATURES: list[DetectionSignature] = [
    # -- IDOR indicators --
    DetectionSignature(VulnCategory.IDOR, "sequential_id_exposure",
                       "response_body", re.compile(r'"(?:id|user_id|account_id|order_id)":\s*(\d{1,8})\b'),
                       "Sequential numeric IDs in responses suggest IDOR risk", 6.5, "medium", "CWE-639"),
    DetectionSignature(VulnCategory.IDOR, "uuid_in_error",
                       "response_body", re.compile(r'(?:not found|unauthorized|forbidden).*[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I),
                       "UUID leaked in error message enables targeted IDOR", 5.3, "medium", "CWE-639"),
    # -- SSRF indicators --
    DetectionSignature(VulnCategory.SSRF, "internal_ip_in_response",
                       "response_body", re.compile(r'\b(?:127\.0\.0\.1|0\.0\.0\.0|localhost|169\.254\.169\.254|::1)\b'),
                       "Internal/metadata IPs in response body indicate SSRF risk", 8.6, "high", "CWE-918"),
    DetectionSignature(VulnCategory.SSRF, "cloud_metadata_leak",
                       "response_body", re.compile(r'(?:ami-[0-9a-f]+|i-[0-9a-f]+|arn:aws|instance-id|availability-zone|meta-data)', re.I),
                       "Cloud metadata in response indicates SSRF or misconfiguration", 9.0, "high", "CWE-918"),
    DetectionSignature(VulnCategory.SSRF, "dns_rebinding_indicator",
                       "response_body", re.compile(r'(?:1u\.ms|nip\.io|sslip\.io|xip\.io|localtest\.me|lvh\.me|vcap\.me|bewildcard\.com)', re.I),
                       "DNS rebinding domain in response suggests SSRF via rebinding", 8.0, "high", "CWE-918"),
    DetectionSignature(VulnCategory.SSRF, "ipv6_bypass_indicator",
                       "response_body", re.compile(r'(?:\[::(?:ffff:(?:127\.0\.0\.1|7f00:1)|1)\]|::ffff:(?:127\.0\.0\.1|7f00:0001))', re.I),
                       "IPv6-mapped loopback address in response indicates SSRF filter bypass", 8.5, "high", "CWE-918"),
    DetectionSignature(VulnCategory.SSRF, "url_parser_differential",
                       "response_body", re.compile(r'(?:http://[^/]*@127\.0\.0\.1|http://127\.0\.0\.1#|http://127\.1)', re.I),
                       "URL with authentication/fragment confusion targeting internal IP", 8.2, "medium", "CWE-918"),
    # -- SQLi indicators --
    DetectionSignature(VulnCategory.SQLI, "sql_error_in_response",
                       "response_body", re.compile(r'(?:SQL\s*syntax|mysql_fetch|pg_query|sqlite3?\.|ORA-\d{5}|quoted string not properly terminated|unclosed quotation mark)', re.I),
                       "SQL error messages indicate injection vulnerability", 8.6, "high", "CWE-89"),
    DetectionSignature(VulnCategory.SQLI, "orm_error_leak",
                       "response_body", re.compile(r'(?:ActiveRecord|Sequelize|Prisma|TypeORM|Hibernate|SQLAlchemy).*(?:Error|Exception)', re.I),
                       "ORM error leak may reveal database structure", 5.3, "medium", "CWE-89"),
    # -- XSS indicators --
    DetectionSignature(VulnCategory.XSS, "unescaped_input_reflection",
                       "response_body", re.compile(r'<script[^>]*>[^<]*(?:alert|prompt|confirm|document\.|window\.)', re.I),
                       "Unescaped script execution in response", 6.1, "high", "CWE-79"),
    DetectionSignature(VulnCategory.XSS, "event_handler_reflection",
                       "response_body", re.compile(r'(?:on(?:error|load|click|mouseover|focus))\s*=\s*["\']?[^"\'>\s]+', re.I),
                       "Event handler reflection suggests XSS", 6.1, "medium", "CWE-79"),
    # -- Auth bypass indicators --
    DetectionSignature(VulnCategory.AUTH_BYPASS, "auth_header_in_response",
                       "response_body", re.compile(r'(?:bearer|token|session_id|auth_token|access_token)\s*[=:]\s*["\']?[A-Za-z0-9._-]{20,}', re.I),
                       "Authentication token leaked in response body", 7.5, "high", "CWE-200"),
    DetectionSignature(VulnCategory.AUTH_BYPASS, "default_credentials_hint",
                       "response_body", re.compile(r'(?:default.*(?:password|credential|login)|admin.*admin|test.*test123)', re.I),
                       "Default credential hints in response", 7.2, "medium", "CWE-798"),
    DetectionSignature(VulnCategory.AUTH_BYPASS, "oauth_misconfiguration",
                       "response_body", re.compile(r'(?:redirect_uri.*(?:mismatch|invalid)|invalid_grant|unsupported_response_type|authorization_code.*expired)', re.I),
                       "OAuth misconfiguration error reveals auth flow weakness", 6.5, "medium", "CWE-287"),
    DetectionSignature(VulnCategory.AUTH_BYPASS, "saml_assertion_leak",
                       "response_body", re.compile(r'(?:saml[:\s]*(?:Assertion|Response|AuthnStatement)|urn:oasis:names:tc:SAML)', re.I),
                       "SAML assertion data in response body", 7.0, "high", "CWE-287"),
    # -- Command injection indicators --
    DetectionSignature(VulnCategory.COMMAND_INJECTION, "shell_output_in_response",
                       "response_body", re.compile(r'(?:uid=\d+|root:x:0|/bin/(?:bash|sh)|total\s+\d+\s+drwx)', re.I),
                       "Shell command output in response body", 9.8, "high", "CWE-78"),
    # -- Path traversal indicators --
    DetectionSignature(VulnCategory.PATH_TRAVERSAL, "traversal_artifact",
                       "response_body", re.compile(r'(?:\.\./\.\./|root:.*:0:0:|boot\.ini|\[extensions\]|<web-app)', re.I),
                       "Path traversal artifacts in response", 7.5, "high", "CWE-22"),
    # -- Deserialization indicators --
    DetectionSignature(VulnCategory.DESERIALIZATION, "java_deser_marker",
                       "response_body", re.compile(r'(?:java\.lang\.Runtime|java\.io\.ObjectInputStream|ysoserial|CommonsCollections|InvokerTransformer)', re.I),
                       "Java deserialization gadget chain indicators", 9.8, "high", "CWE-502"),
    DetectionSignature(VulnCategory.DESERIALIZATION, "pickle_marker",
                       "response_body", re.compile(r'(?:__reduce__|pickle\.loads|cPickle|_reconstructor)', re.I),
                       "Python pickle deserialization indicators", 9.0, "high", "CWE-502"),
    # -- Info disclosure --
    DetectionSignature(VulnCategory.INFO_DISCLOSURE, "version_disclosure",
                       "response_body", re.compile(r'(?:(?:nginx|apache|php|node|express|django|flask|rails|spring|tomcat)[/\s]*v?[\d.]+)', re.I),
                       "Server/framework version disclosure", 3.7, "low", "CWE-200"),
    DetectionSignature(VulnCategory.INFO_DISCLOSURE, "source_code_leak",
                       "response_body", re.compile(r'(?:def\s+\w+\s*\(|function\s+\w+\s*\(|class\s+\w+\s*(?:extends|implements|{)|\bimport\s+\w+\b.*\bfrom\b)', re.I),
                       "Source code fragments in response", 5.3, "medium", "CWE-540"),
    DetectionSignature(VulnCategory.INFO_DISCLOSURE, "environment_var_leak",
                       "response_body", re.compile(r'(?:DATABASE_URL|SECRET_KEY|AWS_SECRET|STRIPE_SECRET|API_KEY|REDIS_URL|MONGODB_URI)\s*[=:]', re.I),
                       "Environment variable names/values in response", 7.5, "high", "CWE-215"),
    # -- GraphQL abuse --
    DetectionSignature(VulnCategory.GRAPHQL_ABUSE, "introspection_enabled",
                       "response_body", re.compile(r'(?:__schema|__type|queryType|mutationType|subscriptionType)', re.I),
                       "GraphQL introspection enabled exposes entire schema", 5.3, "high", "CWE-200"),
    DetectionSignature(VulnCategory.GRAPHQL_ABUSE, "graphql_batching_response",
                       "response_body", re.compile(r'\[\s*\{\s*"data"\s*:', re.I),
                       "GraphQL batched response indicates query batching is enabled", 4.5, "medium", "CWE-770"),
    DetectionSignature(VulnCategory.GRAPHQL_ABUSE, "graphql_alias_abuse",
                       "response_body", re.compile(r'"(?:alias_\d+|a\d+|q\d+)"\s*:\s*\{', re.I),
                       "GraphQL alias-based amplification response detected", 5.0, "medium", "CWE-770"),
    # -- Open redirect --
    DetectionSignature(VulnCategory.OPEN_REDIRECT, "redirect_in_body",
                       "response_body", re.compile(r'(?:redirect_uri|return_url|next|continue|goto|dest|destination|redir|return_to)\s*[=:]\s*["\']?https?://', re.I),
                       "Open redirect parameter in response body", 4.7, "medium", "CWE-601"),
    # -- Payment manipulation --
    DetectionSignature(VulnCategory.PAYMENT_MANIPULATION, "price_in_response",
                       "response_body", re.compile(r'"(?:amount|price|total|unit_amount|cost)":\s*(?:0(?:\.0+)?|-\d+|0\.0*1)\b'),
                       "Zero/negative/trivial price in payment response", 8.1, "high", "CWE-799"),
    DetectionSignature(VulnCategory.PAYMENT_MANIPULATION, "currency_mismatch",
                       "response_body", re.compile(r'"currency":\s*"(\w{3})".*?"currency":\s*"(?!\1)\w{3}"', re.S),
                       "Currency mismatch within same payment response", 6.5, "medium", "CWE-799"),
    DetectionSignature(VulnCategory.PAYMENT_MANIPULATION, "quantity_overflow",
                       "response_body", re.compile(r'"(?:quantity|qty)":\s*(?:-\d+|0|(?:214748|999999)\d+)\b'),
                       "Overflow/negative quantity accepted in payment", 8.5, "high", "CWE-190"),
    DetectionSignature(VulnCategory.PAYMENT_MANIPULATION, "coupon_stacking",
                       "response_body", re.compile(r'"(?:discount|percent_off)":\s*(?:1\d{2}|[2-9]\d{2,})\b'),
                       "Discount exceeds 100% indicating coupon stacking", 8.0, "high", "CWE-840"),
    DetectionSignature(VulnCategory.PAYMENT_MANIPULATION, "subscription_state_manipulation",
                       "response_body", re.compile(r'"(?:status|subscription_status)":\s*"(?:active|trialing)".*?"(?:amount_due|amount_paid)":\s*0\b', re.S),
                       "Active subscription with zero payment amount", 9.0, "high", "CWE-862"),
    # -- SSTI indicators (new) --
    DetectionSignature(VulnCategory.SSTI, "ssti_math_evaluation",
                       "response_body", re.compile(r'(?:49|7777777|12345679\d)'),
                       "Template math evaluation (7*7=49) in response suggests SSTI", 4.0, "low", "CWE-1336"),
    DetectionSignature(VulnCategory.SSTI, "ssti_jinja_marker",
                       "response_body", re.compile(r'(?:jinja2\.exceptions|UndefinedError|TemplateSyntaxError|TemplateNotFound)', re.I),
                       "Jinja2 template error in response body", 8.5, "high", "CWE-1336"),
    DetectionSignature(VulnCategory.SSTI, "ssti_freemarker",
                       "response_body", re.compile(r'(?:freemarker\.template|FreeMarkerException|ParseException.*template)', re.I),
                       "FreeMarker template error in response body", 8.5, "high", "CWE-1336"),
    DetectionSignature(VulnCategory.SSTI, "ssti_twig_marker",
                       "response_body", re.compile(r'(?:Twig_Error|Twig\\Error|twig\.exception)', re.I),
                       "Twig template error in response body", 8.5, "high", "CWE-1336"),
    DetectionSignature(VulnCategory.SSTI, "ssti_velocity",
                       "response_body", re.compile(r'(?:org\.apache\.velocity|VelocityException|#set\s*\(\s*\$)', re.I),
                       "Apache Velocity template error in response body", 8.5, "high", "CWE-1336"),
    # -- NoSQL injection indicators (new) --
    DetectionSignature(VulnCategory.NOSQL_INJECTION, "nosql_operator_in_response",
                       "response_body", re.compile(r'(?:\$(?:gt|gte|lt|lte|ne|in|nin|regex|where|exists|elemMatch)\b)', re.I),
                       "MongoDB query operator in response body indicates NoSQL injection", 7.5, "high", "CWE-943"),
    DetectionSignature(VulnCategory.NOSQL_INJECTION, "nosql_error_message",
                       "response_body", re.compile(r'(?:MongoError|MongoServerError|BSONTypeError|CastError.*ObjectId|BSON|ns not found|not master)', re.I),
                       "MongoDB error in response body reveals NoSQL injection surface", 6.5, "high", "CWE-943"),
    DetectionSignature(VulnCategory.NOSQL_INJECTION, "nosql_js_injection",
                       "response_body", re.compile(r'(?:\$where\s*:\s*["\']function|mapReduce|group\s*:\s*\{.*?\$keyf)', re.I),
                       "NoSQL JavaScript injection indicators in response", 8.0, "high", "CWE-943"),
    # -- XXE indicators (new) --
    DetectionSignature(VulnCategory.XXE, "xxe_entity_marker",
                       "response_body", re.compile(r'(?:<!ENTITY|SYSTEM\s+["\']file://|SYSTEM\s+["\']http://|PUBLIC\s+["\'-])', re.I),
                       "XML entity declaration in response body indicates XXE processing", 8.5, "high", "CWE-611"),
    DetectionSignature(VulnCategory.XXE, "xxe_error_message",
                       "response_body", re.compile(r'(?:SAXParseException|XMLParseError|DOMException|lxml\.etree|libxml2|expat\.ExpatError)', re.I),
                       "XML parser error in response body reveals XXE surface", 6.0, "medium", "CWE-611"),
    DetectionSignature(VulnCategory.XXE, "xxe_external_dtd",
                       "response_body", re.compile(r'(?:DOCTYPE\s+\w+\s+SYSTEM|ENTITY\s+%\s+\w+\s+SYSTEM)', re.I),
                       "External DTD reference indicates XXE processing", 8.5, "high", "CWE-611"),
    # -- JWT abuse indicators (new) --
    DetectionSignature(VulnCategory.JWT_ABUSE, "jwt_alg_none",
                       "response_body", re.compile(r'"alg"\s*:\s*"(?:none|None|NONE|nOnE)"'),
                       "JWT with algorithm 'none' indicates signature bypass vulnerability", 9.0, "high", "CWE-347"),
    DetectionSignature(VulnCategory.JWT_ABUSE, "jwt_hs256_confusion",
                       "response_body", re.compile(r'"alg"\s*:\s*"HS256".*?"(?:kty|n|e)"\s*:', re.S),
                       "JWT algorithm confusion (RS256 key used as HS256 secret)", 9.0, "high", "CWE-327"),
    DetectionSignature(VulnCategory.JWT_ABUSE, "jwt_kid_injection",
                       "response_body", re.compile(r'"kid"\s*:\s*"(?:\.\./|/|sql|;|union|select|\||`)', re.I),
                       "JWT kid parameter injection indicates key retrieval bypass", 8.5, "high", "CWE-347"),
    DetectionSignature(VulnCategory.JWT_ABUSE, "jwt_jku_ssrf",
                       "response_body", re.compile(r'"jku"\s*:\s*"https?://(?:127\.0\.0\.1|localhost|10\.|172\.(?:1[6-9]|2\d|3[01])|192\.168\.)', re.I),
                       "JWT jku pointing to internal URL indicates SSRF via JWT", 8.5, "high", "CWE-918"),
    # -- Prototype pollution indicators (new) --
    DetectionSignature(VulnCategory.PROTOTYPE_POLLUTION, "proto_in_response",
                       "response_body", re.compile(r'(?:__proto__|constructor\s*\.\s*prototype|Object\.prototype)', re.I),
                       "Prototype pollution indicators in response body", 7.5, "medium", "CWE-1321"),
    DetectionSignature(VulnCategory.PROTOTYPE_POLLUTION, "proto_pollution_accepted",
                       "response_body", re.compile(r'"__proto__"\s*:\s*\{|"constructor"\s*:\s*\{.*?"prototype"', re.I),
                       "Server accepted __proto__ or constructor.prototype in response", 8.0, "high", "CWE-1321"),
    # -- Cache poisoning indicators (new) --
    DetectionSignature(VulnCategory.CACHE_POISONING, "forwarded_host_reflected",
                       "response_body", re.compile(r'(?:X-Forwarded-Host|X-Original-URL|X-Rewrite-URL)\s*[:=]', re.I),
                       "Forwarded host header reflected in response enables cache poisoning", 7.0, "medium", "CWE-444"),
    DetectionSignature(VulnCategory.CACHE_POISONING, "cache_key_mismatch",
                       "response_body", re.compile(r'(?:x-cache:\s*(?:HIT|MISS)|cf-cache-status:\s*(?:HIT|MISS)|age:\s*\d+)', re.I),
                       "Cache status header reveals caching behaviour for poisoning", 4.0, "low", "CWE-444"),
    # -- HTTP smuggling indicators (new) --
    DetectionSignature(VulnCategory.HTTP_SMUGGLING, "cl_te_discrepancy",
                       "response_body", re.compile(r'(?:content-length.*transfer-encoding|transfer-encoding.*content-length)', re.I),
                       "CL/TE header discrepancy in response indicates smuggling surface", 8.0, "high", "CWE-444"),
    DetectionSignature(VulnCategory.HTTP_SMUGGLING, "smuggling_error",
                       "response_body", re.compile(r'(?:request smuggling|desync|invalid chunk size|malformed Transfer-Encoding|bad chunk|unexpected body)', re.I),
                       "HTTP desynchronization error message", 7.5, "high", "CWE-444"),
    # -- Parameter pollution indicators (new) --
    DetectionSignature(VulnCategory.PARAMETER_POLLUTION, "duplicate_param_echo",
                       "response_body", re.compile(r'(?:duplicate.*(?:parameter|key|field)|multiple values.*(?:parameter|key))', re.I),
                       "Server error from duplicate parameters suggests HPP surface", 5.0, "medium", "CWE-235"),
    # -- Type confusion indicators (new) --
    DetectionSignature(VulnCategory.TYPE_CONFUSION, "type_error_message",
                       "response_body", re.compile(r'(?:TypeError|type\s+error|expected\s+(?:string|number|boolean|array|object)\s+got|invalid.*type|Cannot\s+read\s+propert)', re.I),
                       "Type confusion error message in response", 5.5, "medium", "CWE-843"),
    DetectionSignature(VulnCategory.TYPE_CONFUSION, "type_coercion_indicator",
                       "response_body", re.compile(r'"(?:amount|price|quantity|count)":\s*"(?:-?\d+)"'),
                       "Numeric field returned as string suggests type coercion issue", 5.0, "low", "CWE-843"),
    # -- Session fixation indicators (new) --
    DetectionSignature(VulnCategory.SESSION_FIXATION, "session_unchanged_after_auth",
                       "response_body", re.compile(r'(?:session.*(?:fixation|fixed|unchanged|reuse)|same.*session.*(?:before|after))', re.I),
                       "Session ID unchanged after authentication state change", 7.0, "medium", "CWE-384"),
    # -- Webhook abuse indicators (new) --
    DetectionSignature(VulnCategory.WEBHOOK_ABUSE, "webhook_no_signature_check",
                       "response_body", re.compile(r'(?:webhook.*(?:received|accepted|processed).*(?:no|without|missing).*(?:signature|verification|validation))', re.I),
                       "Webhook processed without signature verification", 8.0, "high", "CWE-345"),
    DetectionSignature(VulnCategory.WEBHOOK_ABUSE, "webhook_replay_accepted",
                       "response_body", re.compile(r'(?:event.*(?:already|previously).*processed|duplicate.*event|idempotency.*(?:ignored|missing|not checked))', re.I),
                       "Webhook replay accepted without idempotency check", 7.5, "high", "CWE-294"),
    # -- CAPTCHA bypass indicators (new) --
    DetectionSignature(VulnCategory.CAPTCHA_BYPASS, "captcha_token_reuse",
                       "response_body", re.compile(r'(?:captcha.*(?:token|response).*(?:reused|expired|invalid)|recaptcha.*(?:expired|already used))', re.I),
                       "CAPTCHA token reuse or expiry error reveals bypass surface", 5.0, "medium", "CWE-863"),
    DetectionSignature(VulnCategory.CAPTCHA_BYPASS, "captcha_missing_on_sensitive",
                       "response_body", re.compile(r'(?:no.*captcha|captcha.*(?:disabled|not required|skipped))', re.I),
                       "CAPTCHA not required on sensitive endpoint", 5.5, "medium", "CWE-863"),
    # -- Advanced rate limit bypass indicators (new) --
    DetectionSignature(VulnCategory.RATE_LIMIT_BYPASS_ADVANCED, "rate_limit_header_leak",
                       "response_body", re.compile(r'(?:x-ratelimit-(?:limit|remaining|reset)|retry-after|rate.*limit.*exceeded)', re.I),
                       "Rate limit headers in response reveal throttling behaviour", 3.5, "low", "CWE-770"),
    DetectionSignature(VulnCategory.RATE_LIMIT_BYPASS_ADVANCED, "rate_limit_inconsistency",
                       "response_body", re.compile(r'(?:x-ratelimit-remaining:\s*(?:-\d+|0))', re.I),
                       "Negative or zero remaining rate limit counter", 5.0, "medium", "CWE-770"),
    # -- v8: GraphQL alias batching indicators --
    DetectionSignature(VulnCategory.GRAPHQL_ALIAS_BATCHING, "alias_batching_response",
                       "response_body", re.compile(r'"(?:a\d{2,}|alias_\d+|q\d{2,})"\s*:\s*\{.*?"(?:a\d{2,}|alias_\d+|q\d{2,})"\s*:', re.S),
                       "Multiple aliased query results indicate alias batching is unrestricted", 7.0, "high", "CWE-770"),
    DetectionSignature(VulnCategory.GRAPHQL_ALIAS_BATCHING, "graphql_complexity_absent",
                       "response_body", re.compile(r'(?:query\s+complexity|cost\s+limit|depth\s+limit).*(?:not\s+enabled|disabled)', re.I),
                       "GraphQL query complexity/depth limits not enforced", 6.0, "medium", "CWE-770"),
    # -- v8: Device code flow indicators --
    DetectionSignature(VulnCategory.DEVICE_CODE_FLOW, "device_code_endpoint_exposed",
                       "response_body", re.compile(r'"(?:device_code|user_code|verification_uri|verification_url)"', re.I),
                       "Device code flow endpoint returns device/user codes for phishing", 7.5, "high", "CWE-287"),
    DetectionSignature(VulnCategory.DEVICE_CODE_FLOW, "device_code_no_binding",
                       "response_body", re.compile(r'(?:expires_in.*(?:600|900|1[0-8]00))', re.I),
                       "Long device code expiry (10+ min) enables phishing window", 6.5, "medium", "CWE-613"),
    # -- v8: OAuth consent phishing indicators --
    DetectionSignature(VulnCategory.OAUTH_CONSENT_PHISHING, "oauth_scope_overreach",
                       "response_body", re.compile(r'"scope"\s*:\s*"[^"]*(?:admin|write|delete|manage|full_access|openid\s+profile\s+email\s+offline_access)', re.I),
                       "OAuth consent scope includes dangerous permissions", 7.0, "high", "CWE-287"),
    DetectionSignature(VulnCategory.OAUTH_CONSENT_PHISHING, "consent_auto_approve",
                       "response_body", re.compile(r'(?:consent.*(?:auto|skip|bypass)|prompt\s*=\s*none)', re.I),
                       "OAuth consent screen can be auto-approved or bypassed", 7.5, "high", "CWE-862"),
    # -- v8: Log-To-Leak metadata injection indicators --
    DetectionSignature(VulnCategory.LOG_TO_LEAK, "structured_log_injection",
                       "response_body", re.compile(r'(?:\{[^}]*"(?:level|severity|msg|message|logger)"[^}]*\})', re.I),
                       "Structured log entry in response body exposes Log-To-Leak surface", 6.5, "medium", "CWE-117"),
    DetectionSignature(VulnCategory.LOG_TO_LEAK, "log_metadata_reflected",
                       "response_body", re.compile(r'(?:user-agent|referer|x-forwarded-for|x-request-id).*(?:logged|recorded|stored)', re.I),
                       "Request metadata reflected in logs enables injection", 7.0, "high", "CWE-117"),
    # -- v8: WAF bypass indicators --
    DetectionSignature(VulnCategory.WAF_BYPASS, "waf_body_size_limit_exposed",
                       "response_body", re.compile(r'(?:request.*(?:too large|body.*(?:exceeds|limit))|413\s+(?:Request Entity|Payload))', re.I),
                       "WAF body size limit exposed - payloads beyond threshold pass uninspected", 7.5, "high", "CWE-693"),
    DetectionSignature(VulnCategory.WAF_BYPASS, "waf_identification_header",
                       "response_body", re.compile(r'(?:x-(?:akamai|cloudflare|sucuri|imperva|incapsula|aws-waf|waf)-|server:\s*(?:cloudflare|akamaighost|bigip))', re.I),
                       "WAF vendor identified - vendor-specific bypass techniques applicable", 5.0, "medium", "CWE-693"),
    # -- v8: Agentic browser hijack indicators --
    DetectionSignature(VulnCategory.AGENTIC_BROWSER_HIJACK, "agent_instruction_in_page",
                       "response_body", re.compile(r'(?:<!--\s*(?:SYSTEM|ASSISTANT|INSTRUCTION)|data-(?:agent|prompt|instruction)=)', re.I),
                       "Hidden agent instructions in page content enable browser hijacking", 8.0, "high", "CWE-74"),
    DetectionSignature(VulnCategory.AGENTIC_BROWSER_HIJACK, "mcp_tool_reference_in_page",
                       "response_body", re.compile(r'(?:mcp://|tool_call|function_call|agent_action)', re.I),
                       "MCP/tool references in page content enable agent manipulation", 7.5, "high", "CWE-74"),
    # -- v8: MCP tool poisoning indicators --
    DetectionSignature(VulnCategory.MCP_TOOL_POISONING, "mcp_server_override",
                       "response_body", re.compile(r'(?:mcp.*(?:server|tool).*(?:override|redirect|proxy)|tool_description.*(?:actually|instead|ignore))', re.I),
                       "MCP tool poisoning attempt via description override", 8.5, "high", "CWE-94"),
    DetectionSignature(VulnCategory.MCP_TOOL_POISONING, "mcp_cross_server_injection",
                       "response_body", re.compile(r'(?:cross.*server.*(?:call|invoke|query)|tool_name.*(?:\.\./|;|&&|\|))', re.I),
                       "Cross-MCP-server injection attempt detected", 8.5, "high", "CWE-77"),
    # -- v8: Webhook forgery indicators --
    DetectionSignature(VulnCategory.WEBHOOK_FORGERY, "webhook_no_sig_header",
                       "response_body", re.compile(r'(?:stripe-signature|x-hub-signature|paypal-transmission-sig).*(?:missing|absent|empty|null)', re.I),
                       "Webhook processed without required signature header", 9.0, "high", "CWE-345"),
    DetectionSignature(VulnCategory.WEBHOOK_FORGERY, "webhook_empty_secret_accepted",
                       "response_body", re.compile(r'(?:signing.*secret.*(?:empty|null|default|not set)|webhook.*(?:secret|key).*(?:empty|not configured))', re.I),
                       "Webhook signing secret empty/default - CVE-2026-41432 pattern", 9.5, "high", "CWE-345"),
]

# Header-based signatures
HEADER_SIGNATURES: list[DetectionSignature] = [
    DetectionSignature(VulnCategory.CORS_MISCONFIGURATION, "cors_wildcard",
                       "response_headers", re.compile(r'access-control-allow-origin:\s*\*', re.I),
                       "Wildcard CORS allows any origin", 5.4, "high", "CWE-942"),
    DetectionSignature(VulnCategory.CORS_MISCONFIGURATION, "cors_null_origin",
                       "response_headers", re.compile(r'access-control-allow-origin:\s*null', re.I),
                       "CORS allows null origin (sandbox bypass)", 5.4, "high", "CWE-942"),
    DetectionSignature(VulnCategory.CORS_MISCONFIGURATION, "cors_credentials_with_wildcard",
                       "response_headers", re.compile(r'access-control-allow-credentials:\s*true', re.I),
                       "CORS with credentials flag set", 6.5, "medium", "CWE-942"),
    DetectionSignature(VulnCategory.INFO_DISCLOSURE, "server_header_version",
                       "response_headers", re.compile(r'server:\s*\S+/[\d.]+', re.I),
                       "Server version in headers", 3.1, "low", "CWE-200"),
    DetectionSignature(VulnCategory.INFO_DISCLOSURE, "powered_by_header",
                       "response_headers", re.compile(r'x-powered-by:', re.I),
                       "X-Powered-By header reveals technology stack", 3.1, "low", "CWE-200"),
    DetectionSignature(VulnCategory.AUTH_BYPASS, "missing_security_headers",
                       "response_headers", None,
                       "Missing critical security headers (CSP, HSTS, X-Frame-Options)", 4.3, "low", "CWE-693"),
    DetectionSignature(VulnCategory.CSRF, "no_csrf_protection",
                       "response_headers", None,
                       "No SameSite cookie attribute or CSRF token", 5.4, "medium", "CWE-352"),
    # --- New header signatures ---
    DetectionSignature(VulnCategory.INFO_DISCLOSURE, "server_timing_exposed",
                       "response_headers", re.compile(r'server-timing:', re.I),
                       "Server-Timing header exposes backend timing details", 4.0, "medium", "CWE-200"),
    DetectionSignature(VulnCategory.INFO_DISCLOSURE, "via_header_exposed",
                       "response_headers", re.compile(r'via:\s*\d', re.I),
                       "Via header reveals proxy/CDN infrastructure topology", 3.5, "low", "CWE-200"),
    DetectionSignature(VulnCategory.AUTH_BYPASS, "insecure_cookie_no_secure",
                       "response_headers", re.compile(r'set-cookie:(?!.*;\s*secure\b).*=', re.I),
                       "Cookie set without Secure flag", 4.5, "medium", "CWE-614"),
    DetectionSignature(VulnCategory.AUTH_BYPASS, "insecure_cookie_no_httponly",
                       "response_headers", re.compile(r'set-cookie:(?!.*;\s*httponly\b).*=', re.I),
                       "Cookie set without HttpOnly flag", 4.0, "medium", "CWE-1004"),
    DetectionSignature(VulnCategory.AUTH_BYPASS, "insecure_cookie_no_samesite",
                       "response_headers", re.compile(r'set-cookie:(?!.*;\s*samesite\b).*=', re.I),
                       "Cookie set without SameSite attribute", 4.5, "medium", "CWE-1275"),
    DetectionSignature(VulnCategory.XSS, "csp_unsafe_inline",
                       "response_headers", re.compile(r"content-security-policy:.*'unsafe-inline'", re.I),
                       "CSP allows unsafe-inline, weakening XSS protection", 4.0, "high", "CWE-79"),
    DetectionSignature(VulnCategory.XSS, "csp_unsafe_eval",
                       "response_headers", re.compile(r"content-security-policy:.*'unsafe-eval'", re.I),
                       "CSP allows unsafe-eval, weakening XSS protection", 4.5, "high", "CWE-79"),
    DetectionSignature(VulnCategory.AUTH_BYPASS, "hsts_no_includesubdomains",
                       "response_headers", re.compile(r'strict-transport-security:(?!.*includeSubDomains)', re.I),
                       "HSTS without includeSubDomains", 3.5, "medium", "CWE-319"),
    DetectionSignature(VulnCategory.INFO_DISCLOSURE, "missing_coep",
                       "response_headers", None,
                       "Missing Cross-Origin-Embedder-Policy header", 3.0, "low", "CWE-693"),
    DetectionSignature(VulnCategory.INFO_DISCLOSURE, "missing_coop",
                       "response_headers", None,
                       "Missing Cross-Origin-Opener-Policy header", 3.0, "low", "CWE-693"),
    DetectionSignature(VulnCategory.INFO_DISCLOSURE, "missing_corp",
                       "response_headers", None,
                       "Missing Cross-Origin-Resource-Policy header", 3.0, "low", "CWE-693"),
    DetectionSignature(VulnCategory.INFO_DISCLOSURE, "deprecated_feature_policy",
                       "response_headers", re.compile(r'feature-policy:', re.I),
                       "Deprecated Feature-Policy header (use Permissions-Policy)", 2.0, "low", "CWE-693"),
    DetectionSignature(VulnCategory.INFO_DISCLOSURE, "sensitive_no_cache_control",
                       "response_headers", re.compile(r'(?!.*cache-control).*(?:set-cookie|authorization)', re.I),
                       "Sensitive headers without Cache-Control: no-store", 4.0, "medium", "CWE-525"),
]


# ---------------------------------------------------------------------------
# 3. KNOWN CVE CHAIN PATTERNS (expanded: 27 chains)
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
    # --- 15 new chains ---
    CVEChainTemplate(
        "CHAIN-013", "SSTI -> Command Execution -> Data Exfiltration",
        "Server-side template injection allows arbitrary code execution, enabling "
        "data exfiltration through the template engine's execution context.",
        (VulnCategory.SSTI, VulnCategory.COMMAND_INJECTION, VulnCategory.INFO_DISCLOSURE),
        9.8, "CWE-1336 -> CWE-78 -> CWE-200",
        "Common in Python Flask/Jinja2, Java FreeMarker, PHP Twig"
    ),
    CVEChainTemplate(
        "CHAIN-014", "HTTP Smuggling -> Cache Poisoning -> XSS",
        "HTTP request smuggling poisons CDN/proxy cache with attacker-controlled "
        "content, delivering stored XSS to all subsequent visitors.",
        (VulnCategory.HTTP_SMUGGLING, VulnCategory.CACHE_POISONING, VulnCategory.XSS),
        9.1, "CWE-444 -> CWE-444 -> CWE-79",
        "PortSwigger Research: HTTP desync attacks"
    ),
    CVEChainTemplate(
        "CHAIN-015", "JWT Abuse -> Auth Bypass -> IDOR",
        "JWT signature bypass (alg:none, key confusion) grants forged authentication, "
        "enabling IDOR attacks against any user's resources.",
        (VulnCategory.JWT_ABUSE, VulnCategory.AUTH_BYPASS, VulnCategory.IDOR),
        9.3, "CWE-347 -> CWE-287 -> CWE-639",
        "JWT implementations in Node.js, Go, Python"
    ),
    CVEChainTemplate(
        "CHAIN-016", "Prototype Pollution -> XSS -> Account Takeover",
        "Server-side or client-side prototype pollution enables DOM-based XSS, "
        "leading to session hijacking and full account takeover.",
        (VulnCategory.PROTOTYPE_POLLUTION, VulnCategory.XSS, VulnCategory.AUTH_BYPASS),
        8.8, "CWE-1321 -> CWE-79 -> CWE-287",
        "Node.js Express/Lodash/jQuery"
    ),
    CVEChainTemplate(
        "CHAIN-017", "NoSQL Injection -> Auth Bypass -> Data Exfiltration",
        "NoSQL injection in authentication query bypasses login controls, "
        "enabling exfiltration of arbitrary database documents.",
        (VulnCategory.NOSQL_INJECTION, VulnCategory.AUTH_BYPASS, VulnCategory.INFO_DISCLOSURE),
        9.0, "CWE-943 -> CWE-287 -> CWE-200",
        "MongoDB-backed Node.js/Python applications"
    ),
    CVEChainTemplate(
        "CHAIN-018", "XXE -> SSRF -> Credential Theft",
        "XML external entity injection enables SSRF to internal services, "
        "leading to cloud credential theft via metadata endpoints.",
        (VulnCategory.XXE, VulnCategory.SSRF, VulnCategory.PRIVILEGE_ESCALATION),
        9.5, "CWE-611 -> CWE-918 -> CWE-522",
        "Java XML parsers, .NET XML deserialization"
    ),
    CVEChainTemplate(
        "CHAIN-019", "Parameter Pollution -> Auth Bypass -> Privilege Escalation",
        "HTTP parameter pollution confuses server-side auth logic, bypassing "
        "authentication and enabling privilege escalation.",
        (VulnCategory.PARAMETER_POLLUTION, VulnCategory.AUTH_BYPASS, VulnCategory.PRIVILEGE_ESCALATION),
        8.6, "CWE-235 -> CWE-287 -> CWE-269",
    ),
    CVEChainTemplate(
        "CHAIN-020", "Session Fixation -> CSRF -> Account Takeover",
        "Pre-set session ID survives authentication, combined with CSRF to "
        "force victim to authenticate an attacker-known session.",
        (VulnCategory.SESSION_FIXATION, VulnCategory.CSRF, VulnCategory.AUTH_BYPASS),
        8.1, "CWE-384 -> CWE-352 -> CWE-287",
    ),
    CVEChainTemplate(
        "CHAIN-021", "Rate Limit Bypass -> Credential Stuffing -> Account Takeover",
        "Advanced rate limit bypass (identity key confusion, path normalization) "
        "enables high-volume credential stuffing against authentication.",
        (VulnCategory.RATE_LIMIT_BYPASS_ADVANCED, VulnCategory.API_RATE_LIMIT_BYPASS, VulnCategory.AUTH_BYPASS),
        8.8, "CWE-770 -> CWE-307 -> CWE-287",
        "CDN/WAF bypass via edge-to-origin discrepancy"
    ),
    CVEChainTemplate(
        "CHAIN-022", "CAPTCHA Bypass -> Rate Limit Bypass -> Brute Force",
        "CAPTCHA evasion combined with rate limit bypass enables unrestricted "
        "brute force against authentication or payment endpoints.",
        (VulnCategory.CAPTCHA_BYPASS, VulnCategory.API_RATE_LIMIT_BYPASS, VulnCategory.AUTH_BYPASS),
        7.5, "CWE-863 -> CWE-770 -> CWE-307",
    ),
    CVEChainTemplate(
        "CHAIN-023", "Webhook Abuse -> Payment Manipulation -> Entitlement Bypass",
        "Forged or replayed webhook events manipulate payment state, granting "
        "entitlements without actual payment completion.",
        (VulnCategory.WEBHOOK_ABUSE, VulnCategory.PAYMENT_MANIPULATION, VulnCategory.ENTITLEMENT_BYPASS),
        9.3, "CWE-345 -> CWE-799 -> CWE-862",
        "THE payment webhook exploit chain -- Stripe/PayPal/Braintree"
    ),
    CVEChainTemplate(
        "CHAIN-024", "Cache Poisoning -> Open Redirect -> Credential Theft",
        "Cache poisoning injects redirect to attacker-controlled site, capturing "
        "OAuth tokens or credentials from redirected users.",
        (VulnCategory.CACHE_POISONING, VulnCategory.OPEN_REDIRECT, VulnCategory.AUTH_BYPASS),
        8.1, "CWE-444 -> CWE-601 -> CWE-522",
    ),
    CVEChainTemplate(
        "CHAIN-025", "Type Confusion -> Deserialization -> RCE",
        "Type confusion in input parsing triggers unsafe deserialization path, "
        "enabling remote code execution via crafted objects.",
        (VulnCategory.TYPE_CONFUSION, VulnCategory.DESERIALIZATION, VulnCategory.COMMAND_INJECTION),
        9.8, "CWE-843 -> CWE-502 -> CWE-78",
    ),
    CVEChainTemplate(
        "CHAIN-026", "GraphQL Batching -> Rate Limit Bypass -> Data Exfiltration",
        "GraphQL query batching/aliasing bypasses per-request rate limits, enabling "
        "mass data exfiltration through amplified queries.",
        (VulnCategory.GRAPHQL_ABUSE, VulnCategory.API_RATE_LIMIT_BYPASS, VulnCategory.INFO_DISCLOSURE),
        7.8, "CWE-770 -> CWE-770 -> CWE-200",
        "GraphQL APIs without query complexity limits"
    ),
    CVEChainTemplate(
        "CHAIN-027", "Subscription State Manipulation -> Entitlement Bypass -> Free Premium",
        "Manipulating subscription lifecycle state (cancel/reactivate race, trial "
        "extension, status confusion) grants premium access without payment.",
        (VulnCategory.BUSINESS_LOGIC, VulnCategory.ENTITLEMENT_BYPASS, VulnCategory.PAYMENT_MANIPULATION),
        9.1, "CWE-840 -> CWE-862 -> CWE-799",
        "Direct access-without-payment via subscription lifecycle"
    ),
]


# ---------------------------------------------------------------------------
# 4. TRUST BOUNDARY TAXONOMY (expanded: 14 boundaries)
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
    # --- 6 new boundaries ---
    SUBSCRIPTION_TO_FEATURE = "subscription_to_feature"
    FREE_TO_PREMIUM = "free_to_premium"
    TRIAL_TO_PAID = "trial_to_paid"
    INTERNAL_TO_EXTERNAL = "internal_to_external"
    MICROSERVICE_TO_MICROSERVICE = "microservice_to_microservice"
    CDN_TO_ORIGIN = "cdn_to_origin"


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
    # --- New boundary indicators ---
    TrustBoundary.SUBSCRIPTION_TO_FEATURE: [
        re.compile(r'/(?:subscriptions?|entitlements?|features?|access|permissions?)/(?:\d+|[a-f0-9-]{20,})', re.I),
        re.compile(r'/(?:plan|tier|product)/(?:\d+|[a-f0-9-]{20,})/(?:features?|access)', re.I),
    ],
    TrustBoundary.FREE_TO_PREMIUM: [
        re.compile(r'/(?:upgrade|premium|pro|enterprise|plans?/(?:premium|pro|enterprise|business))', re.I),
        re.compile(r'/(?:features?|capabilities)/(?:premium|pro|advanced|enterprise)', re.I),
    ],
    TrustBoundary.TRIAL_TO_PAID: [
        re.compile(r'/(?:trial|trials?/(?:convert|end|extend)|activate)', re.I),
        re.compile(r'/(?:subscribe|checkout).*trial', re.I),
    ],
    TrustBoundary.INTERNAL_TO_EXTERNAL: [
        re.compile(r'/(?:internal|private|_internal|\.internal)', re.I),
        re.compile(r'/(?:proxy|forward|redirect|fetch|ssrf_?test)', re.I),
    ],
    TrustBoundary.MICROSERVICE_TO_MICROSERVICE: [
        re.compile(r'/(?:rpc|grpc|internal-api|service|microservice|inter-service)', re.I),
        re.compile(r'/(?:health|readiness|liveness|metrics|status)', re.I),
    ],
    TrustBoundary.CDN_TO_ORIGIN: [
        re.compile(r'/(?:cdn|edge|cache|origin|static|assets?|dist)', re.I),
        re.compile(r'/(?:purge|invalidate|refresh|warm)', re.I),
    ],
}


# ---------------------------------------------------------------------------
# 5. CVSS v3.1 SCORING ENGINE (Full-Chain-Sentinel methodology)
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
    return math.ceil(x * 10) / 10


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
    # --- 14 new category defaults ---
    VulnCategory.SSTI: CVSSVector(
        confidentiality=Impact.HIGH, integrity=Impact.HIGH, availability=Impact.HIGH,
        scope=Scope.CHANGED),
    VulnCategory.NOSQL_INJECTION: CVSSVector(
        confidentiality=Impact.HIGH, integrity=Impact.HIGH, availability=Impact.LOW),
    VulnCategory.XXE: CVSSVector(
        confidentiality=Impact.HIGH, integrity=Impact.LOW, availability=Impact.LOW,
        scope=Scope.CHANGED),
    VulnCategory.JWT_ABUSE: CVSSVector(
        confidentiality=Impact.HIGH, integrity=Impact.HIGH,
        privileges_required=PrivilegesRequired.NONE),
    VulnCategory.PROTOTYPE_POLLUTION: CVSSVector(
        confidentiality=Impact.LOW, integrity=Impact.HIGH,
        attack_complexity=AttackComplexity.HIGH, scope=Scope.CHANGED),
    VulnCategory.CACHE_POISONING: CVSSVector(
        integrity=Impact.HIGH, confidentiality=Impact.LOW,
        attack_complexity=AttackComplexity.HIGH, scope=Scope.CHANGED),
    VulnCategory.HTTP_SMUGGLING: CVSSVector(
        confidentiality=Impact.HIGH, integrity=Impact.HIGH,
        attack_complexity=AttackComplexity.HIGH),
    VulnCategory.PARAMETER_POLLUTION: CVSSVector(
        integrity=Impact.LOW, confidentiality=Impact.LOW,
        attack_complexity=AttackComplexity.LOW),
    VulnCategory.TYPE_CONFUSION: CVSSVector(
        integrity=Impact.HIGH, confidentiality=Impact.LOW,
        attack_complexity=AttackComplexity.HIGH),
    VulnCategory.INSECURE_DESERIALIZATION_ACTIVE: CVSSVector(
        confidentiality=Impact.HIGH, integrity=Impact.HIGH, availability=Impact.HIGH),
    VulnCategory.CAPTCHA_BYPASS: CVSSVector(
        availability=Impact.LOW, integrity=Impact.LOW,
        attack_complexity=AttackComplexity.LOW),
    VulnCategory.RATE_LIMIT_BYPASS_ADVANCED: CVSSVector(
        availability=Impact.LOW, integrity=Impact.LOW,
        attack_complexity=AttackComplexity.HIGH),
    VulnCategory.SESSION_FIXATION: CVSSVector(
        confidentiality=Impact.HIGH, integrity=Impact.HIGH,
        attack_complexity=AttackComplexity.HIGH),
    VulnCategory.WEBHOOK_ABUSE: CVSSVector(
        integrity=Impact.HIGH, confidentiality=Impact.LOW,
        privileges_required=PrivilegesRequired.NONE),
}


# ---------------------------------------------------------------------------
# 6. PAYLOAD SIGNATURE PATTERNS (expanded)
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
    (VulnCategory.SSTI, "ssti_reflection", re.compile(r'(?:\$\{[^}]*\}|\{\{[^}]*\}\}|<%[^%]*%>|#\{[^}]*\})', re.I)),
    # LDAP injection
    (VulnCategory.SQLI, "ldap_injection_reflection", re.compile(r'(?:\)\(&|\)\(|\*\)\(|objectClass=\*)', re.I)),
    # NoSQL injection
    (VulnCategory.NOSQL_INJECTION, "nosql_injection_indicator", re.compile(r'(?:\$(?:gt|gte|lt|lte|ne|in|nin|regex|where|exists)\b|\$(?:or|and|not)\s*:)', re.I)),
    # --- New payload reflections ---
    (VulnCategory.SSTI, "ssti_jinja_reflection", re.compile(r'\{\{\s*(?:7\s*\*\s*7|config|self\.__class__|lipsum)', re.I)),
    (VulnCategory.SSTI, "ssti_mako_reflection", re.compile(r'<\%\s*(?:import\s|from\s|include\s)', re.I)),
    (VulnCategory.XXE, "xxe_entity_reflection", re.compile(r'(?:<!ENTITY|SYSTEM\s+["\'](?:file|http|ftp|expect|php)://)', re.I)),
    (VulnCategory.PROTOTYPE_POLLUTION, "proto_pollution_reflection", re.compile(r'(?:__proto__|constructor\[.?prototype)', re.I)),
    (VulnCategory.HTTP_SMUGGLING, "smuggling_cl_te_reflection", re.compile(r'(?:Transfer-Encoding:\s*chunked.*Content-Length)', re.I | re.S)),
    (VulnCategory.PARAMETER_POLLUTION, "hpp_reflection", re.compile(r'(?:(\w+)=[^&]*&\1=)', re.I)),
    (VulnCategory.NOSQL_INJECTION, "nosql_js_injection_reflection", re.compile(r'(?:\$where\s*:\s*["\']|this\.\w+\s*==)', re.I)),
    (VulnCategory.JWT_ABUSE, "jwt_alg_none_reflection", re.compile(r'"alg"\s*:\s*"(?:none|None|NONE)"')),
    (VulnCategory.CACHE_POISONING, "cache_poison_reflection", re.compile(r'(?:X-Forwarded-Host|X-Original-URL|X-Rewrite-URL)\s*:', re.I)),
]


# ---------------------------------------------------------------------------
# 7. HUNTING SKILLS (expanded: 45 skills)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class HuntingSkill:
    skill_id: str
    name: str
    category: VulnCategory
    description: str
    indicators: list[str]
    severity_weight: float
    cwe_id: str = ""


HUNTING_SKILLS: list[HuntingSkill] = [
    HuntingSkill("HUNT-001", "Price Parameter Tampering", VulnCategory.PAYMENT_MANIPULATION,
                 "Detect when price/amount fields in responses differ from expected values or show signs of client-side manipulation acceptance",
                 ["amount", "price", "total", "unit_amount", "subtotal", "cost", "fee"], 1.0, "CWE-799"),
    HuntingSkill("HUNT-002", "Subscription Tier Confusion", VulnCategory.ENTITLEMENT_BYPASS,
                 "Detect responses that return higher-tier features to lower-tier sessions",
                 ["plan", "tier", "subscription", "entitlement", "feature_flags", "plan_id"], 0.9, "CWE-862"),
    HuntingSkill("HUNT-003", "Coupon/Promo Stack Abuse", VulnCategory.BUSINESS_LOGIC,
                 "Detect when discount codes stack or when total goes below zero",
                 ["coupon", "discount", "promo", "voucher", "promotion_code", "percent_off", "amount_off"], 0.8, "CWE-840"),
    HuntingSkill("HUNT-004", "Trial Extension Abuse", VulnCategory.ENTITLEMENT_BYPASS,
                 "Detect when trial period can be extended or restarted improperly",
                 ["trial", "trial_end", "trial_start", "trial_period_days", "trial_status"], 0.7, "CWE-862"),
    HuntingSkill("HUNT-005", "Webhook Replay Acceptance", VulnCategory.BUSINESS_LOGIC,
                 "Detect when webhooks are accepted without proper idempotency checks",
                 ["webhook", "event_id", "idempotency_key", "created", "livemode"], 0.9, "CWE-294"),
    HuntingSkill("HUNT-006", "Currency Arbitrage", VulnCategory.PAYMENT_MANIPULATION,
                 "Detect when currency mismatches between request and response indicate arbitrage opportunity",
                 ["currency", "exchange_rate", "converted_amount", "settlement_currency"], 0.8, "CWE-799"),
    HuntingSkill("HUNT-007", "Quantity Manipulation", VulnCategory.PAYMENT_MANIPULATION,
                 "Detect negative quantities or zero-quantity orders that bypass validation",
                 ["quantity", "qty", "count", "items", "line_items"], 0.9, "CWE-190"),
    HuntingSkill("HUNT-008", "Refund Excess", VulnCategory.PAYMENT_MANIPULATION,
                 "Detect refund amounts exceeding original payment",
                 ["refund", "refund_amount", "amount_refunded", "refund_status"], 1.0, "CWE-799"),
    HuntingSkill("HUNT-009", "Idempotency Key Reuse", VulnCategory.RACE_CONDITION,
                 "Detect when idempotency keys are reusable across different resources",
                 ["idempotency_key", "idempotency-key", "request_id"], 0.7, "CWE-362"),
    HuntingSkill("HUNT-010", "Object Reference Enumeration", VulnCategory.IDOR,
                 "Detect sequential or predictable resource identifiers enabling enumeration",
                 ["id", "user_id", "account_id", "order_id", "invoice_id", "ref"], 0.8, "CWE-639"),
    HuntingSkill("HUNT-011", "Role Confusion in JWT", VulnCategory.AUTH_BYPASS,
                 "Detect JWT payloads with role/scope fields that differ from expected authorization",
                 ["role", "scope", "permissions", "groups", "is_admin", "admin"], 0.9, "CWE-287"),
    HuntingSkill("HUNT-012", "Webhook Signature Bypass", VulnCategory.AUTH_BYPASS,
                 "Detect webhooks accepted without proper signature validation",
                 ["stripe-signature", "x-hub-signature", "x-webhook-signature", "sig"], 1.0, "CWE-345"),
    HuntingSkill("HUNT-013", "API Version Downgrade", VulnCategory.BROKEN_ACCESS_CONTROL,
                 "Detect when older API versions have weaker security controls",
                 ["api-version", "version", "api_version", "v1", "v2"], 0.7, "CWE-693"),
    HuntingSkill("HUNT-014", "Batch Operation Abuse", VulnCategory.BUSINESS_LOGIC,
                 "Detect batch endpoints that bypass per-item validation",
                 ["batch", "bulk", "items", "operations", "requests"], 0.8, "CWE-770"),
    HuntingSkill("HUNT-015", "State Machine Violation", VulnCategory.BUSINESS_LOGIC,
                 "Detect responses indicating illegal state transitions were accepted",
                 ["status", "state", "phase", "stage", "lifecycle_status"], 0.9, "CWE-840"),
    HuntingSkill("HUNT-016", "Feature Flag Leakage", VulnCategory.INFO_DISCLOSURE,
                 "Detect internal feature flags exposed in API responses",
                 ["feature_flags", "features", "flags", "experiments", "ab_test", "feature_enabled"], 0.6, "CWE-200"),
    HuntingSkill("HUNT-017", "Debug Endpoint Exposure", VulnCategory.INFO_DISCLOSURE,
                 "Detect debug/admin endpoints accessible in production",
                 ["debug", "trace", "profiler", "metrics", "health", "info", "env"], 0.7, "CWE-489"),
    HuntingSkill("HUNT-018", "Session Fixation Opportunity", VulnCategory.AUTH_BYPASS,
                 "Detect session tokens that survive authentication state changes",
                 ["session_id", "session_token", "sid", "jsessionid", "phpsessid"], 0.8, "CWE-384"),
    HuntingSkill("HUNT-019", "Metadata Injection", VulnCategory.MASS_ASSIGNMENT,
                 "Detect when metadata/custom fields can be used to inject controlled values",
                 ["metadata", "custom_fields", "extra", "attributes", "properties", "tags"], 0.7, "CWE-915"),
    HuntingSkill("HUNT-020", "Timing-Based Enumeration", VulnCategory.INFO_DISCLOSURE,
                 "Detect timing differences that reveal existence of resources",
                 [], 0.6, "CWE-208"),
    HuntingSkill("HUNT-021", "Invoice Manipulation", VulnCategory.PAYMENT_MANIPULATION,
                 "Detect when invoice amounts can be modified after creation",
                 ["invoice", "invoice_id", "amount_due", "amount_paid", "amount_remaining"], 0.9, "CWE-799"),
    HuntingSkill("HUNT-022", "Subscription Downgrade Retention", VulnCategory.ENTITLEMENT_BYPASS,
                 "Detect when downgraded subscriptions retain higher-tier features",
                 ["plan", "product", "features", "entitlements", "access_level"], 0.8, "CWE-862"),
    HuntingSkill("HUNT-023", "Webhook Event Type Confusion", VulnCategory.BUSINESS_LOGIC,
                 "Detect when webhook handlers process events they shouldn't accept",
                 ["type", "event_type", "event", "action", "event_name"], 0.7, "CWE-345"),
    HuntingSkill("HUNT-024", "Multi-Currency Exploit", VulnCategory.PAYMENT_MANIPULATION,
                 "Detect when switching currencies mid-flow yields incorrect conversion",
                 ["currency", "amount", "exchange_rate", "presentment_currency"], 0.8, "CWE-799"),
    # --- 21 new hunting skills ---
    HuntingSkill("HUNT-025", "Subscription State Machine Bypass", VulnCategory.ENTITLEMENT_BYPASS,
                 "Detect when subscription status transitions skip payment verification states (e.g. canceled->active without payment)",
                 ["subscription_status", "status", "cancel_at_period_end", "canceled_at", "current_period_end", "pause_collection"], 1.0, "CWE-840"),
    HuntingSkill("HUNT-026", "Webhook Idempotency Key Forge", VulnCategory.WEBHOOK_ABUSE,
                 "Detect when webhook event_id or idempotency_key can be forged or reused to replay payment confirmations",
                 ["event_id", "idempotency_key", "webhook_id", "request_id", "delivery_id"], 1.0, "CWE-294"),
    HuntingSkill("HUNT-027", "Payment Intent Manipulation", VulnCategory.PAYMENT_MANIPULATION,
                 "Detect when payment intent amount/currency can be modified between creation and confirmation",
                 ["payment_intent", "client_secret", "amount", "currency", "setup_future_usage", "capture_method"], 1.0, "CWE-799"),
    HuntingSkill("HUNT-028", "Stripe Connect Account Abuse", VulnCategory.PAYMENT_MANIPULATION,
                 "Detect when connected accounts can receive funds without proper authorization or when transfer amounts are manipulable",
                 ["connected_account", "destination", "transfer_data", "application_fee_amount", "on_behalf_of"], 0.9, "CWE-862"),
    HuntingSkill("HUNT-029", "Checkout Session Reuse", VulnCategory.PAYMENT_MANIPULATION,
                 "Detect when completed checkout sessions can be reused to obtain goods/services without additional payment",
                 ["checkout_session", "session_id", "success_url", "cancel_url", "mode", "payment_status"], 1.0, "CWE-294"),
    HuntingSkill("HUNT-030", "Price Lookup Key Manipulation", VulnCategory.PAYMENT_MANIPULATION,
                 "Detect when price lookup keys can be swapped to get higher-tier products at lower-tier prices",
                 ["price_id", "price", "lookup_key", "recurring", "unit_amount", "product"], 0.9, "CWE-799"),
    HuntingSkill("HUNT-031", "Tax Calculation Bypass", VulnCategory.PAYMENT_MANIPULATION,
                 "Detect when tax calculation can be bypassed or manipulated to reduce total charge",
                 ["tax_amount", "tax_rate", "tax_behavior", "automatic_tax", "tax_code", "tax_exempt"], 0.7, "CWE-840"),
    HuntingSkill("HUNT-032", "Metered Billing Undercount", VulnCategory.PAYMENT_MANIPULATION,
                 "Detect when usage-based billing counters can be manipulated to report less usage than actual",
                 ["usage_record", "quantity", "timestamp", "subscription_item", "action", "meter_event"], 0.8, "CWE-799"),
    HuntingSkill("HUNT-033", "Usage Record Manipulation", VulnCategory.PAYMENT_MANIPULATION,
                 "Detect when usage records can be overwritten with lower values or deleted",
                 ["usage_record", "subscription_item_id", "quantity", "action", "increment", "set"], 0.8, "CWE-799"),
    HuntingSkill("HUNT-034", "Setup Intent Reuse", VulnCategory.PAYMENT_MANIPULATION,
                 "Detect when setup intents for future payments can be reused or their mandate overridden",
                 ["setup_intent", "mandate", "payment_method", "confirm", "usage", "single_use"], 0.8, "CWE-294"),
    HuntingSkill("HUNT-035", "Customer Portal Session Hijack", VulnCategory.AUTH_BYPASS,
                 "Detect when customer portal session URLs can be accessed by other customers or replayed",
                 ["portal_session", "return_url", "customer", "url", "configuration"], 0.8, "CWE-384"),
    HuntingSkill("HUNT-036", "Entitlement Cache Poisoning", VulnCategory.ENTITLEMENT_BYPASS,
                 "Detect when entitlement/feature-flag caching can be poisoned to grant features to wrong tier",
                 ["cache", "ttl", "expires", "max-age", "etag", "last-modified", "vary"], 0.9, "CWE-444"),
    HuntingSkill("HUNT-037", "Grace Period Exploitation", VulnCategory.ENTITLEMENT_BYPASS,
                 "Detect when payment failure grace periods can be extended indefinitely to retain premium access",
                 ["grace_period", "past_due", "days_until_due", "collection_method", "pending_invoice_item_interval"], 0.9, "CWE-862"),
    HuntingSkill("HUNT-038", "Proration Manipulation", VulnCategory.PAYMENT_MANIPULATION,
                 "Detect when subscription plan changes with proration can result in net-negative charges or credit accumulation",
                 ["proration", "proration_behavior", "proration_date", "credit_balance", "invoice_items", "prorated"], 0.8, "CWE-799"),
    HuntingSkill("HUNT-039", "Dunning Process Bypass", VulnCategory.ENTITLEMENT_BYPASS,
                 "Detect when automated payment retry (dunning) can be circumvented to keep access despite failed payments",
                 ["dunning", "retry", "next_payment_attempt", "auto_advance", "collection_method", "max_retries"], 0.8, "CWE-862"),
    HuntingSkill("HUNT-040", "Invoice Finalization Race", VulnCategory.RACE_CONDITION,
                 "Detect when draft invoices can be manipulated before finalization to change the charge amount",
                 ["invoice", "draft", "finalized", "finalize_invoice", "auto_advance", "pending"], 0.9, "CWE-362"),
    HuntingSkill("HUNT-041", "Payment Method Swap Mid-Flow", VulnCategory.PAYMENT_MANIPULATION,
                 "Detect when payment method can be swapped to a declined/insufficient-funds method after authorization",
                 ["payment_method", "default_payment_method", "attach", "detach", "type", "card"], 0.8, "CWE-799"),
    HuntingSkill("HUNT-042", "Webhook Timestamp Drift Exploitation", VulnCategory.WEBHOOK_ABUSE,
                 "Detect when webhook timestamp tolerance is too wide, allowing replay of old events",
                 ["timestamp", "created", "stripe-signature", "t=", "tolerance", "webhook_received_at"], 0.7, "CWE-294"),
    HuntingSkill("HUNT-043", "Cross-Tenant Resource Leak", VulnCategory.IDOR,
                 "Detect when resources from one tenant/customer are accessible to another",
                 ["customer_id", "account_id", "tenant_id", "org_id", "workspace_id", "team_id"], 1.0, "CWE-639"),
    HuntingSkill("HUNT-044", "API Key Scope Escalation", VulnCategory.PRIVILEGE_ESCALATION,
                 "Detect when restricted API keys can access resources beyond their configured scope",
                 ["api_key", "restricted_key", "scope", "permissions", "allowed_operations", "key_type"], 0.9, "CWE-269"),
    HuntingSkill("HUNT-045", "GraphQL Depth/Complexity Bypass", VulnCategory.GRAPHQL_ABUSE,
                 "Detect when GraphQL depth/complexity limits can be bypassed through aliasing, fragments, or batching",
                 ["query", "mutation", "fragment", "alias", "depth", "complexity", "cost"], 0.7, "CWE-770"),
]


# ---------------------------------------------------------------------------
# 8. ATTACK SURFACE COMPLETENESS MAP (expanded: 16 surfaces)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SurfaceCategory:
    category_id: str
    name: str
    path_patterns: list[re.Pattern[str]]
    critical: bool
    vuln_categories: list[VulnCategory]


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
    # --- 7 new surfaces ---
    SurfaceCategory("SURF-SUBSCRIPTION", "Subscription Management Surface",
                    [re.compile(r'/(?:subscriptions?|plans?|tiers?|entitlements?|features?/access)', re.I)],
                    True, [VulnCategory.ENTITLEMENT_BYPASS, VulnCategory.PAYMENT_MANIPULATION, VulnCategory.BUSINESS_LOGIC]),
    SurfaceCategory("SURF-WEBHOOK-PAYMENT", "Payment Webhook Surface",
                    [re.compile(r'/(?:webhook|callback|hook).*(?:pay|stripe|charge|invoice)', re.I),
                     re.compile(r'/(?:stripe|paypal|braintree)/(?:webhook|callback|event)', re.I)],
                    True, [VulnCategory.WEBHOOK_ABUSE, VulnCategory.PAYMENT_MANIPULATION, VulnCategory.AUTH_BYPASS]),
    SurfaceCategory("SURF-CDN", "CDN/Edge Surface",
                    [re.compile(r'/(?:cdn|edge|cache|static|assets?|dist|\.well-known)', re.I)],
                    False, [VulnCategory.CACHE_POISONING, VulnCategory.HTTP_SMUGGLING]),
    SurfaceCategory("SURF-GRAPHQL", "GraphQL Surface",
                    [re.compile(r'/(?:graphql|gql)(?:/|$|\?)', re.I)],
                    False, [VulnCategory.GRAPHQL_ABUSE, VulnCategory.IDOR, VulnCategory.INFO_DISCLOSURE]),
    SurfaceCategory("SURF-WEBSOCKET", "WebSocket Surface",
                    [re.compile(r'/(?:ws|wss|socket|websocket|realtime|stream|push)', re.I)],
                    False, [VulnCategory.WEBSOCKET_ABUSE, VulnCategory.AUTH_BYPASS]),
    SurfaceCategory("SURF-SSO", "SSO/SAML/OAuth Surface",
                    [re.compile(r'/(?:sso|saml|oidc|oauth|\.well-known/openid|jwks|authorize|consent)', re.I)],
                    True, [VulnCategory.AUTH_BYPASS, VulnCategory.JWT_ABUSE, VulnCategory.OPEN_REDIRECT]),
    SurfaceCategory("SURF-INTERNAL-API", "Internal/Microservice Surface",
                    [re.compile(r'/(?:internal|private|rpc|grpc|inter-service|_internal|\.internal)', re.I)],
                    False, [VulnCategory.BROKEN_ACCESS_CONTROL, VulnCategory.SSRF, VulnCategory.INFO_DISCLOSURE]),
]


# ---------------------------------------------------------------------------
# 9. ADVERSARIAL VALIDATION RULES (expanded: 12 rules)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ValidationRule:
    rule_id: str
    name: str
    upgrade_condition: str
    downgrade_condition: str
    weight: float


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
    # --- 7 new rules ---
    ValidationRule("VAL-006", "Chain Completeness",
                   "All steps of an exploit chain are present in findings with confirmed evidence",
                   "Chain has only partial steps or steps rely on low-confidence indicators", 0.25),
    ValidationRule("VAL-007", "Behavioral Consistency",
                   "Finding reproduces under different authentication contexts (anon, user, admin)",
                   "Finding appears only under one specific auth context (may be auth-dependent artifact)", 0.2),
    ValidationRule("VAL-008", "Payload Specificity",
                   "Finding triggered by a targeted, context-specific indicator, not a generic pattern",
                   "Finding from a broad/generic pattern that fires on benign content (high false positive rate)", 0.15),
    ValidationRule("VAL-009", "Defense Bypass Confirmation",
                   "Finding persists despite observable security controls (WAF headers, CSP, rate limit headers present)",
                   "No evidence the target has defenses this finding would need to bypass", 0.1),
    ValidationRule("VAL-010", "Environmental Correlation",
                   "Finding matches a known vulnerable framework version or configuration pattern",
                   "No environmental context available to corroborate the finding", 0.1),
    ValidationRule("VAL-011", "Timing Correlation",
                   "Suspicious timing pattern across related requests supports the finding (e.g. race condition window)",
                   "No timing data available or timing is consistent with normal operation", 0.15),
    ValidationRule("VAL-012", "Business Logic Validation",
                   "Finding aligns with expected business flow violations (e.g. payment without charge, access without subscription)",
                   "Finding does not map to a concrete business-logic bypass scenario", 0.2),
]


# ---------------------------------------------------------------------------
# 10. RATE LIMIT BYPASS SIGNATURES (HackTricks + SecureLayer7 + PortSwigger)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RateLimitBypassSignature:
    bypass_class: str
    name: str
    description: str
    indicator_pattern: re.Pattern[str] | None = None
    indicator_target: str = "response_headers"
    severity: float = 5.0


RATE_LIMIT_BYPASS_SIGNATURES: list[RateLimitBypassSignature] = [
    # Identity key confusion
    RateLimitBypassSignature("identity_key_confusion", "xff_trusted",
                             "X-Forwarded-For accepted without stripping suggests identity key spoofing",
                             re.compile(r'x-forwarded-for:', re.I), "response_headers", 6.0),
    RateLimitBypassSignature("identity_key_confusion", "true_client_ip_accepted",
                             "True-Client-IP header reflected/trusted enables identity rotation",
                             re.compile(r'true-client-ip:', re.I), "response_headers", 6.0),
    RateLimitBypassSignature("identity_key_confusion", "x_real_ip_trusted",
                             "X-Real-IP header trusted from client enables IP spoofing for rate limit",
                             re.compile(r'x-real-ip:', re.I), "response_headers", 6.0),
    # Edge/origin mismatch
    RateLimitBypassSignature("edge_origin_mismatch", "cdn_bypass_indicator",
                             "Direct origin access possible (no CDN cache headers)",
                             re.compile(r'(?:x-cache|cf-cache-status|x-varnish|x-cdn)', re.I), "response_headers", 5.5),
    RateLimitBypassSignature("edge_origin_mismatch", "pop_sharded_counters",
                             "CDN PoP identifier in response suggests per-PoP rate limiting",
                             re.compile(r'(?:cf-ray|x-served-by|x-amz-cf-pop|x-edge-location)', re.I), "response_headers", 4.5),
    # Path normalization discrepancy
    RateLimitBypassSignature("path_normalization", "path_variation_accepted",
                             "Response indicates path normalization discrepancy between limiter and router",
                             re.compile(r'(?:not.?found|redirect|moved)', re.I), "response_body", 5.0),
    # Batching / fan-out
    RateLimitBypassSignature("batching_fanout", "graphql_batch_allowed",
                             "GraphQL batching enabled allows multiple operations per request",
                             re.compile(r'\[\s*\{\s*"data"', re.I), "response_body", 5.5),
    RateLimitBypassSignature("batching_fanout", "bulk_endpoint_available",
                             "Bulk/batch API endpoint available bypasses per-request limits",
                             re.compile(r'(?:/bulk|/batch|/multi|/import)\b', re.I), "response_body", 5.0),
    # Race condition window
    RateLimitBypassSignature("race_window", "concurrent_success",
                             "Multiple concurrent requests succeeded suggesting race in rate limit check",
                             None, "structural", 6.5),
    # Time window exploitation
    RateLimitBypassSignature("time_window", "fixed_window_reset",
                             "Rate limit reset header reveals fixed window boundary",
                             re.compile(r'x-ratelimit-reset:\s*\d+', re.I), "response_headers", 4.0),
    RateLimitBypassSignature("time_window", "retry_after_header",
                             "Retry-After header reveals exact window timing for boundary attacks",
                             re.compile(r'retry-after:\s*\d+', re.I), "response_headers", 4.0),
    # Distributed identity
    RateLimitBypassSignature("distributed_identity", "session_rotation_possible",
                             "New session/token obtainable cheaply enables distributed identity abuse",
                             re.compile(r'(?:set-cookie:\s*\w+session|csrf.?token)', re.I), "response_headers", 5.0),
    # Protocol version bypass
    RateLimitBypassSignature("protocol_bypass", "http2_available",
                             "HTTP/2 multiplexing available may bypass HTTP/1.1-specific rate limits",
                             re.compile(r'(?:alt-svc:\s*h2|upgrade:\s*h2c)', re.I), "response_headers", 4.0),
]


# ---------------------------------------------------------------------------
# 11. REVERSE ENGINEERING PATTERNS
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ReverseEngineeringPattern:
    pattern_id: str
    name: str
    description: str
    pattern: re.Pattern[str]
    target: str
    severity: float = 3.0


REVERSE_ENGINEERING_PATTERNS: list[ReverseEngineeringPattern] = [
    ReverseEngineeringPattern("RE-001", "obfuscated_js_code",
                              "Heavily obfuscated JavaScript indicating client-side security logic",
                              re.compile(r'(?:_0x[0-9a-f]{4,}|\\x[0-9a-f]{2}){5,}|(?:eval\s*\(\s*(?:atob|unescape|decodeURIComponent))', re.I),
                              "response_body", 4.0),
    ReverseEngineeringPattern("RE-002", "binary_protocol_marker",
                              "Binary/protobuf markers suggesting non-HTTP internal protocol",
                              re.compile(r'(?:\\x00\\x00|\\xff\\xfe|\\xef\\xbb\\xbf|\\x08\\x01|\\x0a\\x)', re.I),
                              "response_body", 3.5),
    ReverseEngineeringPattern("RE-003", "custom_serialization",
                              "Custom serialization format in response body",
                              re.compile(r'(?:\\x[0-9a-f]{2}){4,}|base64:[A-Za-z0-9+/=]{20,}|hex:[0-9a-f]{20,}', re.I),
                              "response_body", 3.0),
    ReverseEngineeringPattern("RE-004", "api_version_discrepancy",
                              "API version mismatch suggesting multiple backend versions coexist",
                              re.compile(r'"(?:api_version|version|schema_version)":\s*"[^"]*".*?"(?:api_version|version)":\s*"[^"]*"', re.S),
                              "response_body", 4.0),
    ReverseEngineeringPattern("RE-005", "hidden_endpoint_reference",
                              "Reference to undocumented/internal endpoint in response",
                              re.compile(r'(?:/internal/|/debug/|/admin-api/|/private/|/_hidden/|/backdoor/|/test-only/)', re.I),
                              "response_body", 5.5),
    ReverseEngineeringPattern("RE-006", "internal_routing_info",
                              "Internal routing/load balancer information leaked",
                              re.compile(r'(?:x-upstream|x-backend|x-origin-server|x-served-by|x-balancer|x-forwarded-server)', re.I),
                              "response_headers", 4.0),
    ReverseEngineeringPattern("RE-007", "debug_diagnostic_breadcrumbs",
                              "Debug/diagnostic breadcrumbs in response (trace IDs, request IDs, internal timing)",
                              re.compile(r'(?:x-request-id|x-trace-id|x-correlation-id|x-debug|x-runtime|x-processing-time)', re.I),
                              "response_headers", 2.5),
    ReverseEngineeringPattern("RE-008", "source_map_reference",
                              "Source map reference in response enables source code reconstruction",
                              re.compile(r'(?://[#@]\s*sourceMappingURL\s*=|\.map(?:"|\'|\s|$))', re.I),
                              "response_body", 4.5),
    ReverseEngineeringPattern("RE-009", "webpack_chunk_reference",
                              "Webpack chunk references reveal build/module structure",
                              re.compile(r'(?:webpackChunk|__webpack_require__|webpack_modules)', re.I),
                              "response_body", 3.5),
    ReverseEngineeringPattern("RE-010", "graphql_schema_fragments",
                              "GraphQL schema fragments in response reveal internal data model",
                              re.compile(r'(?:__typename|fragment\s+\w+\s+on\s+\w+|type\s+\w+\s*\{)', re.I),
                              "response_body", 4.0),
    ReverseEngineeringPattern("RE-011", "anti_debug_detection",
                              "Anti-debugging/anti-RE code detected indicating protected client logic",
                              re.compile(r'(?:debugger\s*;|Function\(["\']debugger["\']\)|console\.clear\(\)|devtools)', re.I),
                              "response_body", 4.5),
    ReverseEngineeringPattern("RE-012", "wasm_binary_reference",
                              "WebAssembly binary reference suggests performance-critical or security-critical client logic",
                              re.compile(r'(?:\.wasm|WebAssembly\.(?:instantiate|compile)|wasm-function)', re.I),
                              "response_body", 4.0),
    ReverseEngineeringPattern("RE-013", "waf_cloudflare_fingerprint",
                              "Cloudflare WAF/CDN detected: cf-ray, cf-cache-status, __cfduid headers/cookies",
                              re.compile(r'(?:cf-ray|cf-cache-status|__cfduid|cf-request-id|server:\s*cloudflare)', re.I),
                              "response_headers", 3.5),
    ReverseEngineeringPattern("RE-014", "waf_akamai_fingerprint",
                              "Akamai WAF detected: x-akamai, ak_bmsc, bm_sz, _abck cookies",
                              re.compile(r'(?:x-akamai-|akamai-origin|ak_bmsc|bm_sz|_abck)', re.I),
                              "response_headers", 3.5),
    ReverseEngineeringPattern("RE-015", "waf_incapsula_fingerprint",
                              "Imperva Incapsula WAF: visid_incap, incap_ses cookies, X-Iinfo header",
                              re.compile(r'(?:incap_ses_|visid_incap_|x-cdn.*incapsula|_incapsula|x-iinfo)', re.I),
                              "response_headers", 3.5),
    ReverseEngineeringPattern("RE-016", "waf_datadome_fingerprint",
                              "DataDome bot protection: datadome cookie, x-datadome header",
                              re.compile(r'(?:datadome|_dd_s|x-datadome)', re.I),
                              "response_headers", 3.5),
    ReverseEngineeringPattern("RE-017", "waf_perimeterx_fingerprint",
                              "PerimeterX bot protection: _px cookies, x-px headers",
                              re.compile(r'(?:_px[0-9]|px-|perimeterx|x-px-|_pxhd|__pxvid)', re.I),
                              "response_headers", 3.5),
    ReverseEngineeringPattern("RE-018", "jwt_alg_weakness",
                              "JWT token with weak/no algorithm: alg=none or HS256 with potential key confusion",
                              re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*', re.I),
                              "response_body", 5.0),
    ReverseEngineeringPattern("RE-019", "browser_fingerprinting_code",
                              "Client-side browser fingerprinting: canvas, WebGL, AudioContext, navigator probing",
                              re.compile(r'(?:canvas.*?toDataURL|navigator\.(?:plugins|languages|hardwareConcurrency)|WebGLRenderingContext|AudioContext.*?createOscillator)', re.I),
                              "response_body", 4.0),
    ReverseEngineeringPattern("RE-020", "bot_detection_cookie",
                              "Bot detection tracking cookie: __cf_bm, _abck, reese84, cf_clearance",
                              re.compile(r'(?:__cf_bm|_abck|ak_bmsc|bm_sz|reese84|cf_clearance|_pxhd|__pxvid)', re.I),
                              "response_headers", 3.0),
    ReverseEngineeringPattern("RE-021", "error_oracle_auth",
                              "Authentication error oracle: different messages for valid vs invalid users",
                              re.compile(r'(?:not found|does not exist|invalid.*user|no such|unknown.*(?:user|email)|incorrect.*password)', re.I),
                              "response_body", 5.5),
    ReverseEngineeringPattern("RE-022", "timing_side_channel_indicator",
                              "Timing-sensitive operations detected (bcrypt, PBKDF2, constant-time compare)",
                              re.compile(r'(?:bcrypt|pbkdf2|scrypt|argon2|hmac\.compare_digest|constant_time|timing_safe)', re.I),
                              "response_body", 4.5),
    ReverseEngineeringPattern("RE-023", "waf_block_page",
                              "WAF block page detected: access denied, challenge required, bot detection response",
                              re.compile(r'(?:access denied|request blocked|security policy|captcha.*required|challenge.*required)', re.I),
                              "response_body", 3.0),
    ReverseEngineeringPattern("RE-024", "rate_limit_header_leak",
                              "Rate limit configuration leaked via headers: x-ratelimit-limit, remaining, reset",
                              re.compile(r'(?:x-ratelimit-(?:limit|remaining|reset)|retry-after)', re.I),
                              "response_headers", 3.5),
    ReverseEngineeringPattern("RE-025", "tech_stack_leak",
                              "Backend technology stack leaked via headers/errors: framework, server, language version",
                              re.compile(r'(?:x-powered-by|x-aspnet-version|x-runtime|x-application-context|server:\s*(?:apache|nginx|iis|express|gunicorn|uvicorn))', re.I),
                              "response_headers", 3.0),
]


# ---------------------------------------------------------------------------
# 12. CWE MAPPING (VulnCategory -> (CWE-ID, CWE-Name))
# ---------------------------------------------------------------------------

CWE_MAPPING: dict[VulnCategory, tuple[str, str]] = {
    VulnCategory.IDOR: ("CWE-639", "Authorization Bypass Through User-Controlled Key"),
    VulnCategory.SSRF: ("CWE-918", "Server-Side Request Forgery"),
    VulnCategory.XSS: ("CWE-79", "Cross-site Scripting"),
    VulnCategory.SQLI: ("CWE-89", "SQL Injection"),
    VulnCategory.AUTH_BYPASS: ("CWE-287", "Improper Authentication"),
    VulnCategory.BROKEN_ACCESS_CONTROL: ("CWE-285", "Improper Authorization"),
    VulnCategory.MASS_ASSIGNMENT: ("CWE-915", "Improperly Controlled Modification of Dynamically-Determined Object Attributes"),
    VulnCategory.RACE_CONDITION: ("CWE-362", "Concurrent Execution Using Shared Resource with Improper Synchronization"),
    VulnCategory.BUSINESS_LOGIC: ("CWE-840", "Business Logic Errors"),
    VulnCategory.INFO_DISCLOSURE: ("CWE-200", "Exposure of Sensitive Information"),
    VulnCategory.PRIVILEGE_ESCALATION: ("CWE-269", "Improper Privilege Management"),
    VulnCategory.CSRF: ("CWE-352", "Cross-Site Request Forgery"),
    VulnCategory.DESERIALIZATION: ("CWE-502", "Deserialization of Untrusted Data"),
    VulnCategory.FILE_UPLOAD: ("CWE-434", "Unrestricted Upload of File with Dangerous Type"),
    VulnCategory.PATH_TRAVERSAL: ("CWE-22", "Path Traversal"),
    VulnCategory.COMMAND_INJECTION: ("CWE-78", "OS Command Injection"),
    VulnCategory.OPEN_REDIRECT: ("CWE-601", "URL Redirection to Untrusted Site"),
    VulnCategory.CORS_MISCONFIGURATION: ("CWE-942", "Overly Permissive Cross-domain Whitelist"),
    VulnCategory.SUBDOMAIN_TAKEOVER: ("CWE-923", "Improper Restriction of Communication Channel to Intended Endpoints"),
    VulnCategory.GRAPHQL_ABUSE: ("CWE-200", "Exposure of Sensitive Information via GraphQL"),
    VulnCategory.WEBSOCKET_ABUSE: ("CWE-1385", "Missing Origin Validation in WebSockets"),
    VulnCategory.API_RATE_LIMIT_BYPASS: ("CWE-770", "Allocation of Resources Without Limits or Throttling"),
    VulnCategory.PAYMENT_MANIPULATION: ("CWE-799", "Improper Control of Interaction Frequency"),
    VulnCategory.ENTITLEMENT_BYPASS: ("CWE-862", "Missing Authorization"),
    VulnCategory.SSTI: ("CWE-1336", "Improper Neutralization of Special Elements Used in a Template Engine"),
    VulnCategory.NOSQL_INJECTION: ("CWE-943", "Improper Neutralization of Special Elements in Data Query Logic"),
    VulnCategory.XXE: ("CWE-611", "Improper Restriction of XML External Entity Reference"),
    VulnCategory.JWT_ABUSE: ("CWE-347", "Improper Verification of Cryptographic Signature"),
    VulnCategory.PROTOTYPE_POLLUTION: ("CWE-1321", "Improperly Controlled Modification of Object Prototype Attributes"),
    VulnCategory.CACHE_POISONING: ("CWE-444", "Inconsistent Interpretation of HTTP Requests"),
    VulnCategory.HTTP_SMUGGLING: ("CWE-444", "Inconsistent Interpretation of HTTP Requests"),
    VulnCategory.PARAMETER_POLLUTION: ("CWE-235", "Improper Handling of Extra Parameters"),
    VulnCategory.TYPE_CONFUSION: ("CWE-843", "Access of Resource Using Incompatible Type"),
    VulnCategory.INSECURE_DESERIALIZATION_ACTIVE: ("CWE-502", "Deserialization of Untrusted Data"),
    VulnCategory.CAPTCHA_BYPASS: ("CWE-863", "Incorrect Authorization"),
    VulnCategory.RATE_LIMIT_BYPASS_ADVANCED: ("CWE-770", "Allocation of Resources Without Limits or Throttling"),
    VulnCategory.SESSION_FIXATION: ("CWE-384", "Session Fixation"),
    VulnCategory.WEBHOOK_ABUSE: ("CWE-345", "Insufficient Verification of Data Authenticity"),
}


# ---------------------------------------------------------------------------
# 13. HELPER FUNCTIONS (expanded)
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


def get_cwe_for_category(category: VulnCategory) -> tuple[str, str] | None:
    """Returns (CWE-ID, CWE-Name) for a vulnerability category, or None."""
    return CWE_MAPPING.get(category)


def compute_chain_cvss(finding_scores: list[float]) -> float:
    """Compute compound CVSS for an exploit chain: the chain's impact exceeds
    the sum of parts because each step enables the next. Formula: take the max
    individual score, then add a diminishing fraction of each subsequent
    score (sorted descending), capped at 10.0.

    This models the NIST NVD guidance that chained vulnerabilities should be
    scored by their combined exploitability, not independently."""
    if not finding_scores:
        return 0.0
    scores = sorted(finding_scores, reverse=True)
    compound = scores[0]
    for i, s in enumerate(scores[1:], start=1):
        compound += s * (0.5 ** i)
    return min(10.0, _roundup(compound))


def classify_bypass_technique(
    headers: dict[str, str],
    path: str,
    method: str,
) -> list[str]:
    """Classify potential rate limit bypass techniques from a request's attributes."""
    techniques: list[str] = []
    lower_headers = {k.lower(): v for k, v in headers.items()}

    if any(h in lower_headers for h in ("x-forwarded-for", "x-real-ip", "true-client-ip", "cf-connecting-ip")):
        techniques.append("identity_key_confusion")

    has_path_tricks = bool(re.search(r'(?://|/\./|/%2e/|/%2f|\.%00|%09|%0d%0a)', path, re.I))
    has_case_variation = path != path.lower() and re.search(r'/[a-z]', path) and re.search(r'/[A-Z]', path)
    has_trailing_variation = path.endswith('/') or path.endswith('.')
    if has_path_tricks or has_case_variation or has_trailing_variation:
        techniques.append("path_normalization")

    if "x-http-method-override" in lower_headers or "x-method-override" in lower_headers:
        techniques.append("method_override")

    if method.upper() in ("GET", "HEAD") and any(h in lower_headers for h in ("x-http-method-override",)):
        techniques.append("method_switching")

    if re.search(r'(?:graphql|gql)(?:/|$)', path, re.I):
        techniques.append("graphql_batching")

    if re.search(r'(?:/bulk|/batch|/multi|/import)\b', path, re.I):
        techniques.append("batching_fanout")

    for qp in path.split("?")[1:]:
        if "&" in qp:
            params = [p.split("=")[0] for p in qp.split("&") if "=" in p]
            if len(params) != len(set(params)):
                techniques.append("parameter_pollution")

    return techniques


def score_business_impact(
    vuln_category: VulnCategory | None,
    trust_boundary: TrustBoundary | None,
    is_payment_path: bool,
) -> str:
    """Score business impact: critical / high / medium / low."""
    critical_cats = {
        VulnCategory.PAYMENT_MANIPULATION, VulnCategory.ENTITLEMENT_BYPASS,
        VulnCategory.COMMAND_INJECTION, VulnCategory.DESERIALIZATION,
        VulnCategory.SQLI, VulnCategory.WEBHOOK_ABUSE,
        VulnCategory.INSECURE_DESERIALIZATION_ACTIVE,
    }
    high_cats = {
        VulnCategory.AUTH_BYPASS, VulnCategory.PRIVILEGE_ESCALATION,
        VulnCategory.BROKEN_ACCESS_CONTROL, VulnCategory.SSRF,
        VulnCategory.BUSINESS_LOGIC, VulnCategory.JWT_ABUSE,
        VulnCategory.SSTI, VulnCategory.XXE,
    }
    critical_boundaries = {
        TrustBoundary.PAYMENT_TO_ENTITLEMENT, TrustBoundary.FREE_TO_PREMIUM,
        TrustBoundary.SUBSCRIPTION_TO_FEATURE,
    }

    if vuln_category in critical_cats:
        return "critical"
    if is_payment_path and vuln_category in high_cats:
        return "critical"
    if trust_boundary in critical_boundaries:
        return "critical" if vuln_category in high_cats else "high"
    if vuln_category in high_cats:
        return "high"
    return "medium"


def get_remediation_priority(
    cvss_score: float | None,
    confidence: str,
    chain_position: int | None,
) -> str:
    """Compute remediation priority: p0 (immediate) / p1 (urgent) / p2 (normal) / p3 (low)."""
    score = cvss_score or 0.0
    is_chain_entry = chain_position == 0
    is_confirmed = confidence == "confirmed"

    if score >= 9.0 and is_confirmed:
        return "p0"
    if score >= 9.0 or (score >= 7.0 and is_confirmed and is_chain_entry):
        return "p0"
    if score >= 7.0 and is_confirmed:
        return "p1"
    if score >= 7.0 or (score >= 4.0 and is_confirmed):
        return "p1"
    if score >= 4.0:
        return "p2"
    return "p3"


def match_rate_limit_bypass_signatures(
    headers: dict[str, str],
    body_text: str,
) -> list[RateLimitBypassSignature]:
    """Match response against rate limit bypass signatures."""
    matches: list[RateLimitBypassSignature] = []
    header_text = "\n".join(f"{k}: {v}" for k, v in headers.items())
    for sig in RATE_LIMIT_BYPASS_SIGNATURES:
        if sig.indicator_pattern is None:
            continue
        target_text = header_text if sig.indicator_target == "response_headers" else body_text
        if sig.indicator_pattern.search(target_text):
            matches.append(sig)
    return matches


def match_reverse_engineering_patterns(
    headers: dict[str, str],
    body_text: str,
) -> list[ReverseEngineeringPattern]:
    """Match response against reverse engineering indicator patterns."""
    matches: list[ReverseEngineeringPattern] = []
    header_text = "\n".join(f"{k}: {v}" for k, v in headers.items())
    for pat in REVERSE_ENGINEERING_PATTERNS:
        target_text = header_text if pat.target == "response_headers" else body_text
        if pat.pattern.search(target_text):
            matches.append(pat)
    return matches
