"""Lightweight pattern-based scanner for information disclosure in error
responses: stack traces, file paths, database errors, internal
hosts/IPs, cloud metadata, source code leaks, and security
misconfigurations -- the category OWASP's Web Security Testing Guide
covers under "Testing for Error Handling" (WSTG-ERR-01/02).

Massively expanded with patterns from PayloadsAllTheThings, BugHunter,
Full-Chain-Sentinel, Shannon, and reverse-skill knowledge bases.

Pattern-based, not exhaustive: a clean scan means none of these known
signatures fired, not a guarantee of no leak at all. Findings should be
treated as leads for the QA engineer to confirm, same as the recon
module's discoveries.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class LeakFinding:
    category: str
    pattern: str
    snippet: str
    severity: str = "info"  # info / low / medium / high / critical
    cwe: str | None = None
    recommendation: str | None = None


_PATTERNS: list[tuple[str, re.Pattern[str], str, str | None]] = [
    # -- Stack traces (CWE-209: Generation of Error Message Containing Sensitive Information) --
    ("stack_trace", re.compile(r"Traceback \(most recent call last\)", re.IGNORECASE), "medium", "CWE-209"),
    ("stack_trace", re.compile(r"^\s*at\s+[\w.$]+\s*\([^)]*\)", re.MULTILINE), "medium", "CWE-209"),
    ("stack_trace", re.compile(r'File "[^"]+", line \d+'), "medium", "CWE-209"),
    ("stack_trace", re.compile(r'\.(?:py|rb|java|go|php)["\']?,?\s*line\s+\d+', re.IGNORECASE), "medium", "CWE-209"),
    ("stack_trace", re.compile(r"at\s+(?:Object\.|Module\.|Function\.)?[\w.]+\s+\([^)]*\.js:\d+:\d+\)"), "medium", "CWE-209"),
    ("stack_trace", re.compile(r"(?:NullPointerException|ClassCastException|ArrayIndexOutOfBounds|StackOverflowError)", re.IGNORECASE), "medium", "CWE-209"),
    ("stack_trace", re.compile(r"(?:System\.NullReferenceException|System\.ArgumentException|System\.InvalidOperationException)"), "medium", "CWE-209"),
    ("stack_trace", re.compile(r"(?:panic:\s|goroutine\s+\d+\s+\[running\])"), "medium", "CWE-209"),

    # -- File path disclosure (CWE-548: Exposure of Information Through Directory Listing) --
    ("file_path", re.compile(r"(?:/usr/|/home/[\w-]+/|/var/www|/opt/[\w./-]+|/etc/[\w./-]+)"), "low", "CWE-548"),
    ("file_path", re.compile(r"[A-Za-z]:\\Users\\", re.IGNORECASE), "low", "CWE-548"),
    ("file_path", re.compile(r"(?:/proc/self/|/dev/null|/tmp/[\w./-]+)"), "medium", "CWE-548"),
    ("file_path", re.compile(r"(?:C:\\inetpub\\|C:\\Windows\\Temp\\|C:\\ProgramData\\)", re.IGNORECASE), "medium", "CWE-548"),

    # -- Database errors (CWE-89: SQL Injection / CWE-209) --
    ("database_error", re.compile(r"\b(?:SQLSTATE|ORA-\d{5}|duplicate key value violates|syntax error at or near)\b", re.IGNORECASE), "high", "CWE-89"),
    ("database_error", re.compile(r"\b(?:psycopg2|pymongo|mysql\.connector|System\.Data\.SqlClient)\b"), "high", "CWE-209"),
    ("database_error", re.compile(r"\b(?:MySQL server version for the right syntax|You have an error in your SQL syntax)\b", re.IGNORECASE), "high", "CWE-89"),
    ("database_error", re.compile(r"\b(?:SQLITE_ERROR|sqlite3\.OperationalError)\b"), "high", "CWE-89"),
    ("database_error", re.compile(r"\b(?:ActiveRecord::StatementInvalid|Sequel::DatabaseError|Prisma\.PrismaClientKnownRequestError)\b"), "high", "CWE-209"),
    ("database_error", re.compile(r"\b(?:MongoError|MongoServerError|E11000 duplicate key)\b"), "medium", "CWE-209"),

    # -- Framework debug information (CWE-215: Insertion of Sensitive Information Into Debugging Code) --
    ("framework_debug", re.compile(r"\b(?:Django Version|Werkzeug Debugger|WSGIRequest|Whoops|Laravel\\)\b"), "high", "CWE-215"),
    ("framework_debug", re.compile(r"\b(?:FLASK_DEBUG|NODE_ENV\s*[=:]\s*development|DEBUG\s*=\s*True)\b", re.IGNORECASE), "high", "CWE-215"),
    ("framework_debug", re.compile(r"\b(?:Spring Boot Actuator|__CakePHP|Symfony\\)\b"), "high", "CWE-215"),
    ("framework_debug", re.compile(r"\b(?:X-Debug-Token|X-Debug-Token-Link|Xdebug)\b", re.IGNORECASE), "high", "CWE-215"),
    ("framework_debug", re.compile(r"(?:phpinfo\(\)|<title>phpinfo\(\)</title>)", re.IGNORECASE), "critical", "CWE-215"),

    # -- Internal host/IP disclosure (CWE-200: Exposure of Sensitive Information) --
    ("internal_host", re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b"), "medium", "CWE-200"),
    ("internal_host", re.compile(r"\bip-10-\d{1,3}-\d{1,3}-\d{1,3}\b|\.internal\b(?!\w)"), "medium", "CWE-200"),
    ("internal_host", re.compile(r"\b(?:localhost|127\.0\.0\.1|0\.0\.0\.0|::1)\b"), "low", "CWE-200"),
    ("internal_host", re.compile(r"\.(?:corp|local|intra|private|staging|dev)\b(?!\w)"), "medium", "CWE-200"),

    # -- Cloud metadata exposure (CWE-918: SSRF / CWE-200) --
    ("cloud_metadata", re.compile(r"169\.254\.169\.254"), "critical", "CWE-918"),
    ("cloud_metadata", re.compile(r"(?:ami-[0-9a-f]+|i-[0-9a-f]{8,}|arn:aws:)", re.IGNORECASE), "high", "CWE-200"),
    ("cloud_metadata", re.compile(r"(?:computeMetadata|metadata\.google\.internal|metadata\.azure\.com)", re.IGNORECASE), "critical", "CWE-918"),
    ("cloud_metadata", re.compile(r"(?:IMDS|instance-identity|user-data|security-credentials)", re.IGNORECASE), "high", "CWE-200"),

    # -- Secret/credential exposure (CWE-798: Use of Hard-coded Credentials) --
    ("credential_leak", re.compile(r"(?:sk_live_|rk_live_|pk_live_)[A-Za-z0-9]{10,}"), "critical", "CWE-798"),
    ("credential_leak", re.compile(r"AKIA[0-9A-Z]{16}"), "critical", "CWE-798"),
    ("credential_leak", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "critical", "CWE-798"),
    ("credential_leak", re.compile(r"(?:ghp_|gho_|ghu_|github_pat_)[A-Za-z0-9_]{20,}"), "critical", "CWE-798"),
    ("credential_leak", re.compile(r"(?:xoxb-|xoxp-)[0-9]+-[0-9]+-[A-Za-z0-9]+"), "critical", "CWE-798"),
    ("credential_leak", re.compile(r"AIza[0-9A-Za-z_-]{35}"), "critical", "CWE-798"),

    # -- Version disclosure (CWE-200) --
    ("version_disclosure", re.compile(r"(?:(?:nginx|apache|php|node|express|django|flask|rails|spring|tomcat|gunicorn|iis)[/\s]*v?[\d.]+)", re.IGNORECASE), "low", "CWE-200"),
    ("version_disclosure", re.compile(r"(?:X-Powered-By:\s*\S+)", re.IGNORECASE), "low", "CWE-200"),
    ("version_disclosure", re.compile(r"(?:Server:\s*\S+/[\d.]+)", re.IGNORECASE), "low", "CWE-200"),

    # -- Source code / configuration leak (CWE-540/CWE-615) --
    ("source_code_leak", re.compile(r"(?:\.git/config|\.git/HEAD|refs/heads/)", re.IGNORECASE), "high", "CWE-540"),
    ("source_code_leak", re.compile(r"(?:\.env|\.dockerignore|docker-compose\.yml|Dockerfile)", re.IGNORECASE), "medium", "CWE-540"),
    ("source_code_leak", re.compile(r"(?:wp-config\.php|web\.config|appsettings\.json|application\.properties)", re.IGNORECASE), "high", "CWE-540"),
    ("source_code_leak", re.compile(r'(?:DB_PASSWORD|DATABASE_URL|SECRET_KEY|STRIPE_SECRET_KEY)\s*[=:]', re.IGNORECASE), "critical", "CWE-798"),

    # -- Deserialization markers (CWE-502) --
    ("deserialization_risk", re.compile(r"(?:java\.lang\.Runtime|ObjectInputStream|ysoserial|CommonsCollections)", re.IGNORECASE), "critical", "CWE-502"),
    ("deserialization_risk", re.compile(r"(?:__reduce__|pickle\.loads|cPickle)", re.IGNORECASE), "critical", "CWE-502"),
    ("deserialization_risk", re.compile(r'(?:O:\d+:"[^"]+"|__VIEWSTATE)', re.IGNORECASE), "high", "CWE-502"),

    # -- Command execution indicators (CWE-78) --
    ("command_execution", re.compile(r"(?:uid=\d+\(\w+\)|root:x:0:0:|/bin/(?:bash|sh))"), "critical", "CWE-78"),
    ("command_execution", re.compile(r"(?:total\s+\d+\s+drwx|Permission denied|No such file or directory)"), "high", "CWE-78"),
]


def scan_for_leaks(text: str) -> list[LeakFinding]:
    """Returns one LeakFinding per pattern that matched (first hit only per
    pattern) -- enough to flag the category and show evidence, without
    flooding the report with every occurrence."""
    findings: list[LeakFinding] = []
    for item in _PATTERNS:
        category, pattern, severity, cwe = item
        match = pattern.search(text)
        if not match:
            continue
        start = max(0, match.start() - 20)
        end = min(len(text), match.end() + 40)
        findings.append(LeakFinding(
            category=category,
            pattern=pattern.pattern,
            snippet=text[start:end].strip(),
            severity=severity,
            cwe=cwe,
        ))
    return findings


def scan_for_leaks_with_severity(text: str) -> dict[str, list[LeakFinding]]:
    """Groups leak findings by severity level for prioritized reporting."""
    all_findings = scan_for_leaks(text)
    by_severity: dict[str, list[LeakFinding]] = {
        "critical": [], "high": [], "medium": [], "low": [], "info": [],
    }
    for finding in all_findings:
        by_severity.setdefault(finding.severity, []).append(finding)
    return by_severity
