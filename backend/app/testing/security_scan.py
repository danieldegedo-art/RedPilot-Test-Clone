"""Lightweight pattern-based scanner for information disclosure in error
responses: stack traces, file paths, database errors, internal
hosts/IPs -- the category OWASP's Web Security Testing Guide covers under
"Testing for Error Handling" (WSTG-ERR-01/02).

Pattern-based, not exhaustive: a clean scan means none of these known
signatures fired, not a guarantee of no leak at all. Findings should be
treated as leads for the QA engineer to confirm, same as the recon
module's discoveries.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class LeakFinding:
    category: str
    pattern: str
    snippet: str


_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("stack_trace", re.compile(r"Traceback \(most recent call last\)", re.IGNORECASE)),
    ("stack_trace", re.compile(r"^\s*at\s+[\w.$]+\s*\([^)]*\)", re.MULTILINE)),
    ("stack_trace", re.compile(r"File \"[^\"]+\", line \d+")),
    ("stack_trace", re.compile(r"\.(?:py|rb|java|go|php)[\"']?,?\s*line\s+\d+", re.IGNORECASE)),
    ("file_path", re.compile(r"(?:/usr/|/home/[\w-]+/|/var/www|/opt/[\w./-]+|/etc/[\w./-]+)")),
    ("file_path", re.compile(r"[A-Za-z]:\\Users\\", re.IGNORECASE)),
    ("database_error", re.compile(r"\b(SQLSTATE|ORA-\d{5}|duplicate key value violates|syntax error at or near)\b", re.IGNORECASE)),
    ("database_error", re.compile(r"\b(psycopg2|pymongo|mysql\.connector|System\.Data\.SqlClient)\b")),
    ("framework_debug", re.compile(r"\b(Django Version|Werkzeug Debugger|WSGIRequest|Whoops|Laravel\\)\b")),
    ("internal_host", re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b")),
    ("internal_host", re.compile(r"\bip-10-\d{1,3}-\d{1,3}-\d{1,3}\b|\.internal\b(?!\w)")),
]


def scan_for_leaks(text: str) -> list[LeakFinding]:
    """Returns one LeakFinding per pattern category that matched (first hit
    only, per pattern) -- enough to flag the category and show evidence,
    without flooding the report with every occurrence."""
    findings: list[LeakFinding] = []
    for category, pattern in _PATTERNS:
        match = pattern.search(text)
        if not match:
            continue
        start = max(0, match.start() - 20)
        end = min(len(text), match.end() + 40)
        findings.append(LeakFinding(category=category, pattern=pattern.pattern, snippet=text[start:end].strip()))
    return findings
