"""Target-access allowlist enforcement (mandate: 'Target access allowlist').

The ScopeGuard (enterprise_controls/scope.py) already answers "is this host authorised for the run?". This gate answers the second
question the Pure Black-Box rule adds: "is this request addressed to a CUSTOMER-FACING surface at all?". It runs inside
``ScopeGuard.preflight``/``acquire`` -- the single choke point every request, retry and redirect hop passes -- so it is
technical enforcement, not a convention a module has to remember.

Blocked, with a stable reason code each:
  * non-HTTP(S) schemes and database/cache/queue/log/trace/orchestrator ports        (purity_scheme / purity_port)
  * userinfo in a URL                                                                 (purity_userinfo)
  * provider dashboards, cloud consoles, observability and DB-admin hosts, cloud metadata (purity_host)
  * internal / admin / debug / ops / hidden-test-route PATHS on the target            (purity_path)

The only exception is the explicit probe class ``negative_access_control``: a module that deliberately checks that an
admin-looking route REJECTS a customer-level session (ROLE-003, system-path recon, hidden/legacy-route probes) tags its
request with it. Those requests are counted, never produce oracle evidence, and still obey the host/scheme/port rules.
Stdlib only.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Iterable
from urllib.parse import unquote, urlparse

from app.core.control_port.contract import NEGATIVE_ACCESS_CONTROL, TargetAccessRejected

KNOWN_PROBE_CLASSES = frozenset({NEGATIVE_ACCESS_CONTROL})

CODE_SCHEME = "purity_scheme_not_customer_facing"
CODE_PORT = "purity_port_not_customer_facing"
CODE_USERINFO = "purity_userinfo_not_permitted"
CODE_HOST = "purity_host_not_customer_facing"
CODE_PATH = "purity_path_internal_surface"
CODE_PROBE = "purity_unknown_probe_class"
CODE_URL = "purity_invalid_url"

_FORBIDDEN_PORTS = frozenset({
    5432, 3306, 1433, 1521, 27017, 6379, 11211, 9042, 5672, 15672, 2181, 9092, 4222, 2379, 6443, 10250, 8500, 8200,
    9200, 9300, 5601, 3100, 16686, 4317, 4318,
})

_EXACT_FORBIDDEN_HOSTS = frozenset({
    "dashboard.stripe.com", "api.stripe.com", "dashboard.paddle.com", "vendors.paddle.com", "sandbox-vendors.paddle.com",
    "console.aws.amazon.com", "portal.azure.com", "console.cloud.google.com", "cloud.digitalocean.com", "dash.cloudflare.com",
    "app.datadoghq.com", "app.datadoghq.eu", "one.newrelic.com", "sentry.io", "app.logz.io", "cloud.mongodb.com",
    "console.firebase.google.com", "metadata.google.internal", "169.254.169.254", "fd00:ec2::254", "kubernetes.default.svc",
})
_SUFFIX_FORBIDDEN_HOSTS = (".console.aws.amazon.com", ".grafana.net", ".sentry.io", ".internal", ".cluster.local", ".svc")
_FORBIDDEN_FIRST_LABELS = frozenset({
    "grafana", "kibana", "prometheus", "jaeger", "argocd", "vault", "k8s", "kubernetes", "phpmyadmin", "adminer", "pgadmin",
    "mongo-express", "redis-commander", "admin", "backoffice", "back-office", "internal", "intranet",
})

_INTERNAL_SEGMENTS = frozenset({
    "admin", "administrator", "internal", "_internal", "actuator", "jolokia", "heapdump", "threaddump", "debug", "phpmyadmin",
    "pgadmin", "adminer", "h2-console", "server-status", "server-info", "ground_truth", "ground-truth", "groundtruth",
    "test-support", "test_support", "testsupport", "fixtures", "fixture", "hints", "flaws", ".git", ".env", ".svn", ".htaccess",
})
_DUNDER_SEGMENT = re.compile(r"^__.+__$")


def withhold_body(body: Any) -> dict[str, Any]:
    """Evidence-safe stand-in for the response body of a ``negative_access_control`` probe.

    Such a probe asks "is this route reachable / does it reject me?" -- the ANSWER is the status code. If the route turns out to be
    an exposed internal surface (actuator/env, debug, config ...) its body is exactly the internal information the Pure Black-Box
    rule forbids us to ingest, so only the size and a short digest survive (enough to tell a real response from an SPA fallback)."""
    import hashlib
    import json as _json

    raw = body if isinstance(body, str) else _json.dumps(body, sort_keys=True, default=str) if body is not None else ""
    data = raw.encode("utf-8", errors="replace")
    return {"_withheld": NEGATIVE_ACCESS_CONTROL, "bytes": len(data), "sha256_16": hashlib.sha256(data).hexdigest()[:16]}


def body_size(body: Any) -> int:
    """Length of a body, understanding the withheld stand-in."""
    if isinstance(body, dict) and body.get("_withheld") == NEGATIVE_ACCESS_CONTROL:
        return int(body.get("bytes", 0))
    if body is None:
        return 0
    return len(body) if isinstance(body, str) else len(str(body))


@dataclass(frozen=True)
class AccessDecision:
    allowed: bool
    code: str | None = None
    message: str | None = None


_ALLOW = AccessDecision(True)


def _host_decision(host: str) -> AccessDecision:
    if not host:
        return AccessDecision(False, CODE_URL, "URL has no host")
    if host in _EXACT_FORBIDDEN_HOSTS or any(host.endswith(s) for s in _SUFFIX_FORBIDDEN_HOSTS):
        return AccessDecision(False, CODE_HOST, f"host {host!r} is a provider dashboard / cloud console / observability / metadata surface, not a customer-facing one")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        first = host.split(".", 1)[0]
        if first in _FORBIDDEN_FIRST_LABELS:
            return AccessDecision(False, CODE_HOST, f"host {host!r} is an admin/internal/ops host label ({first!r}), not a customer-facing one")
    return _ALLOW


def _path_decision(path: str) -> AccessDecision:
    segments = [s for s in unquote(path or "/").lower().split("/") if s]
    for seg in segments:
        if seg in _INTERNAL_SEGMENTS or _DUNDER_SEGMENT.match(seg):
            return AccessDecision(False, CODE_PATH, f"path segment {seg!r} marks an internal/admin/debug/hidden-test surface")
    return _ALLOW


class AccessGate:
    """Stateless rules + counters. One instance per run (owned by the ScopeGuard); thread/loop-safe (plain int adds)."""

    def __init__(self) -> None:
        self._denied: dict[str, int] = {}
        self._negative_probes = 0

    def check(self, url: str, *, probe_class: str | None = None, count: bool = True) -> AccessDecision:
        decision = self._decide(url, probe_class)
        if count and not decision.allowed:
            self._denied[decision.code or "purity_denied"] = self._denied.get(decision.code or "purity_denied", 0) + 1
        return decision

    def note_negative_probe(self) -> None:
        """Called once per wire attempt that was authorised ONLY because it is a tagged negative_access_control probe."""
        self._negative_probes += 1

    def require(self, url: str, *, probe_class: str | None = None) -> None:
        decision = self.check(url, probe_class=probe_class)
        if not decision.allowed:
            raise TargetAccessRejected(decision.code or "purity_denied", decision.message or "request refused")

    def _decide(self, url: str, probe_class: str | None) -> AccessDecision:
        if probe_class is not None and probe_class not in KNOWN_PROBE_CLASSES:
            return AccessDecision(False, CODE_PROBE, f"unknown probe class {probe_class!r}")
        try:
            parsed = urlparse(url)
            port = parsed.port
        except ValueError:
            return AccessDecision(False, CODE_URL, "unparseable URL")
        scheme = (parsed.scheme or "").lower()
        if scheme not in ("http", "https"):
            return AccessDecision(False, CODE_SCHEME, f"scheme {scheme or '?'!r} is not a customer-facing web scheme")
        if "@" in parsed.netloc:
            return AccessDecision(False, CODE_USERINFO, "userinfo in URL is not permitted")
        host = (parsed.hostname or "").lower()
        host_decision = _host_decision(host)
        if not host_decision.allowed:
            return host_decision
        if port in _FORBIDDEN_PORTS:
            return AccessDecision(False, CODE_PORT, f"port {port} is a database/cache/queue/log/trace/orchestrator port, not a customer-facing one")
        if probe_class == NEGATIVE_ACCESS_CONTROL:
            return _ALLOW
        return _path_decision(parsed.path)

    def check_path(self, path: str) -> AccessDecision:
        """Path-only check (brief validation: declared operations/features must not name internal surfaces)."""
        return _path_decision(path)

    def validate_allowed_hosts(self, hosts: Iterable[str]) -> None:
        """Reject an authorised-host list that contains a non-customer-facing surface (config-time enforcement)."""
        bad: list[str] = []
        for entry in hosts:
            raw = (entry or "").strip().lower()
            probe = raw[2:] if raw.startswith("*.") else raw
            host, _, port_text = probe.partition(":") if probe.count(":") == 1 else (probe.strip("[]"), "", "")
            decision = _host_decision(host)
            if not decision.allowed or (port_text.isdigit() and int(port_text) in _FORBIDDEN_PORTS):
                bad.append(entry)
        if bad:
            raise TargetAccessRejected(CODE_HOST, f"allowed_hosts contains non-customer-facing surface(s): {bad}")

    def stats(self) -> dict[str, Any]:
        return {"denied": sum(self._denied.values()), "denied_by_code": dict(self._denied), "negative_access_control_probes": self._negative_probes}
