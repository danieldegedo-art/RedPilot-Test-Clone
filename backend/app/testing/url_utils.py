"""URL normalization shared by the runner and the recon module.

httpx's `Client(base_url=...)` + relative-path joining is a simple string
concatenation, not full RFC 3986 URI resolution: if base_url still carries
its own path/query (e.g. a user pastes
`https://site.com/payment?productId=X` as the Test Environment URL) and a
module then requests the absolute path `/api/v1/payments`, the two get
concatenated onto the SAME string instead of the path replacing the
base's path -- producing garbage like
`https://site.com/payment?productId=Xapi/v1/payments`, which the target
serves as its ordinary HTML page (200 OK) rather than routing to any API,
so every module built on EndpointMap ends up testing the wrong thing.

The fix: every EndpointMap-based module talks to the clean origin
(scheme://host[:port]), never the raw entered URL. The raw entered URL is
preserved separately (TestContext.entry_url) for the one module that
actually needs to load that exact page: ReconModule, which crawls whatever
page the user pointed it at.
"""
from __future__ import annotations

import hashlib
import re
from urllib.parse import urlparse


def origin_of(url: str) -> str:
    """Returns just scheme://host[:port], discarding path/query/fragment."""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def path_of(url_or_path: str) -> str:
    """Returns just the path (no scheme/host/query/fragment). Accepts either
    a full URL or an already-bare path (e.g. from a hand-configured
    EndpointMap override) and normalizes both to a leading-slash path."""
    if url_or_path.startswith("http://") or url_or_path.startswith("https://"):
        parsed = urlparse(url_or_path)
        return parsed.path or "/"
    return url_or_path if url_or_path.startswith("/") else f"/{url_or_path}"


def target_identity_key(url: str) -> str:
    """Returns a stable, filesystem-safe identifier for the target system
    behind `url` -- same origin in, same key out, every time, regardless of
    which run produced it.

    Used to key the cognitive architecture's persistent storage
    (PersistentMemoryStore, CoverageMapper) by *target*, not by *run*: see
    CognitiveEngine's `storage_path` -- without this, storage keyed by
    run_id gives every run a brand-new, empty database, which silently
    defeats the entire premise of "cross-session knowledge accumulation"
    the cognitive layer's own docstrings describe (episodic memories never
    accumulate past a single run; consolidate() never has more than one
    session's evidence to work with; coverage-over-time can never be
    computed). Hostname + port is normalized (case-insensitive, no
    scheme) so http/https or a trailing-slash difference in how the URL
    was typed don't fragment one target's history across two keys.
    """
    origin = origin_of(url).lower()
    host_port = origin.split("://", 1)[-1]
    digest = hashlib.sha256(host_port.encode("utf-8")).hexdigest()[:16]
    # Keep a short, readable prefix for humans browsing the storage
    # volume -- the digest is what actually guarantees uniqueness/stability.
    safe_host = re.sub(r"[^a-zA-Z0-9.-]", "_", host_port)[:40]
    return f"{safe_host}-{digest}"
