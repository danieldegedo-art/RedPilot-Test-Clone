"""Static, best-effort extraction of fetch()/axios() call patterns from raw
JavaScript source text.

Complements browser_crawler's live network capture by catching calls gated
behind user interaction the crawler's plain page load didn't trigger (e.g.
a checkout button's click handler). This is regex-plus-brace-matching, not
a real JS parser/AST -- it will miss calls built from concatenated strings
or template-literal variables (e.g. `"/subscriptions/" + id`), and won't
survive heavy minification/obfuscation. Treat its findings as leads to
confirm, not ground truth.
"""
from __future__ import annotations

import re

from app.testing.recon.browser_crawler import DiscoveredCall

_HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}

_FETCH_CALL_RE = re.compile(r"""fetch\(\s*['"`](?P<path>/[^'"`]*?)['"`]""", re.IGNORECASE)
_AXIOS_METHOD_RE = re.compile(
    r"""axios\s*\.\s*(?P<method>get|post|put|patch|delete)\(\s*['"`](?P<path>/[^'"`]*?)['"`]""",
    re.IGNORECASE,
)
_AXIOS_CONFIG_URL_RE = re.compile(r"""axios\(\s*\{""", re.IGNORECASE)
_URL_IN_OPTS_RE = re.compile(r"""url\s*:\s*['"`](?P<path>/[^'"`]*?)['"`]""")
_METHOD_IN_OPTS_RE = re.compile(r"""method\s*:\s*['"`](?P<method>[a-zA-Z]+)['"`]""")
_BODY_KEY_START_RE = re.compile(r"""body\s*:\s*(?:JSON\.stringify\(\s*)?""")
_BODY_KEY_RE = re.compile(r"""['"`]?([a-zA-Z_$][\w$]*)['"`]?\s*:""")


def _strip_query(path: str) -> str:
    return path.split("?")[0]


def _extract_balanced_block(text: str, search_from: int) -> str | None:
    """Finds the first '{' at or after `search_from` and returns the full
    text of that block INCLUDING braces, correctly matching nested '{'/'}'
    pairs (unlike a single non-nesting regex capture group)."""
    open_index = text.find("{", search_from)
    if open_index == -1:
        return None
    depth = 0
    for i in range(open_index, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[open_index : i + 1]
    return None  # unbalanced -- truncated/minified source, give up on this one


def _extract_fetch_calls(source: str) -> list[DiscoveredCall]:
    calls: list[DiscoveredCall] = []
    for match in _FETCH_CALL_RE.finditer(source):
        # Only look for an options object if a comma follows shortly after
        # the URL literal (i.e. fetch(url, {...}) rather than fetch(url)).
        lookahead = source[match.end() : match.end() + 10]
        opts_block = ""
        if "," in lookahead:
            opts_block = _extract_balanced_block(source, match.end()) or ""

        method_match = _METHOD_IN_OPTS_RE.search(opts_block)
        method = method_match.group("method").upper() if method_match else "GET"
        if method not in _HTTP_METHODS:
            continue

        params: set[str] = set()
        body_start = _BODY_KEY_START_RE.search(opts_block)
        if body_start:
            body_block = _extract_balanced_block(opts_block, body_start.end())
            if body_block is not None:
                params = set(_BODY_KEY_RE.findall(body_block))

        calls.append(DiscoveredCall(method=method, path=_strip_query(match.group("path")), param_names=params, source="static-js"))
    return calls


def _extract_axios_method_calls(source: str) -> list[DiscoveredCall]:
    return [
        DiscoveredCall(method=match.group("method").upper(), path=_strip_query(match.group("path")), param_names=set(), source="static-js")
        for match in _AXIOS_METHOD_RE.finditer(source)
    ]


def _extract_axios_config_calls(source: str) -> list[DiscoveredCall]:
    calls: list[DiscoveredCall] = []
    for match in _AXIOS_CONFIG_URL_RE.finditer(source):
        block = _extract_balanced_block(source, match.start())
        if block is None:
            continue
        url_match = _URL_IN_OPTS_RE.search(block)
        if not url_match:
            continue
        method_match = _METHOD_IN_OPTS_RE.search(block)
        method = method_match.group("method").upper() if method_match else "GET"
        params = set()
        body_start = _BODY_KEY_START_RE.search(block)
        if body_start:
            body_block = _extract_balanced_block(block, body_start.end())
            if body_block is not None:
                params = set(_BODY_KEY_RE.findall(body_block))
        calls.append(DiscoveredCall(method=method, path=_strip_query(url_match.group("path")), param_names=params, source="static-js"))
    return calls


def extract_calls_from_js(source: str) -> list[DiscoveredCall]:
    return _extract_fetch_calls(source) + _extract_axios_method_calls(source) + _extract_axios_config_calls(source)
