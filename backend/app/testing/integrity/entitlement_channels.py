"""Curated catalog of common entitlement-bypass channels (BOUNDED, FAIL-CLOSED).

WHY: the base PBB-U experiment proves or rules out "access without a valid payment"
only through the channel it already exercises (the return-flow status claim). Real
paywalls are also defeated through channels an ordinary brief does not disclose: a
debug/override request header left enabled in production, a 'preview'/'trial' query
flag, an unverified grant token the feature trusts, or an undocumented
complimentary-grant endpoint. A strong black-box payment tester probes for these --
it is ordinary business-logic/authorization testing, on the authorized surface.

SAFETY (matches the platform's bounded, fail-closed style):
  * BOUNDED: this FIXED, pre-registered list only. No fuzzing, no enumeration, no
    guessing of identifiers/tokens/accounts.
  * AUTHORIZED SURFACE ONLY: customer-plausible headers, query flags and endpoints on
    the same host. Never the privileged back-office or debug routes -- those stay refused by the
    Access Gate / purity gate regardless of this module.
  * CONFIRMED BY THE REAL ORACLE: the engine treats a channel as a finding ONLY when
    the Protected-Feature Oracle shows a genuine USE of the declared feature,
    reproduced in a clean session. A lookalike endpoint that returns a convincing body
    but grants nothing cannot become a false positive.
  * FAIL-CLOSED: the capability is off unless the engine is explicitly enabled.

Stdlib only; pure (no I/O here -- this module only declares what to try).
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Channel:
    id: str
    kind: str  # "header" | "query" | "endpoint"
    description: str
    headers: dict[str, str] = field(default_factory=dict)
    params: dict[str, str] = field(default_factory=dict)
    method: str = "POST"
    path_suffix: str = ""  # for kind == "endpoint": appended to the derived API prefix


# A small, unverified grant token: a plausible client-supplied entitlement claim that a
# broken feature might trust without verification. We never mint real credentials.
_UNSIGNED_GRANT = base64.b64encode(b"plan=top;entitled=1").decode()

HEADER_CHANNELS: tuple[Channel, ...] = (
    Channel("hdr_entitlement_override", "header", "an override entitlement request header", headers={"X-Entitlement-Override": "1"}),
    Channel("hdr_debug_grant", "header", "a debug grant request header", headers={"X-Debug-Grant": "true"}),
    Channel("hdr_unverified_grant", "header", "an unverified client-supplied grant token", headers={"X-Grant": _UNSIGNED_GRANT}),
    Channel("hdr_preview", "header", "a preview request header", headers={"X-Preview": "1"}),
)

QUERY_CHANNELS: tuple[Channel, ...] = (
    Channel("q_preview", "query", "a preview query flag", params={"preview": "true"}),
    Channel("q_trial", "query", "a trial query flag", params={"trial": "true"}),
    Channel("q_complimentary", "query", "a complimentary query flag", params={"comp": "1"}),
    Channel("q_debug", "query", "a debug query flag", params={"debug": "1"}),
)

# Endpoint suffixes appended to the API prefix the engine derives from the declared surface.
ENDPOINT_CHANNELS: tuple[Channel, ...] = (
    Channel("ep_account_comp", "endpoint", "an undocumented complimentary-grant endpoint", method="POST", path_suffix="/account/comp"),
    Channel("ep_promo_apply", "endpoint", "an undocumented promo-apply endpoint", method="POST", path_suffix="/promo/apply"),
    Channel("ep_billing_comp", "endpoint", "an undocumented billing comp endpoint", method="POST", path_suffix="/billing/comp"),
    Channel("ep_account_upgrade_free", "endpoint", "an undocumented free-upgrade endpoint", method="POST", path_suffix="/account/upgrade-free"),
)

MAX_CHANNELS = 32  # hard ceiling: the catalog is bounded and never grows at runtime


def catalog(api_prefix: str = "") -> tuple[Channel, ...]:
    """The full bounded channel set. Endpoint channels get the derived API prefix
    (e.g. '/api/v1') so they target the authorized surface, not a guessed host root."""
    prefix = (api_prefix or "").rstrip("/")
    endpoints = tuple(
        Channel(c.id, c.kind, c.description, method=c.method, path_suffix=prefix + c.path_suffix)
        for c in ENDPOINT_CHANNELS
    )
    full = HEADER_CHANNELS + QUERY_CHANNELS + endpoints
    assert len(full) <= MAX_CHANNELS, "entitlement-channel catalog must stay bounded"
    return full
