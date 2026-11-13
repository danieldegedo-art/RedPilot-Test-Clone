"""Identity-bound customer sessions: the only way the engine talks to a target, and the only producer of evidence.

Every call goes through ``CustomerSession.call``/``feature_call``:
  * it is sent by the guarded QAHttpClient (host allowlist, rate/budget, purity gate) with ONLY the synthetic identity's own bearer token,
  * the response is scrubbed of anything the target volunteered beyond product behaviour (debug headers, ``_debug`` fields, ...) BEFORE the
    engine can read it -- the number of dropped hints is counted so "present AND ignored" is provable,
  * an evidence artifact with full provenance (alias, tenant alias, session isolation id, authorisation ref, hash, external classification) is
    built automatically and admitted by the EvidenceLedger -- a caller cannot forget or forge provenance,
  * payment ids / tenant ids / tokens / emails are pseudonymised or redacted in the stored artifact (the engine keeps the raw values in memory only).
A *clean session* is a new CustomerSession object: new isolation id, no cookies, no client state, only the identity's token. Stdlib only.
"""
from __future__ import annotations

import hashlib
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from app.testing.http_client import QAHttpClient
from app.testing.integrity.brief import ExecutionBrief, FeatureSpec, OperationSpec
from app.core.control_port import EvidenceClass, EvidenceLedgerHandle, get_control_adapter
from app.testing.purity.taxonomy import TruthLabel

_SECRET_KEY = re.compile(r"(token|secret|password|authorization|cookie|session_id|api_?key|bearer)", re.I)
_ID_KEY = re.compile(r"(^id$|_id$|^payment$|^payment_ref$|reference$|^tenant$|^tenant_ref$|^owner$|^account$)", re.I)
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def pseudonym(value: Any) -> str:
    return "ref:" + hashlib.sha256(str(value).encode()).hexdigest()[:8]


def harvest_sensitive(obj: Any) -> list[str]:
    """Values of id-/secret-named fields in a request or response structure (payment ids, tenant ids, tokens). They are registered BEFORE the artifact for
    that very call is built, so a target that echoes its own id/token into another field (message, note ...) is redacted in the same artifact."""
    found: list[str] = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            if isinstance(value, str) and len(value) >= 4 and (_ID_KEY.search(str(key)) or _SECRET_KEY.search(str(key))):
                found.append(value)
            else:
                found.extend(harvest_sensitive(value))
    elif isinstance(obj, list):
        for item in obj:
            found.extend(harvest_sensitive(item))
    return found


def redact(obj: Any, *, _key: str = "", sensitive: dict[str, str] | None = None) -> Any:
    """Key-based AND value-based redaction. ``sensitive`` maps raw values this run is known to hold (tokens, payment ids, tenant ids) to pseudonyms and is applied
    to every string wherever it occurs, whatever the key is called (a claim such as ``tenant=<id>`` is caught by value, not by guessing key names)."""
    if isinstance(obj, dict):
        return {k: redact(v, _key=str(k), sensitive=sensitive) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(v, _key=_key, sensitive=sensitive) for v in obj]
    if _SECRET_KEY.search(_key) and obj not in (None, True, False):
        return "[REDACTED]"
    if isinstance(obj, str):
        if _ID_KEY.search(_key) and obj:
            return pseudonym(obj)
        text = _EMAIL.sub("[EMAIL]", obj)
        for raw in sorted(sensitive or (), key=len, reverse=True):
            text = text.replace(raw, (sensitive or {})[raw])
        return text
    return obj


class IdentityPoolExhausted(Exception):
    """No further synthetic identity can be obtained (no signup operation approved and the static pool is used up)."""


@dataclass
class CallResult:
    op: str
    status: int | None
    body: Any
    headers: dict[str, str]
    error: str | None
    elapsed_ms: float
    artifact_id: str | None
    admitted: bool
    rejection_codes: list[str] = field(default_factory=list)

    @property
    def transport_ok(self) -> bool:
        return self.error is None and self.status is not None


class EvidenceRecorder:
    """Shared by all sessions of one engine run: sequence numbers, hint counters, ledger access."""

    def __init__(self, brief: ExecutionBrief, ledger: EvidenceLedgerHandle, base_url: str) -> None:
        self.brief, self.ledger, self.base_url = brief, ledger, base_url.rstrip("/")
        self.sequence = 0
        self.hints_dropped = 0
        self.hint_samples: list[str] = []
        self.calls = 0
        self.sensitive: dict[str, str] = {}

    def register_sensitive(self, *values: Any) -> None:
        """Remember raw values that must never appear in stored evidence: they are pseudonymised everywhere and the ledger rejects any artifact that still contains one."""
        for v in values:
            if isinstance(v, str) and len(v) >= 4:
                self.sensitive[v] = pseudonym(v)
                self.ledger.protect(v)

    def next_seq(self) -> int:
        self.sequence += 1
        return self.sequence

    def note_hints(self, names: list[str]) -> None:
        self.hints_dropped += len(names)
        for n in names[:3]:
            if len(self.hint_samples) < 6 and n not in self.hint_samples:
                self.hint_samples.append(n)


class CustomerSession:
    def __init__(self, *, recorder: EvidenceRecorder, http: QAHttpClient, identity_alias: str, tenant_alias: str, token: str | None, tenant_id: str | None = None) -> None:
        self._rec, self._http, self._token = recorder, http, token
        self.identity_alias, self.tenant_alias, self.tenant_id = identity_alias, tenant_alias, tenant_id
        self.session_id = f"{identity_alias}:{uuid.uuid4().hex[:8]}"
        recorder.register_sensitive(token, tenant_id)

    def clean_copy(self) -> "CustomerSession":
        """Independent clean session of the SAME identity: fresh isolation id, no carried client state, token only."""
        return CustomerSession(recorder=self._rec, http=self._http, identity_alias=self.identity_alias, tenant_alias=self.tenant_alias, token=self._token, tenant_id=self.tenant_id)

    def _classification(self, op_name: str) -> EvidenceClass:
        if self._rec.brief.target_kind == "controlled_benchmark":
            return EvidenceClass.CONTROLLED_BLACK_BOX_BENCHMARK
        return EvidenceClass.APPROVED_SANDBOX_PAYMENT if op_name == "sandbox_pay" else EvidenceClass.EXTERNAL_CUSTOMER_API

    async def _send(self, op_name: str, label: str, method: str, path_template: str, path: str, *, json_body: Any, params: dict[str, Any] | None, uses_token: bool, extra_headers: dict[str, str] | None = None) -> CallResult:
        headers = {"Accept": "application/json"}
        if uses_token and self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        if extra_headers:
            headers.update(extra_headers)
        started = time.perf_counter()
        _, resp = await self._http.request(method, path, json_body=json_body, params=params, extra_headers=headers)
        elapsed = (time.perf_counter() - started) * 1000
        self._rec.calls += 1
        controls = get_control_adapter()
        safe_headers, dropped_headers = controls.scrub_headers(resp.headers)
        safe_body, dropped_body = controls.scrub_body(resp.body)
        self._rec.note_hints(dropped_headers + dropped_body)
        # Register sensitive values the TARGET volunteered in its RESPONSE (tokens, payment/tenant ids), so they
        # are redacted everywhere (including in later request artifacts, since redaction applies the whole
        # sensitive map by value). We deliberately do NOT harvest from the engine's OWN request fields: during
        # field learning the engine may send a low-entropy value it saw in recon (a plan code like "basic", a
        # service name like "relay") as a SPECULATIVE candidate under an id-named slot (price_id/payment_id/...),
        # and registering that guess as a globally substring-redacted "sensitive" value then falsely rejects every
        # artifact whose op name / label / path legitimately contains that common word (provenance
        # unredacted_sensitive_value). A genuinely sensitive value the engine re-sends was already registered from
        # the response that issued it, so request-side redaction of real secrets is unaffected.
        self._rec.register_sensitive(*harvest_sensitive(safe_body))
        payload = {
            "op": op_name, "label": label, "request": {"method": method, "path": path_template, "fields": redact(json_body if json_body is not None else params, sensitive=self._rec.sensitive)},
            "response": {"status": resp.status_code, "error": resp.error, "headers": safe_headers, "body": redact(safe_body, sensitive=self._rec.sensitive)},
        }
        artifact = controls.build_artifact(
            payload=payload, source_type=op_name, classification=self._classification(op_name), identity_alias=self.identity_alias, tenant_alias=self.tenant_alias,
            target=f"{self._rec.base_url}{path}", session_isolation_id=self.session_id, authorization_ref=self._rec.brief.authorization_ref, redaction_status="redacted",
            truth_label=TruthLabel.EXTERNALLY_OBSERVED, sequence=self._rec.next_seq(),
        )
        ok, reasons = self._rec.ledger.try_admit(artifact)
        return CallResult(op=op_name, status=resp.status_code, body=safe_body, headers=safe_headers, error=resp.error, elapsed_ms=round(elapsed, 2),
                          artifact_id=artifact.artifact_id if ok else None, admitted=ok, rejection_codes=[r.code for r in reasons])

    async def call(self, op_name: str, *, label: str | None = None, path_params: dict[str, Any] | None = None, fields: dict[str, Any] | None = None, uses_token: bool = True, extra_headers: dict[str, str] | None = None) -> CallResult:
        spec: OperationSpec | None = self._rec.brief.op(op_name)
        if spec is None:
            return CallResult(op_name, None, None, {}, f"operation_not_declared:{op_name}", 0.0, None, False, ["operation_not_declared"])
        path = spec.path.format(**{k: v for k, v in (path_params or {}).items()}) if "{" in spec.path else spec.path
        wire = {spec.wire(k): v for k, v in (fields or {}).items() if v is not None}
        return await self._send(op_name, label or op_name, spec.method, spec.path, path, json_body=None if spec.uses_query else (wire or None), params=wire if spec.uses_query else None, uses_token=uses_token, extra_headers=extra_headers)

    async def feature_call(self, feature: FeatureSpec, *, label: str, extra_headers: dict[str, str] | None = None, extra_params: dict[str, Any] | None = None) -> CallResult:
        uses_query = feature.method in ("GET", "DELETE")
        return await self._send(f"feature:{feature.feature_id}", label, feature.method, feature.path, feature.path,
                                json_body=None if uses_query else {}, params=dict(extra_params) if extra_params else None,
                                uses_token=True, extra_headers=extra_headers)

    async def raw(self, method: str, path: str, *, label: str, json_body: Any = None, params: dict[str, Any] | None = None, extra_headers: dict[str, str] | None = None) -> CallResult:
        """A single GUARDED request to an explicit customer-surface path that is not a declared brief op --
        used only by the engine's bounded entitlement-channel probe. Goes through the same ScopeGuard
        (host/scheme/rate/purity gate) as every other call; it never bypasses the guard."""
        return await self._send("channel_probe", label, method, path, path, json_body=json_body, params=params, uses_token=True, extra_headers=extra_headers)


class IdentityProvisioner:
    """Hands out synthetic identities: mints them through the approved ``signup`` operation, or walks the brief's static pool."""

    def __init__(self, brief: ExecutionBrief, recorder: EvidenceRecorder, http: QAHttpClient) -> None:
        self._brief, self._rec, self._http = brief, recorder, http
        self._pool = list(brief.identities.values())
        self._used = 0
        self._minted = 0
        self.sessions: dict[str, CustomerSession] = {}

    async def acquire(self, role_label: str) -> CustomerSession:
        if self._brief.allow_signup and self._brief.op("signup") is not None:
            self._minted += 1
            alias = f"{role_label}_{self._minted}"
            tenant_alias = f"tenant_{alias}"
            self._rec.ledger.register_identity(alias, tenant_alias)
            probe = CustomerSession(recorder=self._rec, http=self._http, identity_alias=alias, tenant_alias=tenant_alias, token=None)
            res = await probe.call("signup", label=f"signup:{alias}", uses_token=False)
            spec = self._brief.op("signup")
            token = spec.read(res.body, "token") if spec else None
            tenant_id = spec.read(res.body, "tenant_id") if spec else None
            self._rec.register_sensitive(token, tenant_id)
            if not (res.status and 200 <= res.status < 300) or not token or not res.admitted:
                raise IdentityPoolExhausted(f"signup did not yield a usable synthetic identity (status={res.status}, admitted={res.admitted})")
            session = CustomerSession(recorder=self._rec, http=self._http, identity_alias=alias, tenant_alias=tenant_alias, token=str(token), tenant_id=str(tenant_id) if tenant_id else None)
        else:
            if self._used >= len(self._pool):
                raise IdentityPoolExhausted("the brief's static identity pool is exhausted and no signup operation is approved")
            spec_i = self._pool[self._used]
            self._used += 1
            token = self._brief.tokens.get(spec_i.alias)
            if not token:
                raise IdentityPoolExhausted(f"no token available for approved identity {spec_i.alias!r} (token_env unset)")
            self._rec.ledger.register_identity(spec_i.alias, spec_i.tenant_alias)
            session = CustomerSession(recorder=self._rec, http=self._http, identity_alias=spec_i.alias, tenant_alias=spec_i.tenant_alias, token=token, tenant_id=spec_i.tenant_id)
        self.sessions[session.identity_alias] = session
        return session
