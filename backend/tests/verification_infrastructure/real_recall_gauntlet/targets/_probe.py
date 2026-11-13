"""In-process client for the INDEPENDENT ground-truth probers.

A prober drives a FRESH target instance's public ``handle`` directly (no sockets), as an
omniscient attacker would -- the same external evidence a black-box tester could obtain --
with ZERO reference to the engine's oracle and ZERO reference to the ``flaw_on`` flag beyond
constructing the instance. If a prober confirms a bypass, a real externally-observable flaw
exists; that, not the engine, is ground truth.
"""
from __future__ import annotations

from typing import Any, Optional
from urllib.parse import urlencode


class Client:
    def __init__(self, target: Any) -> None:
        self.t = target

    async def call(self, method: str, path: str, *, token: Optional[str] = None,
                   body: Optional[dict] = None, query: Optional[dict] = None,
                   headers: Optional[dict] = None) -> tuple[int, dict]:
        raw = path + ("?" + urlencode(query) if query else "")
        h = dict(headers or {})
        if token:
            h["authorization"] = f"Bearer {token}"
        res = await self.t.handle(method, raw, body or {}, h)
        status, resp = res[0], res[1]
        return status, resp

    async def signup(self) -> tuple[str, str]:
        s = self.t.s
        _st, r = await self.call("POST", s.route("signup"))
        return r["token"], r["tenant_id"]

    async def feature_allowed(self, token: str, role: str, proof: str, *, method: str = "POST") -> bool:
        s = self.t.s
        st, r = await self.call(method, s.route(role), token=token)
        return st == 200 and proof in r
