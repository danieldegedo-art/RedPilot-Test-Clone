"""Pure Black-Box enforcement tests: the Payment QA System itself cannot use White-Box or Grey-Box target information.

Covers the mandate's required categories (numbers refer to the 'mandatory_purity_tests' list):
 1 target database credentials        2 target admin credentials        3 target internal API base URLs      4 target server-log connectors
 5 provider-dashboard connectors      6 internal entitlement evidence   7 benchmark flaw hints               8 benchmark internal metadata
 9 evidence without external provenance   10 no confirmation without an external Protected-Feature Oracle
 11 no confirmation on UI/redirect/status/cache/local-storage/client state   12 no fallback to internal data after an inconclusive external test
 13 quarantined modules cannot affect anything   14 a controlled benchmark is assessed without source/hints/DB/internal events (see also verification_infrastructure/test_purity_benchmark.py)
Plus: access-gate rules, negative-probe handling, run-start gating, webhook provenance, label channel, config/doc hygiene, inventory/audit gates.
"""
from __future__ import annotations

import ast
import asyncio
import base64
import importlib
import json
import os
import pathlib
import runpy
import sys
from datetime import date

import pytest

_INFRA = os.path.join(os.path.dirname(__file__), "verification_infrastructure")
if _INFRA not in sys.path:
    sys.path.insert(0, _INFRA)

from app.testing.http_client import QAHttpClient  # noqa: E402
from app.testing.integrity.brief import BriefRejected, ExecutionBrief  # noqa: E402
from app.testing.integrity.findings import SPECS, Finding  # noqa: E402
from app.core.control_port.contract import (  # noqa: E402  (shared contract types: exceptions, EvidenceClass)
    BenchmarkLeak, ConfirmationRefused, CredentialRejected, EvidenceClass, QuarantinedModuleError, TargetAccessRejected,
)
from app.enterprise_controls import audit, inventory  # noqa: E402  (the controls are tested directly, not through the adapter)
from app.enterprise_controls.access_gate import NEGATIVE_ACCESS_CONTROL, AccessGate  # noqa: E402
from app.enterprise_controls.blindness import BlindnessMonitor, filter_label_channel, scrub_body, scrub_headers  # noqa: E402
from app.enterprise_controls.credentials import jwt_privileged_claims, scan_for_forbidden, scan_string, validate_identity_spec  # noqa: E402
from app.enterprise_controls.oracle_gate import KIND_FEATURE_USE, NON_AUTHORITATIVE_SIGNALS, ConfirmationCandidate, ConfirmationGate, ConfirmationToken, OracleObservation  # noqa: E402
from app.enterprise_controls.provenance import EvidenceLedger, build_artifact, now_iso  # noqa: E402
from app.enterprise_controls.quarantine import QUARANTINE_REMOVAL_DEADLINE  # noqa: E402
from app.enterprise_controls.run_gate import validate_run_inputs  # noqa: E402
from app.enterprise_controls.scope import SCOPE_ERROR_PREFIX, ScopeGuard, ScopePolicy  # noqa: E402
from app.testing.purity.taxonomy import Verdict  # noqa: E402

REPO = pathlib.Path(__file__).resolve().parents[2]
BACKEND = REPO / "backend"


def _jwt(payload: dict) -> str:
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")  # noqa: E731
    return f"{enc({'alg': 'none'})}.{enc(payload)}.sig"


def _codes(reasons) -> set[str]:
    return {r.code for r in reasons}


def _valid_brief_dict(**over) -> dict:
    from purity_benchmark.lab import public_brief

    brief = public_brief("http://127.0.0.1:9")
    brief.update(over)
    return brief


# ================================================================================ 1. database credentials
def test_credential_gate_rejects_database_credentials():
    reasons = scan_for_forbidden({"database_url": "postgresql://qa:pw@db.internal:5432/shop", "nested": {"db_password": "x", "note": "mysql://u:p@h/db"}})
    assert {"config_secret_key", "credential_database_url"} <= _codes(reasons)
    assert not any("pw" in str(r) for r in reasons), "a reason must never echo the offending value"
    for dsn in ("postgres://a:b@h/d", "mongodb+srv://u:p@c.example/x", "redis://h:6379/0", "jdbc:postgresql://h/db"):
        assert "credential_database_url" in _codes(scan_string(dsn, "x")), dsn


def test_brief_rejects_database_credentials_and_run_gate_refuses_them():
    with pytest.raises(BriefRejected) as exc:
        ExecutionBrief.from_dict(_valid_brief_dict(database_url="postgresql://qa:pw@db/shop"), env={})
    assert "config_secret_key" in _codes(exc.value.reasons)
    with pytest.raises(CredentialRejected):
        validate_run_inputs(integrity_brief={"database_url": "postgresql://qa:pw@db/shop"})
    with pytest.raises(CredentialRejected):
        validate_run_inputs(custom_headers={"X-Conn": "postgres://u:p@h/db"})


# ================================================================================ 2. admin / staff / service credentials
def test_credential_gate_rejects_admin_and_staff_credentials():
    bad_role = validate_identity_spec("identity_a", {"role": "admin", "synthetic": True, "token_env": "QA_ADMIN_TOKEN"})
    assert {"identity_role_not_customer_level", "identity_token_env_invalid"} <= _codes(bad_role)
    for role in ("staff", "superuser", "service_account", "support", "root", "operator"):
        assert "identity_role_not_customer_level" in _codes(validate_identity_spec("identity_a", {"role": role, "synthetic": True})), role
    assert "identity_not_attested_synthetic" in _codes(validate_identity_spec("identity_a", {"role": "customer"}))
    assert "identity_inline_token" in _codes(validate_identity_spec("identity_a", {"role": "customer", "synthetic": True, "token": "abc"}))
    assert validate_identity_spec("identity_a", {"role": "customer", "synthetic": True, "token_env": "QA_IDENTITY_A_TOKEN", "tenant": "tenant_a"}) == []
    assert jwt_privileged_claims(_jwt({"sub": "1", "role": "admin"})) and jwt_privileged_claims(_jwt({"is_staff": True})) and jwt_privileged_claims(_jwt({"roles": ["user", "superuser"]}))
    assert jwt_privileged_claims(_jwt({"sub": "1", "role": "customer"})) == []


def test_run_gate_rejects_privileged_session_material():
    for headers in ({"X-Admin-Token": "x"}, {"X-Impersonate-User": "1"}, {"Authorization": "Bearer " + _jwt({"role": "admin"})}, {"Authorization": "Bearer sk_live_abcdefghijklmnop"}, {"Cookie": "admin_session=abc; theme=dark"}):
        with pytest.raises(CredentialRejected):
            validate_run_inputs(custom_headers=headers)
    with pytest.raises(CredentialRejected):
        validate_run_inputs(custom_headers={}, session_cookies={"staff_token": "abc"})
    validate_run_inputs(custom_headers={"Authorization": "Bearer " + _jwt({"sub": "1", "role": "customer"}), "Cookie": "sid=abc"})  # customer-level material passes


# ================================================================================ 3. internal API base URLs / hidden routes
def test_access_gate_rejects_internal_surfaces():
    g = AccessGate()
    allowed = ["http://127.0.0.1:8080/api/v1/checkout", "https://shop.example.test/api/v1/premium/export", "http://shop.example.test/billing/subscription"]
    assert all(g.check(u).allowed for u in allowed)
    refused = {
        "http://127.0.0.1:8080/internal/ledger": "purity_path_internal_surface", "http://shop.example.test/api/admin/users": "purity_path_internal_surface",
        "http://shop.example.test/actuator/env": "purity_path_internal_surface", "http://shop.example.test/__benchmark__/ground_truth": "purity_path_internal_surface",
        "http://shop.example.test/.env": "purity_path_internal_surface", "http://shop.example.test/%61dmin/x": "purity_path_internal_surface",
        "https://dashboard.stripe.com/test/payments": "purity_host_not_customer_facing", "https://console.aws.amazon.com/rds": "purity_host_not_customer_facing",
        "http://169.254.169.254/latest/meta-data": "purity_host_not_customer_facing", "http://grafana.corp.example/d/1": "purity_host_not_customer_facing",
        "http://shop.example.test:5432/": "purity_port_not_customer_facing", "http://shop.example.test:6379/": "purity_port_not_customer_facing",
        "postgres://db.example.test/shop": "purity_scheme_not_customer_facing", "file:///etc/passwd": "purity_scheme_not_customer_facing", "http://user:pw@shop.example.test/": "purity_userinfo_not_permitted",
    }
    for url, code in refused.items():
        d = g.check(url)
        assert not d.allowed and d.code == code, (url, d)
    assert g.stats()["denied"] == len(refused)
    assert g.check("http://shop.example.test/x", probe_class="made_up").code == "purity_unknown_probe_class"


def test_brief_rejects_internal_api_base_and_internal_paths_and_missing_provenance():
    for key in ("internal_api_base", "private_api_spec", "admin_url", "provider_dashboard_url", "source_path", "repository_url", "entitlement_db"):
        with pytest.raises(BriefRejected) as exc:
            ExecutionBrief.from_dict(_valid_brief_dict(**{key: "x"}), env={})
        assert "config_internal_key" in _codes(exc.value.reasons), key
    brief = _valid_brief_dict()
    brief["surface"]["start_checkout"]["path"] = "/internal/checkout"
    brief["features"]["premium_export"]["path"] = "/admin/export"
    brief["surface"]["return_flow"]["observed_via"] = "internal_api_docs"
    brief["features"]["credits_use"]["observed_via"] = "staff_instructions"
    with pytest.raises(BriefRejected) as exc:
        ExecutionBrief.from_dict(brief, env={})
    codes = _codes(exc.value.reasons)
    assert "purity_path_internal_surface" in codes and "brief_observed_via_invalid" in codes
    brief2 = _valid_brief_dict(allowed_hosts=["grafana.example.test", "dashboard.stripe.com"])
    with pytest.raises(BriefRejected) as exc2:
        ExecutionBrief.from_dict(brief2, env={})
    assert "purity_host_not_customer_facing" in _codes(exc2.value.reasons)


def test_run_gate_rejects_internal_endpoint_overrides_and_hosts():
    from types import SimpleNamespace

    with pytest.raises(CredentialRejected):
        validate_run_inputs(endpoint_overrides={"get_payment": SimpleNamespace(path="/internal/payments/{id}")})
    with pytest.raises(CredentialRejected):
        validate_run_inputs(endpoint_overrides={"refund": {"method": "POST", "path": "/admin/refunds"}})
    with pytest.raises(TargetAccessRejected):
        validate_run_inputs(extra_allowed_hosts=["dashboard.stripe.com"])
    with pytest.raises(TargetAccessRejected):
        validate_run_inputs(extra_allowed_hosts=["shop.example.test:5432"])
    validate_run_inputs(endpoint_overrides={"create_payment": SimpleNamespace(path="/api/v2/pay")}, extra_allowed_hosts=["staging.shop.example.test", "*.shop.example.test"])


def test_runs_py_calls_the_purity_check_before_constructing_the_runner():
    src = (BACKEND / "app" / "api" / "v1" / "runs.py").read_text()
    tree = ast.parse(src)
    fn = next(n for n in ast.walk(tree) if isinstance(n, ast.AsyncFunctionDef) and n.name == "start_run")
    calls = [(n.lineno, getattr(n.func, "id", getattr(n.func, "attr", ""))) for n in ast.walk(fn) if isinstance(n, ast.Call)]
    purity = min(l for l, name in calls if name == "_purity_check_or_400")
    runner = min(l for l, name in calls if name in ("TestRunner", "_execute_and_persist", "create_task"))
    assert purity < runner, "start_run must refuse non-customer-level inputs (HTTP 400) before anything is started"
    runner_src = (BACKEND / "app" / "testing" / "runner.py").read_text()
    assert "validate_run_inputs(" in runner_src, "TestRunner must enforce the same gate for runs started any other way"


@pytest.mark.asyncio
async def test_scope_guard_blocks_internal_path_before_the_wire():
    from purity_benchmark.customer_target import TargetFlags, start_customer_target

    target, server, port = await start_customer_target(TargetFlags(emit_debug_hints=True))
    base = f"http://127.0.0.1:{port}"
    try:
        guard = ScopeGuard(ScopePolicy.for_environment(base, max_requests=50, max_requests_per_second=50))
        http = QAHttpClient(base, 5.0, None, {}, "ua", max_retries=0, guard=guard)
        for path in ("/internal/ledger", "/__benchmark__/ground_truth", "/admin/entitlements", "/api/admin/x"):
            _, resp = await http.request("GET", path)
            assert resp.error and resp.error.startswith(SCOPE_ERROR_PREFIX) and "purity_path_internal_surface" in resp.error, (path, resp.error)
        assert target.internal_hits == 0 and target.request_log == [], "the refused requests must never reach the target"
        assert guard.stats()["purity_gate"]["denied"] == 4
        await http.aclose()
    finally:
        await server.aclose()


# ================================================================================ 4. server-log connectors
def test_config_rejects_server_log_connectors_and_log_hosts():
    for key in ("log_path", "server_log_url", "log_reader", "log_connector", "trace_endpoint", "trace_url", "application_log_file"):
        assert "config_internal_key" in _codes(scan_for_forbidden({key: "x"})), key
    g = AccessGate()
    for host in ("kibana.example.test", "app.logz.io", "app.datadoghq.com", "one.newrelic.com", "jaeger.example.test", "sentry.io"):
        assert not g.check(f"https://{host}/x").allowed, host
    with pytest.raises(TargetAccessRejected):
        AccessGate().validate_allowed_hosts(["kibana.example.test"])


def test_target_facing_code_has_no_log_database_or_cloud_clients():
    assert audit.forbidden_imports() == []


# ================================================================================ 5. provider-dashboard connectors
def test_provider_dashboard_connectors_are_rejected():
    assert "config_internal_key" in _codes(scan_for_forbidden({"provider_dashboard_url": "https://dashboard.stripe.com"}))
    assert "config_internal_key" in _codes(scan_for_forbidden({"dashboard_token": "x"}))
    assert "credential_provider_secret_key" in _codes(scan_string("sk_live_" + "a" * 24, "x")) and "credential_webhook_signing_secret" in _codes(scan_string("whsec_" + "a" * 16, "x"))
    for host in ("dashboard.stripe.com", "dashboard.paddle.com", "vendors.paddle.com", "api.stripe.com"):
        assert not AccessGate().check(f"https://{host}/v1").allowed, host


def test_brief_rejects_webhook_signing_secret():
    with pytest.raises(BriefRejected) as exc:
        ExecutionBrief.from_dict(_valid_brief_dict(webhook_secret="whsec_" + "x" * 20), env={})
    assert "config_secret_key" in _codes(exc.value.reasons) and "credential_webhook_signing_secret" in _codes(exc.value.reasons)
    assert "whsec_" not in str(exc.value), "the rejection must not echo the secret"


def test_credential_gate_rejects_secret_values():
    for value in ("whsec_" + "a" * 12, "sk_test_" + "b" * 12, "rk_live_" + "c" * 12, "AKIA" + "A" * 16, "-----BEGIN RSA PRIVATE KEY-----", "ghp_" + "d" * 24):
        assert scan_string(value, "x"), value[:8]


# ================================================================================ 6. internal entitlement evidence
def _ledger() -> EvidenceLedger:
    return EvidenceLedger(authorization_ref="REF-1", approved_identity_aliases=["identity_a"], approved_tenant_aliases=["tenant_a"])


def _artifact(classification=EvidenceClass.EXTERNAL_CUSTOMER_API, payload=None, **over):
    kw = dict(payload=payload or {"status": 200}, source_type="customer_api", classification=classification, identity_alias="identity_a", tenant_alias="tenant_a",
              target="http://127.0.0.1:9/api/v1/premium/export", session_isolation_id="s1", authorization_ref="REF-1", sequence=1)
    kw.update(over)
    return build_artifact(**kw)


def test_ledger_rejects_internal_entitlement_evidence():
    led = _ledger()
    for cls in ("internal_entitlement_record", "database_row", "server_log", "provider_dashboard", "admin_panel", "benchmark_label", "ground_truth", "internal_state"):
        ok, reasons = led.try_admit(_artifact(classification=cls))
        assert not ok and _codes(reasons) & {"provenance_internal_source", "provenance_classification_invalid"}, cls
    ok, reasons = led.try_admit(_artifact(payload={"status": 200, "entitlement_record": {"plan": "pro"}}))
    assert not ok and "provenance_internal_field_present" in _codes(reasons)
    ok, reasons = led.try_admit(_artifact(payload={"status": 200, "_debug": {"tenant_entitlement": {"plan": "pro"}}}))
    assert not ok and "provenance_internal_field_present" in _codes(reasons)
    assert led.summary()["accepted"] == 0 and led.summary()["rejected"] == 10


# ================================================================================ 7. + 8. benchmark flaw hints / internal metadata
def test_benchmark_flaw_hints_and_internal_metadata_are_rejected():
    for key in ("flaw_hint", "seeded_flaws", "ground_truth", "expected_verdict", "scenario_name", "fixtures", "hints", "vulnerability_label", "bug_class", "truth_from_flags"):
        assert "config_benchmark_key" in _codes(scan_for_forbidden({key: "x"})), key
    with pytest.raises(BriefRejected):
        ExecutionBrief.from_dict(_valid_brief_dict(hints=["the flaw is in the return flow"]), env={})
    mon = BlindnessMonitor(["failed_payment_grants_access", "return_trusts_status_claim"])
    with pytest.raises(BenchmarkLeak):
        mon.assert_blind({"brief": {"note": "see failed_payment_grants_access"}}, where="brief")
    with pytest.raises(BenchmarkLeak):
        mon.assert_blind({"flaw_label": "x"}, where="engine input")
    mon.assert_blind({"brief": {"plans": {"basic": 9}}}, where="brief")  # clean input passes
    body, dropped = scrub_body({"ok": True, "_debug": {"x": 1}, "data": {"flaw_id": "G", "n": 2}, "entitlement_record": {"plan": "pro"}})
    assert body == {"ok": True, "data": {"n": 2}} and len(dropped) == 3
    headers, hints = scrub_headers({"Content-Type": "application/json", "X-Debug-Entitlement": "granted", "X-Benchmark-Flaw-Hint": "G", "X-Internal-State": "s"})
    assert headers == {"content-type": "application/json"} and len(hints) == 3


def test_label_channel_strips_unapproved_ground_truth():
    rows = [{"detected": True, "in_ground_truth": True}, {"detected": True, "in_ground_truth": True, "label_provenance": "synthetic_selftest"}, {"detected": False, "flaw_label": "G", "label_provenance": "benchmark_metadata"}]
    out, stripped = filter_label_channel(rows)
    assert stripped == 2 and "in_ground_truth" not in out[0] and "in_ground_truth" in out[1] and "flaw_label" not in out[2]


# ================================================================================ 9. evidence without external provenance
def test_ledger_rejects_evidence_without_external_provenance():
    import dataclasses

    led = _ledger()
    ok, reasons = led.try_admit(None)
    assert not ok and "provenance_missing" in _codes(reasons)
    good = _artifact()
    ok, _ = led.try_admit(good)
    assert ok
    cases = {
        "provenance_missing": dataclasses.replace(_artifact(sequence=2), provenance=None),
        "provenance_field_missing": _artifact(sequence=3, session_isolation_id=" "),
        "provenance_identity_unapproved": _artifact(sequence=4, identity_alias="mallory"),
        "provenance_tenant_unapproved": _artifact(sequence=5, tenant_alias="tenant_x"),
        "provenance_authorization_mismatch": _artifact(sequence=6, authorization_ref="OTHER"),
        "provenance_redaction_missing": _artifact(sequence=7, redaction_status="raw"),
        "provenance_target_not_customer_facing": _artifact(sequence=8, target="http://127.0.0.1:9/internal/ledger"),
        "provenance_truth_label_invalid": _artifact(sequence=9, truth_label="TRUSTME"),
        "provenance_classification_invalid": _artifact(sequence=10, classification="mystery_source"),
    }
    for code, art in cases.items():
        ok, reasons = led.try_admit(art)
        assert not ok and code in _codes(reasons), (code, _codes(reasons))
    tampered = dataclasses.replace(good, payload={"status": 201})
    ok, reasons = led.try_admit(tampered)
    assert not ok and "provenance_hash_mismatch" in _codes(reasons)
    assert {c.value for c in EvidenceClass} == {"external_browser", "external_customer_api", "external_notification", "approved_sandbox_payment", "controlled_black_box_benchmark"}
    led.protect("tok_secretvalue")
    ok, reasons = led.try_admit(_artifact(sequence=11, payload={"echo": "Bearer tok_secretvalue"}))
    assert not ok and "provenance_unredacted_sensitive_value" in _codes(reasons)


# ================================================================================ 10. + 11. confirmation requires the external oracle chain
def _obs(oid, alias, outcome, session, artifact_ids, *, discriminating=True, proof=True, kind=KIND_FEATURE_USE):
    return OracleObservation(oid, "premium_export", alias, "tenant_a", outcome, kind, proof, session, tuple(artifact_ids), discriminating, now_iso())


def _chain(led: EvidenceLedger):
    ids = [led.admit(_artifact(sequence=i, session_isolation_id=f"s{i}")).artifact_id for i in (1, 2, 3)]
    return ids


def test_confirmed_p0_is_unconstructible_without_the_gate_token():
    with pytest.raises(ConfirmationRefused):
        Finding("PBB-U", "x", "t", Verdict.CONFIRMED_P0, "high", "s", SPECS["PBB-U"])
    with pytest.raises(ConfirmationRefused):
        ConfirmationToken("PBB-U", ())
    led = _ledger()
    ids = _chain(led)
    gate = ConfirmationGate(led)
    d = gate.evaluate(ConfirmationCandidate("PBB-U", _obs("c", "identity_a", "denied", "s1", [ids[0]]), _obs("s", "identity_a", "allowed", "s2", [ids[1]]), _obs("r", "identity_a", "allowed", "s3", [ids[2]]), False))
    assert d.confirmed and d.token is not None
    Finding("PBB-U", "x", "t", Verdict.CONFIRMED_P0, "high", "s", SPECS["PBB-U"], token=d.token)  # now constructible
    with pytest.raises(ConfirmationRefused):  # a token for another hypothesis does not cover this one
        Finding("PBB-F", "x", "t", Verdict.CONFIRMED_P0, "high", "s", SPECS["PBB-F"], token=d.token)


def test_gate_requires_control_use_independent_reproduction_and_admitted_evidence():
    led = _ledger()
    ids = _chain(led)
    gate = ConfirmationGate(led)
    ctl, sc, rp = _obs("c", "identity_a", "denied", "s1", [ids[0]]), _obs("s", "identity_a", "allowed", "s2", [ids[1]]), _obs("r", "identity_a", "allowed", "s3", [ids[2]])
    def ok(**kw):
        parts = dict(control_denied=ctl, scenario_allowed=sc, clean_reproduction=rp, qualifying_payment_present=False)
        parts.update(kw)
        return gate.evaluate(ConfirmationCandidate("H", **parts))
    assert ok().confirmed
    assert not ok(control_denied=None).confirmed
    assert not ok(control_denied=_obs("c", "identity_a", "allowed", "s1", [ids[0]])).confirmed
    assert not ok(control_denied=_obs("c", "identity_a", "denied", "s1", [ids[0]], discriminating=False)).confirmed
    assert not ok(scenario_allowed=_obs("s", "identity_a", "allowed", "s2", [ids[1]], proof=False)).confirmed
    assert not ok(scenario_allowed=_obs("s", "identity_a", "indeterminate", "s2", [ids[1]])).confirmed
    assert not ok(clean_reproduction=None).confirmed
    assert not ok(clean_reproduction=_obs("r", "identity_a", "allowed", "s2", [ids[2]])).confirmed, "reproduction in the SAME session is not independent"
    assert not ok(qualifying_payment_present=True).confirmed
    assert not ok(scenario_allowed=_obs("s", "identity_a", "allowed", "s2", ["ev-9999-notadmitted"])).confirmed
    assert not ok(evidence_classes=("database_row",)).confirmed
    assert not ok(scenario_allowed=_obs("s", "identity_a", "allowed", "s2", [ids[1]], kind="status_read")).confirmed


def test_non_authoritative_signals_never_confirm():
    led = _ledger()
    ids = _chain(led)
    gate = ConfirmationGate(led)
    ctl, sc, rp = _obs("c", "identity_a", "denied", "s1", [ids[0]]), _obs("s", "identity_a", "allowed", "s2", [ids[1]]), _obs("r", "identity_a", "allowed", "s3", [ids[2]])
    expected = {"ui_badge", "success_page", "failure_page", "redirect", "http_status_only", "invoice_looking_page", "browser_cache", "local_storage", "client_side_state",
                "frontend_feature_flag", "optimistic_message", "provider_callback_page", "status_read", "subscription_view", "internal_state", "log", "database", "provider_dashboard", "benchmark_label"}
    assert expected <= NON_AUTHORITATIVE_SIGNALS
    for signal in sorted(NON_AUTHORITATIVE_SIGNALS):
        d = gate.evaluate(ConfirmationCandidate("H", ctl, sc, rp, False, signals_used=(signal,)))
        assert not d.confirmed and any(r.startswith("oracle_requirement_not_met") for r in d.reasons), signal


# ================================================================================ 12. no fallback to internal data
@pytest.mark.asyncio
async def test_inconclusive_external_test_never_falls_back_to_internal_data():
    from purity_benchmark.lab import run_scenario
    from purity_benchmark.scenarios import by_name

    run = await run_scenario(by_name("opaque_async_feature_internal_flaw"))
    verdicts = set(run.result.verdicts().values())
    assert verdicts <= {"UNKNOWN", "BLOCKED"}, verdicts  # never RULED_OUT (false assurance), never CONFIRMED_P0 (the internal flaw is real but not externally provable)
    assert run.internal_hits == 0, "the engine must not touch /internal/*, /admin/* or /__benchmark__/* even though they exist and would reveal the flaw"
    assert run.target.entitlements and any(e["plan"] for e in run.target.entitlements.values()), "precondition: the internal flaw really exists in the target"
    assert (run.result.stats["guard"]["purity_gate"]["denied"]) == 0


def test_engine_and_purity_code_contain_no_internal_route_or_label_access():
    forbidden = ("/internal", "/__benchmark__", "/admin/", "ground_truth", "grant-direct", "webhook_secret", "_revoke_delay")
    # the ENGINE side only: the purity rule files (credentials/blindness/provenance/audit/inventory) legitimately NAME the forbidden vocabulary they detect
    for rel in ("app/testing/integrity", "app/testing/modules/payment_integrity.py"):
        path = BACKEND / rel
        for f in ([path] if path.is_file() else sorted(path.glob("*.py"))):
            text = f.read_text()
            if f.name in ("brief.py", "findings.py"):
                continue  # carry the rule vocabulary in validation messages / pre-registered specs only
            for token in forbidden:
                assert token not in text, f"{f.name} mentions {token!r}"


# ================================================================================ 13. quarantine
def test_quarantined_modules_cannot_load():
    files = sorted((BACKEND / "quarantine").rglob("*.py"))
    assert len(files) >= 20
    for f in files:
        with pytest.raises(QuarantinedModuleError):
            runpy.run_path(str(f), run_name="quarantined_probe")
    with pytest.raises(QuarantinedModuleError):
        importlib.import_module("quarantine.legacy_greybox.app_testing_integrity.oracle_engine")
    assert issubclass(QuarantinedModuleError, ImportError)


def test_quarantine_cannot_influence_planning_execution_evidence_findings_or_reports():
    assert audit.boundary_violations() == [], "nothing under app/ or tests/ may import the quarantine"
    import app.testing.integrity as integrity
    from app.testing import registry

    for legacy_name in ("OracleEngine", "IntegrityContract", "capability_gaps_legacy", "reconcile", "check_claimed_status_matches_authoritative"):
        assert not hasattr(integrity, legacy_name), legacy_name
    assert not any(m.startswith(("quarantine", "legacy_greybox")) for m in sys.modules), "no quarantined module is loaded in this process"
    text = pathlib.Path(registry.__file__).read_text()
    assert "oracle_engine" not in text and "IntegrityContract" not in text
    legacy = BACKEND / "app" / "testing" / "integrity" / "oracle_engine.py"
    assert not legacy.exists() and not (BACKEND / "app" / "testing" / "reconciliation.py").exists()


def test_quarantine_deadline_not_in_the_past():
    deadline = date.fromisoformat(QUARANTINE_REMOVAL_DEADLINE)
    assert date.today() <= deadline, f"quarantine removal deadline {deadline} has passed: delete backend/quarantine and the TAD-001..016/047 inventory entries"
    assert "2026-11-30" in (BACKEND / "quarantine" / "legacy_greybox" / "QUARANTINE.md").read_text()


# ================================================================================ 14. engine inputs are blind (see also test_purity_benchmark.py)
def test_engine_package_cannot_import_benchmark_or_test_code():
    assert [h for h in audit.boundary_violations() if "benchmark blindness" in h.detail] == []
    for f in sorted((BACKEND / "app" / "testing" / "integrity").glob("*.py")):
        for node in ast.walk(ast.parse(f.read_text())):
            names = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module or ""] if isinstance(node, ast.ImportFrom) else []
            assert not any(n.split(".")[0] in ("tests", "purity_benchmark", "quarantine") for n in names), (f.name, names)


# ================================================================================ negative probes, webhook provenance, endpoint overrides
@pytest.mark.asyncio
async def test_negative_access_control_probe_is_tagged_counted_and_body_withheld():
    from purity_benchmark.customer_target import TargetFlags, start_customer_target

    target, server, port = await start_customer_target(TargetFlags())
    base = f"http://127.0.0.1:{port}"
    try:
        guard = ScopeGuard(ScopePolicy.for_environment(base, max_requests=20, max_requests_per_second=50))
        http = QAHttpClient(base, 5.0, None, {}, "ua", max_retries=0, guard=guard)
        _, untagged = await http.request("GET", "/internal/ledger")
        assert untagged.error and untagged.error.startswith(SCOPE_ERROR_PREFIX) and target.internal_hits == 0
        _, tagged = await http.request("GET", "/internal/ledger", probe_class=NEGATIVE_ACCESS_CONTROL)
        assert tagged.status_code == 200 and target.internal_hits == 1, "a tagged probe may ask 'is this reachable?'"
        assert isinstance(tagged.body, dict) and tagged.body.get("_withheld") == NEGATIVE_ACCESS_CONTROL and "entitlements" not in json.dumps(tagged.body), "the CONTENT of a probed internal surface is never ingested"
        assert guard.stats()["purity_gate"]["negative_access_control_probes"] == 1
        _, bad_host = await http.request("GET", "http://127.0.0.1:5432/x", probe_class=NEGATIVE_ACCESS_CONTROL)
        assert bad_host.error, "a tagged probe still obeys host/port rules"
        await http.aclose()
    finally:
        await server.aclose()


@pytest.mark.asyncio
async def test_hidden_route_module_no_longer_reads_bodies_or_writes():
    from types import SimpleNamespace

    from app.testing.modules.business_rule_consistency import BusinessRuleConsistencyModule
    from app.testing.modules.cross_version_consistency import CrossVersionConsistencyModule
    from app.testing.endpoints import EndpointMap
    from purity_benchmark.customer_target import TargetFlags, start_customer_target

    target, server, port = await start_customer_target(TargetFlags())
    base = f"http://127.0.0.1:{port}"
    try:
        guard = ScopeGuard(ScopePolicy.for_environment(base, max_requests=400, max_requests_per_second=50))
        http = QAHttpClient(base, 5.0, None, {}, "ua", max_retries=0, guard=guard)
        ctx = SimpleNamespace(http=http, endpoints=EndpointMap(), settings=SimpleNamespace(), shared_state={}, base_url=base, guard=guard)
        emitted = []
        async def emit(result):
            emitted.append(result)
        for module in (BusinessRuleConsistencyModule(ctx, emit), CrossVersionConsistencyModule(ctx, emit)):
            await (module._case_hidden_routes() if hasattr(module, "_case_hidden_routes") else module._case_legacy_version_discovery())
        assert target.request_log and all(m == "GET" for m, _ in target.request_log), f"only read-only existence probes are allowed: {set(m for m, _ in target.request_log)}"
        text = json.dumps([r.model_dump(mode="json") if hasattr(r, "model_dump") else str(r) for r in emitted], default=str)
        assert "entitlements" not in text and "premium_badge" not in text
        await http.aclose()
    finally:
        await server.aclose()


def test_provider_facing_endpoint_override_is_ignored():
    from app.testing.endpoints import EndpointMap, EndpointSpec

    m = EndpointMap(overrides={"stripe_webhook": EndpointSpec("POST", "/private/hooks/stripe"), "create_payment": EndpointSpec("POST", "/v9/pay")})
    assert m.stripe_webhook.path == "/api/v1/webhooks/stripe" and m.create_payment.path == "/v9/pay"
    assert m.ignored_provider_overrides == ["stripe_webhook"]


@pytest.mark.asyncio
async def test_webhook_provider_without_provenance_is_blocked():
    from types import SimpleNamespace

    from app.testing.checkout_provider_testing import ManualWebhookProvider
    from app.testing.modules.additional_webhook_security import AdditionalWebhookSecurityModule

    calls = []
    class _Http:
        async def request(self, *a, **k):
            calls.append((a, k))
            raise AssertionError("no request may be sent for an unattested provider route")
    provider = ManualWebhookProvider(provider_id="acme", display_name="Acme", method="POST", path="/hooks/acme", signature_header="X-Acme-Signature")
    ctx = SimpleNamespace(http=_Http(), settings=SimpleNamespace(additional_webhook_providers=[provider]), endpoints=SimpleNamespace(), shared_state={}, base_url="http://127.0.0.1:9", guard=None)
    emitted = []
    async def emit(r):
        emitted.append(r)
    module = AdditionalWebhookSecurityModule(ctx, emit)
    await module.run()
    assert not calls and any("BLOCKED" in r.test_case_id for r in emitted), [r.test_case_id for r in emitted]
    assert all(str(getattr(r.status, "value", r.status)).lower() in ("warning", "skipped") for r in emitted if "BLOCKED" in r.test_case_id)


# ================================================================================ config / documentation hygiene
def test_config_no_longer_references_legacy_contract_and_secret():
    for rel in ("backend/.env.example", "docker-compose.yml", "backend/app/core/config.py"):
        text = (REPO / rel).read_text()
        assert "INTEGRITY_CONTRACT" not in text and "integrity_contract" not in text and "INTEGRITY_MEMORY" not in text, rel
        assert "QA_INTEGRITY_BRIEF_PATH" in text or "integrity_brief_path" in text, rel
    assert "SANDBOX webhook signing secret" not in (BACKEND / ".env.example").read_text()


def test_scorecard_has_no_legacy_claims():
    card = (REPO / "docs" / "BENCHMARK_SCORECARD.md").read_text()
    assert "0.8214" not in card.split("The previous scorecard")[0] and "like-for-like" not in card
    assert "must not be cited as black-box capability" in card, "the pure scorecard must say the legacy numbers are invalid"
    legacy = (BACKEND / "quarantine" / "legacy_greybox" / "BENCHMARK_SCORECARD_LEGACY.md").read_text()
    assert legacy.startswith("> **QUARANTINED / INVALID AS A BLACK-BOX CLAIM.**")


def test_no_internal_causal_claims_in_product_text():
    import re

    banned = re.compile(r"the backend (bug|skipped|did|forgot|failed)|webhook failed|the database (contains|was not)|payment database|server forgot|entitlement table|internal payment state|the provider sent|"
                        r"the handler does not|check (your|the) database|\(or check the database\)|server-side state verification should", re.I)
    for f in sorted((BACKEND / "app" / "testing").rglob("*.py")):
        if "cognition" in f.parts or "purity" in f.parts:
            continue
        for lineno, line in enumerate(f.read_text().splitlines(), 1):
            assert not banned.search(line), f"{f.relative_to(BACKEND)}:{lineno}: internal causal claim / internal-inspection advice: {line.strip()[:120]}"


# ================================================================================ inventory + audit gates
def test_inventory_is_complete_and_has_no_forbidden_no_change():
    assert audit.uncovered_files() == [], "complete_inventory gate: every repository file must be classified"
    assert audit.stale_inventory_paths() == [], "inventory entries must not point at nothing"
    assert inventory.forbidden_no_change() == []
    ids = [d.id for d in inventory.INVENTORY]
    assert len(ids) == len(set(ids))
    for d in inventory.INVENTORY:
        for name in ("system_component", "file_or_module", "current_behavior", "target_information_or_access_used", "why_it_is_not_pure_black_box", "impact_on_findings_or_benchmarks", "safe_black_box_replacement", "validation_method", "remaining_limitations"):
            assert getattr(d, name).strip(), (d.id, name)
        assert d.paths and d.migration_action and d.migration_priority
        xml = d.to_xml()
        assert xml.startswith("<target_access_dependency>") and "<migration_action>" in xml and "<classification>" in xml
    assert inventory.counts()["white_box"] + inventory.counts()["grey_box"] >= 10


def test_no_active_whitebox_or_greybox_path_remains():
    results = audit.run_all()
    problems = {k: [str(x) for x in v][:5] for k, v in results.items() if v}
    assert not problems, problems


def test_literal_allowlist_is_minimal():
    for pattern in audit.LITERAL_ALLOWLIST:
        files = [f for f in audit.iter_files() if audit._matches(f, (pattern,)) and f in set(audit._active_files(audit.repo_root()))]
        hit = any(rx.search((audit.repo_root() / f).read_text(errors="replace")) for f in files for _, rx in audit.FORBIDDEN_LITERALS)
        assert hit, f"allowlist entry {pattern!r} is not needed: remove it (every active file must be scanned)"


def test_purity_layer_is_stdlib_only():
    stdlib = set(sys.stdlib_module_names)
    layers = [BACKEND / "app" / "testing" / "purity", BACKEND / "app" / "enterprise_controls", BACKEND / "app" / "control_adapter", BACKEND / "app" / "core" / "control_port"]
    files = sorted(f for d in layers for f in d.glob("*.py"))
    # a moved or renamed layer must not turn this check into an empty (always green) glob
    assert {"scope.py", "access_gate.py", "credentials.py", "provenance.py", "contract.py", "adapter.py", "fallback.py", "taxonomy.py"} <= {f.name for f in files}, [f.name for f in files]
    for f in files:
        for node in ast.walk(ast.parse(f.read_text())):
            roots = [a.name.split(".")[0] for a in node.names] if isinstance(node, ast.Import) else [(node.module or "").split(".")[0]] if isinstance(node, ast.ImportFrom) and node.level == 0 else []
            for r in roots:
                assert r in stdlib or r == "app", (f.name, r)


def test_inventory_validation_references_exist():
    """Every `file::test_name` the inventory cites as validation must exist (a validation claim pointing at nothing is a fake validation)."""
    import re

    missing = []
    for d in inventory.INVENTORY:
        last_file = None
        for m in re.finditer(r"(tests/[\w/\.]+?\.py)|::(test_\w+)", d.validation_method):
            if m.group(1):
                last_file = m.group(1)
                if not (BACKEND / last_file).exists() and "*" not in last_file:
                    missing.append((d.id, last_file))
            elif last_file:
                path = BACKEND / last_file
                names = {n.name for n in ast.walk(ast.parse(path.read_text())) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))} if path.exists() else set()
                if m.group(2) not in names:
                    missing.append((d.id, f"{last_file}::{m.group(2)}"))
    assert not missing, missing
