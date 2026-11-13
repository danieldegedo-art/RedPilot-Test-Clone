"""B35: tests for app/testing/integrity/browser_surface.py. Stdlib only."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.testing.integrity.browser_surface import (  # noqa: E402
    Action, BrowserAction, SurfaceStatus, plan, plan_payload,
)

HOST = "authorized.example"
HOSTS = {HOST}
NAV = Action(BrowserAction.NAVIGATE, host=HOST)
FILL = Action(BrowserAction.FILL, field="card")
SUBMIT = Action(BrowserAction.SUBMIT)
READ = Action(BrowserAction.READ)


def test_fail_closed_when_the_enabling_control_is_absent():
    p = plan([NAV, READ], allowed_hosts=HOSTS, enabled=False)
    assert p.status == SurfaceStatus.FAIL_CLOSED and p.steps == ()


def test_a_valid_flow_is_planned():
    p = plan([NAV, FILL, SUBMIT, READ], allowed_hosts=HOSTS, enabled=True)
    assert p.status == SurfaceStatus.PLANNED and len(p.steps) == 4
    assert p.final_state == {"current_host": HOST, "form_dirty": False, "navigated": True}


def test_navigation_off_the_allowlist_is_refused_for_scope():
    p = plan([Action(BrowserAction.NAVIGATE, host="evil.example")], allowed_hosts=HOSTS, enabled=True)
    assert p.status == SurfaceStatus.REFUSED_SCOPE and p.steps == ()


def test_action_before_navigate_is_refused():
    assert plan([FILL], allowed_hosts=HOSTS, enabled=True).status == SurfaceStatus.REFUSED_STATE


def test_submit_without_a_prior_fill_is_refused():
    p = plan([NAV, SUBMIT], allowed_hosts=HOSTS, enabled=True)
    assert p.status == SurfaceStatus.REFUSED_STATE and "untouched form" in p.reason


def test_action_cap_is_enforced():
    p = plan([NAV, READ, READ], allowed_hosts=HOSTS, enabled=True, max_actions=2)
    assert p.status == SurfaceStatus.REFUSED_STATE and "cap" in p.reason


def test_payload_json_safe():
    payload = plan_payload([NAV, FILL, SUBMIT], allowed_hosts=HOSTS, enabled=True)
    assert payload["status"] == "PLANNED"
    assert json.loads(json.dumps(payload)) == payload
