"""RP-001: tests for app/cli/commands.py and the demo pipeline. Stdlib only."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.cli.app import demo, new_model  # noqa: E402
from app.cli.commands import COMMANDS, handle_key, run_command  # noqa: E402
from app.cli.model import AppModel, CommandPalette  # noqa: E402
from app.cli.theme import Theme  # noqa: E402


def _model():
    return AppModel(palette=CommandPalette(COMMANDS))


def _texts(model):
    return [e.text for e in model.logs.tail(10_000)]


def test_agents_command_logs_the_real_roster():
    m = _model()
    assert run_command(m, "agents") is True
    texts = _texts(m)
    assert any("fleet: 37" in t for t in texts)
    assert any("A31" in t for t in texts)                 # a real (out-of-scope) agent id


def test_orchestrate_command_logs_waves():
    m = _model()
    run_command(m, "orchestrate")
    texts = _texts(m)
    assert any("orchestration:" in t for t in texts) and any("wave 0:" in t for t in texts)


def test_chains_command_logs_the_minimal_chain():
    m = _model()
    run_command(m, "chains")
    assert any("PBB-U -> PBB-X -> PBB-G" in t for t in _texts(m))


def test_unknown_command_is_reported_not_crashing():
    m = _model()
    assert run_command(m, "nope") is False
    assert any("unknown command" in t for t in _texts(m))


def test_quit_command_stops_the_app():
    m = _model()
    run_command(m, "quit")
    assert m.running is False


def test_handle_key_palette_open_type_accept():
    m = _model()
    assert handle_key(m, "ctrl-k") is None and m.palette_open
    for ch in "chains":
        handle_key(m, ch)
    name = handle_key(m, "enter")
    assert name == "chains" and not m.palette_open


def test_handle_key_ctrl_c_quits_and_esc_closes_palette():
    m = _model()
    handle_key(m, "ctrl-k")
    handle_key(m, "esc")
    assert not m.palette_open
    handle_key(m, "ctrl-c")
    assert m.running is False


def test_demo_pipeline_renders_a_frame():
    m = new_model(100, 30)
    blob = demo(m, Theme(enabled=False), ["help", "agents"])
    assert blob.startswith("\x1b[2J\x1b[H")        # a real terminal frame
    assert "RedPilot" in blob and "mode:" in blob   # title + status bar rendered
