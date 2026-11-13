"""RP-001 commands: the command registry, handlers, and key dispatch.

The handlers wire the terminal to the real bounded modules (the kill-chain roster,
the fleet orchestrator, the attack-chain composer, the narrative generator), logging
their output into the model's log buffer. They need no TTY, so they are unit-testable
by inspecting the log buffer after running a command. `handle_key` is the pure
key->action dispatch the event loop calls. Stdlib only; pure (logs into the model).
"""
from __future__ import annotations

from app.cli.model import AppModel, Command
from app.testing.integrity.findings import EXPERIMENT_CLASSES

COMMANDS: list[Command] = [
    Command("help", "list commands", "general"),
    Command("status", "control + engine status", "general"),
    Command("agents", "show the kill-chain roster", "fleet"),
    Command("orchestrate", "show the fleet wave plan", "fleet"),
    Command("chains", "compose attack chains (bounded)", "attack"),
    Command("plan", "the pre-registered oracle plan", "attack"),
    Command("findings", "narrate current findings", "proof"),
    Command("quit", "exit RedPilot", "general"),
]


def cmd_help(model: AppModel) -> None:
    model.log("info", "commands:")
    for c in COMMANDS:
        model.log("info", f"  {c.name:<12}{c.description}")


def cmd_status(model: AppModel) -> None:
    s = model.status
    model.log("pass" if not s.degraded else "warn",
              f"mode={s.mode} target={s.target} scope={s.scope} degraded={s.degraded}")
    model.log("info", "controls: fail-open by design; safety-critical groups fail-closed")


def cmd_agents(model: AppModel) -> None:
    from app.testing.integrity import kill_chain_roster as roster
    model.log("info", f"fleet: {roster.FLEET_SIZE} agents ({len(roster.ROSTER)} documented, gaps {list(roster.KNOWN_GAPS)})")
    for a in roster.ROSTER:
        lvl = "warn" if a.scope_status.value != "in_scope" else "info"
        tag = "" if a.scope_status.value == "in_scope" else f"  <{a.scope_status.value}>"
        model.log(lvl, f"  {a.agent_id:<4}{a.name}  [{a.role.value}]{tag}")


def cmd_orchestrate(model: AppModel) -> None:
    from app.testing.integrity import fleet_orchestration as fleet
    classes = sorted(EXPERIMENT_CLASSES)
    deps = fleet.dependencies_from_catalog(classes)
    plan = fleet.orchestrate(classes, enabled=True, max_workers=4, dependencies=deps)
    model.log("info", f"orchestration: {plan.status.value}, {len(plan.waves)} wave(s), <=4 workers")
    for i, w in enumerate(plan.waves):
        model.log("info", f"  wave {i}: {', '.join(w)}")


def cmd_chains(model: AppModel) -> None:
    from app.testing.integrity import attack_chain
    res = attack_chain.compose_chains("PBB-G", enabled=True)
    model.log("info", f"chains -> PBB-G: {res.status.value} ({len(res.chains)} found)")
    for c in res.chains[:5]:
        model.log("info", "  " + " -> ".join(c.steps))


def cmd_plan(model: AppModel) -> None:
    classes = sorted(EXPERIMENT_CLASSES)
    model.log("info", f"plan: {len(classes)} pre-registered oracles (OPPLAN sequences these under budget)")
    for c in classes:
        model.log("info", f"  {c}")


def cmd_findings(model: AppModel) -> None:
    from app.testing.integrity import narrative
    rep = narrative.report([])   # no live run in this environment
    model.log("pass" if "No confirmed" in rep["headline"] else "fail", rep["headline"])
    model.log("info", "run against an authorized target to populate findings")


def cmd_quit(model: AppModel) -> None:
    model.running = False
    model.log("info", "exiting")


HANDLERS = {
    "help": cmd_help, "status": cmd_status, "agents": cmd_agents, "orchestrate": cmd_orchestrate,
    "chains": cmd_chains, "plan": cmd_plan, "findings": cmd_findings, "quit": cmd_quit,
}


def run_command(model: AppModel, name: str) -> bool:
    """Run a command by name, logging its output. Returns True if it was a known
    command. A handler error is caught and logged (the console never crashes)."""
    handler = HANDLERS.get(name)
    if handler is None:
        model.log("error", f"unknown command: {name}")
        return False
    model.log("accent" if False else "info", f"> {name}")
    try:
        handler(model)
    except Exception as exc:  # the console must survive a handler fault
        model.log("error", f"{name} failed: {type(exc).__name__}: {exc}")
    return True


def handle_key(model: AppModel, key: str) -> str | None:
    """Pure key dispatch. `key` is a normalised token: a single printable char, or one
    of ctrl-k/ctrl-c/ctrl-q/enter/esc/up/down/backspace. Returns a command name to run
    (when the palette accepts one), else None."""
    if model.palette_open:
        if key == "esc":
            model.close_palette()
        elif key == "enter":
            cmd = model.accept_palette()
            return cmd.name if cmd else None
        elif key == "up":
            model.palette.move(-1)
        elif key == "down":
            model.palette.move(1)
        elif key == "backspace":
            model.palette.backspace()
        elif len(key) == 1 and key.isprintable():
            model.palette.type(key)
        return None

    if key == "ctrl-k":
        model.open_palette()
    elif key in ("ctrl-c", "ctrl-q"):
        model.running = False
    return None
