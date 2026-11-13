"""The default-enabled module set must have ONE source and must never drift from what scopes plan,
what the registry implements, or what the dashboard can switch on (Phase-0 finding G6)."""
from __future__ import annotations

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.testing.context import RunSettings  # noqa: E402
from app.testing.module_defaults import DEFAULT_ENABLED_MODULES  # noqa: E402
from app.testing.registry import MODULE_REGISTRY, SCOPE_MODULES  # noqa: E402


def test_every_scoped_module_is_enabled_by_default_and_implemented() -> None:
    planned = set().union(*SCOPE_MODULES.values())
    assert planned - set(DEFAULT_ENABLED_MODULES) == set(), "a scope plans a module that default settings silently drop"
    assert set(DEFAULT_ENABLED_MODULES) <= set(MODULE_REGISTRY), "a default-enabled id has no implementation"
    assert planned <= set(MODULE_REGISTRY)


def test_runsettings_default_is_the_single_source() -> None:
    assert RunSettings().enabled_modules == set(DEFAULT_ENABLED_MODULES)
    assert len(DEFAULT_ENABLED_MODULES) == len(set(DEFAULT_ENABLED_MODULES)), "duplicate ids"


def test_no_second_copy_of_the_module_list_survives_anywhere() -> None:
    """Static check (no sqlalchemy/pydantic needed): the three other definition sites import the constant and
    contain no literal module-id list of their own."""
    for rel in ("app/schemas/settings.py", "app/core/settings_store.py", "app/db/models.py"):
        source = (ROOT / rel).read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported = any(isinstance(n, ast.ImportFrom) and n.module == "app.testing.module_defaults" for n in ast.walk(tree))
        assert imported, f"{rel} does not import DEFAULT_ENABLED_MODULES"
        literal_ids = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str) and n.value in ("stripe_flow", "processing_integrity", "lifecycle_consistency")]
        assert not literal_ids, f"{rel} still carries a hard-coded module list: {literal_ids}"


def test_dashboard_can_switch_on_every_default_module() -> None:
    settings_screen = ROOT.parent / "dashboard" / "src" / "components" / "SettingsScreen.tsx"
    if not settings_screen.is_file():
        return  # backend-only checkout
    text = settings_screen.read_text(encoding="utf-8")
    missing = [m for m in DEFAULT_ENABLED_MODULES if f'"{m}"' not in text]
    assert not missing, f"modules the backend enables by default but the dashboard cannot list/toggle: {missing}"


if __name__ == "__main__":
    import inspect
    import traceback

    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and inspect.isfunction(fn):
            try:
                fn()
                print(f"PASS {name}")
            except Exception:
                failures += 1
                print(f"FAIL {name}")
                traceback.print_exc()
    print(f"\n{'ALL PASSED' if not failures else str(failures) + ' FAILED'}")
    sys.exit(1 if failures else 0)
