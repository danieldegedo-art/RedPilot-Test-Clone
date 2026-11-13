"""ZR-003/ZR-007/ZR-012's on/off switch: RunSettings.prioritize_experiments ->
SettingsSchema -> app.core.settings_store.to_run_settings (pure, no DB -- fully
testable) and modules/payment_integrity.py::build_prioritizer (the one place
it's actually read).

Not covered here, and said plainly: SettingsRecord's new DB column and
load_settings/save_settings (both need a live Postgres), and anything in the
dashboard's own UI -- no React/TS work was done this session; the toggle has
no frontend yet.

Needs the pydantic shim.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "verification_infrastructure" / "shims"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.schemas.settings import SettingsSchema  # noqa: E402
from app.testing.context import RunSettings  # noqa: E402
from app.testing.modules.payment_integrity import build_prioritizer  # noqa: E402

# app.core.settings_store (to_run_settings/to_endpoint_map, both genuinely pure
# -- no DB access, per their own docstrings) cannot even be IMPORTED here:
# load_settings/save_settings in the same file pull in
# `sqlalchemy.ext.asyncio.AsyncSession` and `app.db.models` at module level, so
# the whole file requires sqlalchemy to import, whether or not the function
# under test touches it. Stubbing sqlalchemy well enough to route around that
# would mean trusting a fake I wrote instead of the real conversion code --
# worse than saying plainly that this one needs a real environment:
#   to_run_settings(SettingsSchema(prioritize_experiments=True)).prioritize_experiments
#   must be True, and False must round-trip to False -- run on your machine.


# ---- settings defaults (context.py and schemas/settings.py are both dependency-free) --------

def test_default_is_off_in_both_the_dataclass_and_the_schema():
    assert RunSettings().prioritize_experiments is False
    assert SettingsSchema().prioritize_experiments is False


def test_the_flag_is_a_plain_bool_field_on_both_not_accidentally_typed_differently():
    assert type(RunSettings(prioritize_experiments=True).prioritize_experiments) is bool
    assert type(SettingsSchema(prioritize_experiments=True).prioritize_experiments) is bool


# ---- build_prioritizer: the one place the setting is actually read -------------------------

def test_off_returns_none_and_touches_nothing_else():
    """Must not even attempt the (sqlalchemy-requiring) import when off -- this
    is what keeps the module importable without sqlalchemy at all today."""
    assert asyncio.run(build_prioritizer(False, "fp-1")) is None


def test_on_with_no_database_available_degrades_to_none_rather_than_raising():
    """This sandbox has no sqlalchemy, so `from app.db.memory import
    row_source_for` inside build_prioritizer genuinely fails here -- this test
    exercises the real failure path, not a simulated one."""
    try:
        import sqlalchemy  # noqa: F401
        print("  (skipped: sqlalchemy is installed here; this test targets its absence)")
        return
    except ImportError:
        pass
    result = asyncio.run(build_prioritizer(True, "fp-1"))
    assert result is None, "one unavailable optional capability must not stop the module, let alone the run"


if __name__ == "__main__":
    import traceback
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = failed = 0
    for t in tests:
        try:
            t()
            print(f"PASS {t.__name__}")
            passed += 1
        except Exception:
            print(f"FAIL {t.__name__}")
            traceback.print_exc()
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
