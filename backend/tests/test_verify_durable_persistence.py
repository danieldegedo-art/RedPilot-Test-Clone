"""The durable-persistence verification harness (scripts/verify_durable_persistence.py).

What is verifiable in THIS sandbox is the harness's contract: it imports with no
durable deps and skips cleanly (never errors) when sqlalchemy is absent. The
database round-trip itself runs only where the durable layer exists and is driven
by running the script there -- see its docstring.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

import verify_durable_persistence as vdp  # noqa: E402


def test_module_imports_cleanly_without_durable_deps():
    assert callable(vdp.run_verification) and callable(vdp.main) and callable(vdp.sqlalchemy_available)


def test_skips_cleanly_when_sqlalchemy_absent():
    if vdp.sqlalchemy_available():
        return  # in an env WITH the durable layer the harness runs for real; the skip-path contract doesn't apply there
    result = vdp.run_verification()
    assert result["status"] == "skipped"
    assert "sqlalchemy" in result["detail"].lower()
    assert vdp.main([]) == 0  # skip exits 0, never 1


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
