"""Mutation check: break the code in specific ways and confirm the tests notice.

A passing test only means something if it can fail. For each mutation this
rewrites one source file, runs the given test script, then restores the file.

Bytecode caching is ruled out on purpose: Python trusts a cached .pyc when the
source's mtime (whole seconds) and size match, and a same-length edit made in the
same second as the restore -- e.g. logger.error -> logger.debug -- leaves the
MUTATED bytecode in use after the source is restored. (That bit an earlier
version of this check: the sources were byte-identical to the backups, yet the
restored run still failed.) So every run here starts with every __pycache__
under app/ deleted, runs with `python -B`, and deletes them again afterwards.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path


def _clear_pycache(root: Path) -> None:
    for d in root.rglob("__pycache__"):
        shutil.rmtree(d, ignore_errors=True)


def run(backend: Path, test_script: str, mutations: list[tuple[str, str, str, str]]) -> int:
    """mutations: (name, file relative to backend, old text, new text); old must occur exactly once."""
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    files = {m[1] for m in mutations}
    originals = {f: (backend / f).read_text() for f in files}

    def test() -> subprocess.CompletedProcess:
        _clear_pycache(backend / "app")
        return subprocess.run([sys.executable, "-B", test_script], cwd=backend, capture_output=True, text=True, env=env)

    base = test()
    baseline_ok = base.returncode == 0
    print(f"baseline: {base.stdout.strip().splitlines()[-1]}")
    missed = 0
    try:
        for name, f, old, new in mutations:
            assert originals[f].count(old) == 1, f"mutation anchor must occur exactly once ({originals[f].count(old)}x): {name}"
            (backend / f).write_text(originals[f].replace(old, new))
            r = test()
            (backend / f).write_text(originals[f])
            failed = [l[5:] for l in r.stdout.splitlines() if l.startswith("FAIL ")]
            caught = bool(failed) or r.returncode != 0
            missed += not caught
            detail = ", ".join(failed[:2]) if failed else ("(crashed before reporting)" if caught else "")
            print(f"{'CAUGHT' if caught else 'MISSED':7s}{name}  <- {detail}")
    finally:
        for f, text in originals.items():
            (backend / f).write_text(text)
        _clear_pycache(backend / "app")
    final = test()
    print(f"restored: {final.stdout.strip().splitlines()[-1]}")
    return 0 if (baseline_ok and final.returncode == 0 and not missed) else 1
