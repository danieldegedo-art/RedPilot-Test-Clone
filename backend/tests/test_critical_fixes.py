"""Regression tests for the showstopper bugs found and fixed during the
2026-09 audit. Each of these, before the corresponding fix, made either
the whole backend or the whole cognitive architecture fail to even
import/instantiate -- none of this was previously covered by any
committed test (there was no tests/ directory at all), so these exist
specifically to make sure none of it comes back.
"""
from __future__ import annotations

import ast
from pathlib import Path

APP_ROOT = Path(__file__).resolve().parent.parent / "app"
BENCHMARK_ROOT = Path(__file__).resolve().parent.parent / "benchmark"


def test_every_python_file_parses():
    """The bug that started this audit: app/db/models.py had an unmatched
    bracket (`Mapped[str] | None]`) that made the entire backend fail to
    import. This walks every .py file under app/ and benchmark/ and
    parses it, so a syntax error anywhere is caught immediately rather
    than only when someone happens to exercise that import path."""
    broken: list[str] = []
    for root in (APP_ROOT, BENCHMARK_ROOT):
        for path in root.rglob("*.py"):
            try:
                ast.parse(path.read_text())
            except SyntaxError as exc:
                broken.append(f"{path}: {exc}")
    assert not broken, "Syntax errors found:\n" + "\n".join(broken)


def test_db_models_import():
    """app/db/models.py specifically -- the fix for the unmatched
    bracket that made the whole app fail to start."""
    from app.db import models  # noqa: F401 -- import success is the test


def test_cognition_package_imports():
    """The cognition package had two more syntax errors of its own
    (self_reflection.py's missing '#', experiment_selector.py's
    'times informative' missing an underscore) that blocked the entire
    package from importing, independent of the db/models.py bug."""
    from app.testing import cognition  # noqa: F401


def test_cognitive_engine_instantiates(tmp_path):
    """EmergentStrategyGenerator.__init__ referenced self._stats before
    assigning it, so CognitiveEngine() -- which constructs one
    unconditionally -- crashed on every single instantiation. This is
    the single most important regression test in this file: without it,
    the entire cognitive architecture is dead on arrival."""
    from app.testing.cognition.engine import CognitiveEngine

    engine = CognitiveEngine(
        storage_path=str(tmp_path / "qa_cognition" / "t1"),
        coverage_db_path=str(tmp_path / "qa_cognition" / "t1" / "coverage.db"),
        enable_persistence=True,
        enable_event_bus=False,
        enable_sub_second=False,
    )
    assert engine is not None
    if engine.memory_store:
        engine.memory_store.close()


def test_cognitive_components_create_their_own_directories(tmp_path):
    """novel_discovery.py, coverage_mapper.py and hyperparameter_optimizer.py
    all called sqlite3.connect() on a path inside a subdirectory with
    nothing ever creating that subdirectory first. In the one specific
    Docker Compose deployment this shipped with, the named-volume mount
    happened to create /app/benchmark as a side effect and masked this --
    but it broke in any other context (bare `uvicorn` locally, CI, this
    test). Exercises all three constructors against a subdirectory that
    does NOT already exist to confirm the mkdir-before-connect fix holds
    for each of them independently."""
    from app.testing.cognition.coverage_mapper import CoverageMapper
    from app.testing.cognition.hyperparameter_optimizer import HyperparameterOptimizer
    from app.testing.cognition.novel_discovery import NovelDiscoveryEngine

    nested = tmp_path / "does" / "not" / "exist" / "yet"

    coverage = CoverageMapper(db_path=str(nested / "coverage.db"))
    assert (nested / "coverage.db").exists()
    if coverage.conn:
        coverage.conn.close()

    optimizer = HyperparameterOptimizer(db_path=str(nested / "hp.db"))
    assert (nested / "hp.db").exists()
    optimizer.conn.close()

    novel = NovelDiscoveryEngine(db_path=str(nested / "novel.db"))
    assert (nested / "novel.db").exists()
    novel.conn.close()


def test_benchmark_package_not_shadowed_by_data_paths():
    """None of the cognitive architecture's default/hardcoded data paths
    should point inside backend/benchmark/ anymore: that directory is a
    real Python package now (see benchmark/llm_replacement_layer.py), and
    docker-compose.yml mounts a named volume at /app/benchmark. A data
    path still pointing there would work by accident in this sandbox but
    have its __init__.py/llm_replacement_layer.py shadowed by an empty
    volume the moment the container actually starts."""
    import inspect

    from app.testing.cognition import hyperparameter_optimizer, improvement_loop, novel_discovery

    for module in (hyperparameter_optimizer, improvement_loop, novel_discovery):
        source = inspect.getsource(module)
        assert '"benchmark/' not in source and "'benchmark/" not in source, (
            f"{module.__name__} still references a benchmark/-relative data path"
        )
