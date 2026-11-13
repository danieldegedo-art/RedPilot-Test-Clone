"""ZR-002/ZR-007: the durable PESM store is wired into the REAL run entry point.

runner.py / api/v1/runs.py cannot be imported in this sandbox (httpx / fastapi /
sqlalchemy absent), so this verifies the wiring STRUCTURALLY with the `ast` module --
a real, executed check of the exact call shape -- plus a compile() of each source.
It asserts:
  * TestRunner.__init__ accepts a `feature_registry` parameter,
  * the module TestContext(...) is constructed with `feature_registry=`,
  * start_run() builds the registry via build_feature_registry() and passes it to
    TestRunner(feature_registry=...).
This is the one honest check available without the runtime deps; the durable DB path
itself is still NOT executed here (see HANDOFF.md).
"""
from __future__ import annotations

import ast
from pathlib import Path

BACKEND = Path(__file__).parent.parent
RUNNER = BACKEND / "app" / "testing" / "runner.py"
RUNS = BACKEND / "app" / "api" / "v1" / "runs.py"


def _tree(path: Path) -> ast.Module:
    src = path.read_text()
    compile(src, str(path), "exec")   # real syntax check (raises on failure)
    return ast.parse(src)


def _func(tree: ast.Module, name: str, cls: str | None = None) -> ast.AST:
    scope: list[ast.AST] = [tree]
    if cls is not None:
        scope = [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and n.name == cls]
        assert scope, f"class {cls} not found"
    for root in scope:
        for n in ast.walk(root):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name:
                return n
    raise AssertionError(f"function {name} not found" + (f" in {cls}" if cls else ""))


def _calls(node: ast.AST, callee: str) -> list[ast.Call]:
    out = []
    for n in ast.walk(node):
        if isinstance(n, ast.Call):
            f = n.func
            fname = f.id if isinstance(f, ast.Name) else (f.attr if isinstance(f, ast.Attribute) else None)
            if fname == callee:
                out.append(n)
    return out


def test_testrunner_init_accepts_feature_registry():
    init = _func(_tree(RUNNER), "__init__", cls="TestRunner")
    params = [a.arg for a in init.args.args] + [a.arg for a in init.args.kwonlyargs]
    assert "feature_registry" in params


def test_runner_threads_feature_registry_into_testcontext():
    tree = _tree(RUNNER)
    ctx_calls = _calls(tree, "TestContext")
    assert ctx_calls, "no TestContext(...) construction found"
    assert any(any(k.arg == "feature_registry" for k in c.keywords) for c in ctx_calls), \
        "TestContext is not constructed with feature_registry="


def test_start_run_builds_registry_and_injects_it():
    start = _func(_tree(RUNS), "start_run")
    assert _calls(start, "build_feature_registry"), "start_run never builds the durable registry"
    tr_calls = _calls(start, "TestRunner")
    assert tr_calls, "start_run never constructs a TestRunner"
    assert any(any(k.arg == "feature_registry" for k in c.keywords) for c in tr_calls), \
        "TestRunner is not given feature_registry= at the real call site"
