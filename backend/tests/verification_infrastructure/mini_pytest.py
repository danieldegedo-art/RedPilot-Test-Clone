"""mini_pytest.py -- a MINIMAL STAND-IN for pytest, for offline sandboxes where pytest cannot be installed.

IT IS NOT PYTEST. It implements only what this repository's own tests use (measured by grep, not assumed):
  * discovery of module-level `test_*` functions and `Test*` classes' `test_*` methods
  * `@pytest.mark.asyncio` (each async test runs in its own event loop, like pytest-asyncio's default)
  * fixtures by parameter name: `tmp_path`, `monkeypatch` (setattr/setenv/delenv/setitem/delitem/chdir)
  * `pytest.approx`, `pytest.raises`
Anything else (parametrize, conftest, custom fixtures, plugins) is NOT supported and makes a test ERROR loudly
instead of being silently skipped. A green run here is evidence, not a substitute for the real pytest run in CI.

Usage:  PYTHONPATH=<shims>:. python3 tests/verification_infrastructure/mini_pytest.py tests/test_x.py [...]
Prints one line per test plus a final tally; exit code 1 if anything failed or errored.
"""
from __future__ import annotations

import asyncio
import contextlib
import importlib.util
import inspect
import os
import shutil
import sys
import tempfile
import traceback
import types
from pathlib import Path
from typing import Any


class _Approx:
    def __init__(self, expected: float, rel: float | None = None, abs: float | None = None) -> None:  # noqa: A002
        self.expected, self.rel, self.abs = expected, rel, abs

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, (int, float)):
            return False
        import builtins

        rel = self.rel if self.rel is not None else 1e-6
        tol = max(self.abs if self.abs is not None else 1e-12, rel * builtins.abs(self.expected))
        return builtins.abs(other - self.expected) <= tol

    def __repr__(self) -> str:
        return f"approx({self.expected})"


@contextlib.contextmanager
def _raises(exc_type: type[BaseException] | tuple, match: str | None = None):
    import re

    holder = types.SimpleNamespace(value=None)
    try:
        yield holder
    except exc_type as exc:
        holder.value = exc
        if match is not None and not re.search(match, str(exc)):
            raise AssertionError(f"exception {exc!r} did not match {match!r}") from exc
        return
    raise AssertionError(f"DID NOT RAISE {exc_type}")


class _MonkeyPatch:
    def __init__(self) -> None:
        self._undo: list[Any] = []

    def setattr(self, target: Any, name: Any, value: Any = None, raising: bool = True) -> None:
        if isinstance(target, str):  # "pkg.mod.attr" form
            path, _, attr = target.rpartition(".")
            obj = importlib.import_module(path)
            name, value = attr, name
            target = obj
        old = getattr(target, name, _MISSING)
        if old is _MISSING and raising:
            raise AttributeError(name)
        self._undo.append(lambda t=target, n=name, o=old: delattr(t, n) if o is _MISSING else setattr(t, n, o))
        setattr(target, name, value)

    def setenv(self, name: str, value: str) -> None:
        old = os.environ.get(name)
        self._undo.append(lambda n=name, o=old: os.environ.pop(n, None) if o is None else os.environ.__setitem__(n, o))
        os.environ[name] = str(value)

    def delenv(self, name: str, raising: bool = True) -> None:
        old = os.environ.get(name)
        if old is None and raising:
            raise KeyError(name)
        if old is not None:
            self._undo.append(lambda n=name, o=old: os.environ.__setitem__(n, o))
            del os.environ[name]

    def setitem(self, mapping: Any, key: Any, value: Any) -> None:
        old = mapping.get(key, _MISSING)
        self._undo.append(lambda m=mapping, k=key, o=old: m.pop(k, None) if o is _MISSING else m.__setitem__(k, o))
        mapping[key] = value

    def delitem(self, mapping: Any, key: Any, raising: bool = True) -> None:
        if key in mapping:
            old = mapping[key]
            self._undo.append(lambda m=mapping, k=key, o=old: m.__setitem__(k, o))
            del mapping[key]
        elif raising:
            raise KeyError(key)

    def chdir(self, path: Any) -> None:
        old = os.getcwd()
        self._undo.append(lambda o=old: os.chdir(o))
        os.chdir(path)

    def undo(self) -> None:
        while self._undo:
            self._undo.pop()()


_MISSING = object()


def install_fake_pytest() -> None:
    mod = types.ModuleType("pytest")

    class _Mark:
        def __getattr__(self, name: str):
            def deco(*args: Any, **kwargs: Any):
                if len(args) == 1 and callable(args[0]) and not kwargs:
                    return args[0]
                return lambda fn: fn
            return deco

    mod.mark = _Mark()  # type: ignore[attr-defined]
    mod.approx = _Approx  # type: ignore[attr-defined]
    mod.raises = _raises  # type: ignore[attr-defined]
    mod.fixture = lambda *a, **k: (a[0] if a and callable(a[0]) else (lambda fn: fn))  # type: ignore[attr-defined]
    sys.modules["pytest"] = mod


def _collect(module: types.ModuleType):
    for name, obj in sorted(vars(module).items()):
        if name.startswith("test_") and inspect.isfunction(obj) and obj.__module__ == module.__name__:
            yield name, obj, None
        elif name.startswith("Test") and inspect.isclass(obj) and obj.__module__ == module.__name__:
            for mname, meth in sorted(vars(obj).items()):
                if mname.startswith("test_") and inspect.isfunction(meth):
                    yield f"{name}::{mname}", meth, obj


def _run_one(fn: Any, owner: Any) -> None:
    kwargs: dict[str, Any] = {}
    cleanups: list[Any] = []
    params = [p for p in inspect.signature(fn).parameters if p != "self"]
    for p in params:
        if p == "tmp_path":
            d = Path(tempfile.mkdtemp(prefix="mini_pytest_"))
            kwargs[p] = d
            cleanups.append(lambda d=d: shutil.rmtree(d, ignore_errors=True))
        elif p == "monkeypatch":
            mp = _MonkeyPatch()
            kwargs[p] = mp
            cleanups.append(mp.undo)
        else:
            raise RuntimeError(f"unsupported fixture {p!r} (mini_pytest implements tmp_path and monkeypatch only)")
    try:
        target = fn if owner is None else getattr(owner(), fn.__name__)
        if inspect.iscoroutinefunction(fn):
            asyncio.run(target(**kwargs))
        else:
            target(**kwargs)
    finally:
        for c in reversed(cleanups):
            c()


def main(paths: list[str]) -> int:
    install_fake_pytest()
    sys.path.insert(0, os.getcwd())
    passed = failed = errored = 0
    for raw in paths:
        path = Path(raw).resolve()
        spec = importlib.util.spec_from_file_location(f"mini_{path.stem}", path)
        try:
            module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
            sys.modules[spec.name] = module  # type: ignore[union-attr]
            spec.loader.exec_module(module)  # type: ignore[union-attr]
        except BaseException as exc:  # noqa: BLE001
            errored += 1
            print(f"COLLECTION-ERROR {raw}: {type(exc).__name__}: {str(exc)[:160]}")
            continue
        for name, fn, owner in _collect(module):
            try:
                _run_one(fn, owner)
                passed += 1
                print(f"PASS {raw}::{name}")
            except AssertionError:
                failed += 1
                print(f"FAIL {raw}::{name}")
                traceback.print_exc(limit=3)
            except BaseException as exc:  # noqa: BLE001
                errored += 1
                print(f"ERROR {raw}::{name}: {type(exc).__name__}: {str(exc)[:160]}")
    print(f"\nmini_pytest (STAND-IN, not pytest): {passed} passed, {failed} failed, {errored} errored")
    return 1 if (failed or errored) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
