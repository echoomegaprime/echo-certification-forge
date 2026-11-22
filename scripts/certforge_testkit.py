"""Stdlib-only test runner for Certification Forge journeys (ops-20260924).

The CertForge sandbox runs a journey in ``python:3.12-alpine`` with no network, no
third-party packages, a read-only checkout and a 90 s wall clock. Most ECHO suites are
written for pytest, so this module provides the small pytest surface they use:
``raises``, ``mark.parametrize`` / ``skip`` / ``skipif`` (other marks are no-ops), ``param``,
``skip()``, ``fail()``, ``importorskip()``, ``approx``, and ``@fixture`` functions (plain or
``yield``) from the suite module and its ``conftest.py`` files, plus the built-in fixtures
``tmp_path``, ``monkeypatch`` and ``capsys``. It also runs ``unittest.TestCase`` classes and
pytest-style ``Test*`` classes.

Third-party modules that a suite imports but never exercises can be replaced with inert
stubs (``stub_modules``). Stubs are installed only when the real module is missing, and the
report names them. Every failure, error, import error, empty run or blown time budget fails
the journey (fail closed).
"""
from __future__ import annotations

import contextlib
import importlib
import importlib.util
import inspect
import io
import itertools
import os
import re
import sys
import tempfile
import time
import traceback
import types
import unittest
from pathlib import Path
from typing import Any, Callable, Iterable


class Skipped(Exception):
    """Raised by ``pytest.skip`` / ``importorskip``."""


class Failed(AssertionError):
    """Raised by ``pytest.fail``."""


class BudgetExceeded(Exception):
    """The journey ran out of its wall-clock budget (fails the journey)."""


# ── pytest compatibility surface ─────────────────────────────────────────────────────────
class _Raises:
    def __init__(self, expected: Any, match: str | None = None) -> None:
        self.expected = expected
        self.match = match
        self.value: BaseException | None = None

    def __enter__(self) -> "_Raises":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        if exc_type is None:
            raise Failed(f"DID NOT RAISE {self.expected}")
        if not issubclass(exc_type, self.expected):
            return False
        if self.match is not None and not re.search(self.match, str(exc)):
            raise Failed(f"regex {self.match!r} did not match {str(exc)!r}")
        self.value = exc
        return True


class _Param:
    def __init__(self, *values: Any, id: str | None = None, marks: Any = ()) -> None:  # noqa: A002
        self.values = values
        self.id = id
        self.marks = marks


class _NoopMark:
    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        if len(args) == 1 and not kwargs and callable(args[0]):
            return args[0]
        return lambda fn: fn


class _Mark:
    @staticmethod
    def parametrize(names: Any, values: Iterable[Any], **_: Any) -> Callable:
        if isinstance(names, str):
            names = [n.strip() for n in names.split(",") if n.strip()]
        names = list(names)
        rows = []
        for value in values:
            if isinstance(value, _Param):
                value = value.values if len(names) > 1 else value.values[0]
            rows.append(tuple(value) if len(names) > 1 else (value,))

        def deco(fn: Callable) -> Callable:
            fn.__dict__.setdefault("_cf_params", []).insert(0, (names, rows))
            return fn
        return deco

    @staticmethod
    def skip(reason: str = "") -> Callable:
        def deco(fn: Callable) -> Callable:
            fn._cf_skip = reason or "skip"
            return fn
        return deco

    @staticmethod
    def skipif(condition: Any, reason: str = "") -> Callable:
        def deco(fn: Callable) -> Callable:
            if condition:
                fn._cf_skip = reason or "skipif"
            return fn
        return deco

    def __getattr__(self, name: str) -> _NoopMark:
        return _NoopMark()


class _Approx:
    def __init__(self, expected: Any, rel: float | None = None, abs: float | None = None) -> None:  # noqa: A002
        self.expected, self.rel, self.abs = expected, rel, abs

    def _close(self, a: float, b: float) -> bool:
        rel = 1e-6 if self.rel is None else self.rel
        tol = max(rel * abs(b), 1e-12 if self.abs is None else self.abs)
        return abs(a - b) <= tol

    def __eq__(self, other: Any) -> bool:
        if isinstance(self.expected, (list, tuple)):
            return len(other) == len(self.expected) and all(
                self._close(a, b) for a, b in zip(other, self.expected))
        if isinstance(self.expected, dict):
            return other.keys() == self.expected.keys() and all(
                self._close(other[k], v) for k, v in self.expected.items())
        return self._close(other, self.expected)

    def __repr__(self) -> str:
        return f"approx({self.expected!r})"


def _fixture(*args: Any, **kwargs: Any) -> Any:
    def mark(fn: Callable) -> Callable:
        fn._cf_fixture = True
        return fn
    if len(args) == 1 and callable(args[0]) and not kwargs:
        return mark(args[0])
    return mark


def _skip(reason: str = "", **_: Any) -> None:
    raise Skipped(reason)


def _fail(reason: str = "", **_: Any) -> None:
    raise Failed(reason)


def _importorskip(name: str, *_: Any, **__: Any) -> Any:
    try:
        return importlib.import_module(name)
    except ImportError as exc:
        raise Skipped(f"{name} unavailable: {exc}") from None


def pytest_module() -> types.ModuleType:
    mod = types.ModuleType("pytest")
    mod.__dict__.update(
        raises=_Raises, mark=_Mark(), param=_Param, fixture=_fixture, skip=_skip,
        fail=_fail, importorskip=_importorskip, approx=_Approx,
        __certforge_shim__=True,
    )
    mod.skip.Exception = Skipped  # type: ignore[attr-defined]
    return mod


# ── built-in fixtures ────────────────────────────────────────────────────────────────────
def _resolve_dotted(path: str) -> Any:
    """Import the longest importable prefix of ``path``, then walk the remaining attributes."""
    parts = path.split(".")
    for cut in range(len(parts), 0, -1):
        try:
            obj = importlib.import_module(".".join(parts[:cut]))
        except ImportError:
            continue
        for attr in parts[cut:]:
            obj = getattr(obj, attr)
        return obj
    raise ImportError(f"cannot resolve {path!r}")


class MonkeyPatch:
    _MISSING = object()

    def __init__(self) -> None:
        self._undo: list[Callable[[], None]] = []

    def setattr(self, target: Any, name: Any, value: Any = _MISSING, raising: bool = True) -> None:
        if value is self._MISSING:  # "pkg.mod.attr" form
            value = name
            owner_path, _, name = str(target).rpartition(".")
            target = _resolve_dotted(owner_path)
        old = getattr(target, name, self._MISSING)
        if old is self._MISSING and raising:
            raise AttributeError(f"{target!r} has no attribute {name!r}")
        setattr(target, name, value)
        self._undo.append(lambda: delattr(target, name) if old is self._MISSING
                          else setattr(target, name, old))

    def delattr(self, target: Any, name: str, raising: bool = True) -> None:
        if not hasattr(target, name):
            if raising:
                raise AttributeError(name)
            return
        old = getattr(target, name)
        delattr(target, name)
        self._undo.append(lambda: setattr(target, name, old))

    def setitem(self, mapping: Any, key: Any, value: Any) -> None:
        old = mapping.get(key, self._MISSING)
        mapping[key] = value
        self._undo.append(lambda: mapping.pop(key, None) if old is self._MISSING
                          else mapping.__setitem__(key, old))

    def delitem(self, mapping: Any, key: Any, raising: bool = True) -> None:
        if key not in mapping:
            if raising:
                raise KeyError(key)
            return
        old = mapping.pop(key)
        self._undo.append(lambda: mapping.__setitem__(key, old))

    def setenv(self, name: str, value: Any, prepend: str | None = None) -> None:
        value = str(value)
        if prepend and name in os.environ:
            value = value + prepend + os.environ[name]
        self.setitem(os.environ, name, value)

    def delenv(self, name: str, raising: bool = True) -> None:
        self.delitem(os.environ, name, raising)

    def syspath_prepend(self, path: Any) -> None:
        sys.path.insert(0, str(path))
        self._undo.append(lambda: sys.path.remove(str(path)))

    def chdir(self, path: Any) -> None:
        old = os.getcwd()
        os.chdir(path)
        self._undo.append(lambda: os.chdir(old))

    def undo(self) -> None:
        while self._undo:
            self._undo.pop()()


class CapSys:
    def __init__(self) -> None:
        self._out, self._err = io.StringIO(), io.StringIO()
        self._saved = (sys.stdout, sys.stderr)
        sys.stdout, sys.stderr = self._out, self._err

    def readouterr(self) -> Any:
        out, err = self._out.getvalue(), self._err.getvalue()
        self._out.seek(0), self._out.truncate(), self._err.seek(0), self._err.truncate()
        return types.SimpleNamespace(out=out, err=err)

    def close(self) -> None:
        sys.stdout, sys.stderr = self._saved


# ── inert stubs for unexercised third-party imports ──────────────────────────────────────
class _StubObject:
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        pass

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        if len(args) == 1 and callable(args[0]) and not kwargs:
            return args[0]  # used as a decorator
        return _StubObject()

    def __getattr__(self, name: str) -> Any:
        return _StubObject()


def _stub_module(name: str) -> types.ModuleType:
    mod = types.ModuleType(name)
    mod.__path__ = []  # allow "import pkg.sub"
    mod.__certforge_stub__ = True

    def __getattr__(attr: str) -> Any:
        if attr.startswith("__"):
            raise AttributeError(attr)
        base = Exception if attr.endswith(("Error", "Exception")) else _StubObject
        value = type(attr, (base,), {"__module__": name})
        setattr(mod, attr, value)
        return value
    mod.__getattr__ = __getattr__  # type: ignore[attr-defined]
    return mod


def install_stubs(names: Iterable[str]) -> list[str]:
    installed = []
    for name in names:
        if name in sys.modules:
            continue
        try:
            importlib.import_module(name)
            continue
        except ImportError:
            pass
        sys.modules[name] = _stub_module(name)
        parent, _, child = name.rpartition(".")
        if parent and parent in sys.modules:
            setattr(sys.modules[parent], child, sys.modules[name])
        installed.append(name)
    return installed


# ── collection and execution ─────────────────────────────────────────────────────────────
class _Session:
    def __init__(self, root: Path, deadline: float) -> None:
        self.root = root
        self.deadline = deadline
        self.passed = self.failed = self.skipped = 0
        self.failures: list[str] = []

    # fixtures ----------------------------------------------------------------------------
    def _resolve(self, name: str, fixtures: dict, cache: dict, teardown: list) -> Any:
        if name in cache:
            return cache[name]
        if name == "tmp_path":
            value = Path(tempfile.mkdtemp(prefix="cf-"))
        elif name == "monkeypatch":
            value = MonkeyPatch()
            teardown.append(value.undo)
        elif name == "capsys":
            value = CapSys()
            teardown.append(value.close)
        elif name == "request":
            value = types.SimpleNamespace(param=None, node=None, config=None)
        elif name in fixtures:
            fn = fixtures[name]
            kwargs = {p: self._resolve(p, fixtures, cache, teardown)
                      for p in inspect.signature(fn).parameters}
            value = fn(**kwargs)
            if inspect.isgenerator(value):
                gen = value
                value = next(gen)
                teardown.append(lambda g=gen: next(g, None))
        else:
            raise LookupError(f"fixture {name!r} not found")
        cache[name] = value
        return value

    def _call(self, label: str, fn: Callable, fixtures: dict, bound: dict) -> None:
        if time.monotonic() > self.deadline:
            raise BudgetExceeded(f"journey time budget exhausted before {label}")
        skip = getattr(fn, "_cf_skip", None)
        if skip:
            self.skipped += 1
            return
        cache: dict = dict(bound)
        teardown: list = []
        try:
            params = [p for p in inspect.signature(fn).parameters if p != "self"]
            kwargs = {p: self._resolve(p, fixtures, cache, teardown) for p in params}
            fn(**kwargs)
            self.passed += 1
        except Skipped:
            self.skipped += 1
        except (BudgetExceeded, KeyboardInterrupt):
            raise
        except BaseException as exc:  # noqa: BLE001 - every error (incl. SystemExit) is a failure
            self.failed += 1
            self.failures.append(f"{label}: {type(exc).__name__}: {exc}\n"
                                 + "".join(traceback.format_exc(limit=6))[-1500:])
        finally:
            for fin in reversed(teardown):
                with contextlib.suppress(Exception):
                    fin()

    def _expand(self, label: str, fn: Callable, fixtures: dict) -> None:
        grids = getattr(fn, "_cf_params", [])
        if not grids:
            self._call(label, fn, fixtures, {})
            return
        for i, combo in enumerate(itertools.product(*[rows for _, rows in grids])):
            bound: dict = {}
            for (names, _), row in zip(grids, combo):
                bound.update(zip(names, row))
            self._call(f"{label}[{i}]", fn, fixtures, bound)

    # suites ------------------------------------------------------------------------------
    def _conftest_fixtures(self, suite: Path) -> dict:
        fixtures: dict = {}
        if not getattr(self, "use_conftest", True):
            return fixtures  # self-contained suites; conftest needs packages the sandbox lacks
        chain = [d for d in [suite.parent, *suite.parent.parents] if self.root in (d, *d.parents)]
        for directory in reversed(chain):
            conftest = directory / "conftest.py"
            if conftest.is_file():
                mod = _load(conftest, "cf_conftest_" + _slug(conftest.relative_to(self.root)))
                fixtures.update(_fixtures_of(mod))
        return fixtures

    def run_suite(self, suite: Path) -> None:
        fixtures = self._conftest_fixtures(suite)
        module = _load(suite, "cf_suite_" + _slug(suite.relative_to(self.root)))
        fixtures.update(_fixtures_of(module))
        rel = str(suite.relative_to(self.root))
        for name, obj in list(vars(module).items()):
            if isinstance(obj, type) and issubclass(obj, unittest.TestCase):
                result = unittest.TestResult()
                unittest.defaultTestLoader.loadTestsFromTestCase(obj).run(result)
                self.passed += result.testsRun - len(result.failures) - len(result.errors) - len(result.skipped)
                self.skipped += len(result.skipped)
                for case, tb in result.failures + result.errors:
                    self.failed += 1
                    self.failures.append(f"{rel}::{case.id()}\n{tb[-1500:]}")
            elif isinstance(obj, type) and name.startswith("Test") and "__init__" not in vars(obj):
                for meth in [m for m in dir(obj) if m.startswith("test")]:
                    inst = obj()
                    if hasattr(inst, "setup_method"):
                        inst.setup_method(getattr(inst, meth))
                    try:
                        self._expand(f"{rel}::{name}::{meth}", getattr(inst, meth), fixtures)
                    finally:
                        if hasattr(inst, "teardown_method"):
                            inst.teardown_method(getattr(inst, meth))
            elif (name.startswith("test") and inspect.isfunction(obj)
                  and obj.__module__ == module.__name__):
                self._expand(f"{rel}::{name}", obj, fixtures)


def _slug(path: Any) -> str:
    return re.sub(r"[^0-9A-Za-z]+", "_", str(path))


def _load(path: Path, name: str) -> types.ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _fixtures_of(module: types.ModuleType) -> dict:
    return {n: f for n, f in vars(module).items() if callable(f) and getattr(f, "_cf_fixture", False)}


def run(root: Path, suites: Iterable[str], *, sys_paths: Iterable[str] = (),
        stub_modules: Iterable[str] = (), budget_s: float = 75.0, min_passed: int = 1,
        conftest: bool = True) -> int:
    """Run ``suites`` (paths relative to ``root``); return a process exit code (0 = PASS)."""
    import json

    start = time.monotonic()
    sys.dont_write_bytecode = True  # read-only checkout
    for entry in reversed(list(sys_paths)):
        sys.path.insert(0, str(root / entry))
    shim = importlib.util.find_spec("pytest") is None
    if shim:
        sys.modules["pytest"] = pytest_module()
    stubs = install_stubs(stub_modules)
    suites = list(suites)
    missing = [s for s in suites if not (root / s).is_file()]
    if missing:
        print("CERTFORGE_TESTKIT_FAILED: missing suites: " + ", ".join(missing), file=sys.stderr)
        return 1
    session = _Session(root, start + budget_s)
    session.use_conftest = conftest
    aborted = None
    for suite in suites:
        try:
            session.run_suite(root / suite)
        except BudgetExceeded as exc:
            aborted = str(exc)
            break
        except BaseException as exc:  # noqa: BLE001 - an import/collection error fails the suite
            session.failed += 1
            session.failures.append(f"{suite}: collection error {type(exc).__name__}: {exc}\n"
                                    + traceback.format_exc(limit=6)[-1500:])
    for failure in session.failures[:20]:
        print("FAIL " + failure, file=sys.stderr)
    report = {
        "suites": len(suites), "passed": session.passed, "failed": session.failed,
        "skipped": session.skipped, "pytest_shim": shim, "stubbed_modules": stubs,
        "elapsed_s": round(time.monotonic() - start, 2), "aborted": aborted,
    }
    ok = aborted is None and session.failed == 0 and session.passed >= min_passed
    print(("CERTFORGE_TESTKIT_OK " if ok else "CERTFORGE_TESTKIT_FAILED ")
          + json.dumps(report, sort_keys=True))
    return 0 if ok else 1


def run_isolated(root: Path, suites: Iterable[dict], *, budget_s: float = 60.0,
                 per_suite_timeout_s: float = 30.0, min_passed: int = 1) -> int:
    """Run each suite in its own interpreter (no module-name collisions between suites).

    ``suites``: dicts with ``path`` plus optional ``sys_paths`` / ``stub_modules``.
    """
    import json
    import subprocess

    start = time.monotonic()
    suites = list(suites)
    totals = {"passed": 0, "failed": 0, "skipped": 0}
    failed_suites: list[str] = []
    for spec in suites:
        remaining = budget_s - (time.monotonic() - start)
        if remaining <= 1:
            failed_suites.append(f"{spec['path']}: journey time budget exhausted")
            break
        argv = [sys.executable, "-B", str(Path(__file__).resolve()), "--root", str(root),
                "--suite", spec["path"]]
        for entry in spec.get("sys_paths", []):
            argv += ["--sys-path", entry]
        for name in spec.get("stub_modules", []):
            argv += ["--stub", name]
        try:
            proc = subprocess.run(argv, cwd=str(root), capture_output=True, text=True,
                                  timeout=min(per_suite_timeout_s, remaining), check=False)
        except subprocess.TimeoutExpired:
            failed_suites.append(f"{spec['path']}: timed out")
            continue
        line = next((ln for ln in reversed(proc.stdout.splitlines())
                     if ln.startswith("CERTFORGE_TESTKIT_")), "")
        try:
            report = json.loads(line.split(" ", 1)[1])
        except (IndexError, ValueError):
            report = {}
        for key in totals:
            totals[key] += int(report.get(key, 0) or 0)
        status = "ok" if proc.returncode == 0 else "FAILED"
        print(f"suite {status} {spec['path']} passed={report.get('passed')} "
              f"failed={report.get('failed')} skipped={report.get('skipped')} "
              f"elapsed_s={report.get('elapsed_s')}")
        if proc.returncode != 0:
            failed_suites.append(spec["path"])
            sys.stderr.write(proc.stderr[-3000:])
    ok = not failed_suites and totals["failed"] == 0 and totals["passed"] >= min_passed
    summary = dict(totals, suites=len(suites), failed_suites=failed_suites,
                   elapsed_s=round(time.monotonic() - start, 2))
    print(("CERTFORGE_SUITES_OK " if ok else "CERTFORGE_SUITES_FAILED ")
          + json.dumps(summary, sort_keys=True))
    return 0 if ok else 1


if __name__ == "__main__":  # single-suite worker used by run_isolated
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--suite", required=True)
    parser.add_argument("--sys-path", action="append", default=[])
    parser.add_argument("--stub", action="append", default=[])
    parser.add_argument("--budget", type=float, default=60.0)
    ns = parser.parse_args()
    raise SystemExit(run(Path(ns.root), [ns.suite], sys_paths=ns.sys_path,
                         stub_modules=ns.stub, budget_s=ns.budget))
