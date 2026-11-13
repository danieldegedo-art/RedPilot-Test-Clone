"""Static Pure Black-Box audit of the repository itself (used by tests and by scripts/purity_audit.py). Stdlib only.

Checks (each returns a list of findings; an empty list = the gate passes):
  uncovered_files          every repo file is covered by at least one inventory entry (complete-inventory gate)
  stale_inventory_paths    every inventory glob still matches something (the inventory cannot silently rot)
  forbidden_no_change      no WHITE_BOX/GREY_BOX entry is 'no_change'
  forbidden_literals       grey-box vocabulary (webhook secret handling, grant-direct, test hooks, internal/benchmark routes) in ACTIVE code
  forbidden_imports        DB/log/cloud/cluster clients or raw sockets/subprocess inside target-facing code
  boundary_violations      engine/purity code importing benchmark/test code (benchmark blindness) or anything importing the quarantine
  env_reads                os.environ/os.getenv inside the engine package or the control layer outside enterprise_controls/brief_validation.py (token_env is the only approved path)
  unguarded_http_clients   every QAHttpClient(...) in product code passes guard= (no client may bypass the Control Adapter's request guard)
  control_boundary         the Main System reaches the controls only through the always-present Control Port (app/core/control_port); the optional plug-in adapter and the
                           controls are never imported by it and depend on nothing but the kernel contract and the named core primitives
"""
from __future__ import annotations

import ast
import fnmatch
import re
import sys
from dataclasses import dataclass
from pathlib import Path

from app.enterprise_controls import inventory as inv

EXCLUDED_DIRS = {"node_modules", "__pycache__", "dist", ".git", ".venv", ".mypy_cache", ".pytest_cache"}
EXCLUDED_SUFFIXES = {".pyc", ".pyo"}
ACTIVE_CODE_GLOBS = ("backend/app/*.py", "backend/benchmark/*.py", "dashboard/src/*.ts", "dashboard/src/*.tsx", "dashboard/electron/*.ts")
# files that legitimately NAME the forbidden vocabulary (they are the rules / detectors / redaction labels)
LITERAL_ALLOWLIST = (
    # ONLY files that must NAME the forbidden vocabulary: the rules/detectors themselves and the redaction labels. Everything else (engine, modules, recon, ...)
    # is scanned -- the allowlist was verified minimal (each entry matches at least one pattern, see tests/test_purity_enforcement.py::test_literal_allowlist_is_minimal).
    "backend/app/enterprise_controls/*", "backend/app/testing/redaction.py",
)
FORBIDDEN_LITERALS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("target_webhook_secret_handling", re.compile(r"\bwebhook_secret\b|\bwebhook_secret_is_sandbox\b")),
    ("admin_grant_route", re.compile(r"grant[-_]direct")),
    ("target_test_hook", re.compile(r"_revoke_delay")),
    ("internal_or_benchmark_route", re.compile(r"""["'](/internal/|/__benchmark__|/admin/entitlements)""")),
    ("benchmark_label_access", re.compile(r"\bground_truth\b|\bseeded_flaw\b|\bflaw_label\b")),
)
FORBIDDEN_IMPORT_ROOTS = frozenset({"sqlalchemy", "asyncpg", "psycopg", "psycopg2", "pymongo", "redis", "sqlite3", "boto3", "botocore", "kubernetes", "docker", "paramiko", "subprocess", "socket", "pexpect", "mysql", "pymysql"})
TARGET_FACING_PREFIXES = ("backend/app/testing/integrity/", "backend/app/testing/purity/", "backend/app/testing/modules/", "backend/app/testing/recon/",
                          "backend/app/enterprise_controls/", "backend/app/control_adapter/", "backend/app/core/control_port/")
BENCHMARK_IMPORT_ROOTS = frozenset({"tests", "purity_benchmark", "customer_target", "scenarios", "scorer", "lab", "benchmark_lab", "entitlement_target", "black_box_prober", "quarantine"})
BLINDNESS_PREFIXES = ("backend/app/testing/integrity/", "backend/app/testing/purity/", "backend/app/testing/modules/payment_integrity.py",
                      "backend/app/enterprise_controls/", "backend/app/control_adapter/", "backend/app/core/control_port/")

ENV_SCOPE_PREFIXES = ("backend/app/testing/integrity/", "backend/app/enterprise_controls/", "backend/app/control_adapter/", "backend/app/core/control_port/")
ENV_READ_ALLOWED = "backend/app/enterprise_controls/brief_validation.py"
ENV_READ_EXEMPT = (ENV_READ_ALLOWED, "backend/app/enterprise_controls/audit.py")  # the scanner itself names the pattern in its regular expression
# Control boundary: who may import what (full dotted module names).  KERNEL = the always-present Control Port (core), PLUGIN = the optional delegation adapter,
# EC = the optional Enterprise Controls. The two optional parts may be missing or damaged, so only the kernel may know them (and only through importlib strings).
KERNEL_DIR, PLUGIN_DIR, EC_DIR = "backend/app/core/control_port/", "backend/app/control_adapter/", "backend/app/enterprise_controls/"
OPTIONAL_PACKAGES = ("app.enterprise_controls", "app.control_adapter")
BOUNDARY_ALLOWED_OUTSIDE = (EC_DIR, PLUGIN_DIR, "backend/tests/", "backend/scripts/purity_audit.py", "backend/scripts/render_purity_inventory.py")
KERNEL_MAY_IMPORT = ("app.core.control_port", "app.testing.rate_limiter", "app.testing.purity.taxonomy")
EC_MAY_IMPORT = ("app.core.control_port", "app.enterprise_controls", "app.testing.integrity.brief", "app.testing.rate_limiter", "app.testing.purity.taxonomy")
PLUGIN_MAY_IMPORT = ("app.core.control_port", "app.control_adapter")


@dataclass(frozen=True)
class Hit:
    check: str
    path: str
    detail: str

    def __str__(self) -> str:
        return f"[{self.check}] {self.path}: {self.detail}"


def repo_root() -> Path:
    return Path(__file__).resolve().parents[3]  # backend/app/enterprise_controls/audit.py -> repository root


def iter_files(root: Path | None = None) -> list[str]:
    root = root or repo_root()
    out: list[str] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or any(part in EXCLUDED_DIRS for part in path.relative_to(root).parts) or path.suffix in EXCLUDED_SUFFIXES:
            continue
        out.append(path.relative_to(root).as_posix())
    return out


def _matches(rel: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatch.fnmatchcase(rel, p) for p in patterns)


def uncovered_files(root: Path | None = None) -> list[str]:
    all_patterns = tuple(p for d in inv.INVENTORY for p in d.paths)
    return [f for f in iter_files(root) if not _matches(f, all_patterns)]


def stale_inventory_paths(root: Path | None = None) -> list[str]:
    files = iter_files(root)
    stale = []
    for d in inv.INVENTORY:
        for pattern in d.paths:
            if not any(fnmatch.fnmatchcase(f, pattern) for f in files):
                stale.append(f"{d.id}: {pattern}")
    return stale


def forbidden_no_change() -> list[Hit]:
    return [Hit("forbidden_no_change", i, "WHITE_BOX/GREY_BOX entry with migration_action no_change") for i in inv.forbidden_no_change()]


def _active_files(root: Path) -> list[str]:
    return [f for f in iter_files(root) if _matches(f, ACTIVE_CODE_GLOBS)]


def forbidden_literals(root: Path | None = None) -> list[Hit]:
    root = root or repo_root()
    hits: list[Hit] = []
    for rel in _active_files(root):
        if _matches(rel, LITERAL_ALLOWLIST):
            continue
        text = (root / rel).read_text(encoding="utf-8", errors="replace")
        for name, pattern in FORBIDDEN_LITERALS:
            match = pattern.search(text)
            if match:
                hits.append(Hit("forbidden_literals", rel, f"{name}: {match.group(0)!r}"))
    return hits


def _imports(path: Path) -> list[tuple[str, int]]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except SyntaxError:
        return []
    out: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out.extend((a.name.split(".")[0], node.lineno) for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            out.append((node.module.split(".")[0], node.lineno))
    return out


def forbidden_imports(root: Path | None = None) -> list[Hit]:
    root = root or repo_root()
    hits = []
    for rel in iter_files(root):
        if rel.endswith(".py") and rel.startswith(TARGET_FACING_PREFIXES):
            for mod, line in _imports(root / rel):
                if mod in FORBIDDEN_IMPORT_ROOTS:
                    hits.append(Hit("forbidden_imports", rel, f"line {line}: imports {mod!r} (database/log/cloud/cluster client or raw socket/subprocess in target-facing code)"))
    return hits


def boundary_violations(root: Path | None = None) -> list[Hit]:
    root = root or repo_root()
    hits = []
    for rel in iter_files(root):
        if not rel.endswith(".py") or rel.startswith("backend/quarantine/"):
            continue
        for mod, line in _imports(root / rel):
            if mod in ("quarantine", "legacy_greybox"):
                hits.append(Hit("boundary_violations", rel, f"line {line}: imports the quarantine ({mod!r})"))
            elif rel.startswith(BLINDNESS_PREFIXES) and mod in BENCHMARK_IMPORT_ROOTS:
                hits.append(Hit("boundary_violations", rel, f"line {line}: engine/purity code imports benchmark/test code ({mod!r}) -- benchmark blindness"))
    return hits


def unguarded_http_clients(root: Path | None = None) -> list[Hit]:
    """Every QAHttpClient(...) built in product code must pass guard=: an unguarded client would bypass the allowlist AND the purity gate."""
    root = root or repo_root()
    hits = []
    for rel in iter_files(root):
        if not (rel.startswith("backend/app/") and rel.endswith(".py")):
            continue
        try:
            tree = ast.parse((root / rel).read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(node.func, "id", getattr(node.func, "attr", "")) == "QAHttpClient" and not any(k.arg == "guard" for k in node.keywords):
                hits.append(Hit("unguarded_http_clients", rel, f"line {node.lineno}: QAHttpClient(...) without guard="))
    return hits


def env_reads(root: Path | None = None) -> list[Hit]:
    root = root or repo_root()
    hits = []
    for rel in iter_files(root):
        if rel.startswith(ENV_SCOPE_PREFIXES) and rel.endswith(".py") and rel not in ENV_READ_EXEMPT:
            text = (root / rel).read_text(encoding="utf-8")
            if re.search(r"os\.environ|os\.getenv", text):
                hits.append(Hit("env_reads", rel, f"reads the environment (only {ENV_READ_ALLOWED} may resolve token_env)"))
    return hits


def _import_modules(path: Path) -> list[tuple[str, int]]:
    """Full dotted module names imported by a file (absolute imports only)."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except SyntaxError:
        return []
    out: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out.extend((a.name, node.lineno) for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            out.append((node.module, node.lineno))
            out.extend((f"{node.module}.{a.name}", node.lineno) for a in node.names if node.module == "app")
    return out


def _under(mod: str, allowed: tuple[str, ...]) -> bool:
    return any(mod == a or mod.startswith(a + ".") for a in allowed)


def control_boundary(root: Path | None = None) -> list[Hit]:
    """Main System -> Control Port (kernel) -> optional plug-in adapter -> optional Enterprise Controls.
    * Nothing outside the optional parts (and the two CI scripts and the tests) may import app.control_adapter or app.enterprise_controls: they can be
      missing or damaged, so only the kernel loads them (with importlib, inside try/except).
    * The kernel imports nothing optional; the controls and the plug-in import only the kernel contract and the named core primitives."""
    root = root or repo_root()
    hits = []
    for rel in iter_files(root):
        if not rel.endswith(".py") or rel.startswith("backend/quarantine/"):
            continue
        in_kernel, in_ec, in_plugin = rel.startswith(KERNEL_DIR), rel.startswith(EC_DIR), rel.startswith(PLUGIN_DIR)
        for mod, line in _import_modules(root / rel):
            if in_kernel and mod.startswith("app.") and not _under(mod, KERNEL_MAY_IMPORT):
                hits.append(Hit("control_boundary", rel, f"line {line}: control port (kernel) imports {mod!r} (allowed: itself + stability primitive + core vocabulary; optional parts only via importlib)"))
            elif in_ec and mod.startswith("app.") and not _under(mod, EC_MAY_IMPORT):
                hits.append(Hit("control_boundary", rel, f"line {line}: enterprise control imports {mod!r} (allowed: the kernel contract + named core primitives)"))
            elif in_plugin and mod.startswith("app.") and not _under(mod, PLUGIN_MAY_IMPORT):
                hits.append(Hit("control_boundary", rel, f"line {line}: control adapter plug-in imports {mod!r} (allowed: the kernel + its own package)"))
            elif not (in_kernel or in_ec or in_plugin) and _under(mod, OPTIONAL_PACKAGES) and not rel.startswith(BOUNDARY_ALLOWED_OUTSIDE):
                hits.append(Hit("control_boundary", rel, f"line {line}: imports the optional part {mod!r} directly; the Main System must use app.core.control_port"))
    return hits


def run_all(root: Path | None = None) -> dict[str, list]:
    return {
        "uncovered_files": uncovered_files(root), "stale_inventory_paths": stale_inventory_paths(root), "forbidden_no_change": forbidden_no_change(),
        "forbidden_literals": forbidden_literals(root), "forbidden_imports": forbidden_imports(root), "boundary_violations": boundary_violations(root), "env_reads": env_reads(root),
        "unguarded_http_clients": unguarded_http_clients(root), "control_boundary": control_boundary(root),
    }


def main(argv: list[str] | None = None) -> int:
    results = run_all()
    bad = {k: v for k, v in results.items() if v}
    print(f"files audited: {len(iter_files())}   inventory entries: {len(inv.INVENTORY)}   classification counts: {inv.counts()}")
    for name, items in results.items():
        print(f"{'FAIL' if items else 'ok  '} {name}: {len(items)}")
        for item in items[:25]:
            print("   ", item)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
