"""Architecture guard: keep the service split enforceable.

Packages (one per deployable, plus the shared core):

    sentinel_core       shared by every service; must not import any service
    server              the API service (FastAPI); ships as api-sentinel-api
    sentinel_worker     the scan-worker service
    sentinel_scheduler  the scheduler service
    sentinel_archiver   the archiver service

Rules that keep them independently deployable:
  1. sentinel_core imports none of the service packages.
  2. A service never imports another service's package. They cooperate only through the
     database run queue and Redis events.
  3. Nothing but the API imports server.api.* (the web layer).

A violation would make an image un-buildable without pulling in another service's code and
silently undo the split, so each failure lists the exact offending imports.
"""
from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SERVICES = ("server", "sentinel_worker", "sentinel_scheduler", "sentinel_archiver")


def _py_files(package: str):
    base = ROOT / package
    if not base.exists():
        return
    for path in base.rglob("*.py"):
        if "__pycache__" not in path.parts:
            yield path


def _imported_modules(path: Path):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            yield node.lineno, node.module
        elif isinstance(node, ast.Import):
            for alias in node.names:
                yield node.lineno, alias.name


def _violations(package: str, forbidden: tuple[str, ...]) -> list[str]:
    found = []
    for path in _py_files(package):
        for lineno, module in _imported_modules(path):
            root = module.split(".")[0]
            if root in forbidden:
                found.append(f"{path.relative_to(ROOT)}:{lineno} imports {module}")
    return sorted(found)


def test_sentinel_core_does_not_import_any_service():
    violations = _violations("sentinel_core", SERVICES)
    assert not violations, (
        "sentinel_core is installed by every service and must not depend on one:\n  "
        + "\n  ".join(violations)
    )


def test_services_do_not_import_each_other():
    violations = []
    for package in SERVICES:
        others = tuple(s for s in SERVICES if s != package)
        violations += _violations(package, others)
    assert not violations, (
        "services may only share code through sentinel_core:\n  " + "\n  ".join(sorted(violations))
    )


def test_only_the_api_imports_the_web_layer():
    violations = []
    for package in ("sentinel_core", "sentinel_worker", "sentinel_scheduler", "sentinel_archiver"):
        for path in _py_files(package):
            for lineno, module in _imported_modules(path):
                if module == "server.api" or module.startswith("server.api."):
                    violations.append(f"{path.relative_to(ROOT)}:{lineno} imports {module}")
    assert not violations, "only the API may import server.api.*:\n  " + "\n  ".join(sorted(violations))


def test_api_web_layer_is_only_imported_within_the_api():
    violations = []
    for path in _py_files("server"):
        rel = path.relative_to(ROOT / "server").parts
        if rel[0] == "api":
            continue
        for lineno, module in _imported_modules(path):
            if module == "server.api" or module.startswith("server.api."):
                violations.append(f"{path.relative_to(ROOT)}:{lineno} imports {module}")
    assert not violations, (
        "server/modules, server/services and server/agents must not import server.api.*:\n  "
        + "\n  ".join(sorted(violations))
    )
