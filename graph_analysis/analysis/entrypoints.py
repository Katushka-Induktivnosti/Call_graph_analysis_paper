"""Identify the entry points of a Python project.

Sources, strongest first:

* declared console/GUI scripts: ``entry_points.txt`` (installed metadata),
  ``pyproject.toml`` (``[project.scripts]``, ``[project.gui-scripts]``,
  ``[tool.poetry.scripts]``), ``setup.cfg`` and ``setup.py``;
* every local function called inside an ``if __name__ == "__main__":`` block;
* functions with conventional entry names (``main``, ``cli``, ``run``, ...).

Entry points are functions (F_entry is a subset of F, Section 4.3.3). Call-graph
roots, production functions that no other function calls, are added by the
combiner as the second endpoint tier (Section 4.5.2).
"""
from __future__ import annotations

import ast
import configparser
import tomllib
from pathlib import Path
from typing import Any, Iterable

from ..callgraph.utils import iter_python_files, module_name_for_path
from .names import is_production_name, resolve_in_graph


ROOT_ENTRY_KIND = "callgraph_root"
NAMED_ENTRY_LABELS = {"main", "cli", "run", "start", "create_app"}
ENTRY_PRIORITY = {
    "console_script": 4,
    "gui_script": 4,
    "main_guard_call": 3,
    "named_main": 2,
    ROOT_ENTRY_KIND: 1,
}


def discover_explicit_entries(
    repo_root: Path,
    functions: set[str],
    modules: set[str],
    normalized_index: dict[str, tuple[str, ...]],
    function_files: dict[str, str],
) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    if repo_root.is_dir():
        for kind, label, value, origin in declared_scripts(repo_root):
            target = entry_target(value)
            resolved = resolve_in_graph(target, functions, normalized_index)
            if resolved in functions:
                add_entry(result, resolved, kind, f"{label} = {value} ({origin})", "high")
        for module, called in main_guards(repo_root):
            for name in called:
                resolved = resolve_in_graph(name, functions, normalized_index)
                if resolved in functions:
                    add_entry(result, resolved, "main_guard_call", f"called from {module} main guard", "high")

    for function in functions:
        leaf = function.rsplit(".", 1)[-1].lower()
        if leaf in NAMED_ENTRY_LABELS and is_production_name(
            function, function_files.get(function, "")
        ):
            add_entry(result, function, "named_main", function, "medium")
    return result


def declared_scripts(repo_root: Path) -> list[tuple[str, str, str, str]]:
    """Return (kind, label, "module:attr", origin file) for declared scripts."""
    found: list[tuple[str, str, str, str]] = []
    for path in sorted(repo_root.rglob("entry_points.txt")):
        parser = configparser.ConfigParser(interpolation=None, strict=False)
        try:
            parser.read(path, encoding="utf-8")
        except (configparser.Error, OSError, UnicodeDecodeError):
            continue
        found.extend(_config_scripts(parser, _relative(path, repo_root)))

    setup_cfg = repo_root / "setup.cfg"
    if setup_cfg.is_file():
        parser = configparser.ConfigParser(interpolation=None, strict=False)
        try:
            parser.read(setup_cfg, encoding="utf-8")
        except (configparser.Error, OSError, UnicodeDecodeError):
            parser = None
        if parser is not None and parser.has_section("options.entry_points"):
            for key, raw in parser.items("options.entry_points"):
                kind = _script_kind(key)
                if kind:
                    for line in raw.splitlines():
                        label, _, value = line.partition("=")
                        if value.strip():
                            found.append((kind, label.strip(), value.strip(), "setup.cfg"))

    pyproject = repo_root / "pyproject.toml"
    if pyproject.is_file():
        try:
            data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
            data = {}
        project = data.get("project", {}) if isinstance(data.get("project"), dict) else {}
        poetry = data.get("tool", {}).get("poetry", {}) if isinstance(data.get("tool"), dict) else {}
        for kind, table in (
            ("console_script", project.get("scripts")),
            ("gui_script", project.get("gui-scripts")),
            ("console_script", poetry.get("scripts") if isinstance(poetry, dict) else None),
        ):
            if isinstance(table, dict):
                for label, value in table.items():
                    if isinstance(value, dict):
                        value = value.get("callable") or value.get("reference") or ""
                    if isinstance(value, str) and value:
                        found.append((kind, str(label), value, "pyproject.toml"))

    setup_py = repo_root / "setup.py"
    if setup_py.is_file():
        found.extend(_setup_py_scripts(setup_py))
    return found


def main_guards(repo_root: Path) -> Iterable[tuple[str, list[str]]]:
    """Yield (module, called names) for each ``if __name__ == "__main__":`` block."""
    for path in iter_python_files(repo_root):
        rel = _relative(path, repo_root)
        if not is_production_name("", rel):
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, UnicodeDecodeError, SyntaxError, ValueError):
            continue
        module = module_name_for_path(path, repo_root)
        for node in tree.body:
            if isinstance(node, ast.If) and _is_main_guard(node.test):
                called = sorted(
                    {
                        f"{module}.{name}"
                        for child in node.body
                        for call in ast.walk(child)
                        if isinstance(call, ast.Call)
                        and (name := _call_name(call.func))
                    }
                )
                yield module, called


def add_entry(
    entries: dict[str, dict[str, str]],
    qname: str,
    kind: str,
    declared_value: str,
    confidence: str,
) -> None:
    previous = entries.get(qname)
    if previous and ENTRY_PRIORITY.get(previous["kind"], 0) >= ENTRY_PRIORITY.get(kind, 0):
        return
    entries[qname] = {
        "qname": qname,
        "kind": kind,
        "declared_value": declared_value,
        "confidence": confidence,
    }


def entry_target(value: str) -> str:
    value = value.split(";", 1)[0].strip()
    value = value.split("[", 1)[0].strip()
    module, separator, attribute = value.partition(":")
    if separator and attribute:
        return f"{module.strip()}.{attribute.strip()}"
    return module.strip()


def _config_scripts(parser: configparser.ConfigParser, origin: str) -> list[tuple[str, str, str, str]]:
    found = []
    for section in parser.sections():
        kind = _script_kind(section)
        if kind:
            for label, value in parser.items(section):
                found.append((kind, label, value, origin))
    return found


def _script_kind(section: str) -> str:
    section = section.strip().lower()
    if section == "console_scripts":
        return "console_script"
    if section == "gui_scripts":
        return "gui_script"
    return ""


def _setup_py_scripts(path: Path) -> list[tuple[str, str, str, str]]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, UnicodeDecodeError, SyntaxError, ValueError):
        return []
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for keyword in node.keywords:
            if keyword.arg != "entry_points" or not isinstance(keyword.value, ast.Dict):
                continue
            for key, value in zip(keyword.value.keys, keyword.value.values):
                kind = _script_kind(key.value) if isinstance(key, ast.Constant) and isinstance(key.value, str) else ""
                if not kind or not isinstance(value, (ast.List, ast.Tuple)):
                    continue
                for item in value.elts:
                    if isinstance(item, ast.Constant) and isinstance(item.value, str):
                        label, _, target = item.value.partition("=")
                        if target.strip():
                            found.append((kind, label.strip(), target.strip(), "setup.py"))
    return found


def _is_main_guard(test: ast.expr) -> bool:
    if not isinstance(test, ast.Compare) or len(test.ops) != 1 or not isinstance(test.ops[0], ast.Eq):
        return False
    sides = [test.left, *test.comparators]
    has_name = any(isinstance(side, ast.Name) and side.id == "__name__" for side in sides)
    has_main = any(isinstance(side, ast.Constant) and side.value == "__main__" for side in sides)
    return has_name and has_main


def _call_name(func: ast.expr) -> str:
    parts: list[str] = []
    while isinstance(func, ast.Attribute):
        parts.append(func.attr)
        func = func.value
    if isinstance(func, ast.Name):
        parts.append(func.id)
        return ".".join(reversed(parts))
    return ""


def _relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.name


def summarize_entries(entries: dict[str, dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for entry in entries.values():
        counts[entry["kind"]] = counts.get(entry["kind"], 0) + 1
    return dict(sorted(counts.items()))
