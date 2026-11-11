from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable


TOOL_ENV_VARS = {"codeql": "CODEQL_BIN"}


EXCLUDED_DIRS = {
    ".git",
    ".hg",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "htmlcov",
    "node_modules",
    "output_folder",
}


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def tool_path(name: str) -> str:
    """Locate an external tool via its environment variable or PATH."""
    env_var = TOOL_ENV_VARS.get(name, "")
    configured = os.environ.get(env_var) if env_var else None
    if configured:
        if Path(configured).is_file():
            return configured
        raise FileNotFoundError(f"{env_var}={configured!r} does not point to a file")
    found = shutil.which(name)
    if found:
        return found
    hint = f"set {env_var} or " if env_var else ""
    raise FileNotFoundError(f"Could not find {name!r}; {hint}add it to PATH")


def run_command(
    args: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    check: bool = True,
    timeout: int | None = None,
) -> subprocess.CompletedProcess[str]:
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    return subprocess.run(
        args,
        cwd=str(cwd) if cwd else None,
        env=merged_env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=check,
        timeout=timeout,
    )


def iter_python_files(root: Path, output_folder: Path | None = None) -> list[Path]:
    root = root.resolve()
    output_folder = output_folder.resolve() if output_folder else None
    files: list[Path] = []
    for path in root.rglob("*.py"):
        if should_skip_path(path, root, output_folder):
            continue
        files.append(path)
    return sorted(files)


def should_skip_path(path: Path, root: Path, output_folder: Path | None = None) -> bool:
    try:
        rel = path.resolve().relative_to(root)
    except ValueError:
        return True
    if output_folder:
        try:
            path.resolve().relative_to(output_folder)
            return True
        except ValueError:
            pass
    return any(part in EXCLUDED_DIRS or part.startswith(".") for part in rel.parts[:-1])


def module_name_for_path(path: Path, root: Path) -> str:
    rel = path.resolve().relative_to(root.resolve()).with_suffix("")
    parts = list(rel.parts)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def infer_local_prefixes(repo_root: Path) -> list[str]:
    prefixes: set[str] = set()
    for child in repo_root.iterdir():
        if child.name.startswith("."):
            continue
        if child.is_dir() and (child / "__init__.py").exists():
            prefixes.add(child.name)
        elif child.is_file() and child.suffix == ".py" and child.stem != "setup":
            prefixes.add(child.stem)
    return sorted(prefixes)


def normalize_prefixes(prefixes: Iterable[str] | None, repo_root: Path) -> list[str]:
    clean = sorted({p.strip().strip(".") for p in prefixes or [] if p and p.strip(".")})
    return clean or infer_local_prefixes(repo_root)


def is_under_prefix(name: str, prefixes: Iterable[str]) -> bool:
    return any(name == prefix or name.startswith(prefix + ".") for prefix in prefixes)


def now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def print_step(message: str) -> None:
    print(f"[graph_analysis] {message}", file=sys.stderr)
