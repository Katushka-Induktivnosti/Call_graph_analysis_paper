from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

from .utils import run_command, tool_path


DEFAULT_QUERY_SUITE = "codeql/python-queries:codeql-suites/python-security-and-quality.qls"


def run_codeql(
    repo_root: Path,
    output_folder: Path,
    *,
    query_suite: str = DEFAULT_QUERY_SUITE,
    extra_query_suites: list[str] | None = None,
    force: bool = False,
    reuse_database: bool = False,
    download: bool = False,
) -> dict[str, Any]:
    codeql = tool_path("codeql")
    work_dir = output_folder / ".work"
    db_dir = work_dir / "codeql-db"
    sarif_path = output_folder / "codeql_results.sarif"
    work_dir.mkdir(parents=True, exist_ok=True)
    if force and db_dir.exists():
        shutil.rmtree(db_dir)

    create_cmd = [
        codeql,
        "database",
        "create",
        str(db_dir),
        "--language=python",
        "--source-root",
        str(repo_root.resolve()),
        "--overwrite",
    ]
    query_specs = [query_suite] + list(extra_query_suites or [])
    analyze_cmd = [
        codeql,
        "database",
        "analyze",
        str(db_dir),
        *query_specs,
        "--format=sarif-latest",
        "--sarif-category=python",
        "--output",
        str(sarif_path),
    ]
    if download:
        analyze_cmd.append("--download")
    metadata: dict[str, Any] = {
        "status": "ok",
        "database": str(db_dir),
        "sarif": str(sarif_path),
        "create_command": [] if reuse_database else create_cmd,
        "analyze_command": analyze_cmd,
        "query_suite": query_suite,
        "query_suites": query_specs,
        "database_reused": reuse_database,
    }
    try:
        if reuse_database:
            if not (db_dir / "codeql-database.yml").is_file():
                raise FileNotFoundError(
                    f"Reusable CodeQL database not found: {db_dir}"
                )
            metadata["create_stdout"] = ""
            metadata["create_stderr"] = ""
        else:
            created = run_command(create_cmd, cwd=repo_root)
            metadata["create_stdout"] = created.stdout
            metadata["create_stderr"] = created.stderr
        analyzed = run_command(analyze_cmd, cwd=repo_root)
        metadata["analyze_stdout"] = analyzed.stdout
        metadata["analyze_stderr"] = analyzed.stderr
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        metadata["status"] = "failed"
        metadata["error"] = str(exc)
        if isinstance(exc, subprocess.CalledProcessError):
            metadata["stdout"] = exc.stdout
            metadata["stderr"] = exc.stderr
        (output_folder / "codeql_error.txt").write_text(_format_error(metadata), encoding="utf-8")
        if not sarif_path.exists():
            sarif_path.write_text('{"version":"2.1.0","runs":[]}', encoding="utf-8")
    return metadata


def _format_error(metadata: dict[str, Any]) -> str:
    lines = ["CodeQL failed; an empty SARIF file was written if no result file existed.", ""]
    lines.append(f"Create command: {' '.join(metadata.get('create_command', []))}")
    lines.append(f"Analyze command: {' '.join(metadata.get('analyze_command', []))}")
    lines.append(f"Error: {metadata.get('error', '')}")
    if metadata.get("stdout"):
        lines.extend(["", "STDOUT:", str(metadata["stdout"])])
    if metadata.get("stderr"):
        lines.extend(["", "STDERR:", str(metadata["stderr"])])
    return "\n".join(lines)
