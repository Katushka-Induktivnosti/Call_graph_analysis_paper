from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Any

from .ast_index import build_ast_callgraph_details
from .utils import iter_python_files, run_command, write_json


# Directory containing the graph_analysis package, so the PyCG shim is
# importable from the analysed project's working directory.
PACKAGE_PARENT = str(Path(__file__).resolve().parents[2])


def run_pycg(
    repo_root: Path,
    output_folder: Path,
    function_index: dict[str, Any],
    *,
    max_iter: int | None = None,
    timeout: int = 120,
) -> tuple[dict[str, list[str]], dict[str, Any]]:
    output_path = output_folder / "pycg_callgraph.json"
    python_files = iter_python_files(repo_root, output_folder)
    if not python_files:
        raise ValueError(f"No Python source files found under {repo_root}")
    ast_graph, ast_edges, ast_metadata = build_ast_callgraph_details(
        repo_root, function_index, output_folder
    )
    write_json(output_folder / "function_index.json", function_index)
    command = [
        sys.executable,
        "-m",
        "graph_analysis.callgraph.pycg_shim",
        "--package",
        str(repo_root.resolve()),
    ]
    if max_iter is not None:
        command += ["--max-iter", str(max_iter)]
    command += [str(path) for path in python_files]
    command += ["-o", str(output_path)]

    metadata: dict[str, Any] = {
        "command": command,
        "entry_point_count": len(python_files),
        "status": "ok",
        "timeout_seconds": timeout,
        "used_fallback": False,
        "ast_enrichment": ast_metadata,
    }
    try:
        completed = run_command(
            command, cwd=repo_root, env={"PYTHONPATH": PACKAGE_PARENT}, timeout=timeout
        )
        metadata["stdout"] = completed.stdout
        metadata["stderr"] = completed.stderr
        raw = _read_pycg_output(output_path)
        merged = merge_callgraphs(raw, ast_graph)
        metadata["pycg_edge_count"] = edge_count(raw)
        metadata["combined_edge_count"] = edge_count(merged)
        metadata["_edge_metadata"] = merge_edge_metadata(raw, ast_edges)
        write_json(output_path, merged)
        write_json(
            output_folder / "callgraph_enrichment.json",
            {
                "schema_version": 1,
                "metadata": ast_metadata,
                "edges": ast_edges,
            },
        )
        return merged, metadata
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError, ValueError) as exc:
        metadata["status"] = "failed"
        metadata["used_fallback"] = True
        metadata["error"] = str(exc)
        if isinstance(exc, subprocess.CalledProcessError):
            metadata["stdout"] = exc.stdout
            metadata["stderr"] = exc.stderr
        elif isinstance(exc, subprocess.TimeoutExpired):
            metadata["stdout"] = _to_text(exc.stdout)
            metadata["stderr"] = _to_text(exc.stderr)
        metadata["_edge_metadata"] = ast_edges
        metadata["combined_edge_count"] = edge_count(ast_graph)
        write_json(output_path, ast_graph)
        write_json(
            output_folder / "callgraph_enrichment.json",
            {
                "schema_version": 1,
                "metadata": ast_metadata,
                "edges": ast_edges,
            },
        )
        (output_folder / "pycg_error.txt").write_text(_format_error(metadata), encoding="utf-8")
        return ast_graph, metadata


def merge_callgraphs(
    primary: dict[str, list[str]], supplemental: dict[str, list[str]]
) -> dict[str, list[str]]:
    result = {source: set(targets) for source, targets in primary.items()}
    for source, targets in supplemental.items():
        result.setdefault(source, set()).update(targets)
    return {
        source: sorted(targets - {source})
        for source, targets in sorted(result.items())
    }


def edge_count(graph: dict[str, list[str]]) -> int:
    return sum(len(targets) for targets in graph.values())


def merge_edge_metadata(
    pycg_graph: dict[str, list[str]], ast_edges: list[dict[str, str]]
) -> list[dict[str, str]]:
    records = {
        (row["source"], row["target"]): dict(row) for row in ast_edges
    }
    for source, targets in pycg_graph.items():
        for target in targets:
            pair = (source, target)
            if pair in records:
                records[pair]["provenance"] = "pycg+ast"
            else:
                records[pair] = {
                    "source": source,
                    "target": target,
                    "kind": "call",
                    "provenance": "pycg",
                }
    return [records[pair] for pair in sorted(records)]


def _read_pycg_output(path: Path) -> dict[str, list[str]]:
    import json

    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("PyCG output was not a JSON object")
    graph: dict[str, list[str]] = {}
    for source, targets in payload.items():
        if isinstance(source, str) and isinstance(targets, list):
            norm_source = _normalize_pycg_qualname(source)
            norm_targets = {_normalize_pycg_qualname(t) for t in targets if isinstance(t, str)}
            norm_targets.discard(norm_source)
            existing = set(graph.get(norm_source, []))
            graph[norm_source] = sorted(existing | norm_targets)
    return graph


def _normalize_pycg_qualname(qname: str) -> str:
    return ".".join(p for p in qname.split(".") if p != "__init__")


def _format_error(metadata: dict[str, Any]) -> str:
    lines = ["PyCG failed; AST fallback call graph was written to pycg_callgraph.json.", ""]
    lines.append(f"Command: {' '.join(metadata.get('command', []))}")
    lines.append(f"Error: {metadata.get('error', '')}")
    if metadata.get("stdout"):
        lines.extend(["", "STDOUT:", str(metadata["stdout"])])
    if metadata.get("stderr"):
        lines.extend(["", "STDERR:", str(metadata["stderr"])])
    return "\n".join(lines)


def _to_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value
