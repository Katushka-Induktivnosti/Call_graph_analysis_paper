from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .ast_index import build_ast_callgraph_details, write_function_index
from .codeql_runner import DEFAULT_QUERY_SUITE, run_codeql
from .graph_builder import build_project_bundle
from .pycg_runner import edge_count, run_pycg
from .sarif import load_codeql_alerts
from .utils import normalize_prefixes, print_step, write_json


@dataclass
class CallGraphOptions:
    skip_pycg: bool = False
    skip_codeql: bool = False
    reuse_codeql: bool = False
    max_pycg_iter: int = 3
    pycg_timeout: int = 120
    query_suite: str = DEFAULT_QUERY_SUITE
    codeql_download: bool = False


def analyze_project(
    repo_root: Path,
    output_folder: Path,
    project_id: str,
    options: CallGraphOptions,
    local_prefixes: list[str] | None = None,
) -> dict[str, Any]:
    """Build the call graph of one Python source tree and map CodeQL alerts onto it.

    Writes function_index.json, pycg_callgraph.json, callgraph_enrichment.json,
    codeql_results.sarif, graph_bundle.json and pipeline_manifest.json into
    ``output_folder`` and returns the graph bundle.
    """
    repo_root = repo_root.resolve()
    output_folder = output_folder.resolve()
    output_folder.mkdir(parents=True, exist_ok=True)
    prefixes = normalize_prefixes(local_prefixes, repo_root)

    print_step(f"[{project_id}] indexing Python functions and modules")
    function_index = write_function_index(repo_root, output_folder)

    if options.skip_pycg:
        print_step(f"[{project_id}] skipping PyCG; using AST call graph only")
        callgraph, ast_edges, ast_metadata = build_ast_callgraph_details(
            repo_root, function_index, output_folder
        )
        pycg_metadata: dict[str, Any] = {
            "status": "skipped",
            "used_fallback": True,
            "ast_enrichment": ast_metadata,
            "combined_edge_count": edge_count(callgraph),
            "_edge_metadata": ast_edges,
        }
        write_json(output_folder / "function_index.json", function_index)
        write_json(output_folder / "pycg_callgraph.json", callgraph)
        write_json(
            output_folder / "callgraph_enrichment.json",
            {"schema_version": 1, "metadata": ast_metadata, "edges": ast_edges},
        )
    else:
        print_step(f"[{project_id}] running PyCG")
        max_iter = None if options.max_pycg_iter == -1 else options.max_pycg_iter
        callgraph, pycg_metadata = run_pycg(
            repo_root,
            output_folder,
            function_index,
            max_iter=max_iter,
            timeout=options.pycg_timeout,
        )
        if pycg_metadata.get("used_fallback"):
            print_step(
                f"[{project_id}] WARNING: PyCG failed; using AST call graph only "
                "(see pycg_error.txt)"
            )

    sarif_path = output_folder / "codeql_results.sarif"
    if options.reuse_codeql and sarif_path.exists():
        print_step(f"[{project_id}] reusing existing CodeQL SARIF")
        codeql_metadata: dict[str, Any] = {"status": "reused", "sarif": sarif_path.name}
    elif options.skip_codeql:
        print_step(f"[{project_id}] skipping CodeQL")
        sarif_path.write_text('{"version":"2.1.0","runs":[]}', encoding="utf-8")
        codeql_metadata = {"status": "skipped", "sarif": sarif_path.name}
    else:
        print_step(f"[{project_id}] running CodeQL")
        codeql_metadata = run_codeql(
            repo_root,
            output_folder,
            query_suite=options.query_suite,
            download=options.codeql_download,
        )
        if codeql_metadata.get("status") == "failed":
            print_step(
                f"[{project_id}] WARNING: CodeQL failed (see codeql_error.txt)"
            )

    alerts = load_codeql_alerts(sarif_path, repo_root, function_index)
    print_step(f"[{project_id}] mapped {len(alerts)} CodeQL alerts to graph nodes")

    bundle = build_project_bundle(
        project_id=project_id,
        repo_root=repo_root,
        local_prefixes=prefixes,
        function_index=function_index,
        pycg_graph=callgraph,
        alerts=alerts,
        pycg_metadata=pycg_metadata,
        codeql_metadata=codeql_metadata,
    )
    write_json(output_folder / "graph_bundle.json", bundle)
    write_json(
        output_folder / "pipeline_manifest.json",
        {
            "project_id": project_id,
            "local_prefixes": prefixes,
            "function_count": len(function_index.get("functions", {})),
            "edge_count": len(bundle["edges"]),
            "alert_count": len(alerts),
            "pycg": bundle["tool_metadata"]["pycg"],
            "codeql": {
                key: value
                for key, value in codeql_metadata.items()
                if not key.endswith(("_stdout", "_stderr"))
            },
        },
    )
    return bundle
