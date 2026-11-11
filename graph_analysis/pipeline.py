"""Framework pipeline (Section 4): graph construction, then graph analyses.

Construction (Section 4.2) runs four modules in order. Each reads what earlier
modules wrote and adds typed nodes and edges to the graph G (``graph.py``):

  B1 Dependency Resolution        component nodes C, dependency edges D
  B2 Source Analysis              M, L, F, X nodes; O, K, K_X, A edges
  B3 Cross-Component Resolution   cross-package edges B; entry points F_entry
  B4 Vulnerability Mapping        vulnerability nodes U; R_UC and R_UF edges

Analyses (Section 4.5) only read the finished graph:

  A1 Dependency exposure          paths over D from the root to affected components
  A2 Static reachability          strict paths over K and B from tiered endpoints of
                                  the root to the vulnerable functions

Analyses operate on chain subgraphs: for every vulnerable component the
shortest dependency chains from the root (five by default) are selected, and
each chain's subgraph holds the call graphs of the packages on it plus the B
edges between them. B2 therefore builds call graphs only for packages on such
chains by default (``source_scope="chains"``); the results of A1 and A2 are the
same as with ``source_scope="all"``, which builds every component.
"""
from __future__ import annotations

import csv
import re
import time
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import __version__
from .analysis.combine import (
    CombinedChain,
    PackageGraph,
    combine_chain,
    graph_diagnostics,
    load_package_graph,
    runtime_call_targets,
    trace_to_entry,
)
from .analysis.entrypoints import summarize_entries
from .analysis.names import resolve_in_graph
from .analysis.vulnfuncs import MappingRow, load_mapping, locate_functions, match_mapping
from .callgraph.graph_builder import merge_bundles
from .callgraph.project import CallGraphOptions, analyze_project
from .callgraph.render import render_html
from .callgraph.utils import print_step, read_json, write_json
from .dependencies.common import CACHE_DIR, normalize_package_name
from .dependencies.dependency_resolver import PROJECT_NODE, DependencyResolver
from .dependencies.osv import map_vulnerabilities
from .dependencies.pypi import PyPIClient
from .dependencies.source_collector import (
    NoPythonSourcesError,
    choose_repo_root,
    collect_pypi_source,
)
from .graph import EvidenceGraph

TEMPLATE = Path(__file__).resolve().parent / "callgraph" / "templates" / "index.html"

# Statuses of a vulnerable-function record that never reached the path search.
NOT_LOCATED = "not_located"
NOT_IN_CALL_GRAPH = "not_in_call_graph"


@dataclass
class PipelineConfig:
    project: Path
    output: Path
    vulnerable_functions: Path
    project_name: str = ""
    local_prefixes: list[str] = field(default_factory=list)
    cutoff: str = ""
    include_dev: bool = False
    include_extras: bool = False
    max_dependency_depth: int = 20
    max_chains_per_dependency: int = 5
    source_scope: str = "chains"
    cache_dir: Path = CACHE_DIR
    refresh_cache: bool = False
    callgraph: CallGraphOptions = field(default_factory=CallGraphOptions)


# ---------------------------------------------------------------------------
# Construction modules
# ---------------------------------------------------------------------------


def b1_dependency_resolution(
    project: Path, output: Path, config: PipelineConfig, cutoff: str
) -> dict[str, Any]:
    """B1: component nodes C and dependency edges D (Section 4.2.1, 4.3.1)."""
    resolver = DependencyResolver(
        cutoff=cutoff,
        cache_dir=config.cache_dir,
        include_dev=config.include_dev,
        include_extras=config.include_extras,
        max_depth=config.max_dependency_depth,
        refresh_cache=config.refresh_cache,
    )
    return resolver.resolve_project(project, output / "dependencies")


def b2_source_analysis(
    component: str,
    callgraph_dir: Path,
    options: CallGraphOptions,
    *,
    source_root: Path | None = None,
    source_dir: Path | None = None,
    pypi: PyPIClient | None = None,
    cache_dir: Path = CACHE_DIR,
    local_prefixes: list[str] | None = None,
    reuse: bool = False,
) -> tuple[dict[str, Any], PackageGraph | None, dict[str, Any] | None]:
    """B2: retrieve the source of one component version and build its call graph.

    Returns (status record, package graph, graph bundle). With ``reuse`` an
    existing graph in ``callgraph_dir`` is loaded instead of being rebuilt, so
    graphs are cached per package version (Section 5.2).
    """
    status: dict[str, Any] = {"component": component, "status": []}
    manifest_path = callgraph_dir / "component_status.json"
    bundle_path = callgraph_dir / "graph_bundle.json"
    if reuse and manifest_path.is_file():
        status = read_json(manifest_path)
        if bundle_path.is_file():
            return status, load_package_graph(component, bundle_path), read_json(bundle_path)
        return status, None, None

    started = time.process_time()
    wall_started = time.monotonic()
    if source_root is None:
        package, version = component.rsplit("@", 1)
        assert pypi is not None and source_dir is not None
        try:
            collected = collect_pypi_source(package, version, source_dir, pypi, cache_dir)
        except Exception as exc:  # network or archive errors are recorded, not fatal
            status["status"].append({"status": "download_failed", "detail": error_summary(exc)})
            print_step(f"WARNING: {component}: source download failed: {exc}")
            write_json(manifest_path, status)
            return status, None, None
        if collected.get("status") != "collected":
            status["status"].append({"status": "missing_release_artifact", "detail": "no sdist or wheel"})
            write_json(manifest_path, status)
            return status, None, None
        status["artifact"] = {
            "filename": collected.get("filename"),
            "type": collected.get("artifact_type"),
            "url": collected.get("url"),
            "sha256": collected.get("sha256"),
        }
        try:
            source_root = choose_repo_root(
                Path(collected["source_path"]), normalize_package_name(package), version
            )
        except NoPythonSourcesError as exc:
            status["status"].append({"status": "no_python_sources", "detail": str(exc)})
            write_json(manifest_path, status)
            return status, None, None

    bundle = analyze_project(source_root, callgraph_dir, component, options, local_prefixes)
    pycg = bundle["tool_metadata"]["pycg"]
    codeql = bundle["tool_metadata"]["codeql"]
    if pycg.get("used_fallback"):
        status["status"].append({"status": "pycg_fallback", "detail": str(pycg.get("status"))})
    if codeql.get("status") == "failed":
        status["status"].append({"status": "codeql_failed", "detail": "see codeql_error.txt"})
    status.update(
        {
            "source_root": str(source_root),
            "pycg_used_fallback": bool(pycg.get("used_fallback")),
            "codeql_status": codeql.get("status"),
            "codeql_alerts": len(bundle.get("alerts", [])),
            "build_cpu_seconds": round(time.process_time() - started, 3),
            "build_wall_seconds": round(time.monotonic() - wall_started, 3),
        }
    )
    write_json(manifest_path, status)
    return status, load_package_graph(component, bundle_path), bundle


def b3_cross_component_resolution(
    chain: list[str], graphs: dict[str, PackageGraph]
) -> CombinedChain:
    """B3: cross-package edges B along one chain (Section 4.2.3, 4.3.3).

    Entry points F_entry of the root are labelled when its graph is loaded
    (``analysis/entrypoints.py``).
    """
    return combine_chain(chain, graphs)


def b4_vulnerability_mapping(
    package: str,
    advisories: list[dict[str, Any]],
    mapping: list[MappingRow],
    graph: PackageGraph,
) -> list[dict[str, Any]]:
    """B4: map advisories to vulnerable functions and locate each one (4.2.4, 4.3.4)."""
    candidates = match_mapping(package, advisories, mapping)
    if not candidates:
        return []
    function_index = {"modules": graph.modules_payload, "functions": graph.functions_payload}
    return locate_functions(package, graph.repo_root, function_index, candidates)


# ---------------------------------------------------------------------------
# Analyses
# ---------------------------------------------------------------------------


def a1_dependency_exposure(
    dependency_graph: dict[str, Any], component_key: str, max_chains: int
) -> list[list[str]]:
    """A1: dependency paths over D from the root to an affected component."""
    return dependency_chains(dependency_graph, component_key, max_chains)


def a2_static_reachability(
    combined: CombinedChain,
    root: str,
    graphs: dict[str, PackageGraph],
    component: str,
    function: dict[str, Any],
) -> dict[str, Any]:
    """A2: strict path from a root endpoint to one located vulnerable function."""
    target_graph = graphs[component]
    if not function.get("confirmed"):
        return {"trace_status": NOT_LOCATED, "path_found": False}
    actual = resolve_in_graph(
        str(function["canonical_name"]),
        target_graph.functions,
        target_graph.callable_normalized_index,
    )
    if not actual:
        return {"trace_status": NOT_IN_CALL_GRAPH, "path_found": False}
    targets = [
        (component, candidate)
        for candidate in runtime_call_targets(
            actual, target_graph.function_kinds, target_graph.functions, target_graph.class_bases
        )
    ]
    trace = trace_to_entry(combined, root, graphs, targets, target_graph)
    trace["target_function"] = actual
    return trace


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


def run(config: PipelineConfig) -> dict[str, Any]:
    project = config.project.resolve()
    output = config.output.resolve()
    if not project.is_dir():
        raise FileNotFoundError(f"project directory not found: {project}")
    if output == project or project in output.parents:
        raise ValueError("the output directory must not be inside the analysed project")
    if config.source_scope not in {"chains", "all"}:
        raise ValueError("source_scope must be 'chains' or 'all'")
    output.mkdir(parents=True, exist_ok=True)
    root = config.project_name or project.name
    cutoff = config.cutoff or utc_now()
    warnings: list[str] = []
    mapping = load_mapping(config.vulnerable_functions)
    print_step(f"loaded {len(mapping)} vulnerability -> function mapping rows")
    graph = EvidenceGraph()

    # B1 Dependency Resolution.
    dependency_graph = b1_dependency_resolution(project, output, config, cutoff)
    component_ids = graph.add_dependency_graph(root, dependency_graph)
    nodes = {node["id"]: node for node in dependency_graph["nodes"]}
    print_step(
        f"B1: {len(nodes)} components, {len(dependency_graph['edges'])} dependency edges"
    )

    # Advisories per resolved component version (OSV); needed to select chains.
    advisory_payload = map_vulnerabilities(dependency_graph, output / "dependencies", config.cache_dir)
    warnings.extend(advisory_payload.get("warnings", []))
    vulnerable = []
    for item in advisory_payload["vulnerable_dependencies"]:
        component = component_id(item["package"], item["version"])
        chains = a1_dependency_exposure(
            dependency_graph, item["normalized_name"], config.max_chains_per_dependency
        )
        vulnerable.append(
            {
                "component": component,
                "package": item["package"],
                "version": item["version"],
                "advisories": item["vulnerabilities"],
                "chains": [
                    [root] + [component_id(nodes[n]["name"], nodes[n]["version"]) for n in chain]
                    for chain in chains
                ],
            }
        )

    # B2 Source Analysis.
    options = config.callgraph
    pypi = PyPIClient(cache_dir=config.cache_dir / "pypi_json", refresh_cache=config.refresh_cache)
    graphs: dict[str, PackageGraph] = {}
    bundles: dict[str, dict[str, Any]] = {}
    status_by_component: dict[str, dict[str, Any]] = {}
    root_status, root_graph, root_bundle = b2_source_analysis(
        root,
        output / "callgraphs" / safe_name(root),
        options,
        source_root=project,
        local_prefixes=config.local_prefixes,
    )
    status_by_component[root] = root_status
    if root_graph is None or root_bundle is None:
        raise RuntimeError("source analysis of the root project failed")
    graphs[root], bundles[root] = root_graph, root_bundle
    if config.source_scope == "all":
        needed = sorted(component_id(node["name"], node["version"]) for node in nodes.values())
    else:
        needed = sorted({c for item in vulnerable for chain in item["chains"] for c in chain[1:]})
    for component in needed:
        status, package_graph, bundle = b2_source_analysis(
            component,
            output / "callgraphs" / safe_name(component),
            options,
            source_dir=output / "sources" / safe_name(component),
            pypi=pypi,
            cache_dir=config.cache_dir,
        )
        status_by_component[component] = status
        if package_graph is not None and bundle is not None:
            graphs[component], bundles[component] = package_graph, bundle
    for component, status in status_by_component.items():
        artifact = status.get("artifact")
        graph.set_component_attributes(
            component,
            status=status["status"],
            artifact=artifact,
            pycg_fallback=status.get("pycg_used_fallback"),
            codeql_status=status.get("codeql_status"),
        )
        if component in graphs:
            graph.add_package_graph(component, graphs[component])
    entries = graphs[root].entries
    print_step(
        f"B2: {len(graphs)} package graphs; entry points of the root: {summarize_entries(entries)}"
    )

    # B3 Cross-Component Resolution, one chain subgraph per selected chain.
    combined: dict[tuple[str, ...], CombinedChain] = {}
    for item in vulnerable:
        for chain in item["chains"]:
            key = tuple(chain)
            if key in combined or any(component not in graphs for component in chain):
                continue
            combined[key] = b3_cross_component_resolution(chain, graphs)
            graph.add_cross_package_edges(combined[key].bridges.values(), chain)
    print_step(
        f"B3: {len(combined)} chain subgraphs, "
        f"{sum(len(c.bridges) for c in combined.values())} cross-package edges"
    )

    # B4 Vulnerability Mapping.
    for item in vulnerable:
        for record in item["advisories"]:
            graph.add_advisory(record, item["component"])
        component = item["component"]
        item["located_functions"] = (
            b4_vulnerability_mapping(item["package"], item["advisories"], mapping, graphs[component])
            if component in graphs
            else []
        )
        for located in item["located_functions"]:
            graph.add_vulnerable_function(located["osv_id"], component, located)
    print_step(
        f"B4: {len(graph.nodes['U'])} advisories, {len(graph.edges['R_UF'])} located vulnerable functions"
    )
    problems = graph.check_consistency()
    write_json(output / "graph.json", graph.to_json())

    # A1 Dependency exposure and A2 Static reachability.
    exposure = []
    findings = []
    for item in vulnerable:
        component = item["component"]
        for record in item["advisories"]:
            exposure.append(
                {
                    "advisory": record.get("id"),
                    "aliases": record.get("aliases") or [],
                    "component": component,
                    "exposed": bool(item["chains"]),
                    "dependency_paths": item["chains"],
                }
            )
        for chain in item["chains"]:
            missing = [c for c in chain if c not in graphs]
            for function in item["located_functions"]:
                if missing:
                    trace = {"trace_status": "chain_component_unavailable", "missing": missing, "path_found": False}
                else:
                    trace = a2_static_reachability(combined[tuple(chain)], root, graphs, component, function)
                findings.append(finding_row(function, component, chain, trace))

    summary = summarize(findings, vulnerable, exposure, dependency_graph, entries, graph)
    report = {
        "schema_version": 2,
        "generated_at": utc_now(),
        "tool": {"name": "graph_analysis", "version": __version__},
        "configuration": {
            "root": root,
            "cutoff": cutoff,
            "include_dev": config.include_dev,
            "include_extras": config.include_extras,
            "max_dependency_depth": config.max_dependency_depth,
            "max_chains_per_dependency": config.max_chains_per_dependency,
            "source_scope": config.source_scope,
            "vulnerable_functions_file": config.vulnerable_functions.name,
            "mapping_rows": len(mapping),
            "callgraph": asdict(config.callgraph),
        },
        "summary": summary,
        "graph": {"file": "graph.json", "counts": graph.to_json()["counts"], "consistency_problems": problems},
        "root": {
            "component": root,
            "local_prefixes": root_bundle.get("local_prefixes", []),
            "diagnostics": graph_diagnostics(graphs[root]),
            "codeql_alerts": len(root_bundle.get("alerts", [])),
            "entry_points": sorted(entries.values(), key=lambda e: (e["kind"], e["qname"])),
        },
        "components": {
            component: public_status(status) for component, status in sorted(status_by_component.items())
        },
        "dependency_exposure": exposure,
        "findings": findings,
        "warnings": warnings,
        "interpretation": (
            "A strict path is static evidence (Level 3) that the root can reach the "
            "vulnerable function. A missing path is not proof of unreachability: dynamic "
            "dispatch, reflection, callbacks and incomplete extraction can hide edges, and "
            "absence holds only for the analysed chains."
        ),
    }
    write_json(output / "report.json", report)
    write_findings_csv(output / "vulnerable_paths.csv", findings)
    bridges = {
        (bridge["source"], bridge["target"]): bridge
        for chain in combined.values()
        for bridge in chain.bridges.values()
    }
    viewer = build_combined_graph(root, bundles, bridges, findings)
    write_json(output / "combined_graph.json", viewer)
    render_html(viewer, output, TEMPLATE)
    print_step(
        f"done: {summary['findings_with_path']} of {summary['findings']} vulnerable-function "
        f"findings have a strict path; see {output / 'report.json'}"
    )
    return report


def dependency_chains(graph: dict[str, Any], target: str, limit: int) -> list[list[str]]:
    """Shortest-first simple dependency paths from the root to ``target``."""
    children: dict[str, list[str]] = {}
    for edge in graph["edges"]:
        children.setdefault(edge["from"], [])
        if edge["to"] not in children[edge["from"]]:
            children[edge["from"]].append(edge["to"])
    chains: list[list[str]] = []
    queue: deque[list[str]] = deque([[PROJECT_NODE]])
    while queue and len(chains) < limit:
        path = queue.popleft()
        for child in sorted(children.get(path[-1], [])):
            if child in path:
                continue
            if child == target:
                chains.append(path[1:] + [child])
                if len(chains) >= limit:
                    break
            else:
                queue.append(path + [child])
    return chains


def finding_row(
    function: dict[str, Any], component: str, chain: list[str], trace: dict[str, Any]
) -> dict[str, Any]:
    return {
        "cve": function["cve"],
        "advisory": function["osv_id"],
        "vulnerable_component": component,
        "mapped_function": function["function"],
        "located": bool(function.get("confirmed")),
        "resolution_status": function.get("resolution_status"),
        "canonical_function": function.get("canonical_name") or "",
        "source_file": function.get("source_file") or "",
        "start_line": function.get("start_line") or "",
        "dependency_chain": chain,
        "trace_status": trace["trace_status"],
        "path_found": bool(trace.get("path_found")),
        "endpoint_tier": trace.get("endpoint_tier", ""),
        "entry_point": trace.get("entry_point"),
        "all_edges_from_pycg": bool(trace.get("all_edges_from_pycg")),
        "path": trace.get("path", []),
        "edges": trace.get("edges", []),
        "path_edge_count": trace.get("path_edge_count", 0),
        "cross_package_edge_count": trace.get("cross_package_edge_count", 0),
    }


def summarize(
    findings: list[dict[str, Any]],
    vulnerable: list[dict[str, Any]],
    exposure: list[dict[str, Any]],
    dependency_graph: dict[str, Any],
    entries: dict[str, Any],
    graph: EvidenceGraph,
) -> dict[str, Any]:
    reachable = [row for row in findings if row["path_found"]]
    status_counts: dict[str, int] = {}
    for row in findings:
        status_counts[row["trace_status"]] = status_counts.get(row["trace_status"], 0) + 1
    return {
        "entry_points": len(entries),
        "components": len(dependency_graph["nodes"]),
        "vulnerable_components": len(vulnerable),
        "exposed_advisories": sum(row["exposed"] for row in exposure),
        "vulnerable_function_records": len(graph.edges["R_UF"]),
        "findings": len(findings),
        "findings_located": sum(row["located"] for row in findings),
        "findings_with_path": len(reachable),
        "findings_with_path_from_declared_entry_point": sum(
            row["endpoint_tier"] == "declared_entry_point" for row in reachable
        ),
        "findings_with_pycg_only_path": sum(row["all_edges_from_pycg"] for row in reachable),
        "reachable_cves": sorted({row["cve"] for row in reachable}),
        "trace_status_counts": dict(sorted(status_counts.items())),
    }


def build_combined_graph(
    root: str,
    bundles: dict[str, dict[str, Any]],
    bridges: dict[tuple[str, str], dict[str, Any]],
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Graph for the HTML view: merged call graphs, B edges, CVE and path nodes."""
    ordered = [bundles[root]] + [b for c, b in sorted(bundles.items()) if c != root]
    merged = merge_bundles(root, ordered)
    by_id = {node["id"]: node for node in merged["nodes"]}
    edges_by_pair = {(edge["source"], edge["target"]): edge for edge in merged["edges"]}
    for bridge in bridges.values():
        source = "function:" + bridge["source"].split("::", 1)[1]
        target = "function:" + bridge["target"].split("::", 1)[1]
        if source not in by_id or target not in by_id:
            continue
        edge = edges_by_pair.get((source, target))
        if edge is None:
            edge = {"source": source, "target": target}
            merged["edges"].append(edge)
            edges_by_pair[(source, target)] = edge
        edge["kind"] = "cross_package"
    cves_by_function: dict[str, set[str]] = {}
    path_nodes: set[str] = set()
    for row in findings:
        if row["located"] and row["canonical_function"]:
            cves_by_function.setdefault(row["canonical_function"], set()).add(row["cve"])
        if row["path_found"]:
            path_nodes.update(step["qname"] for step in row["path"])
    for qname in path_nodes:
        node = by_id.get(f"function:{qname}")
        if node:
            node["status"] = "path"
    for qname, cves in cves_by_function.items():
        node = by_id.get(f"function:{qname}")
        if node:
            node["status"] = "cve"
            node["cves"] = sorted(cves)
    priority = {"cve": 4, "path": 3, "red": 2, "yellow": 1, "normal": 0}
    for node in merged["nodes"]:
        module = by_id.get(node.get("module", ""))
        if module and priority.get(node["status"], 0) > priority.get(module["status"], 0):
            module["status"] = node["status"]
    merged["generated_at"] = utc_now()
    merged["stats"].update(
        {
            "edge_count": len(merged["edges"]),
            "cross_package_edge_count": sum(e.get("kind") == "cross_package" for e in merged["edges"]),
            "cve_count": sum(n["status"] == "cve" for n in merged["nodes"]),
            "path_count": sum(n["status"] == "path" for n in merged["nodes"]),
        }
    )
    return merged


FINDING_FIELDS = [
    "cve",
    "advisory",
    "vulnerable_component",
    "mapped_function",
    "located",
    "canonical_function",
    "source_file",
    "start_line",
    "dependency_chain",
    "trace_status",
    "path_found",
    "endpoint_tier",
    "entry_point",
    "all_edges_from_pycg",
    "path",
    "path_edge_count",
    "cross_package_edge_count",
]


def write_findings_csv(path: Path, findings: list[dict[str, Any]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FINDING_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for row in findings:
            writer.writerow(
                {
                    **row,
                    "dependency_chain": " -> ".join(row["dependency_chain"]),
                    "entry_point": (row["entry_point"] or {}).get("qname", ""),
                    "path": " -> ".join(step["node"] for step in row["path"]),
                }
            )


def error_summary(exc: BaseException, limit: int = 200) -> str:
    """Error type and message without local file-system paths."""
    message = re.sub(r"(/[^\s'\",)]+)+", "<path>", str(exc))
    return f"{type(exc).__name__}: {message[:limit]}"


def public_status(status: dict[str, Any]) -> dict[str, Any]:
    """Component status without local absolute paths."""
    return {key: value for key, value in status.items() if key != "source_root"}


def component_id(package: str, version: str) -> str:
    return f"{package}@{version}"


def safe_name(component: str) -> str:
    return component.replace("/", "_").replace("@", "__")


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


__all__ = [
    "PipelineConfig",
    "run",
    "b1_dependency_resolution",
    "b2_source_analysis",
    "b3_cross_component_resolution",
    "b4_vulnerability_mapping",
    "a1_dependency_exposure",
    "a2_static_reachability",
    "dependency_chains",
]
