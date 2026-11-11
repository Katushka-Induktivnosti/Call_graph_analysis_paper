from __future__ import annotations

from collections import deque
from pathlib import Path
from typing import Any

from .utils import is_under_prefix, read_json, write_json


def build_project_bundle(
    *,
    project_id: str,
    repo_root: Path,
    local_prefixes: list[str],
    function_index: dict[str, Any],
    pycg_graph: dict[str, list[str]],
    alerts: list[dict[str, Any]],
    pycg_metadata: dict[str, Any],
    codeql_metadata: dict[str, Any],
) -> dict[str, Any]:
    modules = function_index.get("modules", {})
    functions = function_index.get("functions", {})
    edge_metadata = {
        (str(item.get("source") or ""), str(item.get("target") or "")): item
        for item in pycg_metadata.get("_edge_metadata", [])
    }
    edges = []
    for source, targets in pycg_graph.items():
        if not isinstance(source, str):
            continue
        for target in targets:
            if isinstance(target, str) and source != target:
                metadata = edge_metadata.get((source, target), {})
                edges.append(
                    {
                        "source": source,
                        "target": target,
                        "kind": str(metadata.get("kind") or "call"),
                        "provenance": str(metadata.get("provenance") or "pycg"),
                    }
                )
    return {
        "schema_version": 2,
        "project_id": project_id,
        "repo_root": str(repo_root.resolve()),
        "local_prefixes": local_prefixes,
        "modules": modules,
        "functions": functions,
        "edges": sorted(edges, key=lambda edge: (edge["source"], edge["target"])),
        "alerts": alerts,
        "tool_metadata": {
            "pycg": {
                key: value
                for key, value in pycg_metadata.items()
                if not key.startswith("_")
            },
            "codeql": codeql_metadata,
        },
    }


def load_bundle_from_output(path: Path) -> dict[str, Any]:
    candidate = path / "graph_bundle.json" if path.is_dir() else path
    return read_json(candidate)


def merge_bundles(primary_project_id: str, bundles: list[dict[str, Any]]) -> dict[str, Any]:
    function_records: dict[str, dict[str, Any]] = {}
    module_records: dict[str, dict[str, Any]] = {}
    edges: set[tuple[str, str]] = set()
    alerts_by_target: dict[str, list[dict[str, Any]]] = {}
    local_prefixes_by_project: dict[str, list[str]] = {}

    for bundle in bundles:
        project_id = bundle["project_id"]
        local_prefixes_by_project[project_id] = bundle.get("local_prefixes", [])
        for module_name, module in bundle.get("modules", {}).items():
            rec = module_records.setdefault(
                module_name,
                {
                    "qname": module_name,
                    "label": module_name.split(".")[-1] or module_name,
                    "files": [],
                    "projects": [],
                    "functions": set(),
                },
            )
            if module.get("file") and module["file"] not in rec["files"]:
                rec["files"].append(module["file"])
            if project_id not in rec["projects"]:
                rec["projects"].append(project_id)
        for qname, fn in bundle.get("functions", {}).items():
            module_name = fn.get("module") or _module_for_function(qname)
            rec = function_records.setdefault(
                qname,
                {
                    "qname": qname,
                    "label": qname.split(".")[-1],
                    "module": module_name,
                    "files": [],
                    "projects": [],
                    "start_line": fn.get("start_line"),
                    "end_line": fn.get("end_line"),
                    "node_type": fn.get("node_type", "function"),
                },
            )
            if fn.get("file") and fn["file"] not in rec["files"]:
                rec["files"].append(fn["file"])
            if project_id not in rec["projects"]:
                rec["projects"].append(project_id)
            module_records.setdefault(
                module_name,
                {
                    "qname": module_name,
                    "label": module_name.split(".")[-1] or module_name,
                    "files": [],
                    "projects": [],
                    "functions": set(),
                },
            )["functions"].add(qname)
        for edge in bundle.get("edges", []):
            source = edge.get("source")
            target = edge.get("target")
            if source and target and source != target:
                edges.add((source, target))
                _ensure_endpoint(source, function_records, module_records)
                _ensure_endpoint(target, function_records, module_records)
        for alert in bundle.get("alerts", []):
            target = alert.get("target")
            if target:
                alerts_by_target.setdefault(target, []).append(alert)
                if alert.get("target_type") == "function":
                    _ensure_endpoint(target, function_records, module_records)
                else:
                    module_records.setdefault(
                        target,
                        {
                            "qname": target,
                            "label": target.split(".")[-1] or target,
                            "files": [],
                            "projects": [project_id],
                            "functions": set(),
                        },
                    )

    red_functions = {target for target, alerts in alerts_by_target.items() if target in function_records and alerts}
    direct_red_modules = {target for target, alerts in alerts_by_target.items() if target in module_records and alerts}
    module_children = {module_name: sorted(module.get("functions", set())) for module_name, module in module_records.items()}
    red_modules = direct_red_modules | {
        module_name for module_name, child_functions in module_children.items() if any(qname in red_functions for qname in child_functions)
    }

    graph_edges = []
    for source, target in sorted(edges):
        source_id = _node_id("function" if source in function_records else "module", source)
        target_id = _node_id("function" if target in function_records else "module", target)
        graph_edges.append({"source": source_id, "target": target_id, "kind": "call"})

    red_node_ids = {_node_id("function", qname) for qname in red_functions} | {_node_id("module", qname) for qname in red_modules}
    edge_pairs = {(edge["source"], edge["target"]) for edge in graph_edges}
    yellow_node_ids = _recursive_callers(red_node_ids, edge_pairs) - red_node_ids
    yellow_functions = {node_id.removeprefix("function:") for node_id in yellow_node_ids if node_id.startswith("function:")}

    nodes: dict[str, dict[str, Any]] = {}
    for module_name, module in module_records.items():
        child_functions = module_children[module_name]
        node_id = _node_id("module", module_name)
        status = (
            "red"
            if module_name in red_modules
            else "yellow"
            if node_id in yellow_node_ids or any(qname in yellow_functions for qname in child_functions)
            else "normal"
        )
        scope = _scope_for_name(module_name, primary_project_id, local_prefixes_by_project, module.get("projects", []))
        nodes[node_id] = {
            "id": node_id,
            "qname": module_name,
            "label": module["label"],
            "kind": "module",
            "scope": scope,
            "shape": "square" if scope == "local" else "circle",
            "status": status,
            "size": 34,
            "projects": sorted(module.get("projects", [])),
            "files": sorted(module.get("files", [])),
            "children": [_node_id("function", qname) for qname in child_functions],
            "alerts": alerts_by_target.get(module_name, []),
        }

    for qname, fn in function_records.items():
        node_id = _node_id("function", qname)
        status = "red" if qname in red_functions else "yellow" if node_id in yellow_node_ids else "normal"
        scope = _scope_for_name(qname, primary_project_id, local_prefixes_by_project, fn.get("projects", []))
        nodes[node_id] = {
            "id": node_id,
            "qname": qname,
            "label": fn["label"],
            "kind": "function",
            "scope": scope,
            "shape": "square" if scope == "local" else "circle",
            "status": status,
            "size": 13,
            "module": _node_id("module", fn["module"]),
            "projects": sorted(fn.get("projects", [])),
            "files": sorted(fn.get("files", [])),
            "start_line": fn.get("start_line"),
            "end_line": fn.get("end_line"),
            "node_type": fn.get("node_type", "function"),
            "alerts": alerts_by_target.get(qname, []),
        }

    graph_edges = [edge for edge in graph_edges if edge["source"] in nodes and edge["target"] in nodes]

    return {
        "schema_version": 1,
        "primary_project_id": primary_project_id,
        "nodes": list(nodes.values()),
        "edges": graph_edges,
        "stats": {
            "node_count": len(nodes),
            "edge_count": len(graph_edges),
            "red_count": sum(1 for node in nodes.values() if node["status"] == "red"),
            "yellow_count": sum(1 for node in nodes.values() if node["status"] == "yellow"),
        },
    }


def write_bundle_and_merged(output_folder: Path, bundle: dict[str, Any], merged: dict[str, Any]) -> None:
    write_json(output_folder / "graph_bundle.json", bundle)
    write_json(output_folder / "merged_graph.json", merged)


def _recursive_callers(red_functions: set[str], edges: set[tuple[str, str]]) -> set[str]:
    reverse: dict[str, set[str]] = {}
    for source, target in edges:
        reverse.setdefault(target, set()).add(source)
    seen: set[str] = set()
    queue = deque(red_functions)
    while queue:
        callee = queue.popleft()
        for caller in reverse.get(callee, set()):
            if caller not in seen:
                seen.add(caller)
                queue.append(caller)
    return seen


def _scope_for_name(
    name: str,
    primary_project_id: str,
    prefixes_by_project: dict[str, list[str]],
    projects: list[str],
) -> str:
    primary_prefixes = prefixes_by_project.get(primary_project_id, [])
    if primary_project_id in projects or is_under_prefix(name, primary_prefixes):
        return "local"
    return "external"


def _ensure_endpoint(
    qname: str,
    functions: dict[str, dict[str, Any]],
    modules: dict[str, dict[str, Any]],
) -> None:
    if qname in functions or qname in modules:
        return
    module_name = _module_for_function(qname)
    functions[qname] = {
        "qname": qname,
        "label": qname.split(".")[-1],
        "module": module_name,
        "files": [],
        "projects": [],
        "start_line": None,
        "end_line": None,
        "node_type": "external",
    }
    modules.setdefault(
        module_name,
        {"qname": module_name, "label": module_name.split(".")[-1] or module_name, "files": [], "projects": [], "functions": set()},
    )["functions"].add(qname)


def _module_for_function(qname: str) -> str:
    parts = qname.split(".")
    if len(parts) <= 1:
        return qname
    return ".".join(parts[:-1])


def _node_id(kind: str, qname: str) -> str:
    return f"{kind}:{qname}"
