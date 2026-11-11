"""Combine per-package call graphs along a dependency chain and trace paths.

Each package keeps its own call graph. Cross-package edges are added only when
an unresolved external call in package *i* resolves, uniquely and strictly, to
a declaration in a later package of the same dependency chain (exact
qualified name, public re-export, controlled source-layout normalisation, or a
unique three-part qualified suffix). Calls to classes also add their
``__new__``/``__init__`` constructor edges.
"""
from __future__ import annotations

import ast
import sys
from collections import Counter, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .entrypoints import ROOT_ENTRY_KIND, discover_explicit_entries
from .names import (
    is_production_name,
    name_variants,
    node_id,
    normalized_name,
    resolve_in_graph,
)


STRICT_TRAVERSABLE_EDGE_KINDS = {
    "call",
    "receiver_call",
    "constructor_call",
    "resolved_alias_call",
    "callable_dispatch",
    "dispatch_table_call",
    "factory_return_dispatch",
    "super_dispatch",
    "protocol_dispatch",
}


def read_json(path: Path) -> Any:
    import json

    return json.loads(path.read_text(encoding="utf-8"))


@dataclass
class PackageGraph:
    project_id: str
    repo_root: Path
    graph_bundle: Path
    declarations: set[str]
    functions: set[str]
    modules: set[str]
    normalized_index: dict[str, tuple[str, ...]]
    callable_normalized_index: dict[str, tuple[str, ...]]
    public_aliases: dict[str, tuple[str, ...]]
    import_roots: set[str]
    function_files: dict[str, str]
    function_kinds: dict[str, str]
    class_bases: dict[str, tuple[str, ...]]
    functions_payload: dict[str, Any]
    modules_payload: dict[str, Any]
    internal_edges: list[tuple[str, str]]
    external_edges: list[tuple[str, str]]
    entries: dict[str, dict[str, str]]
    root_entries: set[str]
    typed_edges: list[dict[str, Any]]
    edge_provenance: dict[tuple[str, str], set[str]]
    external_provenance: dict[tuple[str, str], set[str]]
    raw_edge_count: int
    diagnostics: dict[str, int]
    unresolved_receiver_targets: set[str]


def load_package_graph(component: str, graph_bundle: Path) -> PackageGraph:
    bundle = read_json(graph_bundle)
    functions_payload = bundle.get("functions", {})
    modules_payload = bundle.get("modules", {})
    functions = {sys.intern(str(value)) for value in functions_payload}
    modules = {sys.intern(str(value)) for value in modules_payload}
    declarations = functions | modules
    normalized: dict[str, set[str]] = {}
    for name in declarations:
        for variant in name_variants(name):
            normalized.setdefault(variant, set()).add(name)
    normalized_index = {
        key: tuple(sorted(values)) for key, values in normalized.items()
    }
    callable_normalized: dict[str, set[str]] = {}
    for name in functions:
        for variant in name_variants(name):
            callable_normalized.setdefault(variant, set()).add(name)
    callable_normalized_index = {
        key: tuple(sorted(values)) for key, values in callable_normalized.items()
    }
    function_files = {
        str(name): str(item.get("file") or "")
        for name, item in functions_payload.items()
    }
    function_kinds = {
        str(name): str(item.get("node_type") or "function")
        for name, item in functions_payload.items()
    }
    repo_root = Path(str(bundle.get("repo_root") or ""))
    indexed_source_records = dict(modules_payload) | dict(functions_payload)
    import_aliases = collect_import_aliases(repo_root, indexed_source_records)
    public_aliases = collect_public_aliases(
        repo_root,
        indexed_source_records,
        functions,
        callable_normalized_index,
    )

    internal_edges: set[tuple[str, str]] = set()
    external_edges: set[tuple[str, str]] = set()
    excluded_non_production_edges = 0
    excluded_non_traversable_edges = 0
    unresolved_receiver_targets: set[str] = set()
    typed_edges: list[dict[str, Any]] = []
    edge_provenance: dict[tuple[str, str], set[str]] = {}
    external_provenance: dict[tuple[str, str], set[str]] = {}
    class_bases_index = {
        str(name): tuple(str(value) for value in item.get("bases", []))
        for name, item in functions_payload.items()
        if item.get("node_type") == "class"
    }
    for edge in bundle.get("edges", []):
        edge_kind = str(edge.get("kind") or "call")
        provenance = str(edge.get("provenance") or "pycg")
        traversable = edge_kind in STRICT_TRAVERSABLE_EDGE_KINDS
        if not traversable:
            excluded_non_traversable_edges += 1
        raw_source = str(edge.get("source") or "")
        raw_target = str(edge.get("target") or "")
        if not raw_source or not raw_target or raw_source == raw_target:
            continue
        source = resolve_in_graph(raw_source, declarations, normalized_index)
        if not source:
            continue
        source_file = function_files.get(source, "")
        source_production = is_production_name(source, source_file)
        target = resolve_in_graph(
            raw_target, functions, callable_normalized_index
        )
        expanded_target = raw_target
        if not target:
            expanded_target = expand_import_target(
                raw_target, import_aliases.get(source_file, {})
            )
            target = resolve_in_graph(
                expanded_target, functions, callable_normalized_index
            )
        if not target:
            alias_targets = public_aliases.get(normalized_name(raw_target), ())
            if len(alias_targets) == 1:
                expanded_target = alias_targets[0]
                target = resolve_in_graph(
                    expanded_target, functions, callable_normalized_index
                )
        if target:
            for runtime_target in runtime_call_targets(
                target, function_kinds, functions, class_bases_index
            ):
                if source == runtime_target:
                    continue
                target_production = is_production_name(
                    runtime_target, function_files.get(runtime_target, "")
                )
                typed_edges.append(
                    {
                        "source": source,
                        "target": runtime_target,
                        "kind": edge_kind,
                        "provenance": provenance,
                        "resolved": True,
                    }
                )
                if not traversable:
                    continue
                if not (source_production and target_production):
                    excluded_non_production_edges += 1
                    continue
                pair = (sys.intern(source), sys.intern(runtime_target))
                internal_edges.add(pair)
                edge_provenance.setdefault(pair, set()).add(provenance)
        else:
            typed_edges.append(
                {
                    "source": source,
                    "target": expanded_target,
                    "kind": edge_kind,
                    "provenance": provenance,
                    "resolved": False,
                }
            )
            if not traversable:
                continue
            if not source_production:
                excluded_non_production_edges += 1
                continue
            if expanded_target.startswith(("self.", "cls.")):
                unresolved_receiver_targets.add(expanded_target)
            pair = (sys.intern(source), sys.intern(expanded_target))
            external_edges.add(pair)
            external_provenance.setdefault(pair, set()).add(provenance)

    entries = discover_explicit_entries(
        repo_root,
        functions,
        modules,
        normalized_index,
        function_files,
    )
    # Call-graph roots (Section 4.5.2): production functions of the component
    # that no other function calls.
    incoming = Counter(target for _source, target in internal_edges)
    root_entries = {
        name
        for name in functions
        if function_kinds.get(name) != "class"
        and incoming[name] == 0
        and is_production_name(name, function_files.get(name, ""))
    }
    for name in root_entries:
        entries.setdefault(
            name,
            {
                "qname": name,
                "kind": ROOT_ENTRY_KIND,
                "declared_value": "",
                "confidence": "fallback",
            },
        )

    return PackageGraph(
        project_id=component,
        repo_root=repo_root,
        graph_bundle=graph_bundle,
        declarations=declarations,
        functions=functions,
        modules=modules,
        normalized_index=normalized_index,
        callable_normalized_index=callable_normalized_index,
        public_aliases=public_aliases,
        import_roots={normalized_name(name).split(".", 1)[0] for name in declarations},
        function_files=function_files,
        function_kinds=function_kinds,
        class_bases={
            str(name): tuple(str(value) for value in item.get("bases", []))
            for name, item in functions_payload.items()
            if item.get("node_type") == "class"
        },
        functions_payload=functions_payload,
        modules_payload=modules_payload,
        internal_edges=sorted(internal_edges),
        external_edges=sorted(external_edges),
        entries=entries,
        root_entries=root_entries,
        typed_edges=typed_edges,
        edge_provenance=edge_provenance,
        external_provenance=external_provenance,
        raw_edge_count=len(bundle.get("edges", [])),
        diagnostics={
            "ast_added_edges": int(
                bundle.get("tool_metadata", {})
                .get("pycg", {})
                .get("ast_enrichment", {})
                .get("edge_count", 0)
            ),
            "resolved_receiver_calls": int(
                bundle.get("tool_metadata", {})
                .get("pycg", {})
                .get("ast_enrichment", {})
                .get("receiver_call_edges", 0)
            ),
            "unresolved_receiver_calls": int(
                bundle.get("tool_metadata", {})
                .get("pycg", {})
                .get("ast_enrichment", {})
                .get("unresolved_receiver_calls", 0)
            ),
            "excluded_non_production_edges": excluded_non_production_edges,
            "excluded_non_traversable_edges": excluded_non_traversable_edges,
        },
        unresolved_receiver_targets=unresolved_receiver_targets,
    )


def collect_import_aliases(
    repo_root: Path, functions_payload: dict[str, Any]
) -> dict[str, dict[str, str]]:
    """Collect conservative, file-local import aliases for external call targets."""
    file_modules: dict[str, str] = {}
    for item in functions_payload.values():
        file = str(item.get("file") or "")
        module = str(item.get("module") or "")
        if file and module:
            file_modules.setdefault(file, module)

    result: dict[str, dict[str, str]] = {}
    if not repo_root.is_dir():
        return result
    for file, module in file_modules.items():
        path = repo_root / file
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue
        candidates: dict[str, set[str]] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for item in node.names:
                    local = item.asname or item.name.split(".", 1)[0]
                    target = item.name if item.asname else local
                    candidates.setdefault(local, set()).add(target)
            elif isinstance(node, ast.ImportFrom):
                base = absolute_import_module(
                    module, file, node.module or "", node.level
                )
                for item in node.names:
                    if item.name == "*":
                        continue
                    local = item.asname or item.name
                    target = ".".join(part for part in (base, item.name) if part)
                    candidates.setdefault(local, set()).add(target)
        result[file] = {
            local: next(iter(targets))
            for local, targets in candidates.items()
            if len(targets) == 1
        }
    return result


def collect_public_aliases(
    repo_root: Path,
    functions_payload: dict[str, Any],
    callable_declarations: set[str],
    callable_normalized_index: dict[str, tuple[str, ...]],
) -> dict[str, tuple[str, ...]]:
    """Map imported public names (for example ``requests.get``) to declarations."""
    aliases_by_file = collect_import_aliases(repo_root, functions_payload)
    file_modules: dict[str, str] = {}
    for item in functions_payload.values():
        file = str(item.get("file") or "")
        module = str(item.get("module") or "")
        if file and module:
            file_modules.setdefault(file, module)

    raw: dict[str, set[str]] = {}
    for file, aliases in aliases_by_file.items():
        module = file_modules.get(file, "")
        if not module:
            continue
        for local, imported in aliases.items():
            raw.setdefault(f"{module}.{local}", set()).add(imported)

    result: dict[str, set[str]] = {}
    pending = raw
    for _ in range(8):
        changed = False
        for public, imported_names in pending.items():
            targets = result.setdefault(public, set())
            before = len(targets)
            for imported in imported_names:
                resolved = resolve_in_graph(
                    imported, callable_declarations, callable_normalized_index
                )
                if resolved:
                    targets.add(resolved)
                targets.update(result.get(imported, set()))
            changed |= len(targets) != before
        if not changed:
            break
    return {
        normalized_name(public): tuple(sorted(targets))
        for public, targets in result.items()
        if targets
    }


def absolute_import_module(
    current_module: str, source_file: str, imported_module: str, level: int
) -> str:
    if level <= 0:
        return imported_module
    package = (
        current_module
        if Path(source_file).name == "__init__.py"
        else current_module.rpartition(".")[0]
    )
    parts = [part for part in package.split(".") if part]
    ascend = max(0, level - 1)
    if ascend:
        parts = parts[:-ascend] if ascend < len(parts) else []
    if imported_module:
        parts.extend(imported_module.split("."))
    return ".".join(parts)


def expand_import_target(raw_target: str, aliases: dict[str, str]) -> str:
    head, separator, tail = raw_target.partition(".")
    replacement = aliases.get(head)
    if not replacement:
        return raw_target
    if raw_target == replacement or raw_target.startswith(replacement + "."):
        return raw_target
    return replacement + (separator + tail if separator else "")


def runtime_call_targets(
    target: str,
    function_kinds: dict[str, str],
    declarations: set[str],
    class_bases: dict[str, tuple[str, ...]] | None = None,
) -> tuple[str, ...]:
    """Materialize Python constructor calls hidden behind class declaration nodes."""
    targets = {target}
    if function_kinds.get(target) == "class":
        for method in ("__new__", "__init__"):
            candidate = resolve_inherited_method(
                target,
                method,
                declarations,
                class_bases or {},
            )
            if candidate:
                targets.add(candidate)
    return tuple(sorted(targets))


def resolve_inherited_method(
    class_name: str,
    method: str,
    declarations: set[str],
    class_bases: dict[str, tuple[str, ...]],
) -> str | None:
    queue = [(class_name, 0)]
    seen: set[str] = set()
    depth = 0
    candidates: set[str] = set()
    while queue:
        current, current_depth = queue.pop(0)
        if current_depth != depth and candidates:
            break
        depth = current_depth
        if current in seen:
            continue
        seen.add(current)
        candidate = f"{current}.{method}"
        if candidate in declarations:
            candidates.add(candidate)
        for base in class_bases.get(current, ()):
            resolved = resolve_class_name(base, class_bases)
            if resolved:
                queue.append((resolved, current_depth + 1))
    return next(iter(candidates)) if len(candidates) == 1 else None


def resolve_class_name(
    value: str, class_bases: dict[str, tuple[str, ...]]
) -> str | None:
    if value in class_bases:
        return value
    candidates = {
        name for name in class_bases if name == value or name.endswith("." + value)
    }
    return next(iter(candidates)) if len(candidates) == 1 else None


def add_edge(
    edges: set[tuple[tuple[str, str], tuple[str, str]]],
    reverse: dict[tuple[str, str], set[tuple[str, str]]],
    source: tuple[str, str],
    target: tuple[str, str],
) -> None:
    if source == target or (source, target) in edges:
        return
    edges.add((source, target))
    reverse.setdefault(target, set()).add(source)


def resolve_cross_package_targets(
    raw_target: str,
    *,
    source_component: str,
    source_index: int,
    declaration_index: dict[str, list[tuple[int, str, str]]],
    suffix_index: dict[str, list[tuple[int, str, str]]],
) -> tuple[tuple[str, str, str], ...]:
    candidates: set[tuple[int, str, str, str]] = set()
    raw_normalized = normalized_name(raw_target)
    for variant in name_variants(raw_target):
        for index, component, actual in declaration_index.get(variant, []):
            if component != source_component and index > source_index:
                method = (
                    "exact_qualified_name"
                    if variant == raw_normalized
                    else "source_layout_adjusted"
                )
                candidates.add((index, component, actual, method))
    if not candidates:
        parts = raw_normalized.split(".")
        if len(parts) >= 3:
            suffix = ".".join(parts[-3:])
            suffix_candidates = {
                (index, component, actual, "qualified_suffix")
                for index, component, actual in suffix_index.get(suffix, [])
                if component != source_component and index > source_index
            }
            identities = {(item[1], item[2]) for item in suffix_candidates}
            if len(identities) == 1:
                candidates = suffix_candidates
    if not candidates:
        return ()
    nearest = min(item[0] for item in candidates)
    nearest_candidates = sorted(item for item in candidates if item[0] == nearest)
    identities = {(item[1], item[2]) for item in nearest_candidates}
    if len(identities) != 1:
        return ()
    return tuple(
        (component, actual, method)
        for _index, component, actual, method in nearest_candidates
    )


def shortest_reverse_path(
    target: tuple[str, str],
    reverse_edges: dict[tuple[str, str], set[tuple[str, str]]],
    entries: set[tuple[str, str]],
) -> list[tuple[str, str]] | None:
    queue = deque([target])
    parent: dict[tuple[str, str], tuple[str, str] | None] = {target: None}
    while queue:
        node = queue.popleft()
        if node in entries:
            path = []
            cursor: tuple[str, str] | None = node
            while cursor is not None:
                path.append(cursor)
                cursor = parent[cursor]
            return list(reversed(path))
        for caller in sorted(reverse_edges.get(node, set())):
            if caller not in parent:
                parent[caller] = node
                queue.append(caller)
    return None


Node = tuple[str, str]

# Failure categories of Table 7 (call resolution and entry-point detection).
NO_PRODUCTION_ENTRY_POINT = "no_production_entry_point"
NO_CROSS_PACKAGE_EDGE = "no_cross_package_edge"
UNRESOLVED_RECEIVER = "unresolved_receiver"
INTERNAL_PATH_GAP = "internal_path_gap"


@dataclass
class CombinedChain:
    """Chain subgraph: K and K_X of the packages on one dependency chain plus B."""

    components: list[str]
    available: list[str]
    edges: set[tuple[Node, Node]] = field(default_factory=set)
    reverse_edges: dict[Node, set[Node]] = field(default_factory=dict)
    bridges: dict[tuple[str, str, str, str], dict[str, Any]] = field(default_factory=dict)
    unresolved_external_edges: int = 0


def combine_chain(components: list[str], package_graphs: dict[str, PackageGraph]) -> CombinedChain:
    """Cross-Component Resolution (B3) along one dependency chain.

    An external-call edge (f, x) of the package at position i is resolved to a
    declaration g in the nearest later package j > i whose name matches x. The
    edge (f, g) is added to B only if exactly one declaration matches.
    """
    available = [component for component in components if component in package_graphs]
    indices = {component: index for index, component in enumerate(components)}
    combined = CombinedChain(components=list(components), available=available)

    declaration_index: dict[str, list[tuple[int, str, str]]] = {}
    suffix_index: dict[str, list[tuple[int, str, str]]] = {}
    for component in available:
        graph = package_graphs[component]
        for actual in graph.functions:
            for variant in name_variants(actual):
                declaration_index.setdefault(variant, []).append(
                    (indices[component], component, actual)
                )
            parts = normalized_name(actual).split(".")
            if len(parts) >= 3:
                suffix_index.setdefault(".".join(parts[-3:]), []).append(
                    (indices[component], component, actual)
                )
        for public, actuals in graph.public_aliases.items():
            for variant in name_variants(public):
                for actual in actuals:
                    declaration_index.setdefault(variant, []).append(
                        (indices[component], component, actual)
                    )
                    if graph.function_kinds.get(actual) == "class":
                        prefix = actual + "."
                        for member in graph.functions:
                            if not member.startswith(prefix):
                                continue
                            public_member = public + member[len(actual) :]
                            for member_variant in name_variants(public_member):
                                declaration_index.setdefault(member_variant, []).append(
                                    (indices[component], component, member)
                                )

    for component in available:
        for source, target in package_graphs[component].internal_edges:
            add_edge(combined.edges, combined.reverse_edges, (component, source), (component, target))

    for component in available:
        graph = package_graphs[component]
        for source, raw_target in graph.external_edges:
            matches = resolve_cross_package_targets(
                raw_target,
                source_component=component,
                source_index=indices[component],
                declaration_index=declaration_index,
                suffix_index=suffix_index,
            )
            if not matches:
                combined.unresolved_external_edges += 1
                continue
            provenance = sorted(graph.external_provenance.get((source, raw_target), {"pycg"}))
            for target_component, target, method in matches:
                target_graph = package_graphs[target_component]
                for runtime_target in runtime_call_targets(
                    target,
                    target_graph.function_kinds,
                    target_graph.functions,
                    target_graph.class_bases,
                ):
                    if not is_production_name(
                        runtime_target, target_graph.function_files.get(runtime_target, "")
                    ):
                        continue
                    add_edge(
                        combined.edges,
                        combined.reverse_edges,
                        (component, source),
                        (target_component, runtime_target),
                    )
                    combined.bridges[(component, source, target_component, runtime_target)] = {
                        "source": node_id(component, source),
                        "target": node_id(target_component, runtime_target),
                        "source_component": component,
                        "target_component": target_component,
                        "raw_target": raw_target,
                        "resolution_method": (
                            method if runtime_target == target else f"{method}_constructor"
                        ),
                        "provenance": provenance,
                    }
    return combined


ENDPOINT_TIERS = (
    ("declared_entry_point", lambda entry: entry["kind"] != ROOT_ENTRY_KIND),
    ("callgraph_root", lambda entry: entry["kind"] == ROOT_ENTRY_KIND),
)


def edge_provenance(
    combined: CombinedChain,
    package_graphs: dict[str, PackageGraph],
    source: Node,
    target: Node,
) -> list[str]:
    if source[0] == target[0]:
        graph = package_graphs[source[0]]
        return sorted(graph.edge_provenance.get((source[1], target[1]), set()))
    bridge = combined.bridges.get((source[0], source[1], target[0], target[1]))
    return list(bridge["provenance"]) if bridge else []


def trace_to_entry(
    combined: CombinedChain,
    main_component: str,
    package_graphs: dict[str, PackageGraph],
    targets: list[Node],
    target_graph: PackageGraph | None,
) -> dict[str, Any]:
    """Static Reachability (A2): shortest strict path from p0 to a target.

    Endpoints are tried in three tiers and the search stops at the first tier
    that yields a path: (1) declared entry points F_entry, (2) call-graph roots,
    (3) any production function of p0 (Section 4.5.2).
    """
    main_graph = package_graphs[main_component]
    tiers: list[tuple[str, dict[Node, dict[str, str]]]] = []
    for tier_name, predicate in ENDPOINT_TIERS:
        nodes = {
            (main_component, qname): entry
            for qname, entry in main_graph.entries.items()
            if predicate(entry)
        }
        tiers.append((tier_name, nodes))
    tiers.append(
        (
            "local_function",
            {
                (main_component, qname): {
                    "qname": qname,
                    "kind": "local_function",
                    "declared_value": "",
                    "confidence": "fallback",
                }
                for qname in main_graph.functions
                if main_graph.function_kinds.get(qname) != "class"
                and is_production_name(qname, main_graph.function_files.get(qname, ""))
            },
        )
    )

    for tier_name, endpoints in tiers:
        if not endpoints:
            continue
        paths = [
            path
            for target in targets
            if (path := shortest_reverse_path(target, combined.reverse_edges, set(endpoints)))
        ]
        if not paths:
            continue
        reverse_path = min(paths, key=lambda path: (len(path), path))
        directed = list(reversed(reverse_path))
        steps = []
        for source, target in zip(directed, directed[1:]):
            steps.append(
                {
                    "source": node_id(*source),
                    "target": node_id(*target),
                    "type": "B" if source[0] != target[0] else "K",
                    "provenance": edge_provenance(combined, package_graphs, source, target),
                }
            )
        return {
            "path_found": True,
            "trace_status": "path_found",
            "endpoint_tier": tier_name,
            "entry_point": endpoints[directed[0]],
            "path": [
                {
                    "node": node_id(component, qname),
                    "component": component,
                    "qname": qname,
                }
                for component, qname in directed
            ],
            "edges": steps,
            "path_edge_count": len(directed) - 1,
            "cross_package_edge_count": sum(step["type"] == "B" for step in steps),
            "all_edges_from_pycg": all(
                any("pycg" in value for value in step["provenance"]) for step in steps
            ),
        }

    if not any(endpoints for _tier, endpoints in tiers):
        status = NO_PRODUCTION_ENTRY_POINT
    elif not combined.bridges:
        status = NO_CROSS_PACKAGE_EDGE
    elif target_graph is not None and any(
        unresolved.rsplit(".", 1)[-1] == qname.rsplit(".", 1)[-1]
        for unresolved in target_graph.unresolved_receiver_targets
        for _component, qname in targets
    ):
        status = UNRESOLVED_RECEIVER
    else:
        status = INTERNAL_PATH_GAP
    return {
        "path_found": False,
        "trace_status": status,
        "endpoint_tier": "",
        "entry_point": None,
        "path": [],
        "edges": [],
        "path_edge_count": 0,
        "cross_package_edge_count": 0,
        "all_edges_from_pycg": False,
    }


def graph_diagnostics(graph: PackageGraph) -> dict[str, Any]:
    return {
        "declarations": len(graph.declarations),
        "internal_edges": len(graph.internal_edges),
        "external_edges": len(graph.external_edges),
        "entry_points": len(graph.entries),
        **graph.diagnostics,
    }
