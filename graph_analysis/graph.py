"""The typed evidence graph G = (V, E) of Section 4.1 (Table 1).

Node types (disjoint):  C component, M module, L class, F function,
                        X external endpoint, U vulnerability.
Edge types (disjoint):  D dependency, O contains, K direct call,
                        K_X external call, B cross-package call, A decorator,
                        R_UC affects component, R_UF affects function.

Every element carries its provenance (the tool or rule that produced it) and,
where construction can fail, a status. The graph is the union of the graphs
of all analysed packages; analyses query chain subgraphs of it.
"""
from __future__ import annotations

from collections import Counter
from typing import Any, Iterable

from .analysis.combine import STRICT_TRAVERSABLE_EDGE_KINDS, PackageGraph
from .analysis.names import is_production_name

SCHEMA_VERSION = "1.0"
NODE_TYPES = ("C", "M", "L", "F", "X", "U")
EDGE_TYPES = ("D", "O", "K", "K_X", "B", "A", "R_UC", "R_UF")


def component_node(component: str) -> str:
    return f"C:{component}"


def member_node(kind: str, component: str, qname: str) -> str:
    return f"{kind}:{component}::{qname}"


class EvidenceGraph:
    def __init__(self) -> None:
        self.nodes: dict[str, dict[str, dict[str, Any]]] = {kind: {} for kind in NODE_TYPES}
        self.edges: dict[str, dict[tuple[str, str], dict[str, Any]]] = {kind: {} for kind in EDGE_TYPES}
        self.omitted: Counter[str] = Counter()

    # -- construction -----------------------------------------------------
    def add_node(self, node_set: str, node_id: str, **attributes: Any) -> str:
        node = self.nodes[node_set].setdefault(node_id, {"id": node_id})
        node.update({key: value for key, value in attributes.items() if value is not None})
        return node_id

    def add_edge(self, edge_set: str, source: str, target: str, **attributes: Any) -> None:
        edge = self.edges[edge_set].setdefault((source, target), {"source": source, "target": target})
        for key, value in attributes.items():
            if value is None:
                continue
            if key == "provenance" and "provenance" in edge and edge["provenance"] != value:
                edge["provenance"] = "+".join(sorted(set(edge["provenance"].split("+")) | set(str(value).split("+"))))
            else:
                edge[key] = value

    def node_kind(self, node_id: str) -> str | None:
        prefix = node_id.split(":", 1)[0]
        return prefix if prefix in self.nodes and node_id in self.nodes[prefix] else None

    # -- B1: dependency resolution ---------------------------------------
    def add_dependency_graph(self, root: str, dependency_graph: dict[str, Any]) -> dict[str, str]:
        """Add component nodes C and dependency edges D; return resolver id -> node id."""
        ids = {"__project__": self.add_node(
            "C",
            component_node(root),
            name=root,
            version=None,
            root=True,
            status=dependency_graph.get("root_status", []),
        )}
        for node in dependency_graph.get("nodes", []):
            component = f"{node['name']}@{node['version']}"
            ids[node["id"]] = self.add_node(
                "C",
                component_node(component),
                name=node["name"],
                version=node["version"],
                root=False,
                direct=node.get("direct", False),
                status=node.get("status", []),
            )
        for edge in dependency_graph.get("edges", []):
            if edge["from"] in ids and edge["to"] in ids:
                self.add_edge(
                    "D",
                    ids[edge["from"]],
                    ids[edge["to"]],
                    requirement=edge.get("requirement"),
                    source_type=edge.get("source_type"),
                    source_path=edge.get("source_path"),
                    depth=edge.get("depth"),
                    version_source=edge.get("version_source"),
                )
        return ids

    def set_component_attributes(self, component: str, **attributes: Any) -> None:
        node_id = component_node(component)
        node = self.nodes["C"].setdefault(node_id, {"id": node_id, "name": component, "status": []})
        status = attributes.pop("status", None)
        if status:
            node.setdefault("status", [])
            for item in status:
                if item not in node["status"]:
                    node["status"].append(item)
        node.update({key: value for key, value in attributes.items() if value is not None})

    # -- B2: source analysis ---------------------------------------------
    def add_package_graph(self, component: str, graph: PackageGraph) -> None:
        """Add M, L, F, X nodes and O, K, K_X, A edges of one package version."""
        c_id = component_node(component)
        self.nodes["C"].setdefault(c_id, {"id": c_id, "name": component, "status": []})
        for module, record in sorted(graph.modules_payload.items()):
            m_id = self.add_node(
                "M",
                member_node("M", component, module),
                component=component,
                qname=module,
                file=record.get("file"),
                role=record.get("role"),
                parse_status=record.get("parse_status", "failed" if record.get("parse_error") else "ok"),
            )
            self.add_edge("O", c_id, m_id)

        for qname, record in sorted(graph.functions_payload.items()):
            kind = "L" if record.get("node_type") == "class" else "F"
            entry = graph.entries.get(qname) if kind == "F" else None
            node = self.add_node(
                kind,
                member_node(kind, component, qname),
                component=component,
                qname=qname,
                node_type=record.get("node_type"),
                file=record.get("file"),
                start_line=record.get("start_line"),
                end_line=record.get("end_line"),
                production=is_production_name(qname, str(record.get("file") or "")),
                entry_point=entry,
            )
            owner_class = str(record.get("owner_class") or "")
            module = str(record.get("module") or "")
            if owner_class and owner_class in graph.functions_payload:
                self.add_edge("O", member_node("L", component, owner_class), node)
            elif module:
                self.add_edge("O", member_node("M", component, module), node)

        for edge in graph.typed_edges:
            source = self._member(component, graph, edge["source"])
            if source is None or source[0] not in {"F", "L"}:
                # Module-level code is not a function; such calls are not part of K.
                self.omitted[f"{edge['kind']}_from_module_level"] += 1
                continue
            attributes = {"kind": edge["kind"], "provenance": edge["provenance"]}
            if edge["kind"] == "decorator_application":
                target = self._member(component, graph, edge["target"]) if edge["resolved"] else None
                target_id = target[1] if target else self._external(component, edge["target"])
                self.add_edge("A", source[1], target_id, **attributes)
                continue
            if source[0] != "F":
                self.omitted["call_from_class_body"] += 1
                continue
            if edge["resolved"]:
                target = self._member(component, graph, edge["target"])
                if target is None or target[0] != "F":
                    # Calls to a class are represented by their constructor edge.
                    self.omitted["call_to_class_node"] += 1
                    continue
                self.add_edge(
                    "K",
                    source[1],
                    target[1],
                    traversable=edge["kind"] in STRICT_TRAVERSABLE_EDGE_KINDS,
                    **attributes,
                )
            else:
                self.add_edge("K_X", source[1], self._external(component, edge["target"]), **attributes)

    def _member(self, component: str, graph: PackageGraph, qname: str) -> tuple[str, str] | None:
        if qname in graph.functions_payload:
            kind = "L" if graph.functions_payload[qname].get("node_type") == "class" else "F"
            return kind, member_node(kind, component, qname)
        if qname in graph.modules_payload:
            return "M", member_node("M", component, qname)
        return None

    def _external(self, component: str, referenced_name: str) -> str:
        return self.add_node(
            "X",
            member_node("X", component, referenced_name),
            component=component,
            referenced_name=referenced_name,
            status="unresolved",
        )

    # -- B3: cross-component resolution ------------------------------------
    def add_cross_package_edges(self, bridges: Iterable[dict[str, Any]], chain: list[str]) -> None:
        for bridge in bridges:
            source = "F:" + bridge["source"]
            if source not in self.nodes["F"]:
                self.omitted["cross_package_call_from_non_function"] += 1
                continue
            target_kind = "F" if ("F:" + bridge["target"]) in self.nodes["F"] else "L"
            target = f"{target_kind}:" + bridge["target"]
            edge = self.edges["B"].get((source, target))
            chains = edge.get("chains", []) if edge else []
            if " -> ".join(chain) not in chains:
                chains = [*chains, " -> ".join(chain)]
            self.add_edge(
                "B",
                source,
                target,
                resolution_method=bridge["resolution_method"],
                referenced_name=bridge["raw_target"],
                provenance="+".join(bridge.get("provenance", [])),
                chains=chains,
            )
            external = member_node("X", bridge["source_component"], bridge["raw_target"])
            if external in self.nodes["X"]:
                self.nodes["X"][external]["status"] = "resolved_cross_package"

    # -- B4: vulnerability mapping -----------------------------------------
    def add_advisory(self, record: dict[str, Any], component: str) -> str:
        advisory_id = str(record.get("id") or "")
        aliases = sorted(str(alias) for alias in record.get("aliases") or [])
        u_id = self.add_node(
            "U",
            f"U:{advisory_id}",
            advisory_id=advisory_id,
            aliases=aliases,
            cves=sorted({value for value in [advisory_id, *aliases] if value.upper().startswith("CVE-")}),
            record_kind="osv",
            summary=record.get("summary"),
        )
        self.add_edge("R_UC", u_id, component_node(component), provenance="osv")
        return u_id

    def add_vulnerable_function(self, osv_id: str, component: str, located: dict[str, Any]) -> None:
        if not located.get("confirmed") or not located.get("canonical_name"):
            return
        qname = str(located["canonical_name"])
        target = member_node("F", component, qname)
        if target not in self.nodes["F"]:
            target = member_node("L", component, qname)
        if target not in self.nodes["F"] and target not in self.nodes["L"]:
            return
        self.add_edge(
            "R_UF",
            f"U:{osv_id}",
            target,
            cve=located["cve"],
            mapped_name=located["function"],
            resolution_method=located.get("resolution_method"),
            provenance="vulnerability_function_mapping",
        )

    # -- serialisation -----------------------------------------------------
    def to_json(self) -> dict[str, Any]:
        return {
            "schema": "evidence-graph",
            "schema_version": SCHEMA_VERSION,
            "node_types": list(NODE_TYPES),
            "edge_types": list(EDGE_TYPES),
            "counts": {
                "nodes": {kind: len(values) for kind, values in self.nodes.items()},
                "edges": {kind: len(values) for kind, values in self.edges.items()},
            },
            "omitted": dict(sorted(self.omitted.items())),
            "nodes": {
                kind: sorted(values.values(), key=lambda node: node["id"])
                for kind, values in self.nodes.items()
            },
            "edges": {
                kind: sorted(values.values(), key=lambda edge: (edge["source"], edge["target"]))
                for kind, values in self.edges.items()
            },
        }

    def check_consistency(self) -> list[str]:
        """Section 4.4 rules that can be checked on the serialised graph."""
        problems = []
        for (source, target), _edge in self.edges["B"].items():
            if source.split("::", 1)[0] == target.split("::", 1)[0]:
                problems.append(f"B edge within one component: {source} -> {target}")
        for (u_id, f_id) in self.edges["R_UF"]:
            component = component_node(f_id.split(":", 1)[1].split("::", 1)[0])
            if (u_id, component) not in self.edges["R_UC"]:
                problems.append(f"R_UF without R_UC: {u_id} -> {f_id}")
        return problems
