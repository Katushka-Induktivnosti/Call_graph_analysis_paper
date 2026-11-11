from __future__ import annotations

from pathlib import Path
from typing import Any

from .common import normalize_package_name, safe_package_dir, utc_now, write_csv, write_json, write_jsonl
from .dependency_parser import extract_dependencies
from .packaging_compat import InvalidRequirement, Requirement, SpecifierSet, Version, python_marker_environment
from .pypi import PyPIClient


PROJECT_NODE = "__project__"


class DependencyResolver:
    def __init__(
        self,
        cutoff: str,
        cache_dir: Path,
        include_dev: bool = False,
        include_extras: bool = False,
        max_depth: int = 20,
        refresh_cache: bool = False,
        infer_when_missing: bool = True,
    ) -> None:
        self.cutoff = cutoff
        self.include_dev = include_dev
        self.include_extras = include_extras
        self.max_depth = max_depth
        self.infer_when_missing = infer_when_missing
        self.pypi = PyPIClient(cache_dir=cache_dir / "pypi_json", refresh_cache=refresh_cache)
        self.env = python_marker_environment()
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: list[dict[str, Any]] = []
        self.warnings: list[str] = []
        self.expanded: set[tuple[str, str, tuple[str, ...]]] = set()
        self.locked_packages: dict[str, dict[str, Any]] = {}
        self.status: dict[str, list[dict[str, str]]] = {}

    def resolve_project(self, project_path: Path, metadata_dir: Path) -> dict[str, Any]:
        metadata_dir.mkdir(parents=True, exist_ok=True)
        self.nodes = {}
        self.edges = []
        self.warnings = []
        self.expanded = set()
        self.status = {}

        extracted = extract_dependencies(
            project_path,
            include_dev=self.include_dev,
            include_extras=self.include_extras,
            infer_when_missing=self.infer_when_missing,
        )
        self.locked_packages = extracted["locked_packages"]
        self.warnings.extend(extracted["warnings"])

        for requirement in extracted["requirements"]:
            self._resolve_requirement(requirement, PROJECT_NODE, depth=0, parent_extras=tuple())

        for key, locked in self.locked_packages.items():
            if key not in self.nodes:
                self._add_node(
                    key,
                    locked["name"],
                    locked["version"],
                    source_type=locked["source_type"],
                    source_path=locked["source_path"],
                    direct=False,
                    category=locked.get("category", "lock"),
                    upload_time=None,
                    release_metadata={},
                )
            for dependency in locked.get("dependencies", []):
                child = self._parse_requirement_record(
                    dependency,
                    source_type=f"{locked['source_type']}.dependency",
                    source_path=locked["source_path"],
                    category=locked.get("category", "runtime"),
                    direct=False,
                )
                if child:
                    child_key = normalize_package_name(child["name"])
                    if child_key in self.locked_packages:
                        self._add_edge(key, child_key, child, depth=1)

        graph = {
            "generated_at": utc_now(),
            "cutoff": self.cutoff,
            "python_environment": {
                "python_version": self.env["python_version"],
                "python_full_version": self.env["python_full_version"],
            },
            "project": project_path.name,
            "dependency_files": extracted["dependency_files"],
            "include_dev": self.include_dev,
            "include_extras": self.include_extras,
            "root_status": self.status.get(PROJECT_NODE, []),
            "nodes": sorted(
                (
                    {**node, "status": self.status.get(node["id"], [])}
                    for node in self.nodes.values()
                ),
                key=lambda item: item["id"],
            ),
            "edges": sorted(self.edges, key=lambda item: (item["from"], item["to"], item["requirement"])),
            "warnings": self.warnings,
        }
        self._write_outputs(metadata_dir, graph)
        return graph

    def _resolve_requirement(
        self,
        record: dict[str, Any],
        parent: str,
        depth: int,
        parent_extras: tuple[str, ...],
    ) -> str | None:
        parsed = self._requirement_from_record(record)
        if not parsed:
            self._set_status(parent, "unsupported_requirement", str(record.get("requirement", "")))
            return None
        req, req_extras = parsed
        if not self._marker_applies(req, parent_extras):
            return None
        key = normalize_package_name(req.name)
        locked = self.locked_packages.get(key)
        specifier = str(req.specifier)
        version: str | None = None
        upload_time = None
        release_file: dict[str, Any] = {}

        if locked:
            version = locked["version"]
            record = {**record, "locked_version": version, "version_source": "lock_file"}
            selected, release_file, warnings = self.pypi.select_version(req.name, f"=={version}", self.cutoff)
            self.warnings.extend(warnings)
            if selected:
                version = selected
        elif record.get("locked_version"):
            version = record["locked_version"]
            record = {**record, "version_source": "exact_pin"}
            selected, release_file, warnings = self.pypi.select_version(req.name, f"=={version}", self.cutoff)
            self.warnings.extend(warnings)
            if not selected:
                self._set_status(parent, "missing_release", f"{req.name}=={version}")
                return None
            version = selected
        else:
            record = {**record, "version_source": "registry_latest_before_cutoff"}
            version, release_file, warnings = self.pypi.select_version(req.name, specifier, self.cutoff)
            self.warnings.extend(warnings)

        if not version:
            self._set_status(parent, "missing_release", f"{req.name}{specifier}")
            return None

        if key in self.nodes and not self._version_satisfies(version=self.nodes[key]["version"], specifier=specifier):
            self.warnings.append(
                f"version conflict for {req.name}: existing {self.nodes[key]['version']} does not satisfy {specifier!r} from {record.get('source_path')}"
            )
            self._set_status(
                parent,
                "version_conflict",
                f"{req.name}: kept {self.nodes[key]['version']}, required {specifier}",
            )
        upload_time = release_file.get("upload_time_iso_8601") or release_file.get("upload_time")
        node = self._add_node(
            key,
            req.name,
            version,
            source_type=record.get("source_type", "unknown"),
            source_path=record.get("source_path", ""),
            direct=bool(record.get("direct", False)),
            category=record.get("category", "runtime"),
            upload_time=upload_time,
            release_metadata=release_file,
        )
        self._add_edge(parent, key, record, depth)

        active_extras = tuple(sorted(set(req_extras)))
        expansion_key = (key, node["version"], active_extras)
        if depth >= self.max_depth or expansion_key in self.expanded or locked:
            return key
        self.expanded.add(expansion_key)

        requires_dist, release_payload, warnings = self.pypi.release_requires_dist(req.name, node["version"])
        self.warnings.extend(warnings)
        info = release_payload.get("info", {}) if release_payload else {}
        provided_extras = set(info.get("provides_extra") or []) if self.include_extras else set()
        marker_extras = tuple(sorted(set(active_extras) | provided_extras))
        if info:
            node["requires_python"] = info.get("requires_python")
            node["project_urls"] = info.get("project_urls") or {}
            node["home_page"] = info.get("home_page")

        for requirement_text in requires_dist:
            child = self._parse_requirement_record(
                requirement_text,
                source_type="pypi_requires_dist",
                source_path=f"{req.name}=={node['version']}",
                category="runtime",
                direct=False,
            )
            if child:
                self._resolve_requirement(child, key, depth + 1, parent_extras=marker_extras)
        return key

    def _add_node(
        self,
        key: str,
        name: str,
        version: str,
        source_type: str,
        source_path: str,
        direct: bool,
        category: str,
        upload_time: str | None,
        release_metadata: dict[str, Any],
    ) -> dict[str, Any]:
        node = self.nodes.get(key)
        if not node:
            node = {
                "id": key,
                "name": name,
                "normalized_name": key,
                "version": version,
                "direct": bool(direct),
                "categories": [],
                "sources": [],
                "release_upload_time": upload_time,
                "release_file": {
                    "filename": release_metadata.get("filename"),
                    "packagetype": release_metadata.get("packagetype"),
                    "url": release_metadata.get("url"),
                    "digests": release_metadata.get("digests"),
                }
                if release_metadata
                else {},
            }
            self.nodes[key] = node
        node["direct"] = bool(node["direct"] or direct)
        if category and category not in node["categories"]:
            node["categories"].append(category)
        source = {"type": source_type, "path": source_path}
        if source not in node["sources"]:
            node["sources"].append(source)
        return node

    def _add_edge(self, parent: str, child: str, record: dict[str, Any], depth: int) -> None:
        edge = {
            "from": parent,
            "to": child,
            "requirement": record.get("requirement", ""),
            "source_type": record.get("source_type", ""),
            "source_path": record.get("source_path", ""),
            "category": record.get("category", "runtime"),
            "version_source": record.get("version_source", "lock_file" if record.get("source_type", "").endswith(".dependency") else ""),
            "depth": depth,
        }
        if edge not in self.edges:
            self.edges.append(edge)

    def _set_status(self, component: str, status: str, detail: str) -> None:
        entry = {"status": status, "detail": detail}
        entries = self.status.setdefault(component, [])
        if entry not in entries:
            entries.append(entry)

    def _parse_requirement_record(
        self,
        requirement_text: str,
        source_type: str,
        source_path: str,
        category: str,
        direct: bool,
    ) -> dict[str, Any] | None:
        try:
            req = Requirement(requirement_text)
        except InvalidRequirement as exc:
            self.warnings.append(f"unsupported requirement {requirement_text!r} from {source_path}: {exc}")
            return None
        locked_version = None
        for spec in req.specifier:
            if spec.operator in {"==", "==="} and "*" not in spec.version:
                locked_version = spec.version
        return {
            "name": req.name,
            "requirement": str(req),
            "source_type": source_type,
            "source_path": source_path,
            "category": category,
            "direct": direct,
            "locked_version": locked_version,
        }

    def _requirement_from_record(self, record: dict[str, Any]) -> tuple[Requirement, tuple[str, ...]] | None:
        try:
            req = Requirement(record["requirement"])
        except InvalidRequirement as exc:
            self.warnings.append(f"unsupported requirement {record.get('requirement')!r}: {exc}")
            return None
        return req, tuple(sorted(req.extras))

    def _marker_applies(self, req: Requirement, extras: tuple[str, ...]) -> bool:
        if req.marker is None:
            return True
        candidate_extras = set(extras) or {""}
        if self.include_extras:
            candidate_extras.add("")
        for extra in candidate_extras:
            env = {**self.env, "extra": extra}
            try:
                if req.marker.evaluate(env):
                    return True
            except Exception as exc:
                self.warnings.append(f"failed to evaluate marker {req.marker!s} for {req.name}: {exc}")
                return True
        return False

    def _version_satisfies(self, version: str, specifier: str) -> bool:
        if not specifier:
            return True
        try:
            return SpecifierSet(specifier).contains(Version(version), prereleases=True)
        except Exception:
            return True

    def _write_outputs(self, metadata_dir: Path, graph: dict[str, Any]) -> None:
        write_json(metadata_dir / "dependency_graph.json", graph)
        node_rows = [
            {
                "package": node["name"],
                "normalized_name": node["normalized_name"],
                "version": node["version"],
                "direct": node["direct"],
                "categories": ",".join(sorted(node["categories"])),
                "release_upload_time": node.get("release_upload_time") or "",
            }
            for node in graph["nodes"]
        ]
        write_jsonl(metadata_dir / "dependencies.jsonl", graph["nodes"])
        write_csv(
            metadata_dir / "dependencies.csv",
            node_rows,
            ["package", "normalized_name", "version", "direct", "categories", "release_upload_time"],
        )
        write_jsonl(metadata_dir / "dependency_edges.jsonl", graph["edges"])
