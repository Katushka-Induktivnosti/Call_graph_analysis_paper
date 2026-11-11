from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from graph_analysis.dependencies.dependency_resolver import DependencyResolver


class FakePyPI:
    def select_version(self, name: str, specifier: str, cutoff: str, python_version: str = "3.14.5"):
        versions = {
            "rootpkg": "1.0.0",
            "childpkg": "2.0.0",
            "lockedpkg": "0.5.0",
        }
        version = versions.get(name.lower())
        if not version:
            return None, {}, [f"missing {name}"]
        return version, {"filename": f"{name}-{version}.tar.gz", "packagetype": "sdist", "upload_time_iso_8601": "2025-01-01T00:00:00Z"}, []

    def release_requires_dist(self, name: str, version: str):
        if name.lower() == "rootpkg":
            return ["childpkg<3; python_version >= '3.8'"], {"info": {"requires_python": ">=3.8", "provides_extra": []}}, []
        return [], {"info": {"requires_python": ">=3.8", "provides_extra": []}}, []


class DependencyResolverTests(unittest.TestCase):
    def test_resolver_builds_transitive_graph(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "project"
            metadata = Path(tmp) / "output" / "dependencies"
            project.mkdir(parents=True)
            (project / "requirements.txt").write_text("rootpkg>=1\n", encoding="utf-8")

            resolver = DependencyResolver(cutoff="2026-04-30T23:59:59Z", cache_dir=Path(tmp) / "cache")
            resolver.pypi = FakePyPI()
            graph = resolver.resolve_project(project, metadata)

            nodes = {node["normalized_name"]: node for node in graph["nodes"]}
            self.assertEqual(nodes["rootpkg"]["version"], "1.0.0")
            self.assertEqual(nodes["childpkg"]["version"], "2.0.0")
            self.assertTrue(nodes["rootpkg"]["direct"])
            self.assertFalse(nodes["childpkg"]["direct"])
            self.assertTrue((metadata / "dependency_graph.json").exists())
            self.assertTrue((metadata / "dependencies.csv").exists())
            self.assertEqual(
                {(e["from"], e["to"]): e["version_source"] for e in graph["edges"]},
                {
                    ("__project__", "rootpkg"): "registry_latest_before_cutoff",
                    ("rootpkg", "childpkg"): "registry_latest_before_cutoff",
                },
            )

    def test_missing_release_and_conflict_are_recorded_on_requiring_component(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "project"
            project.mkdir()
            (project / "requirements.txt").write_text(
                "rootpkg>=1\nchildpkg>=5\ngonepkg==0.9\n", encoding="utf-8"
            )
            resolver = DependencyResolver(cutoff="2026-04-30T23:59:59Z", cache_dir=Path(tmp) / "cache")
            resolver.pypi = FakePyPI()
            graph = resolver.resolve_project(project, Path(tmp) / "out")
            root_status = {item["status"] for item in graph["root_status"]}
            self.assertEqual(root_status, {"missing_release", "version_conflict"})
            nodes = {node["normalized_name"]: node for node in graph["nodes"]}
            self.assertNotIn("gonepkg", nodes)
            self.assertEqual(nodes["childpkg"]["version"], "2.0.0")


if __name__ == "__main__":
    unittest.main()
