from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from graph_analysis.analysis.combine import (
    combine_chain,
    expand_import_target,
    load_package_graph,
    resolve_cross_package_targets,
    runtime_call_targets,
    shortest_reverse_path,
    trace_to_entry,
)
from graph_analysis.analysis.entrypoints import entry_target


def write_bundle(root: Path, project_id: str, functions: dict, edges: list) -> Path:
    modules = {}
    for qname, item in functions.items():
        modules.setdefault(item["module"], {"file": item["file"]})
    path = root / f"{project_id}.graph_bundle.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "project_id": project_id,
                "repo_root": str(root / project_id),
                "modules": modules,
                "functions": functions,
                "edges": [
                    {"source": s, "target": t, "kind": "call", "provenance": "pycg"}
                    for s, t in edges
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


def fn(module: str, name: str, file: str, kind: str = "function") -> tuple[str, dict]:
    return f"{module}.{name}", {"file": file, "module": module, "node_type": kind}


class CombineTest(unittest.TestCase):
    def test_schema_v1_bundle_loads_and_test_edges_are_excluded(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "pkg").mkdir()
            (root / "tests").mkdir()
            bundle_path = root / "graph_bundle.json"
            bundle_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "project_id": "pkg@1",
                        "repo_root": str(root),
                        "modules": {"pkg.main": {}, "tests.test_main": {}},
                        "functions": {
                            "pkg.main.run": {
                                "file": "pkg/main.py",
                                "node_type": "function",
                            },
                            "pkg.main.target": {
                                "file": "pkg/main.py",
                                "node_type": "function",
                            },
                            "tests.test_main.test_run": {
                                "file": "tests/test_main.py",
                                "node_type": "function",
                            },
                        },
                        "edges": [
                            {"source": "pkg.main.run", "target": "pkg.main.target"},
                            {
                                "source": "tests.test_main.test_run",
                                "target": "pkg.main.target",
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )
            graph = load_package_graph("pkg@1", bundle_path)
            self.assertIn(("pkg.main.run", "pkg.main.target"), graph.internal_edges)
            self.assertNotIn(
                ("tests.test_main.test_run", "pkg.main.target"),
                graph.internal_edges,
            )
            self.assertEqual(graph.diagnostics["excluded_non_production_edges"], 1)

    def test_entry_point_value_is_converted_to_qualified_name(self) -> None:
        self.assertEqual(entry_target("demo.cli:main"), "demo.cli.main")
        self.assertEqual(
            entry_target("demo.cli:main [recommended]"),
            "demo.cli.main",
        )

    def test_cross_package_resolution_only_moves_toward_dependencies(self) -> None:
        declaration_index = {
            "dependency.api.vulnerable": [
                (0, "downstream@1", "dependency.api.vulnerable"),
                (2, "dependency@1", "dependency.api.vulnerable"),
            ]
        }
        result = resolve_cross_package_targets(
            "dependency.api.vulnerable",
            source_component="intermediate@1",
            source_index=1,
            declaration_index=declaration_index,
            suffix_index={},
        )
        self.assertEqual(
            result,
            (
                (
                    "dependency@1",
                    "dependency.api.vulnerable",
                    "exact_qualified_name",
                ),
            ),
        )

    def test_import_alias_expands_external_target(self) -> None:
        self.assertEqual(
            expand_import_target("Cache.open", {"Cache": "suds.cache.FileCache"}),
            "suds.cache.FileCache.open",
        )

    def test_class_call_expands_to_constructor(self) -> None:
        self.assertEqual(
            set(
                runtime_call_targets(
                    "suds.cache.FileCache",
                    {
                        "suds.cache.FileCache": "class",
                        "suds.cache.FileCache.__init__": "function",
                    },
                    {
                        "suds.cache.FileCache",
                        "suds.cache.FileCache.__init__",
                    },
                )
            ),
            {"suds.cache.FileCache", "suds.cache.FileCache.__init__"},
        )

    def test_class_call_expands_to_nearest_inherited_constructor(self) -> None:
        declarations = {
            "pkg.Base",
            "pkg.Base.__init__",
            "pkg.Child",
        }
        self.assertEqual(
            set(
                runtime_call_targets(
                    "pkg.Child",
                    {"pkg.Base": "class", "pkg.Child": "class"},
                    declarations,
                    {"pkg.Base": (), "pkg.Child": ("pkg.Base",)},
                )
            ),
            {"pkg.Child", "pkg.Base.__init__"},
        )

    def test_public_reexport_prefers_callable_class_over_module(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "joblib").mkdir()
            (root / "joblib" / "__init__.py").write_text(
                "from .parallel import Parallel\n", encoding="utf-8"
            )
            (root / "joblib" / "parallel.py").write_text("", encoding="utf-8")
            bundle = root / "graph_bundle.json"
            bundle.write_text(
                json.dumps(
                    {
                        "schema_version": 2,
                        "project_id": "joblib@1",
                        "repo_root": str(root),
                        "modules": {
                            "joblib": {"file": "joblib/__init__.py"},
                            "joblib.parallel": {"file": "joblib/parallel.py"},
                        },
                        "functions": {
                            "joblib.run": {
                                "file": "joblib/__init__.py",
                                "module": "joblib",
                                "node_type": "function",
                            },
                            "joblib.parallel.Parallel": {
                                "file": "joblib/parallel.py",
                                "module": "joblib.parallel",
                                "node_type": "class",
                                "bases": [],
                            },
                            "joblib.parallel.Parallel.__init__": {
                                "file": "joblib/parallel.py",
                                "module": "joblib.parallel",
                                "node_type": "function",
                            },
                        },
                        "edges": [
                            {
                                "source": "joblib.run",
                                "target": "joblib.Parallel",
                                "kind": "constructor_call",
                                "provenance": "ast",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            graph = load_package_graph("joblib@1", bundle)
            self.assertIn(
                ("joblib.run", "joblib.parallel.Parallel"), graph.internal_edges
            )
            self.assertIn(
                ("joblib.run", "joblib.parallel.Parallel.__init__"),
                graph.internal_edges,
            )
            self.assertNotIn(("joblib.run", "joblib.parallel"), graph.internal_edges)

    def test_reverse_trace_returns_vulnerable_to_entry_order(self) -> None:
        entry = ("app@1", "app.main")
        middle = ("bridge@1", "bridge.call")
        vulnerable = ("dependency@1", "dependency.vulnerable")
        reverse = {
            middle: {entry},
            vulnerable: {middle},
        }
        self.assertEqual(
            shortest_reverse_path(vulnerable, reverse, {entry}),
            [vulnerable, middle, entry],
        )

    def _chain_graphs(self, root: Path, with_script: bool) -> dict:
        app_root = root / "app"
        (app_root / "app").mkdir(parents=True)
        if with_script:
            (app_root / "pyproject.toml").write_text(
                '[project]\nname = "app"\n[project.scripts]\napp = "app.cli:main"\n',
                encoding="utf-8",
            )
        app = write_bundle(
            root,
            "app",
            dict(
                [
                    fn("app.cli", "main", "app/cli.py"),
                    fn("app.cli", "helper", "app/cli.py"),
                    fn("app.worker", "process", "app/worker.py"),
                ]
            ),
            [
                ("app.cli.main", "app.cli.helper"),
                ("app.cli.helper", "lib.api.fetch"),
                ("app.worker.process", "lib.api.fetch"),
            ],
        )
        lib = write_bundle(
            root,
            "lib@1.0",
            dict(
                [
                    fn("lib.api", "fetch", "lib/api.py"),
                    fn("lib.core", "parse", "lib/core.py"),
                ]
            ),
            [("lib.api.fetch", "lib.core.parse")],
        )
        return {
            "app": load_package_graph("app", app),
            "lib@1.0": load_package_graph("lib@1.0", lib),
        }

    def test_combined_chain_traces_from_declared_entry_point(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            graphs = self._chain_graphs(Path(td), with_script=True)
            self.assertEqual(graphs["app"].entries["app.cli.main"]["kind"], "console_script")
            combined = combine_chain(["app", "lib@1.0"], graphs)
            self.assertIn(
                ("app", "app.cli.helper", "lib@1.0", "lib.api.fetch"), combined.bridges
            )
            trace = trace_to_entry(
                combined, "app", graphs, [("lib@1.0", "lib.core.parse")], graphs["lib@1.0"]
            )
            self.assertTrue(trace["path_found"])
            self.assertEqual(trace["endpoint_tier"], "declared_entry_point")
            self.assertEqual(
                [step["node"] for step in trace["path"]],
                [
                    "app::app.cli.main",
                    "app::app.cli.helper",
                    "lib@1.0::lib.api.fetch",
                    "lib@1.0::lib.core.parse",
                ],
            )
            self.assertEqual(trace["cross_package_edge_count"], 1)

    def test_trace_falls_back_to_callgraph_roots_without_declared_entries(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            graphs = self._chain_graphs(Path(td), with_script=False)
            combined = combine_chain(["app", "lib@1.0"], graphs)
            trace = trace_to_entry(
                combined, "app", graphs, [("lib@1.0", "lib.core.parse")], graphs["lib@1.0"]
            )
            self.assertTrue(trace["path_found"])
            self.assertIn(trace["endpoint_tier"], {"declared_entry_point", "callgraph_root"})
            self.assertEqual(trace["path"][0]["component"], "app")

    def test_no_bridge_reports_no_cross_package_edge(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            graphs = self._chain_graphs(Path(td), with_script=True)
            combined = combine_chain(["app", "other@1"], graphs)
            trace = trace_to_entry(combined, "app", graphs, [("other@1", "x.y")], None)
            self.assertFalse(trace["path_found"])
            self.assertEqual(trace["trace_status"], "no_cross_package_edge")


if __name__ == "__main__":
    unittest.main()
