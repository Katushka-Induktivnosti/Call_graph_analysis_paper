from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from graph_analysis.callgraph.ast_index import build_ast_callgraph_details, build_function_index
from graph_analysis.callgraph.graph_builder import build_project_bundle, merge_bundles
from graph_analysis.callgraph.sarif import load_codeql_alerts
from graph_analysis.dependencies.source_collector import choose_repo_root


class GraphPipelineTests(unittest.TestCase):
    def test_ast_enrichment_resolves_constructor_and_inherited_receiver_calls(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            package = repo / "requests"
            package.mkdir()
            (package / "__init__.py").write_text("", encoding="utf-8")
            (package / "sessions.py").write_text(
                "\n".join(
                    [
                        "class SessionRedirectMixin:",
                        "    def resolve_redirects(self):",
                        "        return None",
                        "",
                        "class Session(SessionRedirectMixin):",
                        "    def request(self):",
                        "        return self.send()",
                        "",
                        "    def send(self):",
                        "        return self.resolve_redirects()",
                    ]
                ),
                encoding="utf-8",
            )
            (package / "api.py").write_text(
                "from . import sessions\n\n"
                "def request():\n"
                "    session = sessions.Session()\n"
                "    return session.request()\n",
                encoding="utf-8",
            )
            index = build_function_index(repo)
            graph, edges, metadata = build_ast_callgraph_details(repo, index)
            self.assertIn("requests.sessions.Session.request", graph["requests.api.request"])
            self.assertIn(
                "requests.sessions.Session.send",
                graph["requests.sessions.Session.request"],
            )
            self.assertIn(
                "requests.sessions.SessionRedirectMixin.resolve_redirects",
                graph["requests.sessions.Session.send"],
            )
            self.assertGreaterEqual(metadata["receiver_call_edges"], 3)
            self.assertTrue(any(edge["kind"] == "constructor_call" for edge in edges))

    def test_decorator_application_is_recorded_without_reverse_reachability(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            (repo / "pkg.py").write_text(
                "def decorate(fn):\n"
                "    return fn\n\n"
                "@decorate\n"
                "def decorated():\n"
                "    return 1\n",
                encoding="utf-8",
            )
            index = build_function_index(repo)
            graph, edges, _metadata = build_ast_callgraph_details(repo, index)
            decorator_edges = [
                edge for edge in edges if edge["kind"] == "decorator_application"
            ]
            self.assertEqual(len(decorator_edges), 1)
            self.assertEqual(decorator_edges[0]["target"], "pkg.decorate")
            self.assertEqual(decorator_edges[0]["source"], "pkg.decorated")
            self.assertNotIn("pkg.decorated", graph.get("pkg.decorate", []))

    def test_callable_class_chain_expands_inherited_constructor_and_call(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            (repo / "pkg.py").write_text(
                "class Base:\n"
                "    def __init__(self): pass\n\n"
                "class Parallel(Base):\n"
                "    def __call__(self, jobs): return jobs\n\n"
                "def run(jobs):\n"
                "    return Parallel()(jobs)\n",
                encoding="utf-8",
            )
            index = build_function_index(repo)
            graph, edges, _metadata = build_ast_callgraph_details(repo, index)
            targets = set(graph["pkg.run"])
            self.assertIn("pkg.Parallel", targets)
            self.assertIn("pkg.Base.__init__", targets)
            self.assertIn("pkg.Parallel.__call__", targets)
            self.assertTrue(
                any(
                    edge["target"] == "pkg.Parallel.__call__"
                    and edge["kind"] == "callable_dispatch"
                    for edge in edges
                )
            )

    def test_constant_dispatch_table_resolves_and_unknown_key_does_not(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            (repo / "pkg.py").write_text(
                "def escape_dict(value): return value\n"
                "def escape_string(value): return value\n"
                "CONVERTERS = {1: escape_dict, 2: escape_string}\n\n"
                "def known(value): return CONVERTERS[1](value)\n"
                "def unknown(key, value): return CONVERTERS[key](value)\n",
                encoding="utf-8",
            )
            index = build_function_index(repo)
            graph, edges, metadata = build_ast_callgraph_details(repo, index)
            self.assertIn("pkg.escape_dict", graph["pkg.known"])
            self.assertNotIn("pkg.escape_dict", graph.get("pkg.unknown", []))
            self.assertTrue(
                any(edge["kind"] == "dispatch_table_call" for edge in edges)
            )
            self.assertTrue(
                any(
                    item["shape"] == "subscript_dispatch"
                    for item in metadata["unresolved_call_details"]
                )
            )

    def test_factory_super_context_property_and_dynamic_import_dispatch(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            (repo / "pkg.py").write_text(
                "import importlib\n\n"
                "class Base:\n"
                "    def work(self): return 1\n\n"
                "class Resource(Base):\n"
                "    def __enter__(self): return self\n"
                "    def __exit__(self, *args): return None\n"
                "    @property\n"
                "    def value(self): return 1\n"
                "    def work(self): return super().work()\n\n"
                "def factory(): return Resource()\n\n"
                "def run():\n"
                "    module = importlib.import_module('external.api')\n"
                "    module.execute()\n"
                "    with factory() as resource:\n"
                "        return resource.value + resource.work()\n",
                encoding="utf-8",
            )
            index = build_function_index(repo)
            graph, edges, metadata = build_ast_callgraph_details(repo, index)
            targets = set(graph["pkg.run"])
            self.assertIn("pkg.factory", targets)
            self.assertIn("pkg.Resource.__enter__", targets)
            self.assertIn("pkg.Resource.__exit__", targets)
            self.assertIn("pkg.Resource.value", targets)
            self.assertIn("external.api.execute", targets)
            self.assertIn("pkg.Base.work", graph["pkg.Resource.work"])
            self.assertGreaterEqual(metadata["resolved_dynamic_imports"], 1)
            kinds = {edge["kind"] for edge in edges}
            self.assertIn("super_dispatch", kinds)
            self.assertIn("protocol_dispatch", kinds)

    def test_ambiguous_receiver_and_callback_registration_remain_strict(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            (repo / "pkg.py").write_text(
                "class Left:\n"
                "    def run(self): return 1\n\n"
                "class Right:\n"
                "    def run(self): return 2\n\n"
                "def register(callback): return callback\n"
                "def callback(): return 1\n\n"
                "def entry(flag):\n"
                "    value = Left()\n"
                "    value = Right()\n"
                "    register(callback)\n"
                "    return value.run()\n",
                encoding="utf-8",
            )
            index = build_function_index(repo)
            graph, _edges, _metadata = build_ast_callgraph_details(repo, index)
            targets = set(graph["pkg.entry"])
            self.assertNotIn("pkg.Left.run", targets)
            self.assertNotIn("pkg.Right.run", targets)
            self.assertIn("pkg.register", targets)
            self.assertNotIn("pkg.callback", graph.get("pkg.register", []))

    def test_installed_distribution_archive_selects_site_packages_root(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            source = Path(td) / "source"
            site_packages = (
                source
                / "Users"
                / "builder"
                / ".venvs"
                / "demo"
                / "lib"
                / "python3.11"
                / "site-packages"
            )
            (site_packages / "demo_pkg").mkdir(parents=True)
            (site_packages / "demo_pkg" / "__init__.py").write_text(
                "def run():\n    return 1\n", encoding="utf-8"
            )
            (site_packages / "demo_pkg-1.0.0.egg-info").mkdir()
            selected = choose_repo_root(
                source, normalized_package="demo-pkg", version="1.0.0"
            )
            self.assertEqual(selected, site_packages.resolve())

    def test_sarif_alert_mapping_and_recursive_caller_coloring(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            (repo / "pkg").mkdir()
            (repo / "pkg" / "__init__.py").write_text("", encoding="utf-8")
            source = "\n".join(
                [
                    "def entry():",
                    "    caller()",
                    "",
                    "def caller():",
                    "    vuln()",
                    "",
                    "def vuln():",
                    "    return 'bad'",
                    "",
                ]
            )
            (repo / "pkg" / "a.py").write_text(source, encoding="utf-8")
            (repo / "pkg" / "b.py").write_text("def upstream():\n    entry()\n", encoding="utf-8")
            output = repo / "output_folder"
            output.mkdir()

            index = build_function_index(repo, output)
            sarif = {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "name": "CodeQL",
                                "rules": [{"id": "py/test-alert", "shortDescription": {"text": "test"}}],
                            }
                        },
                        "results": [
                            {
                                "ruleId": "py/test-alert",
                                "message": {"text": "alert on vuln"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "pkg/a.py"},
                                            "region": {"startLine": 7},
                                        }
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
            sarif_path = output / "codeql_results.sarif"
            sarif_path.write_text(json.dumps(sarif), encoding="utf-8")
            alerts = load_codeql_alerts(sarif_path, repo, index)
            self.assertEqual(alerts[0]["target"], "pkg.a.vuln")

            bundle = build_project_bundle(
                project_id="primary",
                repo_root=repo,
                local_prefixes=["pkg"],
                function_index=index,
                pycg_graph={
                    "external.lib.wrapper": ["pkg.b.upstream"],
                    "pkg.b.upstream": ["pkg.a.entry"],
                    "pkg.a.entry": ["pkg.a.caller"],
                    "pkg.a.caller": ["pkg.a.vuln"],
                    "pkg.a.vuln": ["pkg.a.entry"],
                },
                alerts=alerts,
                pycg_metadata={"status": "ok"},
                codeql_metadata={"status": "ok"},
            )
            merged = merge_bundles("primary", [bundle])
            by_qname = {node["qname"]: node for node in merged["nodes"]}
            self.assertEqual(by_qname["pkg.a.vuln"]["status"], "red")
            self.assertEqual(by_qname["pkg.a.caller"]["status"], "yellow")
            self.assertEqual(by_qname["pkg.a.entry"]["status"], "yellow")
            self.assertEqual(by_qname["pkg.a"]["status"], "red")
            self.assertEqual(by_qname["pkg.a"]["shape"], "square")
            self.assertEqual(by_qname["pkg.b.upstream"]["status"], "yellow")
            self.assertEqual(by_qname["pkg.b"]["status"], "yellow")
            self.assertEqual(by_qname["external.lib.wrapper"]["status"], "yellow")
            self.assertEqual(by_qname["external.lib.wrapper"]["scope"], "external")
            self.assertEqual(by_qname["external.lib"]["status"], "yellow")

    def test_merged_non_primary_project_is_external(self) -> None:
        primary = {
            "project_id": "app",
            "local_prefixes": ["app"],
            "modules": {"app.main": {"id": "app.main", "file": "app/main.py", "functions": ["app.main.run"]}},
            "functions": {"app.main.run": {"qualname": "app.main.run", "module": "app.main", "file": "app/main.py"}},
            "edges": [{"source": "app.main.run", "target": "lib.core.danger"}],
            "alerts": [],
        }
        library = {
            "project_id": "lib",
            "local_prefixes": ["lib"],
            "modules": {"lib.core": {"id": "lib.core", "file": "lib/core.py", "functions": ["lib.core.danger"]}},
            "functions": {"lib.core.danger": {"qualname": "lib.core.danger", "module": "lib.core", "file": "lib/core.py"}},
            "edges": [],
            "alerts": [{"target": "lib.core.danger", "target_type": "function", "rule_id": "py/x"}],
        }
        merged = merge_bundles("app", [primary, library])
        by_qname = {node["qname"]: node for node in merged["nodes"]}
        self.assertEqual(by_qname["app.main.run"]["scope"], "local")
        self.assertEqual(by_qname["lib.core.danger"]["scope"], "external")
        self.assertEqual(by_qname["lib.core.danger"]["shape"], "circle")
        self.assertEqual(by_qname["lib.core.danger"]["status"], "red")


if __name__ == "__main__":
    unittest.main()
