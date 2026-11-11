from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from graph_analysis.analysis.entrypoints import declared_scripts, main_guards
from graph_analysis.analysis.vulnfuncs import load_mapping, locate_functions, match_mapping
from graph_analysis.callgraph.ast_index import build_function_index
from graph_analysis.callgraph.project import CallGraphOptions
from graph_analysis.pipeline import PipelineConfig, dependency_chains, run


APP_FILES = {
    "pyproject.toml": (
        '[project]\nname = "demo-app"\ndependencies = ["vulnlib==1.0"]\n'
        '[project.scripts]\ndemo = "demo_app.cli:main"\n'
    ),
    "demo_app/__init__.py": "",
    "demo_app/cli.py": (
        "from vulnlib.loader import load\n\n"
        "def main():\n    return handle('payload')\n\n"
        "def handle(data):\n    return load(data)\n\n"
        "def unused():\n    return 1\n"
    ),
}
LIB_FILES = {
    "vulnlib-1.0/setup.py": "from setuptools import setup\nsetup(name='vulnlib')\n",
    "vulnlib-1.0/vulnlib/__init__.py": "",
    "vulnlib-1.0/vulnlib/loader.py": (
        "from vulnlib.parser import unsafe_parse\n\n"
        "def load(data):\n    return unsafe_parse(data)\n"
    ),
    "vulnlib-1.0/vulnlib/parser.py": "def unsafe_parse(data):\n    return eval(data)\n",
}


def write_tree(root: Path, files: dict[str, str]) -> None:
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


class EntryPointTests(unittest.TestCase):
    def test_declared_scripts_from_pyproject_setup_cfg_and_setup_py(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write_tree(
                root,
                {
                    "pyproject.toml": '[project.scripts]\na = "pkg.a:main"\n',
                    "setup.cfg": "[options.entry_points]\nconsole_scripts =\n    b = pkg.b:run\n",
                    "setup.py": "setup(entry_points={'console_scripts': ['c = pkg.c:cli']})\n",
                },
            )
            found = {(kind, value) for kind, _label, value, _origin in declared_scripts(root)}
            self.assertEqual(
                found,
                {
                    ("console_script", "pkg.a:main"),
                    ("console_script", "pkg.b:run"),
                    ("console_script", "pkg.c:cli"),
                },
            )

    def test_main_guard_records_called_functions(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write_tree(
                root,
                {
                    "pkg/__init__.py": "",
                    "pkg/tool.py": "def go():\n    pass\n\nif __name__ == '__main__':\n    go()\n",
                    "tests/test_tool.py": "if __name__ == '__main__':\n    run_tests()\n",
                },
            )
            self.assertEqual(list(main_guards(root)), [("pkg.tool", ["pkg.tool.go"])])


class MappingTests(unittest.TestCase):
    def test_load_mapping_accepts_via_and_header_formats(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            via = Path(td) / "via.csv"
            via.write_text("CVE-2020-1,pkg/mod.a;pkg.mod.b\n", encoding="utf-8")
            header = Path(td) / "header.csv"
            header.write_text("cve,package,functions\ncve-2020-2,Pkg_Name,pkg.mod.c\n", encoding="utf-8")
            self.assertEqual(
                [(row.cve, row.function) for row in load_mapping(via)],
                [("CVE-2020-1", "pkg.mod.b"), ("CVE-2020-1", "pkg/mod.a")],
            )
            rows = load_mapping(header)
            self.assertEqual((rows[0].cve, rows[0].package), ("CVE-2020-2", "pkg-name"))

    def test_match_uses_osv_aliases_and_package_filter(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "map.json"
            path.write_text(
                json.dumps(
                    [
                        {"cve": "CVE-2020-1", "functions": ["lib.f"]},
                        {"cve": "CVE-2020-1", "package": "other", "functions": ["other.g"]},
                    ]
                ),
                encoding="utf-8",
            )
            matches = match_mapping(
                "lib", [{"id": "GHSA-xxxx", "aliases": ["CVE-2020-1"]}], load_mapping(path)
            )
            self.assertEqual(matches, [{"cve": "CVE-2020-1", "osv_id": "GHSA-xxxx", "function": "lib.f"}])

    def test_locate_function_reports_file_and_line(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "vulnlib-1.0"
            write_tree(Path(td), LIB_FILES)
            index = build_function_index(root)
            located = locate_functions(
                "vulnlib",
                root,
                index,
                [{"cve": "CVE-1", "osv_id": "X", "function": "vulnlib/parser.unsafe_parse"}],
            )
            self.assertTrue(located[0]["confirmed"])
            self.assertEqual(located[0]["canonical_name"], "vulnlib.parser.unsafe_parse")
            self.assertEqual((located[0]["source_file"], located[0]["start_line"]), ("vulnlib/parser.py", 1))


class ChainTests(unittest.TestCase):
    def test_dependency_chains_are_shortest_first_and_acyclic(self) -> None:
        graph = {
            "edges": [
                {"from": "__project__", "to": "a"},
                {"from": "__project__", "to": "b"},
                {"from": "a", "to": "v"},
                {"from": "b", "to": "c"},
                {"from": "c", "to": "v"},
                {"from": "v", "to": "a"},
            ]
        }
        self.assertEqual(dependency_chains(graph, "v", 5), [["a", "v"], ["b", "c", "v"]])
        self.assertEqual(dependency_chains(graph, "v", 1), [["a", "v"]])


class FakePyPI:
    def select_version(self, name, specifier, cutoff, python_version="3.14.5"):
        return "1.0", {"upload_time_iso_8601": "2020-01-01T00:00:00Z"}, []

    def release_requires_dist(self, name, version):
        return [], {"info": {}}, []


def fake_vulnerabilities(graph, metadata_dir, cache_dir):
    return {
        "vulnerable_dependency_count": 1,
        "vulnerability_count": 1,
        "warnings": [],
        "vulnerable_dependencies": [
            {
                "package": "vulnlib",
                "normalized_name": "vulnlib",
                "version": "1.0",
                "vulnerabilities": [{"id": "GHSA-test", "aliases": ["CVE-2099-0001"]}],
            }
        ],
    }


class EndToEndTests(unittest.TestCase):
    def test_pipeline_traces_cve_function_to_console_script(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            project = root / "demo-app"
            write_tree(project, APP_FILES)
            lib_archive = root / "lib"
            write_tree(lib_archive, LIB_FILES)
            mapping = root / "vulnerable_functions.csv"
            mapping.write_text("CVE-2099-0001,vulnlib/parser.unsafe_parse\n", encoding="utf-8")

            def fake_collect(package, version, target_dir, pypi, cache_dir):
                shutil.copytree(lib_archive, target_dir / "source")
                return {"status": "collected", "source_path": str(target_dir / "source"), "filename": "vulnlib-1.0.tar.gz"}

            config = PipelineConfig(
                project=project,
                output=root / "out",
                vulnerable_functions=mapping,
                cache_dir=root / "cache",
                callgraph=CallGraphOptions(skip_pycg=True, skip_codeql=True),
            )
            with (
                patch("graph_analysis.dependencies.dependency_resolver.PyPIClient", lambda **_: FakePyPI()),
                patch("graph_analysis.pipeline.map_vulnerabilities", fake_vulnerabilities),
                patch("graph_analysis.pipeline.collect_pypi_source", fake_collect),
            ):
                report = run(config)

            self.assertEqual(report["summary"]["findings_with_path"], 1)
            finding = report["findings"][0]
            self.assertEqual(finding["cve"], "CVE-2099-0001")
            self.assertEqual((finding["source_file"], finding["start_line"]), ("vulnlib/parser.py", 1))
            self.assertEqual(finding["endpoint_tier"], "declared_entry_point")
            self.assertEqual(finding["entry_point"]["kind"], "console_script")
            self.assertEqual(
                [step["node"] for step in finding["path"]],
                [
                    "demo-app::demo_app.cli.main",
                    "demo-app::demo_app.cli.handle",
                    "vulnlib@1.0::vulnlib.loader.load",
                    "vulnlib@1.0::vulnlib.parser.unsafe_parse",
                ],
            )
            out = root / "out"
            for name in ("report.json", "vulnerable_paths.csv", "combined_graph.json", "index.html"):
                self.assertTrue((out / name).is_file(), name)
            combined = json.loads((out / "combined_graph.json").read_text(encoding="utf-8"))
            statuses = {node["qname"]: node["status"] for node in combined["nodes"]}
            self.assertEqual(statuses["vulnlib.parser.unsafe_parse"], "cve")
            self.assertEqual(statuses["demo_app.cli.main"], "path")
            self.assertEqual(combined["stats"]["cross_package_edge_count"], 1)
            self.assertNotIn(str(root), (out / "report.json").read_text(encoding="utf-8"))
            self.assertFalse(finding["all_edges_from_pycg"])  # AST-only run
            self.assertEqual([edge["type"] for edge in finding["edges"]], ["K", "B", "K"])

            graph = json.loads((out / "graph.json").read_text(encoding="utf-8"))
            self.assertEqual(graph["schema_version"], "1.0")
            self.assertEqual(set(graph["nodes"]), {"C", "M", "L", "F", "X", "U"})
            self.assertEqual(set(graph["edges"]), {"D", "O", "K", "K_X", "B", "A", "R_UC", "R_UF"})
            self.assertEqual(report["graph"]["consistency_problems"], [])
            dependency = graph["edges"]["D"][0]
            self.assertEqual(
                (dependency["source"], dependency["target"], dependency["version_source"]),
                ("C:demo-app", "C:vulnlib@1.0", "exact_pin"),
            )
            self.assertEqual(
                [(e["source"], e["target"]) for e in graph["edges"]["B"]],
                [("F:demo-app::demo_app.cli.handle", "F:vulnlib@1.0::vulnlib.loader.load")],
            )
            self.assertEqual(
                [(e["source"], e["target"]) for e in graph["edges"]["R_UF"]],
                [("U:GHSA-test", "F:vulnlib@1.0::vulnlib.parser.unsafe_parse")],
            )
            self.assertIn(("U:GHSA-test", "C:vulnlib@1.0"), {(e["source"], e["target"]) for e in graph["edges"]["R_UC"]})
            entry = next(n for n in graph["nodes"]["F"] if n["id"] == "F:demo-app::demo_app.cli.main")
            self.assertEqual(entry["entry_point"]["kind"], "console_script")
            roles = {n["qname"]: n["role"] for n in graph["nodes"]["M"]}
            self.assertEqual(roles["demo_app.cli"], "production")
            statuses = {n["id"]: n["status"] for n in graph["nodes"]["C"]}
            self.assertEqual(statuses["C:vulnlib@1.0"], [{"status": "pycg_fallback", "detail": "skipped"}])
            self.assertEqual(report["dependency_exposure"][0]["dependency_paths"], [["demo-app", "vulnlib@1.0"]])


if __name__ == "__main__":
    unittest.main()
