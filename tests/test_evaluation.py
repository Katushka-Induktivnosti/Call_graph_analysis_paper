from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from graph_analysis.callgraph.project import CallGraphOptions
from graph_analysis.evaluation.run import EvaluationConfig, chain_recovery, run_evaluation
from graph_analysis.evaluation.sample import select_sample
from graph_analysis.evaluation.via import confirmed_chain_cves, iter_triad

SOURCES = {
    "app@1.0": {
        "app-1.0/setup.py": (
            "from setuptools import setup\n"
            "setup(name='app', install_requires=['lib==1.0'],\n"
            "      entry_points={'console_scripts': ['app = app.cli:main']})\n"
        ),
        "app-1.0/app/__init__.py": "",
        "app-1.0/app/cli.py": "from lib.api import fetch\n\ndef main():\n    return fetch('x')\n",
    },
    "app2@1.0": {
        "app2-1.0/setup.py": "from setuptools import setup\nsetup(name='app2', install_requires=['lib==2.0'])\n",
        "app2-1.0/app2/__init__.py": "",
        "app2-1.0/app2/run.py": "from lib.api import fetch\n\ndef go():\n    return fetch('y')\n",
    },
    "lib@1.0": {
        "lib-1.0/setup.py": "from setuptools import setup\nsetup(name='lib')\n",
        "lib-1.0/lib/__init__.py": "",
        "lib-1.0/lib/api.py": "from lib.parser import unsafe_parse\n\ndef fetch(data):\n    return unsafe_parse(data)\n",
        "lib-1.0/lib/parser.py": "def unsafe_parse(data):\n    return eval(data)\n",
    },
}
TRIAD = (
    'CVE-2099-0001,lib@1.0,app@1.0,"[[""app@1.0"", ""lib@1.0""]]"\n'
    'CVE-2099-0001,lib@1.0,app2@1.0,"[[""app2@1.0"", ""lib@1.0""]]"\n'
    'CVE-2099-0002,other@3.0,unused@1.0,"[[""unused@1.0"", ""mid@1.0"", ""other@3.0""]]"\n'
)


class FakePyPI:
    def select_version(self, name, specifier, cutoff, python_version="3.14.5"):
        version = specifier[2:] if specifier.startswith("==") else "1.0"
        return version, {"upload_time_iso_8601": "2020-01-01T00:00:00Z"}, []

    def release_requires_dist(self, name, version):
        return [], {"info": {}}, []


def write_tree(root: Path, files: dict[str, str]) -> None:
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


class SampleTests(unittest.TestCase):
    def test_sample_adds_roots_until_target_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            triad = Path(td) / "Triad.csv"
            triad.write_text(TRIAD, encoding="utf-8")
            sample = select_sample(triad, fraction=0.5)
            self.assertEqual(sample["via_package_versions"], 6)
            self.assertEqual(sample["roots"], ["app@1.0", "app2@1.0"])
            self.assertGreaterEqual(sample["covered_fraction"], 0.5)
            shuffled = select_sample(triad, fraction=1.0, order="random", seed=1)
            self.assertEqual(sorted(shuffled["roots"]), ["app2@1.0", "app@1.0", "unused@1.0"])

    def test_chain_recovery_distinguishes_names_and_versions(self) -> None:
        graph = {
            "nodes": [{"id": "lib", "version": "2.0"}],
            "edges": [{"from": "__project__", "to": "lib"}],
        }
        self.assertEqual(chain_recovery(graph, ("app@1.0", "lib@2.0")), (True, True))
        self.assertEqual(chain_recovery(graph, ("app@1.0", "lib@1.0")), (True, False))
        self.assertEqual(chain_recovery(graph, ("app@1.0", "other@1.0")), (False, False))

    def test_via_confirmed_requires_every_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            results = Path(td)
            chain = ("app@1.0", "lib@1.0")
            (results / "CVE-1@lib@1.0@app@1.0").write_text(
                json.dumps(
                    {
                        "Versionmap": {"app": "1.0", "lib": "1.0"},
                        "dependency_path": [["app", "lib"]],
                        "fun_reachable_info": {"0": {"app->lib": {"path": ["app.main", "lib.f"]}}},
                    }
                ),
                encoding="utf-8",
            )
            self.assertEqual(confirmed_chain_cves(results, [(chain, "CVE-1"), (chain, "CVE-2")]), {(chain, "CVE-1")})


class EvaluationRunTests(unittest.TestCase):
    def test_evaluation_measures_on_synthetic_via_sample(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            triad = root / "Triad.csv"
            triad.write_text(TRIAD, encoding="utf-8")
            funs = root / "VUL_FUNs.csv"
            funs.write_text("CVE-2099-0001,lib/parser.unsafe_parse;lib.missing.function\n", encoding="utf-8")
            analyze = root / "AnalyzeRes"
            analyze.mkdir()
            (analyze / "CVE-2099-0001@lib@1.0@app@1.0").write_text(
                json.dumps(
                    {
                        "Versionmap": {"app": "1.0", "lib": "1.0"},
                        "dependency_path": [["app", "lib"]],
                        "fun_reachable_info": {"0": {"b": {"path": ["x"]}}},
                    }
                ),
                encoding="utf-8",
            )
            sample = root / "sample.json"
            sample.write_text(json.dumps(select_sample(triad, fraction=0.5)), encoding="utf-8")
            archives = root / "archives"
            for component, files in SOURCES.items():
                write_tree(archives / component, files)

            def fake_collect(package, version, target_dir, pypi, cache_dir):
                shutil.copytree(archives / f"{package}@{version}", target_dir / "source")
                return {"status": "collected", "source_path": str(target_dir / "source"), "filename": f"{package}-{version}.tar.gz"}

            config = EvaluationConfig(
                triad=triad,
                vulnerable_functions=funs,
                sample=sample,
                work=root / "work",
                output=root / "results",
                cutoff="2026-05-26T00:00:00Z",
                analyze_res=analyze,
                advisory_source="via",
                cache_dir=root / "cache",
                callgraph=CallGraphOptions(skip_pycg=True, skip_codeql=True),
            )
            with (
                patch("graph_analysis.pipeline.collect_pypi_source", fake_collect),
                patch("graph_analysis.dependencies.dependency_resolver.PyPIClient", lambda **_: FakePyPI()),
            ):
                measures = run_evaluation(config)
                # Second run reuses the cached graphs.
                again = run_evaluation(config)

            self.assertEqual(measures["table6_recovery"], again["table6_recovery"])
            sample_counts = measures["table3_sample"]
            self.assertEqual(sample_counts["dependency_chains"], 2)
            self.assertEqual(sample_counts["chain_cve_associations"], 2)
            self.assertEqual(sample_counts["covered_package_versions"], 3)
            self.assertEqual(sample_counts["via_confirmed_associations"], 1)
            recovery = measures["table6_recovery"]
            self.assertEqual(recovery["package_names"]["chains"]["count"], 2)
            self.assertEqual(recovery["exact_versions"]["chains"]["count"], 1)
            self.assertEqual(recovery["strict_static_path"]["chains"]["count"], 1)
            self.assertEqual(recovery["via_confirmed_recall"]["associations"]["count"], 1)
            self.assertEqual(
                measures["table7_first_failing_step"]["associations"], {"exact_version_mismatch": 1}
            )
            coverage = measures["table5_coverage"]
            self.assertEqual(coverage["Cov_UF_cve_to_function"]["count"], 2)
            self.assertEqual(coverage["Cov_entry_entry_point"]["count"], 1)
            function_level = measures["function_level"]
            self.assertEqual(function_level["vulnerable_function_records"], 4)
            self.assertEqual(function_level["records_with_strict_path"], 1)
            self.assertEqual(function_level["path_edges_max"], 2)
            self.assertTrue((config.output / "tables.md").is_file())
            self.assertTrue((config.output / "associations.csv").is_file())


class TriadReaderTests(unittest.TestCase):
    def test_reader_filters_roots(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            triad = Path(td) / "Triad.csv"
            triad.write_text(TRIAD, encoding="utf-8")
            records = list(iter_triad(triad, {"unused@1.0"}))
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0].chains, (("unused@1.0", "mid@1.0", "other@3.0"),))


if __name__ == "__main__":
    unittest.main()
