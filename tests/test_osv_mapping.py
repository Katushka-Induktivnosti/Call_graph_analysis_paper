from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from graph_analysis.dependencies.osv import map_vulnerabilities


class FakeOSVClient:
    def __init__(self, cache_dir: Path):
        self.cache_dir = cache_dir

    def query_batch(self, packages, batch_size: int = 100):
        return [
            {
                "package": packages[0],
                "result": {"vulns": [{"id": "PYSEC-TEST-1", "modified": "2025-01-01T00:00:00Z"}]},
            }
        ]

    def vulnerability(self, vuln_id: str):
        return {
            "id": vuln_id,
            "aliases": ["CVE-TEST-1"],
            "summary": "test vulnerability",
            "modified": "2025-01-01T00:00:00Z",
            "references": [{"url": "https://github.com/example/example"}],
        }


class OSVMappingTests(unittest.TestCase):
    def test_osv_mapping_outputs_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            metadata = Path(tmp) / "dependencies"
            graph = (
                {
                    "nodes": [
                        {
                            "name": "Jinja2",
                            "normalized_name": "jinja2",
                            "version": "2.11.3",
                        }
                    ]
                }
            )
            with patch("graph_analysis.dependencies.osv.OSVClient", FakeOSVClient):
                payload = map_vulnerabilities(graph, metadata, cache_dir=Path(tmp) / "cache")
            self.assertEqual(payload["vulnerability_count"], 1)
            self.assertTrue((metadata / "vulnerabilities.json").exists())
            self.assertTrue((metadata / "vulnerabilities.csv").exists())


if __name__ == "__main__":
    unittest.main()
