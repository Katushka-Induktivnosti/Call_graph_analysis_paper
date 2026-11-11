from __future__ import annotations

from pathlib import Path
from typing import Any

from .common import CACHE_DIR, read_json, utc_now, write_csv, write_json, write_jsonl
from .http_client import HttpClient


class OSVClient:
    def __init__(self, cache_dir: Path = CACHE_DIR / "osv") -> None:
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.http = HttpClient(default_headers={"Accept": "application/json"})

    def query_batch(self, packages: list[dict[str, str]], batch_size: int = 100) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for start in range(0, len(packages), batch_size):
            batch = packages[start : start + batch_size]
            payload = {
                "queries": [
                    {
                        "version": item["version"],
                        "package": {"name": item["name"], "ecosystem": "PyPI"},
                    }
                    for item in batch
                ]
            }
            response = self.http.request_json("https://api.osv.dev/v1/querybatch", method="POST", payload=payload)
            for package, result in zip(batch, response.get("results", []), strict=False):
                results.append({"package": package, "result": result})
        return results

    def vulnerability(self, vuln_id: str) -> dict[str, Any]:
        safe = vuln_id.replace("/", "_")
        path = self.cache_dir / f"{safe}.json"
        if path.exists():
            return read_json(path)["payload"]
        payload = self.http.request_json(f"https://api.osv.dev/v1/vulns/{vuln_id}")
        write_json(path, {"id": vuln_id, "fetched_at": utc_now(), "payload": payload})
        return payload


def map_vulnerabilities(graph: dict[str, Any], metadata_dir: Path, cache_dir: Path = CACHE_DIR) -> dict[str, Any]:
    """Query OSV for every resolved dependency version in ``graph``."""
    packages = [
        {"name": node["name"], "normalized_name": node["normalized_name"], "version": node["version"]}
        for node in graph.get("nodes", [])
        if node.get("version")
    ]
    client = OSVClient(cache_dir=cache_dir / "osv")
    warnings: list[str] = []
    vulnerable_dependencies: list[dict[str, Any]] = []
    row_records: list[dict[str, Any]] = []
    full_records: dict[str, dict[str, Any]] = {}

    try:
        batch_results = client.query_batch(packages)
    except Exception as exc:
        warnings.append(f"OSV querybatch failed: {exc}")
        batch_results = []

    for item in batch_results:
        package = item["package"]
        vuln_refs = item.get("result", {}).get("vulns", []) or []
        if not vuln_refs:
            continue
        vulns: list[dict[str, Any]] = []
        for ref in vuln_refs:
            vuln_id = ref["id"]
            try:
                record = client.vulnerability(vuln_id)
            except Exception as exc:
                warnings.append(f"failed to fetch OSV record {vuln_id}: {exc}")
                record = {"id": vuln_id, "fetch_error": str(exc)}
            full_records[vuln_id] = record
            vulns.append(record)
            row_records.append(
                {
                    "package": package["name"],
                    "normalized_name": package["normalized_name"],
                    "version": package["version"],
                    "vulnerability_id": vuln_id,
                    "aliases": ",".join(record.get("aliases", []) or []),
                    "summary": record.get("summary") or "",
                    "published": record.get("published") or "",
                    "modified": record.get("modified") or ref.get("modified") or "",
                    "severity": _severity_summary(record),
                }
            )
        vulnerable_dependencies.append(
            {
                "package": package["name"],
                "normalized_name": package["normalized_name"],
                "version": package["version"],
                "vulnerabilities": vulns,
            }
        )

    payload = {
        "generated_at": utc_now(),
        "source_graph": "dependency_graph.json",
        "dependencies_scanned": len(packages),
        "vulnerable_dependency_count": len(vulnerable_dependencies),
        "vulnerability_count": len(row_records),
        "vulnerable_dependencies": vulnerable_dependencies,
        "vulnerability_records": full_records,
        "warnings": warnings,
    }
    write_json(metadata_dir / "vulnerabilities.json", payload)
    write_jsonl(metadata_dir / "vulnerabilities.jsonl", row_records)
    write_csv(
        metadata_dir / "vulnerabilities.csv",
        row_records,
        ["package", "normalized_name", "version", "vulnerability_id", "aliases", "summary", "published", "modified", "severity"],
    )
    return payload


def _severity_summary(record: dict[str, Any]) -> str:
    severity = record.get("severity") or []
    if not severity:
        return ""
    return ",".join(f"{item.get('type')}:{item.get('score')}" for item in severity)
