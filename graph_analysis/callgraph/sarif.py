from __future__ import annotations

import urllib.parse
from pathlib import Path
from typing import Any


def load_codeql_alerts(sarif_path: Path, repo_root: Path, function_index: dict[str, Any]) -> list[dict[str, Any]]:
    import json

    if not sarif_path.exists():
        return []
    payload = json.loads(sarif_path.read_text(encoding="utf-8"))
    alerts: list[dict[str, Any]] = []
    rules = _collect_rules(payload)
    for run in payload.get("runs", []):
        for result in run.get("results", []):
            rule_id = result.get("ruleId") or result.get("rule", {}).get("id") or "codeql-alert"
            locations = result.get("locations") or []
            if not locations:
                continue
            loc = locations[0].get("physicalLocation", {})
            artifact = loc.get("artifactLocation", {})
            region = loc.get("region", {})
            rel_file = _normalize_uri(artifact.get("uri", ""), repo_root)
            start_line = int(region.get("startLine") or 1)
            target = _find_target(rel_file, start_line, function_index)
            rule = rules.get(rule_id, {})
            alerts.append(
                {
                    "id": f"{rule_id}:{rel_file}:{start_line}:{len(alerts)}",
                    "rule_id": rule_id,
                    "level": result.get("level", "warning"),
                    "message": result.get("message", {}).get("text", ""),
                    "rule_name": rule.get("name", ""),
                    "rule_description": rule.get("shortDescription", {}).get("text", ""),
                    "file": rel_file,
                    "start_line": start_line,
                    "end_line": int(region.get("endLine") or start_line),
                    "target_type": target["type"],
                    "target": target["id"],
                    "module": target["module"],
                }
            )
    return alerts


def _collect_rules(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rules: dict[str, dict[str, Any]] = {}
    for run in payload.get("runs", []):
        driver = run.get("tool", {}).get("driver", {})
        for rule in driver.get("rules", []):
            if rule.get("id"):
                rules[rule["id"]] = rule
    return rules


def _normalize_uri(uri: str, repo_root: Path) -> str:
    if not uri:
        return ""
    parsed = urllib.parse.urlparse(uri)
    path_text = urllib.parse.unquote(parsed.path if parsed.scheme == "file" else uri)
    path = Path(path_text)
    repo_resolved = repo_root.resolve()
    if path.is_absolute():
        try:
            return str(path.resolve().relative_to(repo_resolved))
        except ValueError:
            try:
                return str(path.relative_to(repo_resolved))
            except ValueError:
                return str(path)
    try:
        return str((repo_resolved / path_text).resolve().relative_to(repo_resolved))
    except (ValueError, OSError):
        return path_text.removeprefix("./")


def _find_target(rel_file: str, line: int, function_index: dict[str, Any]) -> dict[str, str]:
    candidates = [
        fn
        for fn in function_index.get("functions", {}).values()
        if fn.get("file") == rel_file and int(fn.get("start_line", 0)) <= line <= int(fn.get("end_line", 0))
    ]
    if candidates:
        fn = min(candidates, key=lambda item: int(item["end_line"]) - int(item["start_line"]))
        return {"type": "function", "id": fn["qualname"], "module": fn["module"]}
    for module in function_index.get("modules", {}).values():
        if module.get("file") == rel_file:
            return {"type": "module", "id": module["id"], "module": module["id"]}
    return {"type": "module", "id": rel_file, "module": rel_file}

