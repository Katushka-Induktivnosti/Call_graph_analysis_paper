"""Map CVEs to vulnerable functions and locate them in dependency sources.

The mapping file is supplied by the user. Accepted formats:

* CSV with a header containing ``cve`` and ``functions`` (or ``function``)
  and, optionally, ``package`` to restrict a row to one distribution;
* header-less two-column CSV ``CVE,func1;func2;...`` (the layout of the
  public VIA ``VUL_FUNs.csv`` file);
* JSON: a list of objects with the same keys (``functions`` may be a list).

Function names may use dotted (``pkg.mod.Class.method``) or path-style
(``src/pkg/mod.Class.method``) notation; they are normalised during
resolution. A row applies to a vulnerable dependency when its CVE equals the
OSV id or one of its aliases.
"""
from __future__ import annotations

import csv
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .symbols import CALLABLE_KINDS, CONFIRMED_STATUSES, ComponentResolver, collect_symbols, package_import_roots


@dataclass(frozen=True)
class MappingRow:
    cve: str
    function: str
    package: str = ""


def load_mapping(path: Path) -> list[MappingRow]:
    text = path.read_text(encoding="utf-8-sig")
    if path.suffix.lower() == ".json":
        records = json.loads(text)
        if isinstance(records, dict):
            records = records.get("rows") or records.get("mapping_rows") or []
    else:
        csv.field_size_limit(1 << 30)
        rows = list(csv.reader(text.splitlines()))
        if not rows:
            return []
        header = [cell.strip().lower() for cell in rows[0]]
        if "cve" in header and ({"functions", "function"} & set(header)):
            records = [dict(zip(header, row)) for row in rows[1:]]
        else:
            records = [{"cve": row[0], "functions": row[1]} for row in rows if len(row) >= 2]

    result: set[MappingRow] = set()
    for record in records:
        cve = str(record.get("cve") or "").strip().upper()
        functions = record.get("functions", record.get("function", ""))
        if isinstance(functions, str):
            functions = functions.split(";")
        package = normalize_package(str(record.get("package") or ""))
        for function in functions or []:
            function = str(function).strip()
            if cve and function:
                result.add(MappingRow(cve=cve, function=function, package=package))
    return sorted(result, key=lambda row: (row.cve, row.package, row.function))


def normalize_package(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value.strip()).lower()


def vulnerability_ids(record: dict[str, Any]) -> set[str]:
    ids = {str(record.get("id") or "").upper()}
    ids.update(str(alias).upper() for alias in record.get("aliases") or [])
    ids.discard("")
    return ids


def match_mapping(
    package: str,
    vulnerabilities: list[dict[str, Any]],
    mapping: list[MappingRow],
) -> list[dict[str, str]]:
    """Return {cve, osv_id, function} rows that apply to one vulnerable dependency."""
    key = normalize_package(package)
    by_cve: dict[str, list[MappingRow]] = {}
    for row in mapping:
        if not row.package or row.package == key:
            by_cve.setdefault(row.cve, []).append(row)
    matches: dict[tuple[str, str], dict[str, str]] = {}
    for record in vulnerabilities:
        osv_id = str(record.get("id") or "")
        for identifier in sorted(vulnerability_ids(record)):
            for row in by_cve.get(identifier, []):
                matches.setdefault(
                    (row.cve, row.function),
                    {"cve": row.cve, "osv_id": osv_id, "function": row.function},
                )
    return [matches[item] for item in sorted(matches)]


def locate_functions(
    package: str,
    repo_root: Path,
    function_index: dict[str, Any],
    candidates: list[dict[str, str]],
) -> list[dict[str, Any]]:
    """Resolve each candidate function to a declaration (file and line) in the package source."""
    symbols = collect_symbols(repo_root, function_index)
    resolver = ComponentResolver(
        symbols, package_import_roots(package, repo_root, symbols), source_available=True
    )
    located = []
    for candidate in candidates:
        resolution = resolver.resolve(candidate["function"])
        confirmed = (
            resolution.get("resolution_status") in CONFIRMED_STATUSES
            and resolution.get("symbol_kind") in CALLABLE_KINDS
        )
        located.append(
            {
                **candidate,
                "confirmed": confirmed,
                "resolution_status": resolution.get("resolution_status"),
                "resolution_method": resolution.get("resolution_method"),
                "symbol_kind": resolution.get("symbol_kind"),
                "canonical_name": resolution.get("canonical_name"),
                "source_file": resolution.get("source_file"),
                "start_line": resolution.get("start_line"),
                "alternate_candidates": resolution.get("alternate_candidates"),
                "reason": resolution.get("reason"),
            }
        )
    return located
