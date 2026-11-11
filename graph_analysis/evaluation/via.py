"""Readers for the VIA dataset (not distributed with this repository).

* ``Triad.csv`` (no header): CVE, vulnerable component, downstream component,
  and a JSON list of dependency chains, each from the downstream package
  version to the vulnerable package version (``name@version`` strings).
* ``VUL_FUNs.csv``: CVE -> vulnerable functions (read by ``analysis/vulnfuncs``).
* ``AnalyzeRes/`` (optional): VIA's call-graph validation results, one JSON file
  per ``CVE@vulnerable@version@downstream@version``; used to identify the
  VIA-confirmed subset.
"""
from __future__ import annotations

import csv
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator


Chain = tuple[str, ...]


@dataclass(frozen=True)
class ViaRecord:
    cve: str
    vulnerable: str
    downstream: str
    chains: tuple[Chain, ...]


def iter_triad(path: Path, roots: set[str] | None = None) -> Iterator[ViaRecord]:
    csv.field_size_limit(sys.maxsize)
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.reader(handle):
            if len(row) < 4 or not row[0].upper().startswith("CVE-"):
                continue
            cve, vulnerable, downstream, raw_chains = row[0].strip().upper(), row[1].strip(), row[2].strip(), row[3]
            if roots is not None and downstream not in roots:
                continue
            try:
                parsed = json.loads(raw_chains)
            except json.JSONDecodeError:
                continue
            chains = tuple(
                tuple(str(node) for node in chain)
                for chain in parsed
                if isinstance(chain, list) and len(chain) >= 2
            )
            if chains:
                yield ViaRecord(cve, vulnerable, downstream, chains)


def split_component(component: str) -> tuple[str, str]:
    name, _, version = component.rpartition("@")
    return name, version


def confirmed_chain_cves(
    analyze_res: Path | None, associations: Iterable[tuple[Chain, str]]
) -> set[tuple[Chain, str]]:
    """Associations whose exact chain VIA validated with a call path at every boundary."""
    if analyze_res is None or not analyze_res.is_dir():
        return set()
    confirmed: set[tuple[Chain, str]] = set()
    for chain, cve in associations:
        downstream, downstream_version = split_component(chain[0])
        vulnerable, vulnerable_version = split_component(chain[-1])
        result_file = analyze_res / f"{cve}@{vulnerable}@{vulnerable_version}@{downstream}@{downstream_version}"
        if not result_file.is_file():
            continue
        try:
            payload = json.loads(result_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        versions = payload.get("Versionmap", {})
        for index, dependency_path in enumerate(payload.get("dependency_path", [])):
            candidate = tuple(f"{name}@{versions.get(name)}" for name in dependency_path)
            if candidate != chain:
                continue
            boundaries = payload.get("fun_reachable_info", {}).get(str(index), {})
            if len(boundaries) == len(chain) - 1 and all(item.get("path") for item in boundaries.values()):
                confirmed.add((chain, cve))
            break
    return confirmed
