"""Sample downstream package versions from VIA (Section 5.1).

The unit of sampling is a downstream package version (the root p0 of one
analysed graph). Roots are taken in the chosen order and all their VIA chains
are added until the package versions on the selected chains cover the target
fraction of all package versions that occur in VIA chains.

``order="file"`` walks roots in Triad.csv order (deterministic, no seed);
``order="random"`` shuffles roots with ``seed`` first.
"""
from __future__ import annotations

import math
import random
from pathlib import Path
from typing import Any

from .via import iter_triad


def select_sample(triad: Path, fraction: float, order: str = "file", seed: int = 0) -> dict[str, Any]:
    if not 0 < fraction <= 1:
        raise ValueError("fraction must be in (0, 1]")
    if order not in {"file", "random"}:
        raise ValueError("order must be 'file' or 'random'")
    universe: set[str] = set()
    nodes_by_root: dict[str, set[str]] = {}
    root_order: list[str] = []
    for record in iter_triad(triad):
        if record.downstream not in nodes_by_root:
            nodes_by_root[record.downstream] = set()
            root_order.append(record.downstream)
        for chain in record.chains:
            universe.update(chain)
            nodes_by_root[record.downstream].update(chain)
    if order == "random":
        random.Random(seed).shuffle(root_order)
    target = math.ceil(len(universe) * fraction)
    covered: set[str] = set()
    selected: list[str] = []
    for root in root_order:
        if len(covered) >= target:
            break
        selected.append(root)
        covered.update(nodes_by_root[root])
    return {
        "schema_version": 1,
        "method": {
            "unit": "downstream package version",
            "order": order,
            "seed": seed if order == "random" else None,
            "target_fraction": fraction,
            "rule": "add all VIA chains of each root until the covered package versions reach the target",
        },
        "via_package_versions": len(universe),
        "via_downstream_versions": len(root_order),
        "covered_package_versions": len(covered),
        "covered_fraction": len(covered) / len(universe) if universe else 0.0,
        "roots": selected,
    }
