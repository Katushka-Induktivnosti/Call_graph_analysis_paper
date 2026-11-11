"""Evaluation procedure and measures (Sections 5.2 and 5.3).

Step 1  Every package version on the sampled VIA chains is processed once by
        B1-B4; its graph is cached by package version (``--work``).
Step 2  For every VIA record, the cached graphs of the packages on the record's
        own chain form the chain subgraph on which dependency exposure (A1) and
        static reachability (A2) are evaluated.
Step 3  Results are compared with VIA (correctness, RQ2) and with the A1
        baseline (utility, RQ3); coverage measures address RQ1.

Units: package versions P, VIA dependency chains H, chain-CVE associations A,
and vulnerable-function records (an association paired with one vulnerable
function of its CVE).
"""
from __future__ import annotations

import csv
import statistics
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..analysis.combine import ROOT_ENTRY_KIND, CombinedChain, PackageGraph, combine_chain
from ..analysis.names import is_production_name
from ..analysis.vulnfuncs import load_mapping, match_mapping, vulnerability_ids
from ..callgraph.project import CallGraphOptions
from ..callgraph.utils import print_step, read_json, write_json
from ..dependencies.common import CACHE_DIR, normalize_package_name
from ..dependencies.dependency_resolver import PROJECT_NODE, DependencyResolver
from ..dependencies.osv import map_vulnerabilities
from ..dependencies.pypi import PyPIClient
from ..pipeline import a2_static_reachability, b2_source_analysis, b4_vulnerability_mapping, safe_name
from .via import Chain, confirmed_chain_cves, iter_triad, split_component

# First failing construction step (Table 7), in the order of Section 5.3.2.
DEPENDENCY_STEP = "dependency_reconstruction"
ENTRY_STEP = "entry_point_detection"
CALL_STEP = "call_resolution"
VULNERABILITY_STEP = "vulnerability_mapping"
CAUSE_STEP = {
    "no_package_name_path": DEPENDENCY_STEP,
    "exact_version_mismatch": DEPENDENCY_STEP,
    "no_production_entry_point": ENTRY_STEP,
    "chain_package_without_graph": CALL_STEP,
    "internal_path_gap": CALL_STEP,
    "no_cross_package_edge": CALL_STEP,
    "unresolved_receiver": CALL_STEP,
    "no_advisory_for_component": VULNERABILITY_STEP,
    "vulnerable_function_not_located": VULNERABILITY_STEP,
}
# When an association has several vulnerable functions (or a chain several
# associations) that fail in call resolution, the cause of the case that got
# furthest is reported.
CALL_CAUSE_PRIORITY = (
    "internal_path_gap",
    "unresolved_receiver",
    "no_cross_package_edge",
    "vulnerable_function_not_located",
    "no_advisory_for_component",
    "chain_package_without_graph",
)


@dataclass
class EvaluationConfig:
    triad: Path
    vulnerable_functions: Path
    sample: Path
    work: Path
    output: Path
    cutoff: str
    analyze_res: Path | None = None
    advisory_source: str = "osv"
    max_dependency_depth: int = 20
    cache_dir: Path = CACHE_DIR
    refresh_cache: bool = False
    callgraph: CallGraphOptions = field(default_factory=lambda: CallGraphOptions(skip_codeql=True))


def run_evaluation(config: EvaluationConfig) -> dict[str, Any]:
    if config.advisory_source not in {"osv", "via"}:
        raise ValueError("advisory_source must be 'osv' or 'via'")
    sample = read_json(config.sample)
    roots = list(sample["roots"])
    associations: dict[Chain, set[str]] = {}
    for record in iter_triad(config.triad, set(roots)):
        for chain in record.chains:
            associations.setdefault(chain, set()).add(record.cve)
    chains = sorted(associations)
    pairs = [(chain, cve) for chain in chains for cve in sorted(associations[chain])]
    packages = sorted({component for chain in chains for component in chain})
    mapping = load_mapping(config.vulnerable_functions)
    print_step(f"sample: {len(roots)} roots, {len(chains)} chains, {len(pairs)} associations, {len(packages)} package versions")

    # Step 1: B1-B4 once per package version, cached.
    pypi = PyPIClient(cache_dir=config.cache_dir / "pypi_json", refresh_cache=config.refresh_cache)
    graphs: dict[str, PackageGraph] = {}
    statuses: dict[str, dict[str, Any]] = {}
    for index, component in enumerate(packages, 1):
        status, graph, _bundle = b2_source_analysis(
            component,
            config.work / "graphs" / safe_name(component),
            config.callgraph,
            source_dir=config.work / "sources" / safe_name(component),
            pypi=pypi,
            cache_dir=config.cache_dir,
            reuse=True,
        )
        statuses[component] = status
        if graph is not None:
            graphs[component] = graph
        if index % 100 == 0 or index == len(packages):
            print_step(f"B2: {index}/{len(packages)} package versions")
    dependency_graphs = resolve_root_dependencies(config, roots, statuses)
    advisories = component_advisories(config, chains, associations)
    located = locate_vulnerable_functions(chains, associations, advisories, mapping, graphs)
    confirmed = confirmed_chain_cves(config.analyze_res, pairs)

    # Steps 2 and 3: chain subgraphs, analyses, comparison with VIA.
    rows = []
    combined_cache: dict[Chain, CombinedChain | None] = {}
    for index, chain in enumerate(chains, 1):
        name_ok, exact_ok = chain_recovery(dependency_graphs.get(chain[0]), chain)
        complete = all(component in graphs for component in chain)
        combined = combined_cache.setdefault(chain, combine_chain(list(chain), graphs) if complete else None)
        root_graph = graphs.get(chain[0])
        for cve in sorted(associations[chain]):
            rows.append(
                evaluate_association(
                    chain, cve, name_ok, exact_ok, combined, root_graph, graphs,
                    advisories, located, mapping, confirmed,
                )
            )
        if index % 1000 == 0 or index == len(chains):
            print_step(f"analysed {index}/{len(chains)} chains")

    measures = compute_measures(sample, packages, chains, rows, graphs, statuses, combined_cache)
    config.output.mkdir(parents=True, exist_ok=True)
    write_json(config.output / "measures.json", measures)
    write_association_rows(config.output / "associations.csv", rows)
    (config.output / "tables.md").write_text(render_tables(measures), encoding="utf-8")
    print_step(f"wrote {config.output / 'measures.json'}")
    return measures


# -- Step 1 helpers ------------------------------------------------------------


def resolve_root_dependencies(
    config: EvaluationConfig, roots: list[str], statuses: dict[str, dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    """B1 for every sampled root, with publication cutoff t0."""
    result: dict[str, dict[str, Any]] = {}
    for root in roots:
        out_dir = config.work / "dependencies" / safe_name(root)
        cached = out_dir / "dependency_graph.json"
        if cached.is_file():
            result[root] = read_json(cached)
            continue
        source_root = statuses.get(root, {}).get("source_root")
        if not source_root:
            continue
        resolver = DependencyResolver(
            cutoff=config.cutoff,
            cache_dir=config.cache_dir,
            max_depth=config.max_dependency_depth,
            refresh_cache=config.refresh_cache,
        )
        result[root] = resolver.resolve_project(Path(source_root), out_dir)
    return result


def component_advisories(
    config: EvaluationConfig, chains: list[Chain], associations: dict[Chain, set[str]]
) -> dict[str, list[dict[str, Any]]]:
    """Advisories (U) and R_UC for every vulnerable component c_h."""
    vulnerable = sorted({chain[-1] for chain in chains})
    if config.advisory_source == "via":
        cves: dict[str, set[str]] = {}
        for chain in chains:
            cves.setdefault(chain[-1], set()).update(associations[chain])
        return {component: [{"id": cve, "aliases": []} for cve in sorted(values)] for component, values in cves.items()}
    nodes = []
    for component in vulnerable:
        name, version = split_component(component)
        nodes.append({"name": name, "normalized_name": normalize_package_name(name), "version": version})
    payload = map_vulnerabilities({"nodes": nodes}, config.work / "advisories", config.cache_dir)
    return {
        f"{item['package']}@{item['version']}": item["vulnerabilities"]
        for item in payload["vulnerable_dependencies"]
    }


def locate_vulnerable_functions(
    chains: list[Chain],
    associations: dict[Chain, set[str]],
    advisories: dict[str, list[dict[str, Any]]],
    mapping: list[Any],
    graphs: dict[str, PackageGraph],
) -> dict[tuple[str, str], list[dict[str, Any]]]:
    """B4: R_UF for every (vulnerable component, CVE) that has an advisory (R_UC)."""
    cves_by_component: dict[str, set[str]] = {}
    for chain in chains:
        cves_by_component.setdefault(chain[-1], set()).update(associations[chain])
    result: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for component, cves in sorted(cves_by_component.items()):
        if component not in graphs:
            continue
        package, _version = split_component(component)
        records = [
            record
            for record in advisories.get(component, [])
            if vulnerability_ids(record) & cves
        ]
        for row in b4_vulnerability_mapping(package, records, mapping, graphs[component]):
            if row["cve"] in cves:
                result.setdefault((component, row["cve"]), []).append(row)
    return result


# -- Step 2 / 3 ----------------------------------------------------------------


def chain_recovery(dependency_graph: dict[str, Any] | None, chain: Chain) -> tuple[bool, bool]:
    """Package-name and exact-version recovery of one VIA chain in D."""
    if not dependency_graph:
        return False, False
    versions = {node["id"]: node["version"] for node in dependency_graph.get("nodes", [])}
    edges = {(edge["from"], edge["to"]) for edge in dependency_graph.get("edges", [])}
    keys = [PROJECT_NODE] + [normalize_package_name(split_component(c)[0]) for c in chain[1:]]
    name_ok = all((keys[i], keys[i + 1]) in edges for i in range(len(keys) - 1))
    exact_ok = name_ok and all(
        versions.get(keys[i]) == split_component(chain[i])[1] for i in range(1, len(chain))
    )
    return name_ok, exact_ok


def has_production_endpoint(graph: PackageGraph | None) -> bool:
    return bool(graph) and any(
        graph.function_kinds.get(name) != "class"
        and is_production_name(name, graph.function_files.get(name, ""))
        for name in graph.functions
    )


def evaluate_association(
    chain: Chain,
    cve: str,
    name_ok: bool,
    exact_ok: bool,
    combined: CombinedChain | None,
    root_graph: PackageGraph | None,
    graphs: dict[str, PackageGraph],
    advisories: dict[str, list[dict[str, Any]]],
    located: dict[tuple[str, str], list[dict[str, Any]]],
    mapping: list[Any],
    confirmed: set[tuple[Chain, str]],
) -> dict[str, Any]:
    component = chain[-1]
    package, _version = split_component(component)
    has_uc = any(cve in vulnerability_ids(record) for record in advisories.get(component, []))
    functions = located.get((component, cve), [])
    mapped = match_mapping(package, [{"id": cve, "aliases": []}], mapping)
    records = []
    if exact_ok and combined is not None and has_production_endpoint(root_graph):
        for function in functions:
            trace = a2_static_reachability(combined, chain[0], graphs, component, function)
            records.append(
                {
                    "function": function["function"],
                    "located": bool(function.get("confirmed")),
                    "trace_status": trace["trace_status"],
                    "path_found": bool(trace.get("path_found")),
                    "path_edge_count": trace.get("path_edge_count", 0),
                    "endpoint_tier": trace.get("endpoint_tier", ""),
                    "all_edges_from_pycg": bool(trace.get("all_edges_from_pycg")),
                }
            )
    strict = any(record["path_found"] for record in records)
    cause = ""
    if not strict:
        if not name_ok:
            cause = "no_package_name_path"
        elif not exact_ok:
            cause = "exact_version_mismatch"
        elif not has_production_endpoint(root_graph):
            cause = "no_production_entry_point"
        elif combined is None:
            cause = "chain_package_without_graph"
        elif not has_uc:
            cause = "no_advisory_for_component"
        elif not any(function.get("confirmed") for function in functions):
            cause = "vulnerable_function_not_located"
        else:
            statuses = {
                "vulnerable_function_not_located" if record["trace_status"] in {"not_located", "not_in_call_graph"}
                else record["trace_status"]
                for record in records
            }
            cause = next((c for c in CALL_CAUSE_PRIORITY if c in statuses), "internal_path_gap")
    return {
        "chain": chain,
        "cve": cve,
        "chain_length": len(chain),
        "name_recovered": name_ok,
        "exact_recovered": exact_ok,
        "via_confirmed": (chain, cve) in confirmed,
        "root_has_entry_point": bool(
            root_graph and any(entry["kind"] != ROOT_ENTRY_KIND for entry in root_graph.entries.values())
        ),
        "chain_has_cross_package_edge": bool(combined and combined.bridges),
        "has_r_uc": has_uc,
        "has_r_uf": any(function.get("confirmed") for function in functions),
        "mapped_functions": len(mapped),
        "located_functions": sum(bool(function.get("confirmed")) for function in functions),
        "function_records": records,
        "strict": strict,
        "first_failing_cause": cause,
        "first_failing_step": CAUSE_STEP.get(cause, ""),
    }


# -- Measures -------------------------------------------------------------------


def ratio(numerator: int, denominator: int) -> dict[str, Any]:
    return {"count": numerator, "total": denominator, "rate": numerator / denominator if denominator else None}


def compute_measures(
    sample: dict[str, Any],
    packages: list[str],
    chains: list[Chain],
    rows: list[dict[str, Any]],
    graphs: dict[str, PackageGraph],
    statuses: dict[str, dict[str, Any]],
    combined: dict[Chain, CombinedChain | None],
) -> dict[str, Any]:
    by_chain: dict[Chain, list[dict[str, Any]]] = {}
    for row in rows:
        by_chain.setdefault(row["chain"], []).append(row)

    def chain_set(predicate) -> set[Chain]:
        return {chain for chain, items in by_chain.items() if any(predicate(item) for item in items)}

    with_functions = {c for c, g in graphs.items() if g.functions}
    with_calls = {c for c, g in graphs.items() if any(e["resolved"] and e["kind"] != "decorator_application" for e in g.typed_edges)}
    name_chains = chain_set(lambda r: r["name_recovered"])
    exact_chains = chain_set(lambda r: r["exact_recovered"])
    strict_chains = chain_set(lambda r: r["strict"])
    name_rows = [r for r in rows if r["name_recovered"]]
    exact_rows = [r for r in rows if r["exact_recovered"]]
    strict_rows = [r for r in rows if r["strict"]]
    confirmed_rows = [r for r in rows if r["via_confirmed"]]
    confirmed_chains = {r["chain"] for r in confirmed_rows}
    confirmed_strict_chains = {r["chain"] for r in confirmed_rows if r["strict"]}

    def reduction(subset: list, baseline: list) -> float | None:
        return 1 - len(subset) / len(baseline) if baseline else None

    failing_rows = Counter(r["first_failing_cause"] for r in rows if not r["strict"])
    failing_chains: Counter[str] = Counter()
    for chain, items in by_chain.items():
        if any(item["strict"] for item in items):
            continue
        causes = {item["first_failing_cause"] for item in items}
        order = ["no_package_name_path", "exact_version_mismatch", "no_production_entry_point", *CALL_CAUSE_PRIORITY]
        failing_chains[next(c for c in order if c in causes)] += 1

    records = [record for row in rows for record in row["function_records"]]
    reached = [record for record in records if record["path_found"]]
    total_records = sum(row["mapped_functions"] for row in rows)
    cves = {row["cve"] for row in rows}
    cves_reached = {row["cve"] for row in rows if row["strict"]}
    lengths = [record["path_edge_count"] for record in reached]
    cpu = [float(statuses[c].get("build_cpu_seconds", 0) or 0) for c in packages if c in statuses]
    wall = [float(statuses[c].get("build_wall_seconds", 0) or 0) for c in packages if c in statuses]
    component_status = Counter(
        item["status"] for c in packages for item in statuses.get(c, {}).get("status", [])
    )

    return {
        "schema_version": 1,
        "table3_sample": {
            "complete_via_population_package_versions": sample.get("via_package_versions"),
            "covered_package_versions": len(packages),
            "with_function_nodes": len(with_functions),
            "with_call_edges": len(with_calls),
            "sampled_downstream_versions": len({chain[0] for chain in chains}),
            "dependency_chains": len(chains),
            "chain_cve_associations": len(rows),
            "cves": len(cves),
            "via_confirmed_chains": len(confirmed_chains),
            "via_confirmed_associations": len(confirmed_rows),
            "chains_without_strict_path": len(chains) - len(strict_chains),
        },
        "table5_coverage": {
            "Cov_D_exact_version_chain_in_D": ratio(len(exact_chains), len(chains)),
            "Cov_F_function_nodes": ratio(len(with_functions), len(packages)),
            "Cov_K_call_edges": ratio(len(with_calls), len(packages)),
            "Cov_entry_entry_point": ratio(len(chain_set(lambda r: r["root_has_entry_point"])), len(chains)),
            "Cov_B_cross_package_call": ratio(len(chain_set(lambda r: r["chain_has_cross_package_edge"])), len(chains)),
            "Cov_UC_cve_to_component": ratio(sum(r["has_r_uc"] for r in rows), len(rows)),
            "Cov_UF_cve_to_function": ratio(sum(r["has_r_uf"] for r in rows), len(rows)),
        },
        "table6_recovery": {
            "package_names": {"chains": ratio(len(name_chains), len(chains)), "associations": ratio(len(name_rows), len(rows))},
            "exact_versions": {
                "chains": ratio(len(exact_chains), len(chains)),
                "associations": ratio(len(exact_rows), len(rows)),
                "reduction_vs_package_names_chains": reduction(sorted(exact_chains), sorted(name_chains)),
                "reduction_vs_package_names_associations": reduction(exact_rows, name_rows),
            },
            "strict_static_path": {
                "chains": ratio(len(strict_chains), len(chains)),
                "associations": ratio(len(strict_rows), len(rows)),
                "reduction_vs_exact_versions_chains": reduction(sorted(strict_chains), sorted(exact_chains)),
                "reduction_vs_exact_versions_associations": reduction(strict_rows, exact_rows),
                "reduction_vs_package_names_chains": reduction(sorted(strict_chains), sorted(name_chains)),
                "reduction_vs_package_names_associations": reduction(strict_rows, name_rows),
            },
            "via_confirmed_recall": {
                "chains": ratio(len(confirmed_strict_chains), len(confirmed_chains)),
                "associations": ratio(sum(r["strict"] for r in confirmed_rows), len(confirmed_rows)),
            },
        },
        "table7_first_failing_step": {
            "chains": dict(sorted(failing_chains.items())),
            "associations": dict(sorted(failing_rows.items())),
            "cause_to_step": CAUSE_STEP,
        },
        "function_level": {
            "vulnerable_function_records": total_records,
            "records_with_strict_path": len(reached),
            "records_with_pycg_only_path": sum(record["all_edges_from_pycg"] for record in reached),
            "records_from_declared_entry_points": sum(record["endpoint_tier"] == "declared_entry_point" for record in reached),
            "cves": len(cves),
            "cves_with_strict_path": len(cves_reached),
            "path_edges_median": statistics.median(lengths) if lengths else None,
            "path_edges_max": max(lengths) if lengths else None,
        },
        "construction": {
            "component_status_counts": dict(sorted(component_status.items())),
            "chain_subgraphs": sum(value is not None for value in combined.values()),
            "cpu_hours": sum(cpu) / 3600,
            "median_cpu_seconds_per_package": statistics.median(cpu) if cpu else None,
            "median_wall_seconds_per_package": statistics.median(wall) if wall else None,
        },
    }


ROW_FIELDS = [
    "chain", "cve", "chain_length", "name_recovered", "exact_recovered", "via_confirmed",
    "root_has_entry_point", "chain_has_cross_package_edge", "has_r_uc", "has_r_uf",
    "mapped_functions", "located_functions", "strict", "first_failing_step", "first_failing_cause",
]


def write_association_rows(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=ROW_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({**row, "chain": " -> ".join(row["chain"])})


def render_tables(measures: dict[str, Any]) -> str:
    def pct(item: dict[str, Any]) -> str:
        rate = item.get("rate")
        return f"{item['count']:,} ({rate:.0%})" if rate is not None else f"{item['count']:,}"

    lines = ["# Evaluation tables", "", "## Table 3 (sample)", ""]
    for key, value in measures["table3_sample"].items():
        lines.append(f"- {key}: {value}")
    lines += ["", "## Table 5 (coverage)", "", "| Measure | Coverage |", "|---|---:|"]
    for key, value in measures["table5_coverage"].items():
        lines.append(f"| {key} | {pct(value)} |")
    recovery = measures["table6_recovery"]
    lines += ["", "## Table 6 (recovery)", "", "| Query | Chains | Associations |", "|---|---:|---:|"]
    for key in ("package_names", "exact_versions", "strict_static_path", "via_confirmed_recall"):
        lines.append(f"| {key} | {pct(recovery[key]['chains'])} | {pct(recovery[key]['associations'])} |")
    failing = measures["table7_first_failing_step"]
    lines += ["", "## Table 7 (first failing step)", "", "| Cause | Step | Chains | Associations |", "|---|---|---:|---:|"]
    for cause in sorted(set(failing["chains"]) | set(failing["associations"])):
        lines.append(
            f"| {cause} | {failing['cause_to_step'].get(cause, '')} | "
            f"{failing['chains'].get(cause, 0):,} | {failing['associations'].get(cause, 0):,} |"
        )
    lines += ["", "## Function level and construction", ""]
    for section in ("function_level", "construction"):
        for key, value in measures[section].items():
            lines.append(f"- {key}: {value}")
    return "\n".join(lines) + "\n"
