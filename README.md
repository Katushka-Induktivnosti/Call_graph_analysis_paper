# Unifying dependency and call-graph evidence to trace vulnerability propagation

Artifact for the paper *Unifying Dependency and Call Graphs to Trace Vulnerability Reachabilityn*. It contains the framework of
Section 4 for Python/PyPI and the evaluation procedure of Section 5. **No
evaluation data is included**: the VIA dataset is obtained from its authors
(see [Data](#data)), and all graphs, reports and measures are produced by the
commands below.

## Where each part of the paper is implemented

| Paper | Code |
|---|---|
| §4.1 Graph schema G = (V, E), Table 1 | `graph_analysis/graph.py` (`EvidenceGraph`, written as `graph.json`) |
| §4.2.1 / §4.3.1 B1 Dependency Resolution | `graph_analysis/dependencies/` (`dependency_parser.py`, `dependency_resolver.py`, `pypi.py`, `packaging_compat.py`); `pipeline.b1_dependency_resolution` |
| §4.2.2 / §4.3.2 B2 Source Analysis | `graph_analysis/dependencies/source_collector.py`, `graph_analysis/callgraph/` (`ast_index.py` AST collector, `pycg_runner.py` + `pycg_shim.py` PyCG 0.0.8, `codeql_runner.py`, `sarif.py`); `pipeline.b2_source_analysis` |
| §4.2.3 / §4.3.3 B3 Cross-Component Resolution, entry points | `graph_analysis/analysis/combine.py` (`combine_chain`, `resolve_cross_package_targets`), `graph_analysis/analysis/entrypoints.py` |
| §4.2.4 / §4.3.4 B4 Vulnerability Mapping | `graph_analysis/dependencies/osv.py`, `graph_analysis/analysis/vulnfuncs.py`, `graph_analysis/analysis/symbols.py` |
| §4.4 Consistency rules | `graph.EvidenceGraph.check_consistency`; unique-match rules in `combine.resolve_cross_package_targets` and `symbols.ComponentResolver` |
| §4.5.1 A1 Dependency exposure | `pipeline.a1_dependency_exposure` |
| §4.5.2 A2 Static reachability (strict paths, endpoint tiers) | `pipeline.a2_static_reachability`, `combine.trace_to_entry` |
| §5.1 Sampling | `graph_analysis/evaluation/sample.py` |
| §5.2 Evaluation procedure, §5.3 measures (Tables 3, 5, 6, 7; RQ3 reduction) | `graph_analysis/evaluation/run.py`, `graph_analysis/evaluation/via.py` |

## Requirements

* Python ≥ 3.12 (tested with 3.14.6); the pinned packages in `requirements.txt`
  (`packaging` 26.2, `pycg` 0.0.8, `certifi`, `setuptools` 80.10.2 for PyCG's
  `pkg_resources` import)
* Optional: CodeQL CLI 2.25.4 with the `codeql/python-queries` pack, on `PATH`
  or set via `CODEQL_BIN`. Alerts only annotate the graph and are never
  reachability targets.
* Network access to `pypi.org` and `api.osv.dev` (responses are cached in
  `~/.cache/graph_analysis`, or `GRAPH_ANALYSIS_CACHE`)

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests -t .     # offline, < 1 s
```

## Analysing one application

```bash
.venv/bin/python -m graph_analysis run \
  --project path/to/application \
  --vulnerable-functions examples/vulnerable_functions.example.csv \
  --cutoff 2026-05-26T00:00:00Z \
  --output out
```

`--cutoff` is the publication cutoff t0 (default: now). `--max-chains-per-dependency`
(default 5) sets the number of shortest dependency chains per vulnerable
component, `--max-dependency-depth` (default 20) the resolution depth d_max,
`--pycg-timeout` (120 s) and `--max-pycg-iter` (3) the PyCG limits, and
`--skip-codeql` disables the optional CodeQL annotation. B2 builds call graphs
for packages on the selected chains (`--source-scope chains`, default) or for
every component (`--source-scope all`); analyses only query chain subgraphs, so
both give the same findings.

### Vulnerability-to-function mapping

OSV advisories do not name functions, so the mapping is an input: a CSV with
`cve`, `functions` (`;`-separated) and optional `package` columns, a
header-less `CVE,func1;func2` file in the layout of VIA's `VUL_FUNs.csv`, or
JSON with the same keys. A row applies to an advisory whose id or alias is the
CVE.

### Outputs

| File | Content |
|---|---|
| `graph.json` | the typed graph G: `nodes.{C,M,L,F,X,U}`, `edges.{D,O,K,K_X,B,A,R_UC,R_UF}`, schema version, provenance and status of every element |
| `report.json` | A1 `dependency_exposure`, A2 `findings`, entry points, per-component status, summary |
| `vulnerable_paths.csv` | one row per (vulnerable function, dependency chain) |
| `combined_graph.json`, `index.html` | interactive view: purple = vulnerable function, pink = strict path, red = CodeQL alert |
| `dependencies/`, `callgraphs/<component>/`, `sources/` | B1 output, per-package call graphs and B2 status, downloaded sources |

Element attributes in `graph.json`:

* **C**: name, version, `status`. Status values: `version_conflict`,
  `missing_release`, `unsupported_requirement` (B1), `download_failed`,
  `missing_release_artifact`, `no_python_sources`, `pycg_fallback`,
  `codeql_failed` (B2). Also the source artifact with its SHA-256.
* **M**: file, `role` (production/test/documentation/example), `parse_status`.
* **L / F**: qualified name, file, lines; `entry_point` (kind and rule) for F_entry.
* **X**: referenced name of an unresolved call.
* **U**: advisory id, aliases, CVEs.
* **D**: requirement, origin file, depth, `version_source` (`lock_file`,
  `exact_pin`, `registry_latest_before_cutoff`).
* **K / K_X / A**: call kind and `provenance` (`pycg`, `ast`, `pycg+ast`).
* **B**: resolution method (exact qualified name, public re-export, source
  layout, unique three-part suffix, constructor) and the chains it belongs to.
* **R_UF**: CVE, mapped name and resolution method.

Each A2 finding has `trace_status`, `endpoint_tier` (`declared_entry_point`,
`callgraph_root`, `local_function`), the directed `path`, per-edge type and
provenance, and `all_edges_from_pycg`. Status values for findings without a
path:

| Status | Meaning |
|---|---|
| `not_located` / `not_in_call_graph` | the mapped function does not resolve to a unique declaration / is not a call-graph node |
| `no_production_entry_point` | the root has no production function to start from |
| `no_cross_package_edge` | no call resolves across the chain's package boundaries |
| `unresolved_receiver` | the function is reachable only through a method call without a unique target |
| `internal_path_gap` | cross-package calls exist, but no directed route reaches the function |

## Evaluation against VIA (Sections 5 and 6)

```bash
# 1. Sample downstream package versions until their chains cover 20% of VIA
.venv/bin/python -m graph_analysis evaluate sample \
  --triad VIA/DataSet/Triad.csv --fraction 0.2 --order file --output sample.json
#    (--order random --seed N draws roots uniformly at random instead)

# 2. Build graphs once per package version, analyse every VIA record's chain, compute measures
.venv/bin/python -m graph_analysis evaluate run \
  --triad VIA/DataSet/Triad.csv \
  --vulnerable-functions VIA/DataSet/VUL_FUNs.csv \
  --analyze-res "VIA/AnalyzeResult/<...>/AnalyzeRes" \
  --sample sample.json --cutoff 2026-05-26T00:00:00Z \
  --work work/ --output results/
```

`results/measures.json` holds every number of Tables 3, 5, 6 and 7, the RQ3
reductions, function-level statistics (records, CVEs, path lengths) and
construction cost (CPU hours, median time per package). `results/tables.md`
renders them, and `results/associations.csv` lists one row per chain-CVE
association with its recovery flags and first failing step. `work/` caches the
per-package graphs, so interrupted runs resume. `--advisory-source via` takes
R_UC from the VIA records instead of OSV, for offline runs.

## Data

The evaluation uses the VIA dataset (Triad.csv, VUL_FUNs.csv and the
call-path validation results), which is published by its authors at
https://github.com/xiaotea/VIA. It is not redistributed here. The paper uses
the snapshot of 26 May 2026. Package sources come from PyPI and advisories from
OSV at run time.

## Limitations

These are the limitations of the paper's Section 4.6. Analysis is static (evidence
up to Level 3). Absence of a path holds only for the analysed chains. Each package
appears at one version per graph, and environment markers are evaluated for
CPython 3.14.5. Dynamic features (reflection, dynamic imports, callbacks,
runtime dispatch), native extensions and generated code can hide calls;
decorator edges are recorded but not traversed. Vulnerability-to-function
mappings are taken as given.

## License

MIT (see `LICENSE`).
