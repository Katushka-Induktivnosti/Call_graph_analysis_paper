from __future__ import annotations

import argparse
from pathlib import Path

from .callgraph.codeql_runner import DEFAULT_QUERY_SUITE
from .callgraph.project import CallGraphOptions
from .dependencies.common import CACHE_DIR
from .pipeline import PipelineConfig, run


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="graph_analysis",
        description=(
            "Trace whether a Python project can reach CVE-associated functions in its "
            "dependencies by combining project and dependency call graphs."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)
    run_parser = sub.add_parser("run", help="Run the full pipeline on a local project.")
    run_parser.add_argument("--project", type=Path, required=True, help="Source directory of the project to analyse.")
    run_parser.add_argument("--vulnerable-functions", type=Path, required=True, help="CVE -> function mapping (CSV or JSON).")
    run_parser.add_argument("--output", type=Path, required=True, help="Output directory (must be outside the project).")
    run_parser.add_argument("--project-name", default="", help="Component name for the project (default: directory name).")
    run_parser.add_argument("--local-prefix", action="append", default=[], help="Top-level package of the project. Repeatable; inferred when omitted.")
    run_parser.add_argument("--cutoff", default="", help="Resolve dependency versions released at or before this ISO-8601 time (default: now).")
    run_parser.add_argument("--include-dev", action="store_true", help="Include dev/test dependency groups.")
    run_parser.add_argument("--include-extras", action="store_true", help="Include optional extras.")
    run_parser.add_argument("--max-dependency-depth", type=int, default=20)
    run_parser.add_argument("--max-chains-per-dependency", type=int, default=5, help="Dependency paths traced per vulnerable dependency (shortest first).")
    run_parser.add_argument(
        "--source-scope",
        choices=("chains", "all"),
        default="chains",
        help="Build call graphs for packages on chains to vulnerable components (default) or for every component.",
    )
    run_parser.add_argument("--cache-dir", type=Path, default=CACHE_DIR, help="Cache for PyPI/OSV responses and downloaded sources.")
    run_parser.add_argument("--refresh-cache", action="store_true")
    run_parser.add_argument("--skip-pycg", action="store_true", help="Use only the AST call graph.")
    run_parser.add_argument("--skip-codeql", action="store_true", help="Do not run CodeQL.")
    run_parser.add_argument("--reuse-codeql", action="store_true", help="Reuse existing SARIF files in the output directory.")
    run_parser.add_argument("--max-pycg-iter", type=int, default=3, help="PyCG iteration cap; -1 runs to a fixpoint.")
    run_parser.add_argument("--pycg-timeout", type=int, default=120, help="Seconds before PyCG falls back to the AST call graph.")
    run_parser.add_argument("--query-suite", default=DEFAULT_QUERY_SUITE, help="CodeQL query suite.")
    run_parser.add_argument("--codeql-download", action="store_true", help="Let CodeQL download missing query packs.")
    eval_parser = sub.add_parser("evaluate", help="Evaluate the framework against the VIA dataset (Section 5).")
    eval_sub = eval_parser.add_subparsers(dest="evaluate_command", required=True)
    sample_parser = eval_sub.add_parser("sample", help="Select downstream package versions from VIA.")
    sample_parser.add_argument("--triad", type=Path, required=True, help="VIA Triad.csv.")
    sample_parser.add_argument("--fraction", type=float, default=0.2, help="Target share of VIA package versions (default 0.2).")
    sample_parser.add_argument("--order", choices=("file", "random"), default="file", help="Root order: Triad.csv order or seeded shuffle.")
    sample_parser.add_argument("--seed", type=int, default=0)
    sample_parser.add_argument("--output", type=Path, required=True, help="Sample file (JSON).")

    eval_run = eval_sub.add_parser("run", help="Run the evaluation procedure and compute the measures.")
    eval_run.add_argument("--triad", type=Path, required=True, help="VIA Triad.csv.")
    eval_run.add_argument("--vulnerable-functions", type=Path, required=True, help="VIA VUL_FUNs.csv (or another mapping).")
    eval_run.add_argument("--analyze-res", type=Path, default=None, help="VIA AnalyzeRes directory (VIA-confirmed subset).")
    eval_run.add_argument("--sample", type=Path, required=True, help="Sample file from 'evaluate sample'.")
    eval_run.add_argument("--cutoff", required=True, help="Publication cutoff t0 (ISO-8601), e.g. the VIA snapshot date.")
    eval_run.add_argument("--work", type=Path, required=True, help="Cache of per-package graphs and sources.")
    eval_run.add_argument("--output", type=Path, required=True, help="Directory for measures.json, tables.md, associations.csv.")
    eval_run.add_argument("--advisory-source", choices=("osv", "via"), default="osv", help="Advisories for R_UC: OSV (default) or the VIA records themselves (offline).")
    eval_run.add_argument("--max-dependency-depth", type=int, default=20)
    eval_run.add_argument("--cache-dir", type=Path, default=CACHE_DIR)
    eval_run.add_argument("--with-codeql", action="store_true", help="Also run CodeQL on every package (annotation only).")
    eval_run.add_argument("--max-pycg-iter", type=int, default=3)
    eval_run.add_argument("--pycg-timeout", type=int, default=120)
    return parser


def run_evaluate(args: argparse.Namespace) -> None:
    from .callgraph.utils import write_json
    from .evaluation.run import EvaluationConfig, run_evaluation
    from .evaluation.sample import select_sample

    if args.evaluate_command == "sample":
        write_json(args.output, select_sample(args.triad, args.fraction, args.order, args.seed))
        return
    run_evaluation(
        EvaluationConfig(
            triad=args.triad,
            vulnerable_functions=args.vulnerable_functions,
            sample=args.sample,
            work=args.work,
            output=args.output,
            cutoff=args.cutoff,
            analyze_res=args.analyze_res,
            advisory_source=args.advisory_source,
            max_dependency_depth=args.max_dependency_depth,
            cache_dir=args.cache_dir,
            callgraph=CallGraphOptions(
                skip_codeql=not args.with_codeql,
                max_pycg_iter=args.max_pycg_iter,
                pycg_timeout=args.pycg_timeout,
            ),
        )
    )


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    if args.command == "evaluate":
        run_evaluate(args)
        return
    config = PipelineConfig(
        project=args.project,
        output=args.output,
        vulnerable_functions=args.vulnerable_functions,
        project_name=args.project_name,
        local_prefixes=args.local_prefix,
        cutoff=args.cutoff,
        include_dev=args.include_dev,
        include_extras=args.include_extras,
        max_dependency_depth=args.max_dependency_depth,
        max_chains_per_dependency=args.max_chains_per_dependency,
        source_scope=args.source_scope,
        cache_dir=args.cache_dir,
        refresh_cache=args.refresh_cache,
        callgraph=CallGraphOptions(
            skip_pycg=args.skip_pycg,
            skip_codeql=args.skip_codeql,
            reuse_codeql=args.reuse_codeql,
            max_pycg_iter=args.max_pycg_iter,
            pycg_timeout=args.pycg_timeout,
            query_suite=args.query_suite,
            codeql_download=args.codeql_download,
        ),
    )
    run(config)


if __name__ == "__main__":
    main()
