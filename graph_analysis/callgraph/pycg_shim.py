"""Run PyCG 0.0.8 on current Python versions.

PyCG 0.0.8 is unmaintained. Its wheel installs the package directory as
``PyCG`` while its own modules import ``pycg``, and it relies on ``ast`` node
classes removed in Python 3.12+. This shim restores both before handing
control to PyCG's command-line entry point, so no console script is needed.

Usage: python -m graph_analysis.callgraph.pycg_shim <PyCG arguments>
"""
from __future__ import annotations

import ast
import importlib
import importlib.metadata  # noqa: F401  PyCG's import hook breaks if this loads lazily
import runpy
import sys


def _patch_ast() -> None:
    for legacy_name in ("Num", "Str", "Bytes", "NameConstant", "Ellipsis"):
        if not hasattr(ast, legacy_name):
            setattr(ast, legacy_name, ast.Constant)
    if not hasattr(ast.Constant, "n"):
        ast.Constant.n = property(lambda self: self.value)
    if not hasattr(ast.Constant, "s"):
        ast.Constant.s = property(lambda self: self.value)


def _alias_package() -> str:
    for name in ("pycg", "PyCG"):
        try:
            module = importlib.import_module(name)
        except ModuleNotFoundError:
            continue
        sys.modules.setdefault("pycg", module)
        sys.modules.setdefault("PyCG", module)
        return name
    raise SystemExit("PyCG is not installed; install the pinned requirements (pycg==0.0.8)")


def main() -> None:
    _patch_ast()
    package = _alias_package()
    sys.argv = ["pycg", *sys.argv[1:]]
    runpy.run_module(package, run_name="__main__", alter_sys=True)


if __name__ == "__main__":
    main()
