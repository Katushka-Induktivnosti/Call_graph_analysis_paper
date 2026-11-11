"""Resolve vulnerable-function names to declarations in a package's source."""
from __future__ import annotations

import ast
import re
import warnings
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


CONFIRMED_STATUSES = {"confirmed_declaration", "confirmed_alias"}
CALLABLE_KINDS = {"function", "method", "class", "property"}
SOURCE_ROOTS = {"src", "lib", "python", "client"}
IGNORED_IMPORT_ROOTS = {
    "docs",
    "doc",
    "examples",
    "example",
    "scripts",
    "script",
    "tests",
    "test",
}
PACKAGE_IMPORT_ALIASES = {
    "apache-airflow": {"airflow"},
    "azure-identity": {"azure"},
    "django-cors-headers": {"corsheaders"},
    "django-rest-framework": {"rest_framework"},
    "pillow": {"pil"},
    "pycryptodome": {"crypto"},
    "pypdf": {"pypdf", "pypdf2"},
    "python-multipart": {"multipart"},
    "scikit-learn": {"sklearn"},
    "sentry-sdk": {"sentry_sdk"},
    "strawberry-graphql": {"strawberry"},
}

warnings.simplefilter("ignore", SyntaxWarning)

@dataclass(frozen=True)
class Symbol:
    name: str
    kind: str
    file: str
    line: int
    alias_target: str = ""


class ComponentResolver:
    def __init__(
        self,
        symbols: list[Symbol],
        import_roots: set[str],
        *,
        source_available: bool = True,
    ) -> None:
        self.symbols = symbols
        self.import_roots = {root.lower() for root in import_roots}
        self.source_available = source_available
        self.callables = [symbol for symbol in symbols if symbol.kind in CALLABLE_KINDS]
        self.non_callables = [
            symbol for symbol in symbols if symbol.kind not in CALLABLE_KINDS
        ]
        self.callable_variants = build_variant_index(self.callables, self.import_roots)
        self.non_callable_variants = build_variant_index(
            self.non_callables, self.import_roots
        )

    def resolve(self, original: str) -> dict[str, Any]:
        candidate_variants = qualified_variants(original, self.import_roots)
        candidate_root = normalized_parts(original)[0] if normalized_parts(original) else ""
        package_owned = candidate_root.lower() in self.import_roots
        if not self.source_available:
            return unresolved(
                "source_unavailable",
                "high",
                "missing_function_index",
                package_owned,
                candidate_root,
                self.import_roots,
                [],
                "No reusable function index/CodeQL database exists for this component.",
            )

        callable_matches = best_exact_matches(
            candidate_variants, self.callable_variants
        )
        callable_identities = {
            (normalize_name(symbol.name), symbol.kind)
            for symbol, _method in callable_matches
        }
        if len(callable_matches) == 1:
            symbol, method = callable_matches[0]
            if is_test_source(symbol.file):
                return resolved(
                    symbol,
                    status="non_production_declaration",
                    confidence="high",
                    method="test_source_declaration",
                    package_owned=package_owned,
                    candidate_root=candidate_root,
                    import_roots=self.import_roots,
                    reason=(
                        "Candidate resolves only to a test-suite declaration, not a "
                        "production vulnerable-package declaration."
                    ),
                )
            return resolved(
                symbol,
                status="confirmed_declaration",
                confidence="high",
                method=method,
                package_owned=package_owned,
                candidate_root=candidate_root,
                import_roots=self.import_roots,
                reason="Unique source declaration matched after controlled normalization.",
            )
        if callable_matches and len(callable_identities) == 1:
            symbol, method = callable_matches[0]
            if is_test_source(symbol.file):
                return resolved(
                    symbol,
                    status="non_production_declaration",
                    confidence="high",
                    method="test_source_declaration",
                    package_owned=package_owned,
                    candidate_root=candidate_root,
                    import_roots=self.import_roots,
                    reason=(
                        "Candidate resolves only to test-suite declaration locations, "
                        "not a production vulnerable-package declaration."
                    ),
                )
            return {
                **resolved(
                    symbol,
                    status="confirmed_declaration",
                    confidence="high",
                    method=method,
                    package_owned=package_owned,
                    candidate_root=candidate_root,
                    import_roots=self.import_roots,
                    reason=(
                        "One canonical declaration identity matched at multiple source "
                        "locations (for example conditional/version-specific definitions)."
                    ),
                ),
                "alternate_candidates": join_locations(
                    item[0] for item in callable_matches[1:]
                ),
            }
        if len(callable_matches) > 1:
            return unresolved(
                "ambiguous_declaration_candidate",
                "medium",
                "normalized_name_ambiguous",
                package_owned,
                candidate_root,
                self.import_roots,
                callable_matches,
                "Multiple declarations match the normalized qualified name.",
            )

        alias_matches = best_alias_matches(
            candidate_variants, self.non_callables, self.callables, self.import_roots
        )
        if len(alias_matches) == 1:
            alias, target = alias_matches[0]
            if is_test_source(target.file):
                return resolved(
                    target,
                    status="non_production_declaration",
                    confidence="high",
                    method="test_source_alias",
                    package_owned=package_owned,
                    candidate_root=candidate_root,
                    import_roots=self.import_roots,
                    alias_target=alias.alias_target,
                    reason="Alias resolves only to a test-suite declaration.",
                )
            return resolved(
                target,
                status="confirmed_alias",
                confidence="high",
                method="local_import_or_reexport_alias",
                package_owned=package_owned,
                candidate_root=candidate_root,
                import_roots=self.import_roots,
                alias_target=alias.alias_target,
                reason=f"Source alias '{alias.name}' resolves to a local declaration.",
            )

        non_callable_matches = best_exact_matches(
            candidate_variants, self.non_callable_variants
        )
        if non_callable_matches:
            matches = [item[0] for item in non_callable_matches]
            symbol = matches[0]
            return {
                **resolved(
                    symbol,
                    status="non_declaration_symbol",
                    confidence="high" if len(matches) == 1 else "medium",
                    method="exact_non_callable_symbol",
                    package_owned=package_owned,
                    candidate_root=candidate_root,
                    import_roots=self.import_roots,
                    reason=(
                        "Candidate resolves to a source symbol, but it is not a callable "
                        "or class declaration."
                    ),
                ),
                "alternate_candidates": join_symbols(matches[1:]),
            }

        enclosing = longest_callable_prefix(
            candidate_variants, self.callables, self.import_roots
        )
        if enclosing:
            return unresolved(
                "non_declaration_symbol",
                "medium",
                "member_or_local_under_callable",
                package_owned,
                candidate_root,
                self.import_roots,
                [(enclosing, "callable_prefix")],
                "Candidate extends a callable declaration and is likely a local/member symbol.",
                kind="local_or_member",
            )

        class_method = unique_suffix_matches(
            original, self.callables, self.import_roots, parts=2
        )
        if len(class_method) == 1:
            return unresolved(
                "ambiguous_declaration_candidate",
                "medium",
                "unique_class_method_suffix",
                package_owned,
                candidate_root,
                self.import_roots,
                [(class_method[0], "class_method_suffix")],
                "A unique class.method suffix exists, but module identity differs.",
            )

        terminal = unique_suffix_matches(
            original, self.callables, self.import_roots, parts=1
        )
        if len(terminal) == 1:
            return unresolved(
                "ambiguous_declaration_candidate",
                "low",
                "unique_terminal_name",
                package_owned,
                candidate_root,
                self.import_roots,
                [(terminal[0], "terminal_name")],
                "Only a terminal-name match exists; it is not sufficient for identity.",
            )

        status = (
            "foreign_symbol"
            if candidate_root and self.import_roots and not package_owned
            else "unresolved"
        )
        reason = (
            "Candidate root is not an import root owned by this distribution."
            if status == "foreign_symbol"
            else "No corresponding declaration or classified source symbol was found."
        )
        return unresolved(
            status,
            "high" if status == "foreign_symbol" else "low",
            "package_root_ownership" if status == "foreign_symbol" else "no_source_match",
            package_owned,
            candidate_root,
            self.import_roots,
            [],
            reason,
        )


def collect_symbols(repo_root: Path, function_index: dict[str, Any]) -> list[Symbol]:
    symbols: dict[tuple[str, str, str, int, str], Symbol] = {}
    declaration_kinds: dict[tuple[str, int], str] = {}
    additional: list[Symbol] = []
    for file_path in sorted(repo_root.rglob("*.py")):
        if any(part.startswith(".") or part in {"node_modules", "__pycache__"} for part in file_path.relative_to(repo_root).parts[:-1]):
            continue
        rel_file = str(file_path.relative_to(repo_root))
        module = module_name_for_path(file_path, repo_root)
        if not module:
            continue
        try:
            tree = ast.parse(file_path.read_text(encoding="utf-8"), filename=str(file_path))
        except (SyntaxError, UnicodeDecodeError, OSError):
            continue
        scanner = SourceSymbolScanner(module, rel_file)
        scanner.visit(tree)
        declaration_kinds.update(scanner.declaration_kinds)
        additional.extend(scanner.symbols)

    indexed_items = list(function_index.get("functions", {}).values())
    class_names = {
        normalize_name(str(item.get("qualname") or ""))
        for item in indexed_items
        if item.get("node_type") == "class"
    }
    for item in indexed_items:
        name = str(item.get("qualname") or item.get("id") or "")
        file = str(item.get("file") or "")
        line = int(item.get("start_line") or 1)
        kind = str(item.get("node_type") or "function")
        kind = declaration_kinds.get((file, line), kind)
        if kind == "function" and len(normalized_parts(name)) >= 3:
            parent = ".".join(normalized_parts(name)[:-1])
            if parent in class_names:
                kind = "method"
        symbol = Symbol(name=name, kind=kind, file=file, line=line)
        symbols[(symbol.name, symbol.kind, symbol.file, symbol.line, "")] = symbol
    for symbol in additional:
        symbols[
            (symbol.name, symbol.kind, symbol.file, symbol.line, symbol.alias_target)
        ] = symbol
    return sorted(
        symbols.values(), key=lambda item: (item.name, item.kind, item.file, item.line)
    )


class SourceSymbolScanner(ast.NodeVisitor):
    def __init__(self, module: str, rel_file: str) -> None:
        self.module = module
        self.rel_file = rel_file
        self.stack: list[tuple[str, str]] = []
        self.symbols: list[Symbol] = []
        self.declaration_kinds: dict[tuple[str, int], str] = {}

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        self.declaration_kinds[(self.rel_file, declaration_start(node))] = "class"
        self.stack.append((node.name, "class"))
        for statement in node.body:
            self.visit(statement)
        self.stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        kind = "property" if is_property(node) else ("method" if self.in_class() else "function")
        self.declaration_kinds[(self.rel_file, declaration_start(node))] = kind
        self.stack.append((node.name, "function"))
        for statement in node.body:
            self.visit(statement)
        self.stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self.visit_FunctionDef(node)

    def visit_Assign(self, node: ast.Assign) -> Any:
        for target in node.targets:
            self.record_assignment(target, node.lineno)
        self.generic_visit(node.value)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        self.record_assignment(node.target, node.lineno)
        if node.value:
            self.visit(node.value)

    def visit_Import(self, node: ast.Import) -> Any:
        if self.in_function():
            return
        for alias in node.names:
            local = alias.asname or alias.name.split(".")[0]
            self.record_named(local, "import_alias", node.lineno, alias.name)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> Any:
        if self.in_function():
            return
        module = resolve_relative_import(self.module, node.module or "", node.level)
        for alias in node.names:
            if alias.name == "*":
                continue
            local = alias.asname or alias.name
            target = ".".join(part for part in (module, alias.name) if part)
            self.record_named(local, "import_alias", node.lineno, target)

    def record_assignment(self, target: ast.AST, line: int) -> None:
        if isinstance(target, ast.Name):
            if self.in_function():
                return
            elif self.in_class():
                kind = "class_attribute"
            else:
                kind = "constant" if target.id.isupper() or is_dunder(target.id) else "module_attribute"
            self.record_named(target.id, kind, line)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self.record_assignment(element, line)

    def record_named(
        self,
        name: str,
        kind: str,
        line: int,
        alias_target: str = "",
        *,
        class_scope: bool = False,
    ) -> None:
        stack = [
            item
            for item, item_kind in self.stack
            if not class_scope or item_kind == "class"
        ]
        qualified = ".".join([self.module, *stack, name])
        self.symbols.append(
            Symbol(qualified, kind, self.rel_file, int(line), alias_target)
        )

    def in_function(self) -> bool:
        return any(kind == "function" for _, kind in self.stack)

    def in_class(self) -> bool:
        return any(kind == "class" for _, kind in self.stack)


def package_import_roots(
    package: str, repo_root: Path, symbols: list[Symbol]
) -> set[str]:
    roots = {value.lower() for value in PACKAGE_IMPORT_ALIASES.get(package, set())}
    normalized_package = re.sub(r"[-.]+", "_", package.lower())
    roots.add(normalized_package)
    roots.add(normalized_package.split("_", 1)[0])
    if repo_root.is_dir():
        for top_level in repo_root.rglob("top_level.txt"):
            try:
                for line in top_level.read_text(encoding="utf-8").splitlines():
                    value = line.strip()
                    if value and value.isidentifier():
                        roots.add(value.lower())
            except (OSError, UnicodeDecodeError):
                continue
    symbol_roots = {
        normalized_parts(symbol.name)[0].lower()
        for symbol in symbols
        if normalized_parts(symbol.name)
    }
    for root in list(symbol_roots):
        if root in SOURCE_ROOTS:
            continue
        if (
            root == normalized_package
            or root.replace("_", "") == normalized_package.replace("_", "")
            or root in PACKAGE_IMPORT_ALIASES.get(package, set())
        ):
            roots.add(root)
    return {root for root in roots if root and root not in IGNORED_IMPORT_ROOTS}


def build_variant_index(
    symbols: Iterable[Symbol], import_roots: set[str]
) -> dict[str, list[tuple[Symbol, str]]]:
    index: dict[str, list[tuple[Symbol, str]]] = {}
    for symbol in symbols:
        raw = normalize_name(symbol.name)
        for variant in qualified_variants(symbol.name, import_roots):
            method = "exact_normalized_name" if variant == raw else "source_layout_adjusted"
            index.setdefault(variant, []).append((symbol, method))
    return index


def best_exact_matches(
    candidate_variants: set[str],
    symbol_index: dict[str, list[tuple[Symbol, str]]],
) -> list[tuple[Symbol, str]]:
    matches: dict[Symbol, str] = {}
    for variant in candidate_variants:
        for symbol, method in symbol_index.get(variant, []):
            previous = matches.get(symbol)
            if previous != "exact_normalized_name":
                matches[symbol] = method
    return sorted(matches.items(), key=lambda item: (item[0].name, item[0].line))


def best_alias_matches(
    candidate_variants: set[str],
    non_callables: list[Symbol],
    callables: list[Symbol],
    import_roots: set[str],
) -> list[tuple[Symbol, Symbol]]:
    callable_index = build_variant_index(callables, import_roots)
    result: list[tuple[Symbol, Symbol]] = []
    for alias in non_callables:
        if alias.kind != "import_alias" or not alias.alias_target:
            continue
        if not (qualified_variants(alias.name, import_roots) & candidate_variants):
            continue
        targets = best_exact_matches(
            qualified_variants(alias.alias_target, import_roots), callable_index
        )
        if len(targets) == 1:
            result.append((alias, targets[0][0]))
    return result


def longest_callable_prefix(
    candidate_variants: set[str],
    callables: list[Symbol],
    import_roots: set[str],
) -> Symbol | None:
    matches = []
    for symbol in callables:
        for symbol_variant in qualified_variants(symbol.name, import_roots):
            if any(
                candidate.startswith(symbol_variant + ".")
                for candidate in candidate_variants
            ):
                matches.append((len(symbol_variant), symbol))
    if not matches:
        return None
    matches.sort(key=lambda item: (-item[0], item[1].name))
    return matches[0][1]


def unique_suffix_matches(
    original: str,
    symbols: list[Symbol],
    import_roots: set[str],
    *,
    parts: int,
) -> list[Symbol]:
    candidate = normalized_parts(original)
    if len(candidate) < parts:
        return []
    suffix = tuple(candidate[-parts:])
    matches = {
        symbol
        for symbol in symbols
        if any(
            tuple(variant.split(".")[-parts:]) == suffix
            for variant in qualified_variants(symbol.name, import_roots)
            if len(variant.split(".")) >= parts
        )
    }
    return sorted(matches, key=lambda item: (item.name, item.line))


def qualified_variants(value: str, import_roots: set[str]) -> set[str]:
    normalized = normalize_name(value)
    if not normalized:
        return set()
    parts = normalized.split(".")
    variants = {normalized}
    while parts and parts[0] in SOURCE_ROOTS:
        parts = parts[1:]
        if parts:
            variants.add(".".join(parts))
    for index, part in enumerate(parts):
        if part in import_roots and len(parts) - index >= 2:
            variants.add(".".join(parts[index:]))
    return variants


def normalize_name(value: str) -> str:
    value = value.strip().removesuffix("()")
    value = value.replace("\\", "/").replace(":", ".").replace("/", ".")
    value = re.sub(r"\.py(?=\.|$)", "", value, flags=re.IGNORECASE)
    # Remove package-file markers such as ``pkg/__init__.Class`` while
    # preserving a real constructor declaration ending in ``Class.__init__``.
    value = re.sub(r"(^|\.)__init__(?=\.)", r"\1", value)
    value = re.sub(r"\s+", "", value)
    value = re.sub(r"\.+", ".", value)
    return value.lower().strip(".")


def normalized_parts(value: str) -> list[str]:
    normalized = normalize_name(value)
    return normalized.split(".") if normalized else []


def module_name_for_path(path: Path, root: Path) -> str:
    parts = list(path.relative_to(root).with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def resolve_relative_import(module: str, imported: str, level: int) -> str:
    if level <= 0:
        return imported
    parts = module.split(".")
    base = parts[: max(0, len(parts) - level)]
    return ".".join([*base, *([imported] if imported else [])])


def declaration_start(node: ast.AST) -> int:
    decorators = getattr(node, "decorator_list", [])
    return int(decorators[0].lineno if decorators else getattr(node, "lineno", 1))


def is_property(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for decorator in node.decorator_list:
        if isinstance(decorator, ast.Name) and decorator.id in {
            "property",
            "cached_property",
        }:
            return True
        if isinstance(decorator, ast.Attribute) and decorator.attr in {
            "property",
            "setter",
            "getter",
            "deleter",
            "cached_property",
        }:
            return True
    return False


def is_dunder(value: str) -> bool:
    return value.startswith("__") and value.endswith("__")


def is_test_source(value: str) -> bool:
    parts = {part.lower() for part in value.replace("\\", "/").split("/")}
    return bool(parts & {"test", "tests", "testing"})


def resolved(
    symbol: Symbol,
    *,
    status: str,
    confidence: str,
    method: str,
    package_owned: bool,
    candidate_root: str,
    import_roots: set[str],
    reason: str,
    alias_target: str = "",
) -> dict[str, Any]:
    return {
        "resolution_status": status,
        "confidence": confidence,
        "symbol_kind": symbol.kind,
        "canonical_name": symbol.name,
        "source_file": symbol.file,
        "start_line": symbol.line,
        "resolution_method": method,
        "package_owned": package_owned,
        "candidate_root": candidate_root,
        "package_import_roots": sorted(import_roots),
        "alternate_candidates": "",
        "alias_target": alias_target or symbol.alias_target,
        "reason": reason,
    }


def unresolved(
    status: str,
    confidence: str,
    method: str,
    package_owned: bool,
    candidate_root: str,
    import_roots: set[str],
    candidates: list[tuple[Symbol, str]],
    reason: str,
    *,
    kind: str = "",
) -> dict[str, Any]:
    first = candidates[0][0] if candidates else None
    return {
        "resolution_status": status,
        "confidence": confidence,
        "symbol_kind": kind or (first.kind if first else ""),
        "canonical_name": first.name if first else "",
        "source_file": first.file if first else "",
        "start_line": first.line if first else "",
        "resolution_method": method,
        "package_owned": package_owned,
        "candidate_root": candidate_root,
        "package_import_roots": sorted(import_roots),
        "alternate_candidates": join_symbols(item[0] for item in candidates[1:]),
        "alias_target": first.alias_target if first else "",
        "reason": reason,
    }


def join_symbols(symbols: Iterable[Symbol]) -> str:
    return "; ".join(sorted({symbol.name for symbol in symbols}))


def join_locations(symbols: Iterable[Symbol]) -> str:
    return "; ".join(
        sorted({f"{symbol.name}@{symbol.file}:{symbol.line}" for symbol in symbols})
    )


def build_stats(rows: list[dict[str, Any]]) -> dict[str, Any]:
    confirmed = [
        row
        for row in rows
        if row["resolution_status"] in CONFIRMED_STATUSES
        and row["symbol_kind"] in CALLABLE_KINDS
    ]
    return {
        "component_cve_candidate_rows": len(rows),
        "components": len({row["component"] for row in rows}),
        "cves": len({row["cve"] for row in rows}),
        "unique_original_candidates": len({row["original"] for row in rows}),
        "confirmed_callable_rows": len(confirmed),
        "unique_confirmed_original_candidates": len(
            {row["original"] for row in confirmed}
        ),
        "unique_confirmed_canonical_declarations": len(
            {(row["component"], row["canonical_name"]) for row in confirmed}
        ),
        "resolution_status_counts": dict(
            Counter(row["resolution_status"] for row in rows)
        ),
        "symbol_kind_counts": dict(
            Counter(row["symbol_kind"] or "unknown" for row in rows)
        ),
        "resolution_method_counts": dict(
            Counter(row["resolution_method"] for row in rows)
        ),
    }
