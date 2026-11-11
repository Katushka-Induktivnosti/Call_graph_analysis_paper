from __future__ import annotations

import ast
from collections import Counter
from pathlib import Path
from typing import Any

from .utils import iter_python_files, module_name_for_path, write_json


def build_function_index(
    repo_root: Path, output_folder: Path | None = None
) -> dict[str, Any]:
    modules: dict[str, dict[str, Any]] = {}
    functions: dict[str, dict[str, Any]] = {}

    for file_path in iter_python_files(repo_root, output_folder):
        module_name = module_name_for_path(file_path, repo_root)
        if not module_name:
            continue
        rel = str(file_path.resolve().relative_to(repo_root.resolve()))
        modules[module_name] = {
            "id": module_name,
            "name": module_name,
            "file": rel,
            "role": module_role(rel),
            "parse_status": "ok",
            "functions": [],
        }
        try:
            tree = ast.parse(
                file_path.read_text(encoding="utf-8"), filename=str(file_path)
            )
        except (SyntaxError, UnicodeDecodeError) as exc:
            modules[module_name]["parse_status"] = "failed"
            modules[module_name]["parse_error"] = f"{type(exc).__name__}: {exc}"
            continue

        imports = _collect_imports(tree, module_name, rel)
        modules[module_name]["imports"] = imports
        visitor = _IndexVisitor(
            module_name,
            rel,
            functions,
            modules[module_name]["functions"],
            imports,
        )
        visitor.visit(tree)

    return {"schema_version": 2, "modules": modules, "functions": functions}


ROLE_PATH_PARTS = {
    "test": {"test", "tests", "testing"},
    "documentation": {"doc", "docs"},
    "example": {"example", "examples"},
}


def module_role(relative_file: str) -> str:
    """Role of a source file from its directory components (Section 4.3.2)."""
    parts = {part.lower() for part in relative_file.replace("\\", "/").split("/")[:-1]}
    for role, names in ROLE_PATH_PARTS.items():
        if parts & names:
            return role
    return "production"


def write_function_index(repo_root: Path, output_folder: Path) -> dict[str, Any]:
    index = build_function_index(repo_root, output_folder)
    write_json(output_folder / "function_index.json", index)
    return index


class _IndexVisitor(ast.NodeVisitor):
    def __init__(
        self,
        module_name: str,
        rel_file: str,
        functions: dict[str, dict[str, Any]],
        module_functions: list[str],
        imports: dict[str, str],
    ) -> None:
        self.module_name = module_name
        self.rel_file = rel_file
        self.functions = functions
        self.module_functions = module_functions
        self.imports = imports
        self.name_stack: list[str] = []
        self.class_stack: list[str] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        qname = self._record(node, "class")
        self.name_stack.append(node.name)
        self.class_stack.append(qname)
        for stmt in node.body:
            self.visit(stmt)
        self.class_stack.pop()
        self.name_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        self._record(node, "function")
        self.name_stack.append(node.name)
        for stmt in node.body:
            self.visit(stmt)
        self.name_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self.visit_FunctionDef(node)

    def _record(self, node: ast.AST, node_type: str) -> str:
        name = str(getattr(node, "name"))
        qualname = ".".join([self.module_name, *self.name_stack, name])
        decorator_list = list(getattr(node, "decorator_list", []))
        start = int(
            decorator_list[0].lineno
            if decorator_list
            else getattr(node, "lineno", 1)
        )
        end = int(getattr(node, "end_lineno", start))
        record: dict[str, Any] = {
            "id": qualname,
            "name": name,
            "qualname": qualname,
            "module": self.module_name,
            "file": self.rel_file,
            "start_line": start,
            "end_line": end,
            "node_type": node_type,
            "owner_class": self.class_stack[-1] if self.class_stack else "",
            "decorators": [
                resolved
                for item in decorator_list
                if (resolved := _resolve_expression(item, self.imports, self.module_name))
            ],
        }
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            positional = [*node.args.posonlyargs, *node.args.args]
            record["parameters"] = [argument.arg for argument in positional]
            record["parameter_annotations"] = {
                argument.arg: resolved
                for argument in [*positional, *node.args.kwonlyargs]
                if argument.annotation
                and (
                    resolved := _resolve_expression(
                        argument.annotation, self.imports, self.module_name
                    )
                )
            }
            if node.returns and (
                returns := _resolve_expression(
                    node.returns, self.imports, self.module_name
                )
            ):
                record["return_annotation"] = returns
        if isinstance(node, ast.ClassDef):
            record["bases"] = [
                resolved
                for item in node.bases
                if (resolved := _resolve_expression(item, self.imports, self.module_name))
            ]
        self.functions[qualname] = record
        self.module_functions.append(qualname)
        return qualname


def build_ast_callgraph(
    repo_root: Path,
    function_index: dict[str, Any],
    output_folder: Path | None = None,
) -> dict[str, list[str]]:
    graph, _edge_metadata, _metadata = build_ast_callgraph_details(
        repo_root, function_index, output_folder
    )
    return graph


def build_ast_callgraph_details(
    repo_root: Path,
    function_index: dict[str, Any],
    output_folder: Path | None = None,
) -> tuple[dict[str, list[str]], list[dict[str, str]], dict[str, Any]]:
    graph: dict[str, set[str]] = {}
    edge_kinds: dict[tuple[str, str], set[str]] = {}
    functions = function_index.get("functions", {})
    functions_by_file: dict[str, list[dict[str, Any]]] = {}
    for fn in functions.values():
        functions_by_file.setdefault(str(fn.get("file") or ""), []).append(fn)
    for values in functions_by_file.values():
        values.sort(
            key=lambda item: (
                int(item.get("start_line") or 0),
                -(int(item.get("end_line") or 0) - int(item.get("start_line") or 0)),
            )
        )

    classes = {
        name for name, item in functions.items() if item.get("node_type") == "class"
    }
    bases = {
        name: tuple(str(value) for value in item.get("bases", []))
        for name, item in functions.items()
        if item.get("node_type") == "class"
    }
    summaries = _build_function_summaries(repo_root, functions, classes, output_folder)
    for name, summary in summaries.items():
        functions[name].update(summary)
    diagnostics: Counter[str] = Counter()
    unresolved_details: list[dict[str, Any]] = []
    for file_path in iter_python_files(repo_root, output_folder):
        module_name = module_name_for_path(file_path, repo_root)
        if not module_name:
            continue
        rel = str(file_path.resolve().relative_to(repo_root.resolve()))
        try:
            tree = ast.parse(
                file_path.read_text(encoding="utf-8"), filename=str(file_path)
            )
        except (SyntaxError, UnicodeDecodeError):
            diagnostics["parse_errors"] += 1
            continue
        imports = _collect_imports(tree, module_name, rel)
        resolver = _CallResolver(
            module_name,
            functions_by_file.get(rel, []),
            set(functions),
            classes,
            bases,
            imports,
            diagnostics,
            functions,
            summaries,
            unresolved_details,
        )
        resolver.prime_module_bindings(tree)
        resolver.visit(tree)
        for pair, kinds in resolver.edges.items():
            source, target = pair
            graph.setdefault(source, set()).add(target)
            edge_kinds.setdefault(pair, set()).update(kinds)

    rows = [
        {
            "source": source,
            "target": target,
            "kind": _preferred_kind(kinds),
            "provenance": "ast",
        }
        for (source, target), kinds in sorted(edge_kinds.items())
    ]
    metadata = {
        **dict(diagnostics),
        "edge_count": len(rows),
        "edge_kind_counts": dict(Counter(row["kind"] for row in rows)),
        "function_summary_count": sum(bool(value) for value in summaries.values()),
        "ambiguous_function_summary_count": sum(
            "ambiguous_return_types" in value
            or "ambiguous_returned_callables" in value
            for value in summaries.values()
        ),
        "unresolved_call_details": unresolved_details,
    }
    return (
        {source: sorted(targets) for source, targets in sorted(graph.items())},
        rows,
        metadata,
    )


class _CallResolver(ast.NodeVisitor):
    def __init__(
        self,
        module_name: str,
        functions_for_file: list[dict[str, Any]],
        local_functions: set[str],
        classes: set[str],
        bases: dict[str, tuple[str, ...]],
        imports: dict[str, str],
        diagnostics: Counter[str],
        function_records: dict[str, dict[str, Any]],
        summaries: dict[str, dict[str, Any]],
        unresolved_details: list[dict[str, Any]],
    ) -> None:
        self.module_name = module_name
        self.functions_for_file = functions_for_file
        self.local_functions = local_functions
        self.classes = classes
        self.bases = bases
        self.imports = imports
        self.diagnostics = diagnostics
        self.function_records = function_records
        self.summaries = summaries
        self.unresolved_details = unresolved_details
        self.function_stack: list[str | None] = []
        self.class_stack: list[str] = []
        self.type_scopes: list[dict[str, str]] = []
        self.callable_scopes: list[dict[str, str]] = []
        self.container_scopes: list[dict[str, dict[object, str]]] = []
        self.module_scopes: list[dict[str, str]] = []
        self.invalid_bindings: list[set[tuple[str, str]]] = []
        self.module_types: dict[str, str] = {}
        self.module_callables: dict[str, str] = {}
        self.module_containers: dict[str, dict[object, str]] = {}
        self.module_modules: dict[str, str] = {}
        self.module_invalid: set[tuple[str, str]] = set()
        self.class_attribute_types: dict[tuple[str, str], str] = {}
        self.edges: dict[tuple[str, str], set[str]] = {}
        self.call_func_nodes: set[int] = set()
        self.property_methods = {
            name
            for name, record in function_records.items()
            if any(
                str(decorator) == "property" or str(decorator).endswith(".property")
                for decorator in record.get("decorators", [])
            )
        }

    def prime_module_bindings(self, tree: ast.AST) -> None:
        for statement in getattr(tree, "body", []):
            if isinstance(statement, ast.Assign):
                value = self._infer_value(statement.value)
                for target in statement.targets:
                    self._bind_value(target, value, module_only=True)
            elif isinstance(statement, ast.AnnAssign):
                value = self._infer_value(statement.value)
                if value[0] is None and statement.annotation:
                    value = (
                        _resolve_expression(
                            statement.annotation, self.imports, self.module_name
                        ),
                        value[1],
                        value[2],
                        value[3],
                    )
                self._bind_value(statement.target, value, module_only=True)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        current = self._function_at(node.lineno)
        for decorator in node.decorator_list:
            target = _resolve_expression(decorator, self.imports, self.module_name)
            if target:
                # A edges run from the decorated element to its decorator.
                self._add_edge(current or self.module_name, target, "decorator_application")
        self.function_stack.append(current)
        self.type_scopes.append({})
        self.callable_scopes.append({})
        self.container_scopes.append({})
        self.module_scopes.append({})
        self.invalid_bindings.append(set())
        if current:
            record = self.function_records.get(current, {})
            owner = str(record.get("owner_class") or "")
            for parameter, inferred in record.get("parameter_types", {}).items():
                self.type_scopes[-1][str(parameter)] = str(inferred)
            for parameter, annotation in record.get(
                "parameter_annotations", {}
            ).items():
                self.type_scopes[-1].setdefault(str(parameter), str(annotation))
            parameters = record.get("parameters", [])
            if owner and parameters:
                self.type_scopes[-1][str(parameters[0])] = owner
        for stmt in node.body:
            self.visit(stmt)
        self.invalid_bindings.pop()
        self.module_scopes.pop()
        self.container_scopes.pop()
        self.callable_scopes.pop()
        self.type_scopes.pop()
        self.function_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self.visit_FunctionDef(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        current = self._function_at(node.lineno)
        if current:
            self.class_stack.append(current)
        for decorator in node.decorator_list:
            target = _resolve_expression(decorator, self.imports, self.module_name)
            if target:
                self._add_edge(current or self.module_name, target, "decorator_application")
        for stmt in node.body:
            self.visit(stmt)
        if current:
            self.class_stack.pop()

    def visit_Assign(self, node: ast.Assign) -> Any:
        self.visit(node.value)
        inferred = self._infer_value(node.value)
        for target in node.targets:
            self._bind_value(target, inferred)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        if node.value:
            self.visit(node.value)
        inferred = self._infer_value(node.value)
        if inferred[0] is None and node.annotation:
            inferred = (
                _resolve_expression(node.annotation, self.imports, self.module_name),
                inferred[1],
                inferred[2],
                inferred[3],
            )
        self._bind_value(node.target, inferred)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> Any:
        self.visit(node.value)
        self._bind_value(node.target, self._infer_value(node.value))

    def visit_With(self, node: ast.With) -> Any:
        source = self._current_source()
        for item in node.items:
            self.visit(item.context_expr)
            inferred = self._infer_type(item.context_expr)
            if source and inferred:
                self._add_protocol_edge(source, inferred, "__enter__")
                self._add_protocol_edge(source, inferred, "__exit__")
            if item.optional_vars:
                entered_type = self._method_return_type(inferred, "__enter__") if inferred else None
                self._bind_value(
                    item.optional_vars,
                    (entered_type or inferred, None, None, None),
                )
        for statement in node.body:
            self.visit(statement)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> Any:
        self.visit_With(node)

    def visit_For(self, node: ast.For) -> Any:
        self.visit(node.iter)
        source = self._current_source()
        inferred = self._infer_type(node.iter)
        if source and inferred:
            self._add_protocol_edge(source, inferred, "__iter__")
            self._add_protocol_edge(source, inferred, "__next__")
        self._bind_value(node.target, (None, None, None, None))
        for statement in [*node.body, *node.orelse]:
            self.visit(statement)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> Any:
        self.visit_For(node)

    def visit_Call(self, node: ast.Call) -> Any:
        if isinstance(node.func, ast.Name) and node.func.id == "super":
            for argument in [*node.args, *(keyword.value for keyword in node.keywords)]:
                self.visit(argument)
            return
        source = self._current_source()
        if source:
            target, kind = self._resolve_call(node.func)
            if target:
                self._add_edge(source, target, kind)
                if kind == "constructor_call" and target in self.classes:
                    for constructor in self._constructor_targets(target):
                        self._add_edge(source, constructor, "constructor_call")
        self.call_func_nodes.add(id(node.func))
        try:
            self.generic_visit(node)
        finally:
            self.call_func_nodes.discard(id(node.func))

    def visit_Attribute(self, node: ast.Attribute) -> Any:
        if id(node) not in self.call_func_nodes and isinstance(node.ctx, ast.Load):
            receiver = self._infer_type(node.value)
            source = self._current_source()
            if source and receiver:
                target = self._resolve_method(receiver, node.attr)
                if target in self.property_methods:
                    self._add_edge(source, target, "protocol_dispatch")
        self.generic_visit(node)

    def _current_source(self) -> str:
        return self.function_stack[-1] if self.function_stack else self.module_name

    def _add_edge(self, source: str, target: str, kind: str) -> None:
        if source and target and source != target:
            self.edges.setdefault((source, target), set()).add(kind)
            self.diagnostics[f"{kind}_edges"] += 1

    def _function_at(self, line: int) -> str | None:
        matches = [
            fn
            for fn in self.functions_for_file
            if int(fn.get("start_line") or 0) <= line <= int(fn.get("end_line") or 0)
        ]
        if not matches:
            return None
        return min(
            matches,
            key=lambda fn: int(fn.get("end_line") or 0)
            - int(fn.get("start_line") or 0),
        )["qualname"]

    def _resolve_call(self, node: ast.AST) -> tuple[str | None, str]:
        if isinstance(node, ast.Call):
            inferred = self._infer_type(node)
            if inferred:
                return self._method_or_external(inferred, "__call__"), "callable_dispatch"
            self.diagnostics["unresolved_callable_object_calls"] += 1
            self._record_unresolved(
                "callable_object", node, "inner call has no unique returned type"
            )
            return None, "callable_dispatch"
        if isinstance(node, ast.Subscript):
            target = self._resolve_dispatch_target(node)
            if target:
                return target, "dispatch_table_call"
            self.diagnostics["unresolved_dispatch_table_calls"] += 1
            self._record_unresolved(
                "subscript_dispatch",
                node,
                "container, key, or callable value is not uniquely known",
            )
            return None, "dispatch_table_call"
        if self._is_super_attribute(node):
            attribute = str(getattr(node, "attr"))
            if self.class_stack:
                candidates = {
                    resolved
                    for base in self.bases.get(self.class_stack[-1], ())
                    if (local := self._resolve_local_class(base))
                    and (resolved := self._resolve_method(local, attribute))
                }
                if len(candidates) == 1:
                    return next(iter(candidates)), "super_dispatch"
            self.diagnostics["unresolved_super_calls"] += 1
            candidates = (
                [
                    f"{base}.{attribute}"
                    for base in self.bases.get(self.class_stack[-1], ())
                ]
                if self.class_stack
                else []
            )
            self._record_unresolved(
                "super", node, "no unique inherited method", candidates
            )
            return None, "super_dispatch"
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Call):
            inferred = self._infer_type(node.value)
            if inferred:
                return (
                    self._method_or_external(inferred, node.attr),
                    "factory_return_dispatch",
                )
            self.diagnostics["unresolved_factory_return_calls"] += 1
            self._record_unresolved(
                "factory_return", node, "factory has no unique return type"
            )
            return None, "factory_return_dispatch"
        dotted = _dotted_name(node)
        if not dotted:
            self.diagnostics["unsupported_call_shapes"] += 1
            self._record_unresolved(
                "unsupported", node, "call target AST shape is not modelled"
            )
            return None, "call"
        first, _, rest = dotted.partition(".")
        if first in {"self", "cls"} and rest and self.class_stack:
            resolved = self._resolve_method(self.class_stack[-1], rest)
            if resolved:
                return resolved, "receiver_call"
            self.diagnostics["unresolved_receiver_calls"] += 1
            self._record_unresolved(
                "ambiguous_receiver",
                node,
                "self or cls method is absent or ambiguous in the inheritance graph",
                [f"{self.class_stack[-1]}.{rest}"],
            )
            return dotted, "call"
        inferred = self._lookup_type(first)
        if inferred:
            attribute = rest or "__call__"
            resolved = self._method_or_external(inferred, attribute)
            if resolved:
                return resolved, "receiver_call" if rest else "callable_dispatch"
            self.diagnostics[
                "unresolved_receiver_calls" if rest else "unresolved_callable_object_calls"
            ] += 1
            self._record_unresolved(
                "ambiguous_receiver" if rest else "callable_object",
                node,
                "receiver type is known but the callable target is not unique",
                [f"{inferred}.{rest or '__call__'}"],
            )
        callable_target = self._lookup_callable(first)
        if callable_target and not rest:
            if callable_target in self.classes:
                return callable_target, "constructor_call"
            return callable_target, "resolved_alias_call"
        dynamic_module = self._lookup_module(first)
        if dynamic_module and rest:
            return f"{dynamic_module}.{rest}", "resolved_alias_call"
        resolved = _resolve_expression(node, self.imports, self.module_name)
        if resolved in self.classes:
            return resolved, "constructor_call"
        return resolved or dotted, "call"

    def _record_unresolved(
        self,
        shape: str,
        node: ast.AST,
        reason: str,
        candidates: list[str] | None = None,
    ) -> None:
        if len(self.unresolved_details) >= 500:
            self.diagnostics["unresolved_call_details_truncated"] += 1
            return
        try:
            expression = ast.unparse(node)
        except Exception:
            expression = type(node).__name__
        self.unresolved_details.append(
            {
                "source": self._current_source(),
                "line": int(getattr(node, "lineno", 0) or 0),
                "shape": shape,
                "expression": expression,
                "reason": reason,
                "candidates": sorted(set(candidates or [])),
            }
        )

    def _method_or_external(self, class_name: str, attribute: str) -> str:
        return self._resolve_method(class_name, attribute) or f"{class_name}.{attribute}"

    def _resolve_method(self, class_name: str, attribute: str) -> str | None:
        queue = [(class_name, 0)]
        seen: set[str] = set()
        current_depth = 0
        candidates: set[str] = set()
        while queue:
            current, depth = queue.pop(0)
            if depth != current_depth and candidates:
                break
            current_depth = depth
            if current in seen:
                continue
            seen.add(current)
            candidate = f"{current}.{attribute}"
            if candidate in self.local_functions:
                candidates.add(candidate)
            for base in self.bases.get(current, ()):
                resolved = self._resolve_local_class(base)
                if resolved:
                    queue.append((resolved, depth + 1))
        return next(iter(candidates)) if len(candidates) == 1 else None

    def _resolve_local_class(self, value: str) -> str | None:
        if value in self.classes:
            return value
        candidates = {
            item
            for item in self.classes
            if item == value or item.endswith("." + value)
        }
        return next(iter(candidates)) if len(candidates) == 1 else None

    def _infer_type(self, node: ast.AST | None) -> str | None:
        return self._infer_value(node)[0]

    def _infer_value(
        self, node: ast.AST | None
    ) -> tuple[str | None, str | None, dict[object, str] | None, str | None]:
        if node is None:
            return None, None, None, None
        if isinstance(node, ast.Subscript):
            target = self._resolve_dispatch_target(node)
            return (None, target, None, None) if target else (None, None, None, None)
        if isinstance(node, ast.Call):
            dynamic = self._constant_dynamic_import(node)
            if dynamic:
                return None, None, None, dynamic
            target, _kind = self._resolve_call(node.func)
            if not target:
                return None, None, None, None
            local_class = self._resolve_local_class(target)
            if local_class:
                return local_class, None, None, None
            summary = self.summaries.get(target, {})
            return_types = summary.get("return_types", [])
            returned_callables = summary.get("returned_callables", [])
            return (
                (
                    str(return_types[0])
                    if len(return_types) == 1
                    else target
                    if _looks_like_constructor(target)
                    else None
                ),
                str(returned_callables[0]) if len(returned_callables) == 1 else None,
                None,
                None,
            )
        callable_target = self._resolve_callable_expr(node)
        if callable_target:
            return None, callable_target, None, None
        container = self._resolve_container(node)
        if container is not None:
            return None, None, container, None
        dotted = _dotted_name(node)
        if dotted:
            return (
                self._lookup_type(dotted),
                self._lookup_callable(dotted),
                self._lookup_container(dotted),
                self._lookup_module(dotted),
            )
        return None, None, None, None

    def _bind_value(
        self,
        node: ast.AST,
        inferred: tuple[
            str | None, str | None, dict[object, str] | None, str | None
        ],
        *,
        module_only: bool = False,
    ) -> None:
        key = _dotted_name(node)
        if not key:
            return
        inferred_type, callable_target, container, dynamic_module = inferred
        if key.startswith("self.") and self.class_stack:
            attr = key.split(".", 1)[1]
            slot = (self.class_stack[-1], attr)
            if inferred_type:
                previous = self.class_attribute_types.get(slot)
                if previous and previous != inferred_type:
                    self.class_attribute_types.pop(slot, None)
                elif not previous:
                    self.class_attribute_types[slot] = inferred_type
            else:
                self.class_attribute_types.pop(slot, None)
            return
        if "." in key:
            return
        use_local = bool(self.type_scopes) and not module_only
        stores = (
            (
                self.type_scopes[-1],
                self.callable_scopes[-1],
                self.container_scopes[-1],
                self.module_scopes[-1],
                self.invalid_bindings[-1],
            )
            if use_local
            else (
                self.module_types,
                self.module_callables,
                self.module_containers,
                self.module_modules,
                self.module_invalid,
            )
        )
        for category, store, value in zip(
            ("type", "callable", "container", "module"),
            stores[:4],
            (inferred_type, callable_target, container, dynamic_module),
        ):
            self._merge_binding(category, key, store, stores[4], value)

    @staticmethod
    def _merge_binding(
        category: str,
        key: str,
        store: dict[str, Any],
        invalid: set[tuple[str, str]],
        value: Any,
    ) -> None:
        marker = (category, key)
        if marker in invalid:
            return
        previous = store.get(key)
        if value is None:
            store.pop(key, None)
        elif previous is not None and previous != value:
            store.pop(key, None)
            invalid.add(marker)
        else:
            store[key] = value

    def _lookup_type(self, value: str) -> str | None:
        if value == "self" or value == "cls":
            return self.class_stack[-1] if self.class_stack else None
        if value.startswith("self.") and self.class_stack:
            return self.class_attribute_types.get(
                (self.class_stack[-1], value.split(".", 1)[1])
            )
        if self.type_scopes and value in self.type_scopes[-1]:
            return self.type_scopes[-1][value]
        return self.module_types.get(value)

    def _lookup_callable(self, value: str) -> str | None:
        if self.callable_scopes and value in self.callable_scopes[-1]:
            return self.callable_scopes[-1][value]
        return self.module_callables.get(value)

    def _lookup_container(self, value: str) -> dict[object, str] | None:
        if self.container_scopes and value in self.container_scopes[-1]:
            return self.container_scopes[-1][value]
        return self.module_containers.get(value)

    def _lookup_module(self, value: str) -> str | None:
        if self.module_scopes and value in self.module_scopes[-1]:
            return self.module_scopes[-1][value]
        return self.module_modules.get(value)

    def _resolve_callable_expr(self, node: ast.AST) -> str | None:
        dotted = _dotted_name(node)
        if not dotted:
            return None
        bound = self._lookup_callable(dotted)
        if bound:
            return bound
        resolved = _resolve_expression(node, self.imports, self.module_name)
        if resolved in self.local_functions or dotted.split(".", 1)[0] in self.imports:
            return resolved
        return None

    def _resolve_container(self, node: ast.AST) -> dict[object, str] | None:
        pairs: list[tuple[ast.AST, ast.AST]] = []
        if isinstance(node, ast.Dict):
            pairs = [
                (key, value)
                for key, value in zip(node.keys, node.values)
                if key is not None
            ]
        elif isinstance(node, (ast.List, ast.Tuple)):
            pairs = [(ast.Constant(index), value) for index, value in enumerate(node.elts)]
        else:
            return None
        result: dict[object, str] = {}
        for key_node, value_node in pairs:
            key = _constant_value(key_node)
            target = self._resolve_callable_expr(value_node)
            if key is None or target is None or key in result:
                return None
            result[key] = target
        return result or None

    def _resolve_dispatch_target(self, node: ast.Subscript) -> str | None:
        name = _dotted_name(node.value)
        container = self._lookup_container(name) if name else None
        key = _constant_value(node.slice)
        return container.get(key) if container is not None and key is not None else None

    def _constant_dynamic_import(self, node: ast.Call) -> str | None:
        target = _resolve_expression(node.func, self.imports, self.module_name)
        if target not in {"importlib.import_module", "builtins.__import__", f"{self.module_name}.__import__"}:
            return None
        if not node.args or not isinstance(node.args[0], ast.Constant):
            self.diagnostics["unresolved_dynamic_imports"] += 1
            self._record_unresolved(
                "dynamic_import", node, "module name is not a constant string"
            )
            return None
        value = node.args[0].value
        if isinstance(value, str) and value:
            self.diagnostics["resolved_dynamic_imports"] += 1
            return value
        return None

    @staticmethod
    def _is_super_attribute(node: ast.AST) -> bool:
        return (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Name)
            and node.value.func.id == "super"
        )

    def _add_protocol_edge(self, source: str, inferred: str, method: str) -> None:
        self._add_edge(source, self._method_or_external(inferred, method), "protocol_dispatch")

    def _constructor_targets(self, class_name: str) -> tuple[str, ...]:
        targets = []
        for method in ("__new__", "__init__"):
            target = self._resolve_method(class_name, method)
            if target:
                targets.append(target)
        return tuple(targets)

    def _method_return_type(self, inferred: str, method: str) -> str | None:
        target = self._resolve_method(inferred, method)
        if not target:
            return None
        values = self.summaries.get(target, {}).get("return_types", [])
        return str(values[0]) if len(values) == 1 else None


def _build_function_summaries(
    repo_root: Path,
    functions: dict[str, dict[str, Any]],
    classes: set[str],
    output_folder: Path | None,
) -> dict[str, dict[str, Any]]:
    nodes: dict[str, tuple[ast.AST, dict[str, str], str]] = {}
    by_file: dict[str, list[dict[str, Any]]] = {}
    for record in functions.values():
        by_file.setdefault(str(record.get("file") or ""), []).append(record)

    trees: list[tuple[ast.AST, str, dict[str, str], str]] = []
    for file_path in iter_python_files(repo_root, output_folder):
        module_name = module_name_for_path(file_path, repo_root)
        if not module_name:
            continue
        rel = str(file_path.resolve().relative_to(repo_root.resolve()))
        try:
            tree = ast.parse(file_path.read_text(encoding="utf-8"), filename=str(file_path))
        except (SyntaxError, UnicodeDecodeError):
            continue
        imports = _collect_imports(tree, module_name, rel)
        trees.append((tree, module_name, imports, rel))
        records = by_file.get(rel, [])
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            record = _function_record_at(records, node.lineno)
            if record:
                nodes[str(record["qualname"])] = (node, imports, module_name)

    summaries: dict[str, dict[str, Any]] = {name: {} for name in nodes}
    for _ in range(8):
        changed = False
        for name, (node, imports, module_name) in nodes.items():
            owner = str(functions.get(name, {}).get("owner_class") or "")
            collector = _ReturnCollector()
            for statement in getattr(node, "body", []):
                collector.visit(statement)
            return_types: set[str] = set()
            returned_callables: set[str] = set()
            annotation = str(functions.get(name, {}).get("return_annotation") or "")
            if annotation in classes:
                return_types.add(annotation)
            for value in collector.values:
                inferred_type, callable_target = _summary_value(
                    value,
                    imports,
                    module_name,
                    owner,
                    functions,
                    classes,
                    summaries,
                )
                if inferred_type:
                    return_types.add(inferred_type)
                if callable_target:
                    returned_callables.add(callable_target)
            update: dict[str, Any] = {}
            if len(return_types) == 1:
                update["return_types"] = sorted(return_types)
            elif len(return_types) > 1:
                update["ambiguous_return_types"] = sorted(return_types)
            if len(returned_callables) == 1:
                update["returned_callables"] = sorted(returned_callables)
            elif len(returned_callables) > 1:
                update["ambiguous_returned_callables"] = sorted(returned_callables)
            if summaries.get(name) != update:
                summaries[name] = update
                changed = True
        if not changed:
            break

    parameter_candidates: dict[tuple[str, str], set[str]] = {}
    for tree, module_name, imports, _rel in trees:
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            target = _resolve_expression(node.func, imports, module_name)
            record = functions.get(str(target or ""))
            if not record:
                continue
            parameters = [str(item) for item in record.get("parameters", [])]
            for parameter, argument in zip(parameters, node.args):
                inferred, _callable = _summary_value(
                    argument,
                    imports,
                    module_name,
                    "",
                    functions,
                    classes,
                    summaries,
                )
                if inferred:
                    parameter_candidates.setdefault((str(target), parameter), set()).add(inferred)
    for (target, parameter), candidates in parameter_candidates.items():
        if len(candidates) == 1:
            summaries.setdefault(target, {}).setdefault("parameter_types", {})[
                parameter
            ] = next(iter(candidates))
    return summaries


class _ReturnCollector(ast.NodeVisitor):
    def __init__(self) -> None:
        self.values: list[ast.AST | None] = []

    def visit_Return(self, node: ast.Return) -> Any:
        self.values.append(node.value)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        return None

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        return None

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        return None


def _function_record_at(
    records: list[dict[str, Any]], line: int
) -> dict[str, Any] | None:
    matches = [
        record
        for record in records
        if int(record.get("start_line") or 0) <= line <= int(record.get("end_line") or 0)
        and record.get("node_type") == "function"
    ]
    return min(
        matches,
        key=lambda record: int(record.get("end_line") or 0)
        - int(record.get("start_line") or 0),
    ) if matches else None


def _summary_value(
    node: ast.AST | None,
    imports: dict[str, str],
    module_name: str,
    owner_class: str,
    functions: dict[str, dict[str, Any]],
    classes: set[str],
    summaries: dict[str, dict[str, Any]],
) -> tuple[str | None, str | None]:
    if node is None:
        return None, None
    if isinstance(node, ast.Name) and node.id in {"self", "cls"} and owner_class:
        return owner_class, None
    if isinstance(node, ast.IfExp):
        left = _summary_value(
            node.body, imports, module_name, owner_class, functions, classes, summaries
        )
        right = _summary_value(
            node.orelse, imports, module_name, owner_class, functions, classes, summaries
        )
        return left if left == right else (None, None)
    if isinstance(node, ast.Call):
        target = _resolve_expression(node.func, imports, module_name)
        if target in classes:
            return str(target), None
        summary = summaries.get(str(target or ""), {})
        types = summary.get("return_types", [])
        callables = summary.get("returned_callables", [])
        return (
            str(types[0]) if len(types) == 1 else None,
            str(callables[0]) if len(callables) == 1 else None,
        )
    target = _resolve_expression(node, imports, module_name)
    if target in functions:
        return None, str(target)
    return None, None


def _constant_value(node: ast.AST) -> object | None:
    if isinstance(node, ast.Constant) and isinstance(
        node.value, (str, int, float, bytes, bool, type(None))
    ):
        return node.value
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        value = _constant_value(node.operand)
        return -value if isinstance(value, (int, float)) else None
    return None


def _looks_like_constructor(value: str) -> bool:
    leaf = value.rsplit(".", 1)[-1]
    return bool(leaf and leaf[0].isupper())


def _collect_imports(
    tree: ast.AST, module_name: str, source_file: str
) -> dict[str, str]:
    imports: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports[alias.asname or alias.name.split(".")[0]] = alias.name
        elif isinstance(node, ast.ImportFrom):
            base = _absolute_import_module(
                module_name, source_file, node.module or "", node.level
            )
            for alias in node.names:
                if alias.name == "*":
                    continue
                imports[alias.asname or alias.name] = ".".join(
                    part for part in (base, alias.name) if part
                )
    return imports


def _absolute_import_module(
    current_module: str, source_file: str, imported_module: str, level: int
) -> str:
    if level <= 0:
        return imported_module
    package = (
        current_module
        if Path(source_file).name == "__init__.py"
        else current_module.rpartition(".")[0]
    )
    parts = [part for part in package.split(".") if part]
    ascend = max(0, level - 1)
    if ascend:
        parts = parts[:-ascend] if ascend < len(parts) else []
    if imported_module:
        parts.extend(imported_module.split("."))
    return ".".join(parts)


def _resolve_expression(
    node: ast.AST, imports: dict[str, str], module_name: str
) -> str | None:
    dotted = _dotted_name(node.func if isinstance(node, ast.Call) else node)
    if not dotted:
        return None
    first, separator, rest = dotted.partition(".")
    if first in imports:
        return imports[first] + (separator + rest if separator else "")
    return f"{module_name}.{dotted}" if "." not in dotted else dotted


def _dotted_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def _preferred_kind(kinds: set[str]) -> str:
    priority = {
        "dispatch_table_call": 9,
        "callable_dispatch": 8,
        "factory_return_dispatch": 7,
        "super_dispatch": 6,
        "protocol_dispatch": 5,
        "receiver_call": 4,
        "constructor_call": 3,
        "resolved_alias_call": 3,
        "call": 2,
        "decorator_application": 1,
    }
    return max(kinds, key=lambda value: priority.get(value, 0))
