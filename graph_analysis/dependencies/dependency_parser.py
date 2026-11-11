from __future__ import annotations

import ast
import configparser
import json
import re
import sys
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .common import normalize_package_name
from .packaging_compat import InvalidRequirement, Requirement


IMPORT_TO_PACKAGE = {
    "PIL": "Pillow",
    "OpenSSL": "pyOpenSSL",
    "Crypto": "pycryptodome",
    "cryptography": "cryptography",
    "cv2": "opencv-python",
    "bs4": "beautifulsoup4",
    "yaml": "PyYAML",
    "sklearn": "scikit-learn",
    "skimage": "scikit-image",
    "dateutil": "python-dateutil",
    "dotenv": "python-dotenv",
    "jwt": "PyJWT",
    "flask": "Flask",
    "django": "Django",
    "jinja2": "Jinja2",
    "lxml": "lxml",
    "matplotlib": "matplotlib",
    "numpy": "numpy",
    "pandas": "pandas",
    "requests": "requests",
    "scipy": "scipy",
    "sqlalchemy": "SQLAlchemy",
    "torch": "torch",
}

DEPENDENCY_BASENAMES = {
    "pyproject.toml",
    "setup.cfg",
    "setup.py",
    "pipfile",
    "pipfile.lock",
    "poetry.lock",
    "uv.lock",
    "pdm.lock",
    "environment.yml",
    "environment.yaml",
    "conda.yml",
    "conda.yaml",
}


@dataclass
class DependencySpec:
    name: str
    requirement: str
    source_type: str
    source_path: str
    category: str = "runtime"
    direct: bool = True
    locked_version: str | None = None
    inferred: bool = False


def discover_dependency_files(project_path: Path) -> list[Path]:
    files: list[Path] = []
    for path in project_path.rglob("*"):
        if not path.is_file() or _is_ignored(path):
            continue
        base = path.name.lower()
        if base in DEPENDENCY_BASENAMES or base.startswith("requirements") and path.suffix in {"", ".txt", ".in", ".pip"}:
            files.append(path)
    return sorted(files)


def extract_dependencies(
    project_path: Path,
    include_dev: bool = False,
    include_extras: bool = False,
    infer_when_missing: bool = True,
) -> dict[str, Any]:
    warnings: list[str] = []
    specs: list[DependencySpec] = []
    locked_packages: dict[str, dict[str, Any]] = {}
    dependency_files = discover_dependency_files(project_path)

    for path in dependency_files:
        base = path.name.lower()
        rel = str(path.relative_to(project_path))
        try:
            if base.startswith("requirements"):
                specs.extend(parse_requirements_file(path, project_path, warnings))
            elif base == "pyproject.toml":
                specs.extend(parse_pyproject(path, include_dev, include_extras, warnings))
            elif base == "setup.cfg":
                specs.extend(parse_setup_cfg(path, include_extras, warnings))
            elif base == "setup.py":
                specs.extend(parse_setup_py(path, include_extras, warnings))
            elif base == "pipfile":
                specs.extend(parse_pipfile(path, include_dev, warnings))
            elif base == "pipfile.lock":
                locked_packages.update(parse_pipfile_lock(path, include_dev, warnings))
            elif base == "poetry.lock":
                locked_packages.update(parse_toml_lock(path, "poetry.lock", include_dev, warnings))
            elif base in {"uv.lock", "pdm.lock"}:
                locked_packages.update(parse_toml_lock(path, base, include_dev, warnings))
            elif base in {"environment.yml", "environment.yaml", "conda.yml", "conda.yaml"}:
                specs.extend(parse_environment_yml(path, warnings))
        except Exception as exc:
            warnings.append(f"failed to parse {rel}: {exc}")

    if infer_when_missing and not specs and not locked_packages:
        specs.extend(infer_import_dependencies(project_path, warnings))

    return {
        "dependency_files": [str(path.relative_to(project_path)) for path in dependency_files],
        "requirements": [asdict(spec) for spec in _dedupe_specs(specs)],
        "locked_packages": locked_packages,
        "warnings": warnings,
    }


def parse_requirements_file(path: Path, project_path: Path, warnings: list[str], seen: set[Path] | None = None) -> list[DependencySpec]:
    seen = seen or set()
    path = path.resolve()
    if path in seen:
        return []
    seen.add(path)
    specs: list[DependencySpec] = []
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = _strip_requirement_line(raw_line)
        if not line:
            continue
        if line.startswith(("-r ", "--requirement ")):
            include_name = line.split(maxsplit=1)[1]
            include_path = (path.parent / include_name).resolve()
            if include_path.exists() and include_path.is_file():
                specs.extend(parse_requirements_file(include_path, project_path, warnings, seen))
            else:
                warnings.append(f"missing included requirements file {include_name} referenced by {path}")
            continue
        if line.startswith(("-", "--")):
            continue
        spec = _dependency_spec_from_requirement(line, "requirements", path, project_path, warnings)
        if spec:
            specs.append(spec)
    return specs


def parse_pyproject(path: Path, include_dev: bool, include_extras: bool, warnings: list[str]) -> list[DependencySpec]:
    payload = tomllib.loads(path.read_text(encoding="utf-8"))
    specs: list[DependencySpec] = []
    project = payload.get("project", {})
    for item in project.get("dependencies", []) or []:
        spec = _dependency_spec_from_requirement(item, "pyproject.project", path, path.parent, warnings)
        if spec:
            specs.append(spec)
    if include_extras:
        for extra_name, deps in (project.get("optional-dependencies", {}) or {}).items():
            for item in deps or []:
                spec = _dependency_spec_from_requirement(item, "pyproject.optional", path, path.parent, warnings, category=f"optional:{extra_name}")
                if spec:
                    specs.append(spec)

    poetry = payload.get("tool", {}).get("poetry", {})
    for name, value in (poetry.get("dependencies", {}) or {}).items():
        if isinstance(value, dict) and value.get("optional") and not include_extras:
            continue
        spec = _spec_from_named_dependency(name, value, "pyproject.poetry", path, warnings)
        if spec:
            specs.append(spec)
    if include_dev:
        for name, value in (poetry.get("dev-dependencies", {}) or {}).items():
            spec = _spec_from_named_dependency(name, value, "pyproject.poetry.dev", path, warnings, category="dev")
            if spec:
                specs.append(spec)
        for group_name, group in (poetry.get("group", {}) or {}).items():
            for name, value in (group.get("dependencies", {}) or {}).items():
                spec = _spec_from_named_dependency(name, value, "pyproject.poetry.group", path, warnings, category=f"group:{group_name}")
                if spec:
                    specs.append(spec)

    if include_dev:
        for group_name, deps in (payload.get("dependency-groups", {}) or {}).items():
            for item in deps or []:
                spec = _dependency_spec_from_requirement(item, "pyproject.dependency-groups", path, path.parent, warnings, category=f"group:{group_name}")
                if spec:
                    specs.append(spec)
    return specs


def parse_setup_cfg(path: Path, include_extras: bool, warnings: list[str]) -> list[DependencySpec]:
    parser = configparser.ConfigParser()
    parser.read(path, encoding="utf-8")
    specs: list[DependencySpec] = []
    if parser.has_option("options", "install_requires"):
        for item in _split_multiline_value(parser.get("options", "install_requires")):
            spec = _dependency_spec_from_requirement(item, "setup.cfg", path, path.parent, warnings)
            if spec:
                specs.append(spec)
    if include_extras and parser.has_section("options.extras_require"):
        for extra_name, value in parser.items("options.extras_require"):
            for item in _split_multiline_value(value):
                spec = _dependency_spec_from_requirement(item, "setup.cfg.extras", path, path.parent, warnings, category=f"optional:{extra_name}")
                if spec:
                    specs.append(spec)
    return specs


def parse_setup_py(path: Path, include_extras: bool, warnings: list[str]) -> list[DependencySpec]:
    specs: list[DependencySpec] = []
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except SyntaxError as exc:
        warnings.append(f"setup.py syntax not parsed in {path}: {exc}")
        return specs
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func_name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
        if func_name != "setup":
            continue
        for keyword in node.keywords:
            if keyword.arg == "install_requires":
                for item in _literal_string_list(keyword.value):
                    spec = _dependency_spec_from_requirement(item, "setup.py", path, path.parent, warnings)
                    if spec:
                        specs.append(spec)
            if include_extras and keyword.arg == "extras_require" and isinstance(keyword.value, ast.Dict):
                for key_node, value_node in zip(keyword.value.keys, keyword.value.values, strict=False):
                    extra_name = ast.literal_eval(key_node) if key_node else "unknown"
                    for item in _literal_string_list(value_node):
                        spec = _dependency_spec_from_requirement(item, "setup.py.extras", path, path.parent, warnings, category=f"optional:{extra_name}")
                        if spec:
                            specs.append(spec)
    return specs


def parse_pipfile(path: Path, include_dev: bool, warnings: list[str]) -> list[DependencySpec]:
    payload = tomllib.loads(path.read_text(encoding="utf-8"))
    specs: list[DependencySpec] = []
    for name, value in (payload.get("packages", {}) or {}).items():
        spec = _spec_from_named_dependency(name, value, "Pipfile", path, warnings)
        if spec:
            specs.append(spec)
    if include_dev:
        for name, value in (payload.get("dev-packages", {}) or {}).items():
            spec = _spec_from_named_dependency(name, value, "Pipfile.dev", path, warnings, category="dev")
            if spec:
                specs.append(spec)
    return specs


def parse_pipfile_lock(path: Path, include_dev: bool, warnings: list[str]) -> dict[str, dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    locked: dict[str, dict[str, Any]] = {}
    for section_name, category in (("default", "runtime"), ("develop", "dev")):
        if category == "dev" and not include_dev:
            continue
        for name, value in (payload.get(section_name, {}) or {}).items():
            version = str(value.get("version", "")).removeprefix("==")
            if not version:
                continue
            _add_locked(locked, name, version, "Pipfile.lock", path, category)
    return locked


def parse_toml_lock(path: Path, source_type: str, include_dev: bool, warnings: list[str]) -> dict[str, dict[str, Any]]:
    payload = tomllib.loads(path.read_text(encoding="utf-8"))
    locked: dict[str, dict[str, Any]] = {}
    packages = payload.get("package", []) or payload.get("packages", []) or []
    if isinstance(packages, dict):
        packages = packages.values()
    for package in packages:
        if not isinstance(package, dict):
            continue
        groups = package.get("groups") or []
        if package.get("category"):
            category = str(package["category"])
        elif groups:
            category = str(groups[0])
        else:
            category = "runtime"
        if not include_dev and category in {"dev", "test", "docs"}:
            continue
        name = package.get("name")
        version = package.get("version")
        if not name or not version:
            continue
        dependencies: list[str] = []
        deps = package.get("dependencies") or {}
        if isinstance(deps, dict):
            for dep_name, dep_value in deps.items():
                dep_spec = _spec_from_named_dependency(dep_name, dep_value, source_type, path, warnings, direct=False)
                if dep_spec:
                    dependencies.append(dep_spec.requirement)
        elif isinstance(deps, list):
            for item in deps:
                if isinstance(item, dict) and item.get("name"):
                    dep_value = item.get("specifier") or item.get("version") or item.get("constraint") or ""
                    dep_spec = _spec_from_named_dependency(item["name"], dep_value, source_type, path, warnings, direct=False)
                    if dep_spec:
                        dependencies.append(dep_spec.requirement)
                else:
                    dependencies.append(str(item))
        _add_locked(locked, str(name), str(version), source_type, path, category, dependencies)
    return locked


def parse_environment_yml(path: Path, warnings: list[str]) -> list[DependencySpec]:
    specs: list[DependencySpec] = []
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    in_dependencies = False
    in_pip = False
    for raw in lines:
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped == "dependencies:":
            in_dependencies = True
            in_pip = False
            continue
        if not in_dependencies:
            continue
        if stripped.startswith("- pip:"):
            in_pip = True
            continue
        if not stripped.startswith("- "):
            if not raw.startswith(" "):
                in_dependencies = False
            continue
        item = stripped[2:].strip().strip("\"'")
        if in_pip:
            spec = _dependency_spec_from_requirement(item, "environment.yml.pip", path, path.parent, warnings)
        else:
            spec = _dependency_spec_from_requirement(_conda_to_requirement(item), "environment.yml", path, path.parent, warnings)
        if spec:
            specs.append(spec)
    return specs


def infer_import_dependencies(project_path: Path, warnings: list[str]) -> list[DependencySpec]:
    local_modules = _local_module_names(project_path)
    stdlib = set(getattr(sys, "stdlib_module_names", set())) | set(sys.builtin_module_names)
    imports: set[str] = set()
    for path in project_path.rglob("*.py"):
        if not path.is_file() or _is_ignored(path):
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except OSError as exc:
            warnings.append(f"failed to read source file {path}: {exc}")
            continue
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.name.split(".", 1)[0])
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                imports.add(node.module.split(".", 1)[0])

    specs: list[DependencySpec] = []
    for module in sorted(imports):
        if module in stdlib or module in local_modules or module.startswith("_"):
            continue
        package = IMPORT_TO_PACKAGE.get(module, module)
        specs.append(
            DependencySpec(
                name=package,
                requirement=package,
                source_type="import_inference",
                source_path="source_imports",
                category="inferred",
                inferred=True,
            )
        )
    if specs:
        warnings.append("dependencies inferred from imports because no supported dependency files were found")
    return specs


def _dependency_spec_from_requirement(
    raw: str,
    source_type: str,
    path: Path,
    project_path: Path,
    warnings: list[str],
    category: str = "runtime",
    direct: bool = True,
) -> DependencySpec | None:
    cleaned = _strip_requirement_line(raw)
    if not cleaned:
        return None
    egg = re.search(r"[#&]egg=([A-Za-z0-9_.-]+)", cleaned)
    if egg:
        cleaned = egg.group(1)
    try:
        req = Requirement(cleaned)
    except InvalidRequirement as exc:
        warnings.append(f"unsupported requirement {raw!r} in {path}: {exc}")
        return None
    if req.url:
        warnings.append(f"skipping non-PyPI direct URL requirement {raw!r} in {path}")
        return None
    locked_version = _exact_version_from_requirement(req)
    try:
        source_path = str(path.relative_to(project_path))
    except ValueError:
        source_path = str(path)
    return DependencySpec(
        name=req.name,
        requirement=str(req),
        source_type=source_type,
        source_path=source_path,
        category=category,
        direct=direct,
        locked_version=locked_version,
    )


def _spec_from_named_dependency(
    name: str,
    value: Any,
    source_type: str,
    path: Path,
    warnings: list[str],
    category: str = "runtime",
    direct: bool = True,
) -> DependencySpec | None:
    if name.lower() == "python":
        return None
    extras = ""
    marker = ""
    if isinstance(value, str):
        spec = poetry_spec_to_pep440(value)
    elif isinstance(value, dict):
        if value.get("path") or value.get("git") or value.get("url"):
            warnings.append(f"skipping non-PyPI dependency {name!r} in {path}")
            return None
        spec = poetry_spec_to_pep440(str(value.get("version", "") or ""))
        extra_values = value.get("extras") or []
        if extra_values:
            extras = "[" + ",".join(extra_values) + "]"
        if value.get("markers"):
            marker = f"; {value['markers']}"
    else:
        spec = ""
    requirement = f"{name}{extras}{spec}{marker}"
    return _dependency_spec_from_requirement(requirement, source_type, path, path.parent, warnings, category=category, direct=direct)


def poetry_spec_to_pep440(spec: str) -> str:
    spec = spec.strip()
    spec = re.sub(r"\s+(?=[<>=!~])", ",", spec)
    if spec in {"", "*"}:
        return ""
    if spec.startswith("^"):
        return _caret_to_range(spec[1:])
    if spec.startswith("~") and not spec.startswith("~="):
        return _tilde_to_range(spec[1:])
    if any(spec.startswith(op) for op in ("<", ">", "=", "!", "~=")):
        return spec
    if "*" in spec:
        return f"=={spec}"
    if re.match(r"^\d+(\.\d+)*([a-zA-Z0-9_.+-]*)?$", spec):
        return f"=={spec}"
    return spec


def _caret_to_range(version: str) -> str:
    parts = [int(part) for part in re.findall(r"\d+", version)[:3]]
    while len(parts) < 3:
        parts.append(0)
    major, minor, patch = parts[:3]
    if major > 0:
        upper = f"{major + 1}.0.0"
    elif minor > 0:
        upper = f"0.{minor + 1}.0"
    else:
        upper = f"0.0.{patch + 1}"
    return f">={version},<{upper}"


def _tilde_to_range(version: str) -> str:
    parts = [int(part) for part in re.findall(r"\d+", version)[:3]]
    if len(parts) <= 1:
        upper = f"{parts[0] + 1}.0" if parts else "1.0"
    else:
        upper = f"{parts[0]}.{parts[1] + 1}"
    return f">={version},<{upper}"


def _exact_version_from_requirement(req: Requirement) -> str | None:
    for specifier in req.specifier:
        if specifier.operator in {"==", "==="} and "*" not in specifier.version:
            return specifier.version
    return None


def _strip_requirement_line(line: str) -> str:
    line = line.strip()
    if not line or line.startswith("#"):
        return ""
    if " #" in line:
        line = line.split(" #", 1)[0].strip()
    return line


def _split_multiline_value(value: str) -> list[str]:
    return [line.strip() for line in value.splitlines() if line.strip() and not line.strip().startswith("#")]


def _literal_string_list(node: ast.AST) -> list[str]:
    try:
        value = ast.literal_eval(node)
    except Exception:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple, set)):
        return [item for item in value if isinstance(item, str)]
    return []


def _conda_to_requirement(item: str) -> str:
    if item.startswith("python"):
        return ""
    if re.match(r"^[A-Za-z0-9_.-]+=[^=]", item):
        pieces = item.split("=")
        if len(pieces) >= 2:
            return f"{pieces[0]}=={pieces[1]}"
    return item


def _add_locked(
    locked: dict[str, dict[str, Any]],
    name: str,
    version: str,
    source_type: str,
    path: Path,
    category: str,
    dependencies: list[str] | None = None,
) -> None:
    key = normalize_package_name(name)
    locked[key] = {
        "name": name,
        "version": version,
        "source_type": source_type,
        "source_path": str(path.name),
        "category": category,
        "dependencies": dependencies or [],
    }


def _dedupe_specs(specs: list[DependencySpec]) -> list[DependencySpec]:
    seen: set[tuple[str, str, str, str]] = set()
    result: list[DependencySpec] = []
    for spec in specs:
        key = (normalize_package_name(spec.name), spec.requirement, spec.source_type, spec.category)
        if key in seen:
            continue
        seen.add(key)
        result.append(spec)
    return result


def _local_module_names(project_path: Path) -> set[str]:
    names: set[str] = set()
    for root in (project_path, project_path / "src"):
        if not root.exists():
            continue
        for child in root.iterdir():
            if child.is_file() and child.suffix == ".py":
                names.add(child.stem)
            elif child.is_dir() and (child / "__init__.py").is_file():
                names.add(child.name)
    return names


def _is_ignored(path: Path) -> bool:
    ignored = {".git", ".hg", ".svn", ".tox", ".venv", "venv", "env", "__pycache__", "build", "dist", ".mypy_cache", ".pytest_cache"}
    return any(part in ignored for part in path.parts)
