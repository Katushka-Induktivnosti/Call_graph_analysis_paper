from __future__ import annotations

import re
import shutil
import tarfile
import zipfile
from pathlib import Path
from typing import Any

from .common import CACHE_DIR, hardlink_or_copy, safe_package_dir, sha256_file
from .pypi import PyPIClient


class NoPythonSourcesError(RuntimeError):
    pass


def collect_pypi_source(
    package: str,
    version: str,
    target_dir: Path,
    pypi: PyPIClient,
    cache_dir: Path = CACHE_DIR,
) -> dict[str, Any]:
    """Download and unpack the PyPI sdist (or a wheel when no sdist exists)."""
    files, release_payload, warnings = pypi.release_files(package, version)
    sdists = [item for item in files if item.get("packagetype") == "sdist"]
    wheels = [item for item in files if item.get("packagetype") == "bdist_wheel"]
    selected = sorted(sdists or wheels, key=lambda item: item.get("filename", ""))[0] if (sdists or wheels) else None
    if not selected:
        return {"status": "missing", "warnings": warnings + ["no sdist or wheel available"]}

    artifact_cache = cache_dir / "artifacts" / safe_package_dir(package) / version / selected["filename"]
    if not artifact_cache.exists():
        pypi.http.download_file(selected["url"], artifact_cache)

    source_cache = cache_dir / "sources" / "pypi" / safe_package_dir(package) / version / selected["filename"].replace("/", "_")
    if not source_cache.exists():
        source_cache.mkdir(parents=True, exist_ok=True)
        _unpack_archive(artifact_cache, source_cache)

    source_target = target_dir / ("source" if selected.get("packagetype") == "sdist" else "wheel_contents")
    hardlink_or_copy(source_cache, source_target)
    return {
        "status": "collected",
        "artifact_type": selected.get("packagetype"),
        "filename": selected.get("filename"),
        "url": selected.get("url"),
        "sha256": sha256_file(artifact_cache),
        "source_path": str(source_target),
        "non_source_fallback": selected.get("packagetype") != "sdist",
        "release_info": {
            "summary": (release_payload.get("info") or {}).get("summary"),
            "requires_python": (release_payload.get("info") or {}).get("requires_python"),
        },
        "warnings": warnings,
    }


def choose_repo_root(
    source_path: Path,
    normalized_package: str = "",
    version: str = "",
) -> Path:
    """Pick the directory to analyse inside an unpacked sdist or wheel."""
    visible = sorted(path for path in source_path.iterdir() if not path.name.startswith("."))
    directories = [path for path in visible if path.is_dir()]
    root_python_files = [path for path in visible if path.is_file() and path.suffix == ".py"]
    conventional = directories[0] if len(directories) == 1 and not root_python_files else source_path
    if contains_python_sources(conventional):
        return conventional.resolve()
    if conventional != source_path and contains_python_sources(source_path):
        return source_path.resolve()

    package_key = canonical_distribution_name(normalized_package)
    installed_candidates: list[Path] = []
    for metadata in source_path.rglob("*"):
        if not metadata.is_dir() or not metadata.name.endswith((".egg-info", ".dist-info")):
            continue
        metadata_key = canonical_distribution_name(
            re.split(r"-(?=\d)", metadata.name.rsplit(".", 1)[0], maxsplit=1)[0]
        )
        if package_key and metadata_key != package_key:
            continue
        candidate = metadata.parent
        if contains_python_sources(candidate):
            installed_candidates.append(candidate)
    unique = sorted({path.resolve() for path in installed_candidates}, key=str)
    if len(unique) == 1:
        return unique[0]
    if len(unique) > 1:
        version_matches = [
            path
            for path in unique
            if any(
                version in child.name
                for child in path.iterdir()
                if child.name.endswith((".egg-info", ".dist-info"))
            )
        ]
        if len(version_matches) == 1:
            return version_matches[0]
        raise NoPythonSourcesError(
            f"ambiguous installed source roots under {source_path}: "
            + ", ".join(str(path) for path in unique)
        )
    raise NoPythonSourcesError(f"no analysable Python files under {source_path}")


def contains_python_sources(path: Path) -> bool:
    if not path.is_dir():
        return False
    for candidate in path.rglob("*.py"):
        try:
            relative = candidate.relative_to(path)
        except ValueError:
            continue
        if not any(part.startswith(".") for part in relative.parts[:-1]):
            return True
    return False


def canonical_distribution_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _unpack_archive(artifact: Path, dest: Path) -> None:
    if tarfile.is_tarfile(artifact):
        with tarfile.open(artifact) as archive:
            archive.extractall(dest, filter="data")
    elif zipfile.is_zipfile(artifact):
        with zipfile.ZipFile(artifact) as archive:
            dest_root = dest.resolve()
            for member in archive.namelist():
                target = (dest / member).resolve()
                try:
                    target.relative_to(dest_root)
                except ValueError as exc:
                    raise RuntimeError(f"unsafe archive member path: {member}") from exc
                archive.extract(member, dest)
    else:
        shutil.copy2(artifact, dest / artifact.name)
