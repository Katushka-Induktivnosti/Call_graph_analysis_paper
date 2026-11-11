from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .common import CACHE_DIR, parse_datetime, sha256_text, utc_now
from .http_client import HttpClient
from .packaging_compat import TARGET_PYTHON_FULL_VERSION, InvalidSpecifier, InvalidVersion, SpecifierSet, Version


class PyPIClient:
    def __init__(self, cache_dir: Path = CACHE_DIR / "pypi_json", refresh_cache: bool = False) -> None:
        self.cache_dir = cache_dir
        self.refresh_cache = refresh_cache
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.http = HttpClient(default_headers={"Accept": "application/json"})

    def project_json(self, name: str) -> dict[str, Any]:
        safe = name.lower().replace("/", "_")
        return self._cached_json(f"https://pypi.org/pypi/{safe}/json", self.cache_dir / f"{safe}.json")

    def release_json(self, name: str, version: str) -> dict[str, Any]:
        safe = name.lower().replace("/", "_")
        version_safe = version.replace("/", "_")
        path = self.cache_dir / safe / f"{version_safe}.json"
        return self._cached_json(f"https://pypi.org/pypi/{safe}/{version_safe}/json", path)

    def select_version(
        self,
        name: str,
        specifier: str,
        cutoff: str,
        python_version: str = TARGET_PYTHON_FULL_VERSION,
    ) -> tuple[str | None, dict[str, Any], list[str]]:
        warnings: list[str] = []
        try:
            spec = SpecifierSet(specifier or "")
        except InvalidSpecifier as exc:
            warnings.append(f"invalid specifier for {name}: {specifier!r} ({exc})")
            spec = SpecifierSet("")
        try:
            payload = self.project_json(name)
        except Exception as exc:
            return None, {}, [f"failed to fetch PyPI metadata for {name}: {exc}"]

        cutoff_dt = parse_datetime(cutoff)
        candidates: list[tuple[Version, str, dict[str, Any]]] = []
        for version_text, files in payload.get("releases", {}).items():
            try:
                version = Version(version_text)
            except InvalidVersion:
                continue
            if spec and not spec.contains(version, prereleases=True):
                continue
            usable_files = []
            for file_info in files or []:
                upload_time = file_info.get("upload_time_iso_8601") or file_info.get("upload_time")
                if not upload_time:
                    continue
                try:
                    if parse_datetime(upload_time) > cutoff_dt:
                        continue
                except Exception:
                    continue
                requires_python = file_info.get("requires_python") or ""
                if requires_python and not self.requires_python_allows(requires_python, python_version):
                    continue
                usable_files.append(file_info)
            if usable_files:
                earliest_usable = sorted(
                    usable_files,
                    key=lambda item: item.get("upload_time_iso_8601") or item.get("upload_time") or "",
                )[0]
                candidates.append((version, version_text, earliest_usable))

        finals = [item for item in candidates if not item[0].is_prerelease]
        selected_pool = finals or candidates
        if not selected_pool:
            return None, {}, warnings + [f"no PyPI release for {name!r} satisfies {specifier!r} by {cutoff}"]
        selected = sorted(selected_pool, key=lambda item: item[0])[-1]
        return selected[1], selected[2], warnings

    def release_requires_dist(self, name: str, version: str) -> tuple[list[str], dict[str, Any], list[str]]:
        try:
            payload = self.release_json(name, version)
        except Exception as exc:
            return [], {}, [f"failed to fetch PyPI release metadata for {name}=={version}: {exc}"]
        info = payload.get("info", {}) or {}
        requires_dist = info.get("requires_dist") or []
        return list(requires_dist), payload, []

    def release_files(self, name: str, version: str) -> tuple[list[dict[str, Any]], dict[str, Any], list[str]]:
        try:
            payload = self.release_json(name, version)
        except Exception as exc:
            return [], {}, [f"failed to fetch PyPI release files for {name}=={version}: {exc}"]
        return list(payload.get("urls") or []), payload, []

    def requires_python_allows(self, requires_python: str, python_version: str = TARGET_PYTHON_FULL_VERSION) -> bool:
        try:
            return SpecifierSet(requires_python).contains(Version(python_version), prereleases=True)
        except Exception:
            return True

    def _cached_json(self, url: str, path: Path) -> dict[str, Any]:
        if path.exists() and not self.refresh_cache:
            with path.open("r", encoding="utf-8") as handle:
                return json.load(handle)["payload"]
        payload = self.http.request_json(url)
        path.parent.mkdir(parents=True, exist_ok=True)
        serialized = json.dumps(payload, sort_keys=True)
        with path.open("w", encoding="utf-8") as handle:
            json.dump(
                {
                    "url": url,
                    "fetched_at": utc_now(),
                    "sha256": sha256_text(serialized),
                    "payload": payload,
                },
                handle,
                indent=2,
                sort_keys=True,
            )
            handle.write("\n")
        return payload
