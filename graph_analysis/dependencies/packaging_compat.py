from __future__ import annotations

try:  # Prefer the public package from requirements.txt.
    from packaging.markers import default_environment
    from packaging.requirements import InvalidRequirement, Requirement
    from packaging.specifiers import InvalidSpecifier, SpecifierSet
    from packaging.utils import canonicalize_name
    from packaging.version import InvalidVersion, Version
except ModuleNotFoundError:  # Fall back to the copy vendored by pip.
    from pip._vendor.packaging.markers import default_environment
    from pip._vendor.packaging.requirements import InvalidRequirement, Requirement
    from pip._vendor.packaging.specifiers import InvalidSpecifier, SpecifierSet
    from pip._vendor.packaging.utils import canonicalize_name
    from pip._vendor.packaging.version import InvalidVersion, Version


# Dependency resolution targets a fixed interpreter version so results do not
# depend on the Python used to run the pipeline.
TARGET_PYTHON_VERSION = "3.14"
TARGET_PYTHON_FULL_VERSION = "3.14.5"


def python_marker_environment() -> dict[str, str]:
    env = default_environment()
    env["python_version"] = TARGET_PYTHON_VERSION
    env["python_full_version"] = TARGET_PYTHON_FULL_VERSION
    return env


__all__ = [
    "InvalidRequirement",
    "InvalidSpecifier",
    "InvalidVersion",
    "Requirement",
    "SpecifierSet",
    "Version",
    "canonicalize_name",
    "TARGET_PYTHON_FULL_VERSION",
    "python_marker_environment",
]
