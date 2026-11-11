"""Qualified-name normalisation shared by the graph combiner and tracer."""
from __future__ import annotations

from functools import lru_cache

from .symbols import normalize_name


TEST_PATH_PARTS = {"test", "tests", "testing", "docs", "doc", "examples", "example"}


@lru_cache(maxsize=None)
def normalized_name(value: str) -> str:
    return normalize_name(value)


def name_variants(value: str) -> set[str]:
    normalized = normalized_name(value)
    if not normalized:
        return set()
    variants = {normalized}
    parts = normalized.split(".")
    while parts and parts[0] in {"src", "lib"}:
        parts = parts[1:]
        if parts:
            variants.add(".".join(parts))
    return variants


def resolve_in_graph(
    value: str,
    declarations: set[str],
    normalized_index: dict[str, tuple[str, ...]],
) -> str | None:
    if value in declarations:
        return value
    candidates = {
        actual
        for variant in name_variants(value)
        for actual in normalized_index.get(variant, ())
    }
    return next(iter(candidates)) if len(candidates) == 1 else None


def is_production_name(qname: str, file: str) -> bool:
    parts = {
        part.lower()
        for part in (file.replace("\\", "/").split("/") if file else qname.split("."))
    }
    return not bool(parts & TEST_PATH_PARTS)


def node_id(component: str, qname: str) -> str:
    return f"{component}::{qname}"
