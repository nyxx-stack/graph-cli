"""Catalog loader with fuzzy search and entry lookup."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from rapidfuzz import fuzz

from graph_cli.types import CatalogEntry, SafetyTier

_catalog: list[CatalogEntry] | None = None
_schemas: dict[str, Any] | None = None

CATALOG_DIR = Path(__file__).resolve().parent.parent.parent / "catalog"


def _load_catalog() -> list[CatalogEntry]:
    """Load all catalog YAML files into CatalogEntry objects."""
    global _catalog
    if _catalog is not None:
        return _catalog

    _catalog = []
    for yaml_file in sorted(CATALOG_DIR.glob("*.yaml")):
        if yaml_file.name.startswith("_"):
            continue
        with open(yaml_file, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        for op_data in data.get("operations", []):
            _catalog.append(CatalogEntry(**op_data))

    return _catalog


def search_catalog(query: str, top: int = 10) -> list[dict]:
    """Fuzzy search catalog entries by query string. Returns sorted by relevance."""
    catalog = _load_catalog()
    query_lower = query.lower()

    scored = []
    for entry in catalog:
        # Score against combined search text using token_set_ratio for flexible matching
        score = fuzz.token_set_ratio(query_lower, entry.search_text)
        if score > 30:  # Minimum relevance threshold
            scored.append({"entry": entry, "score": score})

    scored.sort(key=lambda x: x["score"], reverse=True)
    return scored[:top]


def list_catalog(
    domain: str | None = None,
    tier: str | None = None,
) -> list[CatalogEntry]:
    """List catalog entries, optionally filtered by domain and/or tier."""
    catalog = _load_catalog()
    results = catalog

    if domain:
        results = [e for e in results if e.domain == domain]
    if tier:
        results = [e for e in results if e.safety_tier.value == tier]

    return results


def get_entry(operation_id: str) -> CatalogEntry | None:
    """Look up a specific catalog entry by operation ID."""
    catalog = _load_catalog()
    for entry in catalog:
        if entry.id == operation_id:
            return entry
    return None


def get_schema(resource_type: str) -> dict[str, Any] | None:
    """Look up a resource type schema from the curated schemas file."""
    global _schemas
    if _schemas is None:
        schemas_file = CATALOG_DIR / "_schemas.yaml"
        if schemas_file.exists():
            with open(schemas_file, encoding="utf-8") as f:
                _schemas = yaml.safe_load(f) or {}
        else:
            _schemas = {}

    return _schemas.get(resource_type)
