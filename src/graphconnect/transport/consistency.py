"""Auto-inject ConsistencyLevel: eventual + $count=true for directory endpoints."""

from __future__ import annotations

import re
from urllib.parse import urlsplit


_DIRECTORY_COLLECTIONS = {
    "users",
    "groups",
    "directoryObjects",
    "applications",
    "servicePrincipals",
}

_ADVANCED_PARAMS = {"$filter", "$search", "$orderby", "$count"}

_API_VERSION_PREFIX = re.compile(r"^/?(v1\.0|beta)/", re.IGNORECASE)


def _first_segment(path: str) -> str | None:
    cleaned = path.lstrip("/")
    cleaned = _API_VERSION_PREFIX.sub("", "/" + cleaned).lstrip("/")
    if not cleaned:
        return None
    first = cleaned.split("/", 1)[0].split("(", 1)[0]
    return first or None


def needs_advanced_query(path: str, query: dict) -> bool:
    if not path:
        return False
    parsed = urlsplit(path)
    segment = _first_segment(parsed.path or path)
    if segment not in _DIRECTORY_COLLECTIONS:
        return False
    for key in query.keys():
        if key in _ADVANCED_PARAMS:
            return True
    return False


def apply_advanced_query(
    headers: dict, query: dict
) -> tuple[dict, dict]:
    """Return (headers, query) with ConsistencyLevel and $count=true set.

    Preserves caller-supplied header casing for ConsistencyLevel if present.
    """
    new_headers = dict(headers)
    has_consistency = any(k.lower() == "consistencylevel" for k in new_headers)
    if not has_consistency:
        new_headers["ConsistencyLevel"] = "eventual"
    new_query = dict(query)
    new_query.setdefault("$count", "true")
    return new_headers, new_query
