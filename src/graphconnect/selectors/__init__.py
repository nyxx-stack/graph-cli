"""Entity selector: name/id → Locator, and multi-candidate find."""

from __future__ import annotations

import asyncio

from ._model import AmbiguousMatch, EntityType, Locator, NotFound
from .resolvers import (
    find_assignments,
    find_devices,
    find_groups,
    find_policies,
    find_users,
    looks_like_guid,
    value_list,
)

_ALL_TYPES: tuple[EntityType, ...] = ("device", "user", "group", "policy", "assignment")


async def _find_for_type(
    query: str,
    entity_type: EntityType,
    *,
    profile: str,
    limit: int,
) -> list[Locator]:
    if entity_type == "device":
        return await find_devices(query, profile=profile, limit=limit)
    if entity_type == "user":
        return await find_users(query, profile=profile, limit=limit)
    if entity_type == "group":
        return await find_groups(query, profile=profile, limit=limit)
    if entity_type == "policy":
        return await find_policies(query, profile=profile, limit=limit)
    if entity_type == "assignment":
        return await find_assignments(query, profile=profile, limit=limit)
    raise ValueError(f"unknown entity type: {entity_type}")


async def find(
    query: str,
    *,
    type: EntityType | None = None,
    profile: str = "default",
    limit: int = 10,
) -> list[Locator]:
    """Return ranked candidate locators. Empty list if no matches."""
    if type is not None:
        return await _find_for_type(query, type, profile=profile, limit=limit)

    results = await asyncio.gather(
        *(_find_for_type(query, t, profile=profile, limit=limit) for t in _ALL_TYPES),
        return_exceptions=True,
    )
    flat: list[Locator] = []
    for res in results:
        if isinstance(res, Exception):
            continue
        flat.extend(res)
    return flat[:limit]


async def resolve(
    query: str,
    *,
    type: EntityType | None = None,
    profile: str = "default",
) -> Locator:
    """Return exactly one Locator, or raise NotFound / AmbiguousMatch."""
    candidates = await find(query, type=type, profile=profile, limit=10)
    if not candidates:
        raise NotFound(f"no match for query: {query!r}")
    exact = [c for c in candidates if _is_exact(c, query)]
    if len(exact) == 1:
        return exact[0]
    if len(exact) > 1:
        raise AmbiguousMatch(query, exact)
    if len(candidates) == 1:
        return candidates[0]
    raise AmbiguousMatch(query, candidates)


def _is_exact(locator: Locator, query: str) -> bool:
    q = query.strip().lower()
    if not q:
        return False
    if locator.id.lower() == q:
        return True
    if locator.display_name and locator.display_name.strip().lower() == q:
        return True
    if locator.upn and locator.upn.strip().lower() == q:
        return True
    return False


__all__ = [
    "AmbiguousMatch",
    "EntityType",
    "Locator",
    "NotFound",
    "find",
    "looks_like_guid",
    "resolve",
    "value_list",
]
