"""Per-entity resolvers used by selectors.find / selectors.resolve.

Each public coroutine returns a ranked list of Locator candidates.
A zero-length return means "no match" — callers decide how to react.

All resolvers issue HTTP via ``graphconnect.transport.graph_request`` so
tests only need to mock the transport boundary.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any

from graphconnect.transport import GraphTransportError, graph_request

from ._model import AmbiguousMatch, Locator, NotFound


__all__ = [
    "AmbiguousMatch",
    "Locator",
    "NotFound",
    "find_assignments",
    "find_devices",
    "find_groups",
    "find_policies",
    "find_users",
    "looks_like_guid",
    "value_list",
]


_GUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)


def looks_like_guid(value: str) -> bool:
    return bool(_GUID_RE.match(value.strip()))


def _odata_literal(value: str) -> str:
    return value.replace("'", "''")


def value_list(body: Any) -> list[dict[str, Any]]:
    if isinstance(body, dict):
        value = body.get("value")
        if isinstance(value, list):
            return [row for row in value if isinstance(row, dict)]
        if "id" in body:
            return [body]
    if isinstance(body, list):
        return [row for row in body if isinstance(row, dict)]
    return []


def _rank_by_query(
    rows: list[dict[str, Any]],
    query: str,
    name_keys: tuple[str, ...],
) -> list[dict[str, Any]]:
    q = query.strip().lower()

    def score(row: dict[str, Any]) -> tuple[int, int]:
        for key in name_keys:
            val = str(row.get(key) or "").strip().lower()
            if val and val == q:
                return (0, 0)
        for key in name_keys:
            val = str(row.get(key) or "").strip().lower()
            if val and val.startswith(q):
                return (1, len(val))
        for key in name_keys:
            val = str(row.get(key) or "").strip().lower()
            if val and q in val:
                return (2, len(val))
        return (3, 0)

    ranked = sorted(rows, key=score)
    return [row for row in ranked if score(row)[0] < 3]


# --- devices ---------------------------------------------------------------


async def find_devices(query: str, *, profile: str, limit: int) -> list[Locator]:
    if looks_like_guid(query):
        resp = await graph_request(
            "GET",
            f"/deviceManagement/managedDevices/{query}",
            profile=profile,
            api_version="v1.0",
        )
        row = resp.body if isinstance(resp.body, dict) else None
        if row and row.get("id"):
            return [_device_locator(row)]
        return []

    literal = _odata_literal(query)
    resp = await graph_request(
        "GET",
        "/deviceManagement/managedDevices",
        profile=profile,
        api_version="v1.0",
        extra_headers=None,
        top=limit,
    )
    # Use client-side filter instead of $filter because managedDevices does not
    # support startsWith on deviceName universally; executor.py uses the same
    # fallback pattern (see _resolve_managed_device_reference).
    rows = value_list(resp.body)
    ranked = _rank_by_query(rows, query, ("deviceName",))
    # also attempt a server-side filter for better selectivity when the roster
    # is large — harmless if the client-side pass already found matches
    if not ranked:
        resp = await graph_request(
            "GET",
            f"/deviceManagement/managedDevices?$filter=deviceName eq '{literal}'",
            profile=profile,
            api_version="v1.0",
            top=limit,
        )
        ranked = _rank_by_query(value_list(resp.body), query, ("deviceName",))
    return [_device_locator(row) for row in ranked[:limit]]


def _device_locator(row: dict[str, Any]) -> Locator:
    return Locator(
        type="device",
        id=str(row["id"]),
        display_name=row.get("deviceName"),
        upn=row.get("userPrincipalName"),
    )


# --- users -----------------------------------------------------------------


async def find_users(query: str, *, profile: str, limit: int) -> list[Locator]:
    if looks_like_guid(query):
        resp = await graph_request(
            "GET",
            f"/users/{query}",
            profile=profile,
            api_version="v1.0",
        )
        row = resp.body if isinstance(resp.body, dict) else None
        if row and row.get("id"):
            return [_user_locator(row)]
        return []

    literal = _odata_literal(query)
    # UPN lookup first — direct hit when user typed an email-like string.
    if "@" in query:
        try:
            resp = await graph_request(
                "GET",
                f"/users/{query}",
                profile=profile,
                api_version="v1.0",
            )
            row = resp.body if isinstance(resp.body, dict) else None
            if row and row.get("id"):
                return [_user_locator(row)]
        except Exception:
            pass  # fall through to displayName search

    filter_expr = (
        f"startsWith(displayName,'{literal}') "
        f"or startsWith(userPrincipalName,'{literal}') "
        f"or startsWith(mail,'{literal}')"
    )
    resp = await graph_request(
        "GET",
        f"/users?$filter={filter_expr}",
        profile=profile,
        api_version="v1.0",
        top=limit,
    )
    rows = value_list(resp.body)
    ranked = _rank_by_query(rows, query, ("displayName", "userPrincipalName", "mail"))
    return [_user_locator(row) for row in ranked[:limit]]


def _user_locator(row: dict[str, Any]) -> Locator:
    return Locator(
        type="user",
        id=str(row["id"]),
        display_name=row.get("displayName"),
        upn=row.get("userPrincipalName"),
    )


# --- groups ----------------------------------------------------------------


async def find_groups(query: str, *, profile: str, limit: int) -> list[Locator]:
    if looks_like_guid(query):
        resp = await graph_request(
            "GET",
            f"/groups/{query}",
            profile=profile,
            api_version="v1.0",
        )
        row = resp.body if isinstance(resp.body, dict) else None
        if row and row.get("id"):
            return [_group_locator(row)]
        return []

    literal = _odata_literal(query)
    resp = await graph_request(
        "GET",
        f"/groups?$filter=startsWith(displayName,'{literal}')",
        profile=profile,
        api_version="v1.0",
        top=limit,
    )
    rows = value_list(resp.body)
    ranked = _rank_by_query(rows, query, ("displayName", "mailNickname"))
    return [_group_locator(row) for row in ranked[:limit]]


def _group_locator(row: dict[str, Any]) -> Locator:
    return Locator(
        type="group",
        id=str(row["id"]),
        display_name=row.get("displayName"),
    )


# --- policies --------------------------------------------------------------


_POLICY_ENDPOINTS: tuple[tuple[str, str, str, str, str], ...] = (
    # (kind, endpoint, api_version, name_field, id_field_hint)
    ("settingsCatalog", "/deviceManagement/configurationPolicies", "beta", "name", "id"),
    ("configurationProfile", "/deviceManagement/deviceConfigurations", "v1.0", "displayName", "id"),
    ("compliance", "/deviceManagement/deviceCompliancePolicies", "v1.0", "displayName", "id"),
    ("conditionalAccess", "/identity/conditionalAccess/policies", "v1.0", "displayName", "id"),
)


async def find_policies(
    query: str,
    *,
    profile: str,
    limit: int,
    kind: str | None = None,
) -> list[Locator]:
    endpoints = _POLICY_ENDPOINTS
    if kind is not None:
        endpoints = tuple(e for e in _POLICY_ENDPOINTS if e[0] == kind)
        if not endpoints:
            raise ValueError(f"unknown policy kind: {kind}")

    async def _fetch(endpoint: str, api_version: str, *, by_id: bool) -> Any:
        try:
            return await graph_request(
                "GET",
                f"{endpoint}/{query}" if by_id else endpoint,
                profile=profile,
                api_version=api_version,
                **({} if by_id else {"top": limit}),
            )
        except GraphTransportError:
            return None

    if looks_like_guid(query):
        responses = await asyncio.gather(
            *(_fetch(endpoint, api_version, by_id=True) for _, endpoint, api_version, _, _ in endpoints)
        )
        for (policy_kind, _, _, name_field, _), resp in zip(endpoints, responses, strict=True):
            if resp is None:
                continue
            row = resp.body if isinstance(resp.body, dict) else None
            if row and row.get("id"):
                return [_policy_locator(row, policy_kind, name_field)]
        return []

    responses = await asyncio.gather(
        *(_fetch(endpoint, api_version, by_id=False) for _, endpoint, api_version, _, _ in endpoints)
    )
    collected: list[Locator] = []
    for (policy_kind, _, _, name_field, _), resp in zip(endpoints, responses, strict=True):
        if resp is None:
            continue
        rows = value_list(resp.body)
        ranked = _rank_by_query(rows, query, (name_field,))
        collected.extend(_policy_locator(row, policy_kind, name_field) for row in ranked)
    return collected[:limit]


def _policy_locator(row: dict[str, Any], kind: str, name_field: str) -> Locator:
    return Locator(
        type="policy",
        id=str(row["id"]),
        display_name=row.get(name_field) or row.get("displayName") or row.get("name"),
        kind=kind,
    )


# --- assignments -----------------------------------------------------------


async def find_assignments(query: str, *, profile: str, limit: int) -> list[Locator]:
    """Resolve an assignment by the display name of its target group.

    A fully-specified assignment requires a policy scope to be useful, but for
    exploratory find() we return group hits so callers can drill down.
    """
    if looks_like_guid(query):
        return []
    groups = await find_groups(query, profile=profile, limit=limit)
    return [
        Locator(
            type="assignment",
            id=group.id,
            display_name=group.display_name,
            kind="groupTarget",
        )
        for group in groups
    ]
