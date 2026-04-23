"""Tiny name-resolution helpers for the explain package.

Parallels executor.py's _resolve_managed_device_reference / _resolve_policy_reference
/ _list_policy_lookup but uses the transport boundary. At merge time the merge
lead should swap these for selectors.resolve() once the selectors package lands.

TODO(merge): replace with graphconnect.selectors.resolve() when selector agent lands.
"""

from __future__ import annotations

import asyncio
from typing import Any

from ._transport import _values, graph_get


def _norm(value: Any) -> str:
    return str(value or "").strip().lower()


def _odata_literal(value: str) -> str:
    return value.replace("'", "''")


def _pick_named(
    resources: list[dict[str, Any]], name: str, *, name_key: str
) -> dict[str, Any] | None:
    desired = _norm(name)
    exact = [r for r in resources if _norm(r.get(name_key)) == desired]
    if len(exact) == 1:
        return exact[0]
    if len(exact) > 1:
        return None
    contains = [r for r in resources if desired and desired in _norm(r.get(name_key))]
    if len(contains) == 1:
        return contains[0]
    return None


async def list_policy_lookup(*, profile: str) -> dict[str, dict[str, Any]]:
    settings_body, classic_body = await asyncio.gather(
        graph_get(
            "/deviceManagement/configurationPolicies?$select=id,name",
            profile=profile,
            api_version="beta",
        ),
        graph_get(
            "/deviceManagement/deviceConfigurations?$select=id,displayName",
            profile=profile,
            api_version="v1.0",
        ),
    )
    settings = _values(settings_body)
    classic = _values(classic_body)
    out: dict[str, dict[str, Any]] = {}
    for row in settings:
        pid = row.get("id")
        if pid:
            out[str(pid)] = {
                "id": str(pid),
                "name": row.get("name"),
                "kind": "settings_catalog",
            }
    for row in classic:
        pid = row.get("id")
        if pid:
            out[str(pid)] = {
                "id": str(pid),
                "name": row.get("displayName"),
                "kind": "config_profile",
            }
    return out


async def resolve_device(
    *, device_id: str | None, device_name: str | None, profile: str
) -> dict[str, Any]:
    if not device_id and not device_name:
        raise ValueError("Provide --device-id or --device-name.")
    if device_id:
        body = await graph_get(
            f"/deviceManagement/managedDevices/{device_id}"
            "?$select=id,deviceName,userPrincipalName",
            profile=profile,
        )
        if not isinstance(body, dict) or not body.get("id"):
            raise LookupError(f"Managed device id not found: {device_id}")
        return {
            "id": str(body.get("id")),
            "name": body.get("deviceName"),
            "userPrincipalName": body.get("userPrincipalName"),
        }

    assert device_name is not None
    filtered = _values(
        await graph_get(
            "/deviceManagement/managedDevices"
            "?$select=id,deviceName,userPrincipalName"
            f"&$filter=deviceName eq '{_odata_literal(device_name)}'",
            profile=profile,
        )
    )
    if not filtered:
        filtered = _values(
            await graph_get(
                "/deviceManagement/managedDevices"
                "?$select=id,deviceName,userPrincipalName",
                profile=profile,
            )
        )
    match = _pick_named(filtered, device_name, name_key="deviceName")
    if match is None:
        raise LookupError(f"Managed device not uniquely matched: {device_name}")
    return {
        "id": str(match.get("id")),
        "name": match.get("deviceName"),
        "userPrincipalName": match.get("userPrincipalName"),
    }


async def resolve_policy(
    *,
    policy_id: str | None,
    policy_name: str | None,
    profile: str,
    lookup: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if not policy_id and not policy_name:
        raise ValueError("Provide --policy-id or --policy-name.")
    if lookup is None:
        lookup = await list_policy_lookup(profile=profile)
    if policy_id:
        if policy_id in lookup:
            return lookup[policy_id]
        raise LookupError(f"Configuration policy id not found: {policy_id}")
    assert policy_name is not None
    match = _pick_named(list(lookup.values()), policy_name, name_key="name")
    if match is None:
        raise LookupError(f"Configuration policy not uniquely matched: {policy_name}")
    return match
