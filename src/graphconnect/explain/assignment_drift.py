"""`explain assignment-drift` logic.

Compares a policy's *declared* assignment target set against the *currently-
applied* device set reported by Intune. Emits one row per drifted device with a
`reason` in {unassigned, extra_target, excluded}.
"""

from __future__ import annotations

import uuid
from typing import Any

from ..types import Envelope
from ._transport import _values, graph_get
from ._resolve import list_policy_lookup, resolve_policy


def _group_id_from_target(target: dict[str, Any]) -> str | None:
    """Extract a groupId from an assignment target of various @odata.type shapes."""
    gid = target.get("groupId")
    if isinstance(gid, str) and gid:
        return gid
    return None


def _target_kind(target: dict[str, Any]) -> str:
    odata = str(target.get("@odata.type") or "")
    if "exclusionGroup" in odata:
        return "exclude"
    if "allDevices" in odata:
        return "all_devices"
    if "allLicensedUsers" in odata:
        return "all_users"
    return "include"


async def _fetch_assignments(
    *, policy: dict[str, Any], profile: str
) -> list[dict[str, Any]]:
    base = (
        "/deviceManagement/configurationPolicies"
        if policy.get("kind") == "settings_catalog"
        else "/deviceManagement/deviceConfigurations"
    )
    api = "beta" if policy.get("kind") == "settings_catalog" else "v1.0"
    return _values(
        await graph_get(
            f"{base}/{policy['id']}/assignments",
            profile=profile,
            api_version=api,
        )
    )


async def _expand_group(
    *, group_id: str, profile: str, include_groups: bool
) -> tuple[set[str], list[dict[str, Any]]]:
    members = _values(
        await graph_get(
            f"/groups/{group_id}/transitiveMembers?$select=id,deviceId,displayName",
            profile=profile,
        )
    )
    device_ids: set[str] = set()
    group_rows: list[dict[str, Any]] = []
    for m in members:
        if m.get("deviceId"):
            device_ids.add(str(m["deviceId"]))
        elif include_groups and m.get("@odata.type", "").endswith("group"):
            group_rows.append(m)
    return device_ids, group_rows


async def _fetch_applied_devices(
    *, policy: dict[str, Any], profile: str
) -> set[str]:
    base = (
        "/deviceManagement/configurationPolicies"
        if policy.get("kind") == "settings_catalog"
        else "/deviceManagement/deviceConfigurations"
    )
    api = "beta" if policy.get("kind") == "settings_catalog" else "v1.0"
    rows = _values(
        await graph_get(
            f"{base}/{policy['id']}/deviceStatuses",
            profile=profile,
            api_version=api,
        )
    )
    ids: set[str] = set()
    for r in rows:
        did = r.get("deviceId") or r.get("id")
        if did:
            ids.add(str(did))
    return ids


async def run(
    *,
    policy_id: str | None = None,
    policy_name: str | None = None,
    include_groups: bool = False,
    profile: str = "default",
    trace_id: str | None = None,
) -> Envelope:
    trace_id = trace_id or uuid.uuid4().hex
    lookup = await list_policy_lookup(profile=profile)
    policy = await resolve_policy(
        policy_id=policy_id, policy_name=policy_name, profile=profile, lookup=lookup
    )

    assignments = await _fetch_assignments(policy=policy, profile=profile)

    declared: set[str] = set()
    excluded: set[str] = set()
    declared_groups: list[str] = []
    excluded_groups: list[str] = []

    for a in assignments:
        target = a.get("target") or {}
        kind = _target_kind(target)
        gid = _group_id_from_target(target)
        if kind == "exclude" and gid:
            ids, _ = await _expand_group(
                group_id=gid, profile=profile, include_groups=include_groups
            )
            excluded |= ids
            excluded_groups.append(gid)
        elif kind == "include" and gid:
            ids, _ = await _expand_group(
                group_id=gid, profile=profile, include_groups=include_groups
            )
            declared |= ids
            declared_groups.append(gid)
        elif kind == "all_devices":
            declared_groups.append("allDevices")

    applied = await _fetch_applied_devices(policy=policy, profile=profile)

    effective = declared - excluded
    unassigned = effective - applied
    extra = applied - effective - excluded
    excluded_applied = applied & excluded

    rows: list[dict[str, Any]] = []
    for did in sorted(unassigned):
        rows.append(
            {
                "PolicyId": policy["id"],
                "PolicyName": policy.get("name"),
                "device_id": did,
                "reason": "unassigned",
            }
        )
    for did in sorted(extra):
        rows.append(
            {
                "PolicyId": policy["id"],
                "PolicyName": policy.get("name"),
                "device_id": did,
                "reason": "extra_target",
            }
        )
    for did in sorted(excluded_applied):
        rows.append(
            {
                "PolicyId": policy["id"],
                "PolicyName": policy.get("name"),
                "device_id": did,
                "reason": "excluded",
            }
        )

    if include_groups:
        for gid in declared_groups:
            rows.append(
                {
                    "PolicyId": policy["id"],
                    "PolicyName": policy.get("name"),
                    "group_id": gid,
                    "reason": "declared_group",
                }
            )
        for gid in excluded_groups:
            rows.append(
                {
                    "PolicyId": policy["id"],
                    "PolicyName": policy.get("name"),
                    "group_id": gid,
                    "reason": "excluded_group",
                }
            )

    summary = (
        f"{len(rows)} assignment drift row(s) for policy '{policy.get('name')}'"
        if rows
        else f"No assignment drift for policy '{policy.get('name')}'"
    )
    next_actions: list[str] = []
    if any(r["reason"] == "unassigned" for r in rows):
        next_actions.append(
            "Devices in declared groups have not reported; check last check-in time."
        )
    if any(r["reason"] == "extra_target" for r in rows):
        next_actions.append(
            "Devices received the policy but are not in any declared include group."
        )

    return Envelope(
        ok=True,
        trace_id=trace_id,
        mode="read",
        summary=summary,
        data=rows,
        next_actions=next_actions,
    )
