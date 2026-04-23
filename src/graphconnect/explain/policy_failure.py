"""`explain policy-failure` logic.

Generalized re-implementation of executor._execute_explain_policy_failure.
Produces the same row shape and annotations for the same inputs.
"""

from __future__ import annotations

import uuid
from typing import Any

from ..types import Envelope
from ._intune_reports import fetch_policy_setting_rows
from ._postprocess import (
    apply_intune_setting_hints,
    attach_overlap_context,
    filter_policy_failure_rows,
    policy_setting_status_label,
    truncate_rows,
    _POLICY_SETTING_FAILURE_STATUSES,
)
from ._resolve import list_policy_lookup, resolve_device, resolve_policy


async def run(
    *,
    device_id: str | None = None,
    device_name: str | None = None,
    policy_id: str | None = None,
    policy_name: str | None = None,
    include_compliant: bool = False,
    include_overlap_context: bool = True,
    top: int = 0,
    profile: str = "default",
    trace_id: str | None = None,
) -> Envelope:
    trace_id = trace_id or uuid.uuid4().hex

    lookup = await list_policy_lookup(profile=profile) if include_overlap_context else None
    device = await resolve_device(
        device_id=device_id, device_name=device_name, profile=profile
    )
    policy = await resolve_policy(
        policy_id=policy_id, policy_name=policy_name, profile=profile, lookup=lookup
    )

    target_policy_id = policy["id"]
    if include_overlap_context:
        all_rows = await fetch_policy_setting_rows(
            device_id=device["id"], policy_id=None, profile=profile
        )
        rows = [r for r in all_rows if str(r.get("PolicyId") or "") == target_policy_id]
    else:
        all_rows = []
        rows = await fetch_policy_setting_rows(
            device_id=device["id"], policy_id=target_policy_id, profile=profile
        )

    if not include_compliant:
        rows = filter_policy_failure_rows(rows)

    if include_overlap_context:
        attach_overlap_context(
            rows,
            all_device_rows=all_rows,
            target_policy_id=target_policy_id,
            policy_lookup=lookup or {},
        )

    for row in rows:
        row["DeviceName"] = device.get("name")
        row["PolicyName"] = policy.get("name")
        row["PolicyKind"] = policy.get("kind")

    rows.sort(
        key=lambda r: (
            policy_setting_status_label(r) not in _POLICY_SETTING_FAILURE_STATUSES,
            str(r.get("SettingName") or ""),
        )
    )
    apply_intune_setting_hints(rows)
    sliced, total, has_more = truncate_rows(rows, top)

    failing = sum(
        1
        for r in sliced
        if policy_setting_status_label(r) in _POLICY_SETTING_FAILURE_STATUSES
    )
    summary = (
        f"{failing} failing setting(s) for policy '{policy.get('name')}' "
        f"on device '{device.get('name')}'"
        if failing
        else f"No failing settings for policy '{policy.get('name')}' on device '{device.get('name')}'"
    )

    next_actions: list[str] = []
    if has_more:
        next_actions.append(f"{total - len(sliced)} more row(s) truncated; re-run with --top 0")
    if any(r.get("ConflictHint") for r in sliced):
        next_actions.append(
            "Review overlapping policies listed in ConflictHint before remediating."
        )

    return Envelope(
        ok=True,
        trace_id=trace_id,
        mode="read",
        summary=summary,
        data=sliced,
        next_actions=next_actions,
    )
