"""`explain noncompliance` logic.

Pulls deviceCompliancePolicyStates for a managed device, expands settingStates,
and emits one row per failing rule with remediation hints.
"""

from __future__ import annotations

import uuid
from typing import Any

from ..types import Envelope
from ._transport import _values, graph_get
from ._resolve import resolve_device


_FAILING_STATES = {"nonCompliant", "error", "conflict"}

_GENERIC_HINTS: dict[str, str] = {
    "nonCompliant": "The device did not meet the required setting; verify the configured value on the device.",
    "error": "Device reported an error while evaluating the rule; check Intune event logs on the endpoint.",
    "conflict": "Another policy is asserting a conflicting value for this setting; check assignment overlap.",
    "notApplicable": "Rule does not apply to this device; no action required.",
    "compliant": "Rule satisfied.",
}


def _row_from_setting(
    *,
    policy: dict[str, Any],
    setting_state: dict[str, Any],
    device_name: str | None,
) -> dict[str, Any]:
    state = setting_state.get("state") or setting_state.get("currentValue")
    failed_setting = (
        setting_state.get("settingName")
        or setting_state.get("setting")
        or "unknown"
    )
    expected = setting_state.get("expectedValue") or setting_state.get("sources")
    current = setting_state.get("currentValue")
    err_desc = setting_state.get("errorDescription")
    remediation = setting_state.get("remediationMsg") or err_desc or _GENERIC_HINTS.get(
        str(state), ""
    )
    return {
        "DeviceName": device_name,
        "PolicyId": policy.get("id"),
        "PolicyName": policy.get("displayName") or policy.get("name"),
        "failed_setting": failed_setting,
        "state": state,
        "expected": expected,
        "current": current,
        "error_code": setting_state.get("errorCode"),
        "remediation_hint": remediation,
    }


async def run(
    *,
    device_id: str | None = None,
    device_name: str | None = None,
    profile: str = "default",
    trace_id: str | None = None,
) -> Envelope:
    trace_id = trace_id or uuid.uuid4().hex
    device = await resolve_device(
        device_id=device_id, device_name=device_name, profile=profile
    )

    states = _values(
        await graph_get(
            f"/deviceManagement/managedDevices/{device['id']}"
            "/deviceCompliancePolicyStates",
            profile=profile,
        )
    )

    rows: list[dict[str, Any]] = []
    for policy in states:
        setting_states = policy.get("settingStates") or []
        if not setting_states:
            setting_states = _values(
                await graph_get(
                    f"/deviceManagement/managedDevices/{device['id']}"
                    f"/deviceCompliancePolicyStates/{policy.get('id')}/settingStates",
                    profile=profile,
                )
            )
        for s in setting_states:
            if not isinstance(s, dict):
                continue
            state = str(s.get("state") or "")
            if state not in _FAILING_STATES:
                continue
            rows.append(
                _row_from_setting(
                    policy=policy, setting_state=s, device_name=device.get("name")
                )
            )

    summary = (
        f"{len(rows)} failing compliance rule(s) on device '{device.get('name')}'"
        if rows
        else f"No failing compliance rules on device '{device.get('name')}'"
    )
    next_actions: list[str] = []
    if any(r.get("state") == "conflict" for r in rows):
        next_actions.append(
            "Run `graphconnect explain assignment-drift` on the conflicting policy."
        )

    return Envelope(
        ok=True,
        trace_id=trace_id,
        mode="read",
        summary=summary,
        data=rows,
        next_actions=next_actions,
    )
