"""Intune exportJobs fetch shim used by policy_failure.

The real implementation posts a report to /deviceManagement/reports/exportJobs,
polls until status == completed, then downloads a zipped JSON artifact. Reusing
executor._fetch_policy_setting_rows is the right long-term call; we keep a thin
seam here so tests can monkey-patch at one point.

TODO(merge): replace this module with direct calls to
graphconnect.executor._fetch_policy_setting_rows.
"""

from __future__ import annotations

from typing import Any

from ._postprocess import _POLICY_SETTING_DEDUPE_FIELDS, dedupe_rows
from ._transport import graph_post


_REPORT_SELECT = [
    "DeviceId",
    "PolicyId",
    "SettingId",
    "SettingInstanceId",
    "SettingName",
    "SettingNm",
    "SettingStatus",
    "StateDetails",
    "ErrorCode",
    "ErrorType",
    "SettingValue",
    "UserId",
]


def _report_body(*, device_id: str, policy_id: str | None) -> dict[str, Any]:
    def _lit(v: str) -> str:
        return v.replace("'", "''")

    filters = [f"(DeviceId eq '{_lit(device_id)}')"]
    if policy_id:
        filters.append(f"(PolicyId eq '{_lit(policy_id)}')")
    return {
        "reportName": "DevicePolicySettingsComplianceReport",
        "format": "json",
        "select": list(_REPORT_SELECT),
        "filter": " and ".join(filters),
    }


async def fetch_policy_setting_rows(
    *, device_id: str, policy_id: str | None, profile: str
) -> list[dict[str, Any]]:
    """Fetch per-setting rows. Tests monkey-patch this function directly."""
    body = await graph_post(
        "/deviceManagement/reports/exportJobs",
        _report_body(device_id=device_id, policy_id=policy_id),
        profile=profile,
        api_version="beta",
    )
    rows = body if isinstance(body, list) else (body or {}).get("value") or []
    rows = [r for r in rows if isinstance(r, dict)]
    return dedupe_rows(rows, _POLICY_SETTING_DEDUPE_FIELDS)
