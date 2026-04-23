"""Post-processing helpers for Intune policy-setting rows."""

from __future__ import annotations

from typing import Any

from graphconnect.executor import _POLICY_SETTING_STATUS_BY_CODE

_POLICY_SETTING_FAILURE_STATUSES = {"Conflict", "Error", "NonCompliant"}
_POLICY_SETTING_DEDUPE_FIELDS = ["DeviceId", "PolicyId", "SettingInstanceId", "SettingStatus"]
_INTUNE_ERROR_HINTS = {
    -2016281211: "Conflict: another assigned policy is setting this value.",
    -2016281112: "Remediation failed on the device.",
    65000: "Device returned an unspecified Intune error.",
}


def policy_setting_status_label(row: dict[str, Any]) -> str | None:
    status = row.get("Status")
    if isinstance(status, str) and status:
        return status
    loc = row.get("SettingStatus_loc")
    if isinstance(loc, str) and loc:
        return loc
    raw = row.get("SettingStatus")
    return _POLICY_SETTING_STATUS_BY_CODE.get(raw) if isinstance(raw, int) else None


def filter_policy_failure_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [row for row in rows if policy_setting_status_label(row) in _POLICY_SETTING_FAILURE_STATUSES]


def attach_overlap_context(
    rows: list[dict[str, Any]],
    *,
    all_device_rows: list[dict[str, Any]],
    target_policy_id: str,
    policy_lookup: dict[str, dict[str, Any]],
) -> None:
    by_setting: dict[str, set[str]] = {}
    for row in all_device_rows:
        setting_name = row.get("SettingName")
        policy_id = row.get("PolicyId")
        if not setting_name or not policy_id or policy_id == target_policy_id:
            continue
        by_setting.setdefault(str(setting_name), set()).add(str(policy_id))

    for row in rows:
        other_ids = sorted(by_setting.get(str(row.get("SettingName") or ""), set()))
        if not other_ids:
            continue
        other_names = [
            policy_lookup.get(pid, {}).get("name") or f"retired-or-missing-policy ({pid})"
            for pid in other_ids
        ]
        row["OtherPolicyIds"] = other_ids
        row["OtherPolicies"] = other_names
        if policy_setting_status_label(row) == "Conflict":
            row["ConflictHint"] = "Also set by: " + ", ".join(other_names)


def dedupe_rows(rows: list[dict[str, Any]], fields: list[str]) -> list[dict[str, Any]]:
    seen: set[tuple] = set()
    out: list[dict[str, Any]] = []
    for row in rows:
        key = tuple(row.get(f) for f in fields)
        if key in seen:
            continue
        seen.add(key)
        out.append(row)
    return out


def apply_intune_setting_hints(rows: list[dict[str, Any]]) -> None:
    for row in rows:
        name = row.get("SettingName") or row.get("SettingNm")
        if isinstance(name, str) and name:
            row.setdefault("SettingLabel", _humanize_setting_name(name))
        error_code = row.get("ErrorCode")
        if isinstance(error_code, int) and error_code in _INTUNE_ERROR_HINTS:
            row["ErrorHint"] = _INTUNE_ERROR_HINTS[error_code]
        elif row.get("StateDetails_loc"):
            row["ErrorHint"] = row.get("StateDetails_loc")


def truncate_rows(
    rows: list[dict[str, Any]], top: int
) -> tuple[list[dict[str, Any]], int, bool]:
    total = len(rows)
    if top and top > 0 and total > top:
        return rows[:top], total, True
    return rows, total, False


def _humanize_setting_name(value: str) -> str | None:
    import re

    parts = [p for p in value.split("_") if p]
    humanized: list[str] = []
    for part in parts:
        part = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", part)
        part = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", part)
        part = re.sub(r"([A-Za-z])(\d+)", r"\1 \2", part)
        humanized.append(part.strip())
    return " - ".join(p for p in humanized if p) or None
