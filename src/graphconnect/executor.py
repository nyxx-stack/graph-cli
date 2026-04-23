"""Builds and executes Graph API requests from catalog entries."""

from __future__ import annotations

import asyncio
import csv
import functools
import hashlib
import io
import json
import re
import time
import uuid
import zipfile
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from typing import Any, Awaitable, Callable
from urllib.parse import urlencode
from urllib.request import urlopen

from graphconnect.audit import log_operation
from graphconnect.auth import CONFIG_DIR, peek_user_principal
from graphconnect.safety import check_rate_limit, generate_token, validate_token
from graphconnect.types import (
    AuthMethod,
    CatalogEntry,
    CatalogProjection,
    CliError,
    ErrorCode,
    ErrorPayload,
    OperationResult,
    SafetyTier,
    WritePreview,
)


_EXPORT_CACHE_DIR = CONFIG_DIR / "cache" / "exports"
_EXPORT_CACHE_TTL_SECONDS = 600
_EXPORT_JOB_DEADLINE_SECONDS = 120
_EXPORT_JOB_POLL_INTERVAL_SECONDS = 3
_POLICY_SETTING_STATUS_BY_CODE: dict[int, str] = {
    0: "Unknown",
    1: "NotApplicable",
    2: "Compliant",
    3: "Remediated",
    4: "NonCompliant",
    5: "Error",
    6: "Conflict",
}
_POLICY_SETTING_FAILURE_STATUSES = {"Conflict", "Error", "NonCompliant"}
_POLICY_SETTING_REPORT_SELECT = [
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
_POLICY_SETTING_DEDUPE_FIELDS = ["DeviceId", "PolicyId", "SettingInstanceId", "SettingStatus"]
_INTUNE_ERROR_HINTS = {
    -2016281211: "Conflict: another assigned policy is setting this value.",
    -2016281112: "Remediation failed on the device.",
    65000: "Device returned an unspecified Intune error.",
}


async def execute_read(
    entry: CatalogEntry,
    parameters: dict | None = None,
    top: int = 100,
    select: list[str] | None = None,
    filter_expr: str | None = None,
    expand: str | None = None,
    order_by: str | None = None,
    dedupe: bool = True,
) -> OperationResult:
    """Execute a read-tier catalog operation against Microsoft Graph."""
    retry_after = check_rate_limit(SafetyTier.READ)
    if retry_after is not None:
        raise CliError(
            ErrorPayload(
                code=ErrorCode.THROTTLED,
                message=f"Rate limited by client-side budget. Retry after {retry_after:.0f} seconds.",
                hint="Wait a minute or reduce parallel read ops.",
                retryable=True,
            )
        )

    parameters = _apply_parameter_defaults(entry, parameters or {})
    parameters = _normalize_parameter_types(entry, parameters)
    _validate_parameters(entry, parameters)
    request_id = _new_id()
    correlation_id = _new_id()
    start_time = time.monotonic()

    url = _build_url(entry, parameters)
    headers = _build_headers(entry, correlation_id=correlation_id)
    method = (entry.method or "GET").upper()
    query_params: dict[str, str] = {}
    if method != "POST":
        query_params = _build_query_params(entry, parameters, top, select, filter_expr, expand, order_by)
    audit_url = _audit_url(url, query_params)
    user_principal = peek_user_principal()

    try:
        if entry.id == "devices.policy_setting_statuses":
            data, total_count, has_more, bytes_read, http_status, parameters = await _execute_policy_setting_statuses(
                parameters=parameters,
                top=top,
                correlation_id=correlation_id,
            )
        elif entry.id == "devices.explain_policy_failure":
            data, total_count, has_more, bytes_read, http_status = await _execute_explain_policy_failure(
                parameters=parameters,
                top=top,
                correlation_id=correlation_id,
            )
            audit_url = "/internal/devices/explainPolicyFailure"
        elif method == "POST":
            request_body = _build_body(entry, parameters, None) or {}
            if isinstance(request_body, dict) and select:
                request_body = {**request_body, "select": select}
            if isinstance(request_body, dict) and order_by and "orderBy" in request_body:
                request_body = {
                    **request_body,
                    "orderBy": [part.strip() for part in order_by.split(",") if part.strip()],
                }
            # Reports endpoints take top/skip in the JSON body, not on the URL.
            if isinstance(request_body, dict) and "top" in request_body:
                request_body = {**request_body, "top": 500 if top <= 0 else top}
            if entry.download_export:
                data, total_count, has_more, bytes_read, http_status = await _execute_export_job_read(
                    url=url,
                    api_version=entry.api_version.value,
                    request_body=request_body,
                    headers=headers,
                    top=top,
                    correlation_id=correlation_id,
                )
            else:
                raw, bytes_read, http_status = await _execute_mutation(
                    method="POST",
                    url=url,
                    api_version=entry.api_version.value,
                    body=request_body,
                    headers=headers,
                    expected_status=200,
                )
                data, total_count, has_more = _normalize_post_read_response(raw, top)
        else:
            data, total_count, has_more, bytes_read, http_status = await _execute_get(
                url,
                entry.api_version.value,
                query_params,
                top,
                singleton=entry.singleton,
                headers=headers,
            )
        data = _post_process_rows(data, entry.projections, entry.drop_paths, entry.id)
        if dedupe and entry.dedupe_by:
            data = _dedupe_rows(data, entry.dedupe_by)
        if entry.id == "devices.policy_setting_statuses" and parameters.get("failures_only"):
            data = _filter_policy_failure_rows(data)
            total_count = len(data)
    except Exception as exc:
        elapsed = int((time.monotonic() - start_time) * 1000)
        payload = _map_graph_exception(exc, correlation_id=correlation_id)
        log_operation(
            operation_id=entry.id,
            safety_tier=entry.safety_tier,
            method=method,
            graph_url=audit_url,
            parameters=parameters,
            user_principal=user_principal,
            status="error",
            execution_time_ms=elapsed,
            error=str(exc),
            error_code=payload.code.value,
            http_status=payload.http_status,
            request_id=request_id,
            correlation_id=correlation_id,
        )
        raise CliError(payload) from exc

    elapsed = int((time.monotonic() - start_time) * 1000)

    log_operation(
        operation_id=entry.id,
        safety_tier=entry.safety_tier,
        method=method,
        graph_url=audit_url,
        parameters=parameters,
        user_principal=user_principal,
        status="success",
        http_status=http_status,
        item_count=len(data),
        execution_time_ms=elapsed,
        response_bytes=bytes_read,
        request_id=request_id,
        correlation_id=correlation_id,
    )

    return OperationResult(
        operation_id=entry.id,
        item_count=len(data),
        total_count=total_count,
        has_more=has_more,
        data=data,
        execution_time_ms=elapsed,
        graph_url=url,
        request_id=request_id,
        correlation_id=correlation_id,
    )


def _normalize_match_text(value: Any) -> str:
    """Case-insensitive compare key for operator-supplied names."""
    return str(value or "").strip().lower()


def _odata_literal(value: str) -> str:
    """Escape a value for inclusion in an OData single-quoted literal."""
    return value.replace("'", "''")


def _format_resolution_candidate(resource: dict[str, Any], name_key: str) -> str:
    """Render a concise candidate label for ambiguous name resolution errors."""
    name = resource.get(name_key) or resource.get("name") or resource.get("displayName") or resource.get("deviceName")
    resource_id = resource.get("id")
    if resource_id and resource_id != name:
        return f"{name} ({resource_id})"
    return str(name or resource_id or "resource")


def _pick_named_resource(
    resources: list[dict[str, Any]],
    desired_name: str,
    *,
    label: str,
    name_key: str,
) -> dict[str, Any]:
    """Resolve an exact or unique substring name match from a list of resources."""
    desired = _normalize_match_text(desired_name)
    exact = [row for row in resources if _normalize_match_text(row.get(name_key)) == desired]
    if len(exact) == 1:
        return exact[0]
    if len(exact) > 1:
        choices = ", ".join(_format_resolution_candidate(row, name_key) for row in exact[:5])
        raise CliError(
            ErrorPayload(
                code=ErrorCode.CONFLICT,
                message=f"Multiple {label}s matched '{desired_name}'.",
                hint=f"Be more specific or pass the id directly. Matches: {choices}",
            )
        )

    contains = [row for row in resources if desired and desired in _normalize_match_text(row.get(name_key))]
    if len(contains) == 1:
        return contains[0]
    if len(contains) > 1:
        choices = ", ".join(_format_resolution_candidate(row, name_key) for row in contains[:5])
        raise CliError(
            ErrorPayload(
                code=ErrorCode.CONFLICT,
                message=f"Multiple {label}s contain '{desired_name}'.",
                hint=f"Use the exact name or id. Matches: {choices}",
            )
        )

    raise CliError(
        ErrorPayload(
            code=ErrorCode.NOT_FOUND,
            message=f"{label.capitalize()} not found: {desired_name}",
            hint=f"Run the matching list op to confirm the exact {label} name or id.",
        )
    )


async def _list_managed_devices_for_resolution(
    correlation_id: str,
    *,
    filter_expr: str | None = None,
) -> list[dict[str, Any]]:
    """Load managed devices for name resolution, optionally pre-filtered server-side."""
    query: dict[str, str] = {"$select": "id,deviceName,userPrincipalName"}
    if filter_expr:
        query["$filter"] = filter_expr
    rows, _, _, _, _ = await _execute_get(
        "/deviceManagement/managedDevices",
        "v1.0",
        query,
        top=0,
        headers={"client-request-id": correlation_id},
    )
    return rows


async def _resolve_managed_device_reference(
    *,
    device_id: str | None,
    device_name: str | None,
    correlation_id: str,
) -> dict[str, Any]:
    """Resolve a managed device by id or operator-friendly name."""
    if device_id:
        device, _, _ = await _fetch_single_resource(
            f"/deviceManagement/managedDevices/{device_id}",
            "v1.0",
            correlation_id=correlation_id,
            select=["id", "deviceName", "userPrincipalName"],
        )
        if not device:
            raise CliError(
                ErrorPayload(
                    code=ErrorCode.NOT_FOUND,
                    message=f"Managed device id not found: {device_id}",
                    hint="Run `graphconnect read devices.list_managed` to find a valid device id.",
                )
            )
        if device_name and _normalize_match_text(device.get("deviceName")) != _normalize_match_text(device_name):
            raise CliError(
                ErrorPayload(
                    code=ErrorCode.CONFLICT,
                    message=f"device_id {device_id} does not match device_name '{device_name}'.",
                    hint=f"Resolved device name: {device.get('deviceName')}",
                )
            )
        return {
            "id": str(device.get("id")),
            "name": device.get("deviceName"),
            "userPrincipalName": device.get("userPrincipalName"),
        }

    if not device_name:
        raise CliError(
            ErrorPayload(
                code=ErrorCode.USAGE_ERROR,
                message="Provide device_id or device_name.",
                hint="Example: -p device_name=DANAEH-PC",
            )
        )

    devices = await _list_managed_devices_for_resolution(
        correlation_id,
        filter_expr=f"deviceName eq '{_odata_literal(device_name)}'",
    )
    # Fall back to full roster only when the exact-filter missed — handles the
    # substring match case and tenants where deviceName has leading/trailing
    # whitespace that $filter can't see through.
    if not devices:
        devices = await _list_managed_devices_for_resolution(correlation_id)
    match = _pick_named_resource(devices, device_name, label="managed device", name_key="deviceName")
    return {
        "id": str(match.get("id")),
        "name": match.get("deviceName"),
        "userPrincipalName": match.get("userPrincipalName"),
    }


async def _list_policy_lookup(correlation_id: str) -> dict[str, dict[str, Any]]:
    """Build a policy-id lookup spanning Settings Catalog and classic config profiles."""
    headers = {"client-request-id": correlation_id}
    settings_task = _execute_get(
        "/deviceManagement/configurationPolicies",
        "beta",
        {"$select": "id,name"},
        top=0,
        headers=headers,
    )
    classic_task = _execute_get(
        "/deviceManagement/deviceConfigurations",
        "v1.0",
        {"$select": "id,displayName"},
        top=0,
        headers=headers,
    )
    (settings_rows, _, _, _, _), (classic_rows, _, _, _, _) = await asyncio.gather(
        settings_task, classic_task
    )

    lookup: dict[str, dict[str, Any]] = {}
    for row in settings_rows:
        policy_id = row.get("id")
        if policy_id:
            lookup[str(policy_id)] = {
                "id": str(policy_id),
                "name": row.get("name"),
                "kind": "settings_catalog",
            }
    for row in classic_rows:
        policy_id = row.get("id")
        if policy_id:
            lookup[str(policy_id)] = {
                "id": str(policy_id),
                "name": row.get("displayName"),
                "kind": "config_profile",
            }
    return lookup


_POLICY_KIND_ENDPOINTS = (
    ("settings_catalog", "/deviceManagement/configurationPolicies", "beta", "name"),
    ("config_profile", "/deviceManagement/deviceConfigurations", "v1.0", "displayName"),
)


async def _fetch_policy_by_id(
    policy_id: str,
    *,
    policy_kind: str,
    correlation_id: str,
) -> dict[str, Any] | None:
    """Fetch a single policy by id, trying the endpoint(s) matching policy_kind."""
    endpoints = [
        (kind, endpoint, version, name_field)
        for kind, endpoint, version, name_field in _POLICY_KIND_ENDPOINTS
        if policy_kind == "auto" or kind == policy_kind
    ]
    for kind, endpoint, version, name_field in endpoints:
        resource, _, _ = await _fetch_single_resource(
            f"{endpoint}/{policy_id}",
            version,
            correlation_id=correlation_id,
            select=["id", name_field],
        )
        if resource:
            return {"id": str(resource.get("id")), "name": resource.get(name_field), "kind": kind}
    return None


async def _resolve_policy_reference(
    *,
    policy_id: str | None,
    policy_name: str | None,
    policy_kind: str | None,
    correlation_id: str,
    policy_lookup: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Resolve a policy id/name across Settings Catalog and classic config profiles.

    Pass `policy_lookup` to reuse a prefetched lookup dict (e.g., when the caller
    also needs it for overlap annotation) instead of refetching.
    """
    kind_filter = (policy_kind or "auto").strip().lower()

    if policy_id:
        match = await _fetch_policy_by_id(policy_id, policy_kind=kind_filter, correlation_id=correlation_id)
        if not match:
            raise CliError(
                ErrorPayload(
                    code=ErrorCode.NOT_FOUND,
                    message=f"Configuration policy id not found: {policy_id}",
                    hint="Run `graphconnect read policies.list_settings_catalog` and `graphconnect read policies.list_config_profiles` to find a valid policy id.",
                )
            )
        if policy_name and _normalize_match_text(match.get("name")) != _normalize_match_text(policy_name):
            raise CliError(
                ErrorPayload(
                    code=ErrorCode.CONFLICT,
                    message=f"policy_id {policy_id} does not match policy_name '{policy_name}'.",
                    hint=f"Resolved policy name: {match.get('name')}",
                )
            )
        return match

    if not policy_name:
        raise CliError(
            ErrorPayload(
                code=ErrorCode.USAGE_ERROR,
                message="Provide policy_id or policy_name.",
                hint="Example: -p policy_name=BitLocker",
            )
        )

    lookup = policy_lookup if policy_lookup is not None else await _list_policy_lookup(correlation_id)
    candidates = list(lookup.values())
    if kind_filter != "auto":
        candidates = [row for row in candidates if row.get("kind") == kind_filter]
    return _pick_named_resource(candidates, policy_name, label="configuration policy", name_key="name")


async def _resolve_policy_setting_context(
    parameters: dict[str, Any],
    correlation_id: str,
    *,
    policy_lookup: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Resolve the device and policy references needed for policy setting reports."""
    device, policy = await asyncio.gather(
        _resolve_managed_device_reference(
            device_id=parameters.get("device_id"),
            device_name=parameters.get("device_name"),
            correlation_id=correlation_id,
        ),
        _resolve_policy_reference(
            policy_id=parameters.get("policy_id"),
            policy_name=parameters.get("policy_name"),
            policy_kind=str(parameters.get("policy_kind") or "auto"),
            correlation_id=correlation_id,
            policy_lookup=policy_lookup,
        ),
    )
    return {
        "device_id": device["id"],
        "device_name": device.get("name"),
        "device_user_principal_name": device.get("userPrincipalName"),
        "policy_id": policy["id"],
        "policy_name": policy.get("name"),
        "policy_kind": policy.get("kind"),
    }


def _merge_resolved_policy_setting_params(
    parameters: dict[str, Any],
    context: dict[str, Any],
) -> dict[str, Any]:
    """Back-fill resolved device/policy identifiers into parameters for audit logging."""
    resolved = dict(parameters)
    resolved["device_id"] = context["device_id"]
    resolved["policy_id"] = context["policy_id"]
    if context.get("device_name"):
        resolved.setdefault("device_name", context["device_name"])
    if context.get("policy_name"):
        resolved.setdefault("policy_name", context["policy_name"])
    if context.get("policy_kind"):
        resolved["policy_kind"] = context["policy_kind"]
    return resolved


def _policy_setting_report_body(*, device_id: str, policy_id: str | None = None) -> dict[str, Any]:
    """Build the Intune exportJobs request body for policy setting status rows."""
    filters = [f"(DeviceId eq '{_odata_literal(device_id)}')"]
    if policy_id:
        filters.append(f"(PolicyId eq '{_odata_literal(policy_id)}')")
    return {
        "reportName": "DevicePolicySettingsComplianceReport",
        "format": "json",
        "select": list(_POLICY_SETTING_REPORT_SELECT),
        "filter": " and ".join(filters),
    }


async def _fetch_policy_setting_rows(
    device_id: str,
    *,
    policy_id: str | None = None,
    correlation_id: str,
) -> tuple[list[dict[str, Any]], int]:
    """Fetch raw per-setting rows for one device, optionally scoped to one policy."""
    rows, _, _, bytes_read, _ = await _execute_export_job_read(
        url="/deviceManagement/reports/exportJobs",
        api_version="beta",
        request_body=_policy_setting_report_body(device_id=device_id, policy_id=policy_id),
        headers={"client-request-id": correlation_id},
        top=0,
        correlation_id=correlation_id,
    )
    return _dedupe_rows(rows, _POLICY_SETTING_DEDUPE_FIELDS), bytes_read


def _policy_setting_status_label(row: dict[str, Any]) -> str | None:
    """Return a consistent human-readable status label from raw or projected rows."""
    status = row.get("Status")
    if isinstance(status, str) and status:
        return status
    loc = row.get("SettingStatus_loc")
    if isinstance(loc, str) and loc:
        return loc
    raw = row.get("SettingStatus")
    return _POLICY_SETTING_STATUS_BY_CODE.get(raw) if isinstance(raw, int) else None


def _filter_policy_failure_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keep only rows whose status is a real failure signal."""
    return [row for row in rows if _policy_setting_status_label(row) in _POLICY_SETTING_FAILURE_STATUSES]


def _attach_overlap_context(
    rows: list[dict[str, Any]],
    *,
    all_device_rows: list[dict[str, Any]],
    target_policy_id: str,
    policy_lookup: dict[str, dict[str, Any]],
) -> None:
    """Annotate rows with other policies on the same device touching the same setting."""
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
            policy_lookup.get(policy_id, {}).get("name") or f"retired-or-missing-policy ({policy_id})"
            for policy_id in other_ids
        ]
        row["OtherPolicyIds"] = other_ids
        row["OtherPolicies"] = other_names
        if _policy_setting_status_label(row) == "Conflict":
            row["ConflictHint"] = "Also set by: " + ", ".join(other_names)


async def _fetch_policy_setting_rows_for_target(
    *,
    device_id: str,
    target_policy_id: str,
    want_overlap: bool,
    correlation_id: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int]:
    """Fetch target + (optionally) all-device rows for one device.

    When overlap is wanted, the device-wide export is a strict superset of the
    policy-filtered export — derive the target rows client-side instead of
    running a second export (each export takes ~10-30s).
    Returns (target_rows, all_device_rows, bytes_read). all_device_rows is []
    when overlap is not requested.
    """
    if want_overlap:
        all_rows, bytes_read = await _fetch_policy_setting_rows(
            device_id,
            correlation_id=correlation_id,
        )
        target_rows = [row for row in all_rows if str(row.get("PolicyId") or "") == target_policy_id]
        return target_rows, all_rows, bytes_read
    target_rows, bytes_read = await _fetch_policy_setting_rows(
        device_id,
        policy_id=target_policy_id,
        correlation_id=correlation_id,
    )
    return target_rows, [], bytes_read


async def _execute_policy_setting_statuses(
    *,
    parameters: dict[str, Any],
    top: int,
    correlation_id: str,
) -> tuple[list[dict[str, Any]], int | None, bool, int, int | None, dict[str, Any]]:
    """Resolve names, fetch per-setting rows for one device/policy, optionally with overlap."""
    want_overlap = bool(parameters.get("include_overlap_context"))

    # Prefetch the policy lookup when overlap is requested so name resolution
    # and overlap annotation share a single fetch (two Graph calls total
    # instead of four).
    policy_lookup = await _list_policy_lookup(correlation_id) if want_overlap else None
    context = await _resolve_policy_setting_context(
        parameters, correlation_id, policy_lookup=policy_lookup
    )
    resolved = _merge_resolved_policy_setting_params(parameters, context)
    target_policy_id = context["policy_id"]

    target_rows, all_rows, bytes_read = await _fetch_policy_setting_rows_for_target(
        device_id=context["device_id"],
        target_policy_id=target_policy_id,
        want_overlap=want_overlap,
        correlation_id=correlation_id,
    )
    if want_overlap:
        _attach_overlap_context(
            target_rows,
            all_device_rows=all_rows,
            target_policy_id=target_policy_id,
            policy_lookup=policy_lookup or {},
        )
    return target_rows, None, False, bytes_read, 200, resolved


async def _execute_explain_policy_failure(
    *,
    parameters: dict[str, Any],
    top: int,
    correlation_id: str,
) -> tuple[list[dict[str, Any]], int | None, bool, int, int | None]:
    """Resolve names, fetch exact policy setting rows, and annotate the likely cause."""
    want_overlap = parameters.get("include_overlap_context", True)

    policy_lookup = await _list_policy_lookup(correlation_id) if want_overlap else None
    context = await _resolve_policy_setting_context(
        parameters, correlation_id, policy_lookup=policy_lookup
    )
    target_policy_id = context["policy_id"]

    rows, all_rows, bytes_read = await _fetch_policy_setting_rows_for_target(
        device_id=context["device_id"],
        target_policy_id=target_policy_id,
        want_overlap=want_overlap,
        correlation_id=correlation_id,
    )

    if not parameters.get("include_compliant"):
        rows = _filter_policy_failure_rows(rows)

    if want_overlap:
        _attach_overlap_context(
            rows,
            all_device_rows=all_rows,
            target_policy_id=target_policy_id,
            policy_lookup=policy_lookup or {},
        )

    for row in rows:
        row["DeviceName"] = context.get("device_name")
        row["PolicyName"] = context.get("policy_name")
        row["PolicyKind"] = context.get("policy_kind")

    rows.sort(key=lambda row: (_policy_setting_status_label(row) not in _POLICY_SETTING_FAILURE_STATUSES, str(row.get("SettingName") or "")))
    sliced, total_count, has_more = _truncate_rows(rows, top)
    return sliced, total_count, has_more, bytes_read, 200


async def preview_write(
    entry: CatalogEntry,
    parameters: dict | None = None,
    body: dict | None = None,
) -> WritePreview:
    """Generate a dry-run preview for a write operation."""
    parameters = _apply_parameter_defaults(entry, parameters or {})
    parameters = _normalize_parameter_types(entry, parameters)
    _validate_parameters(entry, parameters)
    url = _build_url(entry, parameters)

    correlation_id = _new_id()
    idempotency_key = _new_id()
    start_time = time.monotonic()
    user_principal = peek_user_principal()

    try:
        request_body = await _resolve_request_body(
            entry,
            parameters,
            body,
            correlation_id=correlation_id,
        )
        preview_lookup = await _resolve_preview_lookup(
            entry,
            parameters,
            correlation_id=correlation_id,
        )
    except CliError as exc:
        elapsed = int((time.monotonic() - start_time) * 1000)
        payload = exc.payload
        log_operation(
            operation_id=entry.id,
            safety_tier=entry.safety_tier,
            method=entry.method,
            graph_url=url,
            parameters=parameters,
            user_principal=user_principal,
            status="error",
            execution_time_ms=elapsed,
            error=str(exc),
            error_code=payload.code.value,
            http_status=payload.http_status,
            correlation_id=correlation_id,
            idempotency_key=idempotency_key,
        )
        raise
    except Exception as exc:
        elapsed = int((time.monotonic() - start_time) * 1000)
        payload = _map_graph_exception(exc, correlation_id=correlation_id)
        log_operation(
            operation_id=entry.id,
            safety_tier=entry.safety_tier,
            method=entry.method,
            graph_url=url,
            parameters=parameters,
            user_principal=user_principal,
            status="error",
            execution_time_ms=elapsed,
            error=str(exc),
            error_code=payload.code.value,
            http_status=payload.http_status,
            correlation_id=correlation_id,
            idempotency_key=idempotency_key,
        )
        raise CliError(payload) from exc

    token = generate_token(
        operation_id=entry.id,
        safety_tier=entry.safety_tier,
        parameters=parameters,
        body=request_body,
        correlation_id=correlation_id,
        idempotency_key=idempotency_key,
        resource_fingerprint=preview_lookup["fingerprint"],
    )

    warnings: list[str] = []
    if entry.safety_tier == SafetyTier.DESTRUCTIVE:
        warnings.append("DESTRUCTIVE: This operation cannot be undone.")
        warnings.append("You MUST confirm this action explicitly before proceeding.")
    warnings.extend(preview_lookup["warnings"])

    description = _build_description(entry, parameters)

    log_operation(
        operation_id=entry.id,
        safety_tier=entry.safety_tier,
        method=entry.method,
        graph_url=url,
        parameters=parameters,
        user_principal=user_principal,
        status="preview",
        http_status=preview_lookup["http_status"],
        preview_shown=True,
        confirm_token=token.token,
        correlation_id=correlation_id,
        idempotency_key=idempotency_key,
    )

    return WritePreview(
        operation_id=entry.id,
        safety_tier=entry.safety_tier,
        method=entry.method,
        url=url,
        body=_sanitize_preview_body(entry, request_body),
        description=description,
        affected_resources=preview_lookup["affected_resources"],
        reversible=entry.safety_tier != SafetyTier.DESTRUCTIVE,
        confirm_token=token.token,
        expires_at=token.expires_at,
        warnings=warnings,
        correlation_id=correlation_id,
        idempotency_key=idempotency_key,
    )


async def execute_write(
    entry: CatalogEntry,
    parameters: dict | None = None,
    body: dict | None = None,
    confirm_token: str = "",
) -> dict[str, Any] | None:
    """Execute a write operation after validating the confirmation token."""
    parameters = _apply_parameter_defaults(entry, parameters or {})
    parameters = _normalize_parameter_types(entry, parameters)
    _validate_parameters(entry, parameters)
    correlation_seed = _new_id()
    try:
        request_body = await _resolve_request_body(
            entry,
            parameters,
            body,
            correlation_id=correlation_seed,
        )
    except CliError:
        raise  # don't wrap CliError in another CliError below
    except Exception as exc:
        raise CliError(_map_graph_exception(exc, correlation_id=correlation_seed)) from exc

    try:
        token = validate_token(
            confirm_token=confirm_token,
            operation_id=entry.id,
            parameters=parameters,
            body=request_body,
        )
    except ValueError as exc:
        msg = str(exc)
        code = ErrorCode.TOKEN_EXPIRED if "expired" in msg.lower() else ErrorCode.TOKEN_INVALID
        raise CliError(
            ErrorPayload(
                code=code,
                message=msg,
                hint="Re-run the command without --execute to get a fresh token.",
            )
        ) from exc

    correlation_id = token.correlation_id or _new_id()
    idempotency_key = token.idempotency_key or _new_id()
    request_id = _new_id()

    retry_after = check_rate_limit(entry.safety_tier)
    if retry_after is not None:
        raise CliError(
            ErrorPayload(
                code=ErrorCode.THROTTLED,
                message=f"Rate limited by client-side budget. Retry after {retry_after:.0f} seconds.",
                hint="Wait, then retry with the same token (still valid until TTL).",
                retryable=True,
                correlation_id=correlation_id,
            )
        )

    url = _build_url(entry, parameters)
    headers = _build_headers(entry, correlation_id=correlation_id, idempotency_key=idempotency_key)
    start_time = time.monotonic()
    user_principal = peek_user_principal()

    try:
        await _validate_resource_fingerprint(
            entry,
            parameters,
            token.resource_fingerprint,
            correlation_id=correlation_id,
        )
        result, bytes_written, http_status = await _execute_mutation(
            entry.method,
            url,
            entry.api_version.value,
            request_body,
            headers=headers,
            expected_status=entry.expected_success_status or _expected_success_status(entry.method),
        )
    except CliError as exc:
        elapsed = int((time.monotonic() - start_time) * 1000)
        payload = exc.payload
        log_operation(
            operation_id=entry.id,
            safety_tier=entry.safety_tier,
            method=entry.method,
            graph_url=url,
            parameters=parameters,
            user_principal=user_principal,
            status="error",
            execution_time_ms=elapsed,
            confirm_token=confirm_token,
            confirmed_at=datetime.now(timezone.utc),
            error=str(exc),
            error_code=payload.code.value,
            http_status=payload.http_status,
            request_id=request_id,
            correlation_id=correlation_id,
            idempotency_key=idempotency_key,
        )
        raise
    except Exception as exc:
        elapsed = int((time.monotonic() - start_time) * 1000)
        payload = _map_graph_exception(exc, correlation_id=correlation_id)
        log_operation(
            operation_id=entry.id,
            safety_tier=entry.safety_tier,
            method=entry.method,
            graph_url=url,
            parameters=parameters,
            user_principal=user_principal,
            status="error",
            execution_time_ms=elapsed,
            confirm_token=confirm_token,
            confirmed_at=datetime.now(timezone.utc),
            error=str(exc),
            error_code=payload.code.value,
            http_status=payload.http_status,
            request_id=request_id,
            correlation_id=correlation_id,
            idempotency_key=idempotency_key,
        )
        raise CliError(payload) from exc

    elapsed = int((time.monotonic() - start_time) * 1000)

    log_operation(
        operation_id=entry.id,
        safety_tier=entry.safety_tier,
        method=entry.method,
        graph_url=url,
        parameters=parameters,
        user_principal=user_principal,
        status="success",
        http_status=http_status,
        execution_time_ms=elapsed,
        confirm_token=confirm_token,
        confirmed_at=datetime.now(timezone.utc),
        response_bytes=bytes_written,
        request_id=request_id,
        correlation_id=correlation_id,
        idempotency_key=idempotency_key,
    )

    return result


async def execute_batch(
    entries: list[CatalogEntry],
    top: int = 100,
    params_by_index: list[dict[str, Any]] | None = None,
) -> list[OperationResult]:
    """Execute read operations concurrently (Graph $batch endpoint can be added later).

    `params_by_index[i]` supplies per-op parameters so callers can batch drill-ins
    like `policies.settings_catalog_assignments` across multiple policy IDs without
    a shell loop. Omit `params_by_index` to run each op with its catalog defaults.
    """
    calls = []
    for i, entry in enumerate(entries):
        params = params_by_index[i] if params_by_index else None
        calls.append(execute_read(entry=entry, parameters=params, top=top))
    return list(await asyncio.gather(*calls))


# -- Internal helpers -------------------------------------------------------


def _new_id() -> str:
    return uuid.uuid4().hex


def _build_url(entry: CatalogEntry, parameters: dict) -> str:
    """Build the Graph API URL from the catalog entry endpoint and parameters."""
    return _interpolate_placeholders(entry.endpoint, parameters)


def _apply_parameter_defaults(entry: CatalogEntry, parameters: dict) -> dict:
    """Fill in declared default values for parameters the caller didn't provide."""
    merged = dict(parameters)
    for param in entry.parameters:
        if param.name not in merged and param.default is not None:
            merged[param.name] = param.default
    return merged


def _validate_parameters(entry: CatalogEntry, parameters: dict) -> None:
    """Reject unknown parameters and unresolved path placeholders up front.

    Unknown keys catch typos (e.g. `-p polcy_id=...`) that would otherwise be
    silently dropped. Unresolved `{placeholder}` in the endpoint catches missing
    required params *before* we send a URL-encoded `%7Bdevice_id%7D` to Graph
    and earn a confusing 400.
    """
    declared = {p.name for p in entry.parameters}
    unknown = sorted(k for k in parameters if k not in declared)
    if unknown:
        raise CliError(
            ErrorPayload(
                code=ErrorCode.USAGE_ERROR,
                message=f"Unknown parameter(s) for {entry.id}: {', '.join(unknown)}",
                hint=(
                    f"Declared: {', '.join(sorted(declared)) or '(none)'}. "
                    f"Run `graphconnect catalog detail {entry.id}` to see the full parameter list."
                ),
            )
        )

    placeholder_re = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}")
    referenced = set(placeholder_re.findall(entry.endpoint))
    def _is_empty(v: object) -> bool:
        return v is None or (isinstance(v, str) and not v.strip())
    missing = sorted(name for name in referenced if _is_empty(parameters.get(name)))
    if missing:
        raise CliError(
            ErrorPayload(
                code=ErrorCode.USAGE_ERROR,
                message=f"{entry.id} requires parameter(s): {', '.join(missing)}",
                hint=f"Example: --param {missing[0]}=<value>",
            )
        )


def _normalize_parameter_types(entry: CatalogEntry, parameters: dict) -> dict:
    """Coerce CLI string parameters into declared catalog types."""
    normalized = dict(parameters)
    for param in entry.parameters:
        if param.name not in normalized:
            continue
        normalized[param.name] = _coerce_parameter_value(
            param.name,
            normalized[param.name],
            param.type,
        )
    return normalized


def _build_headers(
    entry: CatalogEntry,
    correlation_id: str | None = None,
    idempotency_key: str | None = None,
) -> dict[str, str]:
    """Build request headers: OData advanced query, correlation, idempotency."""
    headers: dict[str, str] = {}
    if entry.advanced_query:
        headers["ConsistencyLevel"] = "eventual"
    if correlation_id:
        headers["client-request-id"] = correlation_id
    if idempotency_key:
        # Graph relays client-request-id as the retry-correlating identity; Stripe-style
        # idempotency is captured on our side via the token hash (see safety.py).
        headers["x-ms-client-request-id"] = idempotency_key
    return headers


def _build_query_params(
    entry: CatalogEntry,
    parameters: dict,
    top: int,
    select: list[str] | None,
    filter_expr: str | None,
    expand: str | None,
    order_by: str | None,
) -> dict[str, str]:
    """Build OData query parameters."""
    query: dict[str, str] = {}

    if entry.singleton:
        select_fields = select or entry.default_select
        if select_fields:
            query["$select"] = ",".join(select_fields)
        expand_expr = expand or entry.default_expand
        if expand_expr:
            query["$expand"] = expand_expr
        return query

    if entry.supports_top and top > 0:
        query["$top"] = str(min(top, 999))

    select_fields = select or entry.default_select
    if select_fields:
        query["$select"] = ",".join(select_fields)

    filters = []
    if entry.default_filter:
        filters.append(entry.default_filter)

    if entry.computed_filter:
        computed = entry.computed_filter
        if "{cutoff_datetime}" in computed:
            days_param = next(
                (p for p in entry.parameters if p.name in ("days_inactive", "days")),
                None,
            )
            if days_param and days_param.name in parameters:
                days = int(parameters[days_param.name])
                cutoff = datetime.now(timezone.utc) - timedelta(days=days)
                computed = computed.replace(
                    "{cutoff_datetime}", cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")
                )
        if "{cutoff_datetime}" not in computed:
            filters.append(computed)

    for param in entry.parameters:
        if param.name not in parameters:
            continue
        raw_value = str(parameters[param.name])
        # value_map wins over maps_to_filter: each enum value produces its own
        # OData clause (e.g. status_filter=failure → status/errorCode ne 0).
        if param.value_map and raw_value in param.value_map:
            filters.append(param.value_map[raw_value])
            continue
        if param.maps_to_filter:
            if param.multi:
                items = [item.strip() for item in raw_value.split(",") if item.strip()]
                rendered = ",".join(f"'{_odata_literal(item)}'" for item in items)
            else:
                rendered = raw_value
            mapped = param.maps_to_filter.replace("{value}", rendered)
            filters.append(mapped)

    if filter_expr:
        filters.append(filter_expr)

    if filters:
        query["$filter"] = " and ".join(filters)

    order = order_by or entry.default_orderby
    if order:
        query["$orderby"] = order

    if entry.advanced_query:
        query["$count"] = "true"

    expand_expr = expand or entry.default_expand
    if expand_expr:
        query["$expand"] = expand_expr

    return query


def _build_body(entry: CatalogEntry, parameters: dict, body: dict | None) -> dict | None:
    """Build request body from template and parameters."""
    if body is not None:
        return body
    if entry.body_template:
        return _render_template_value(entry.body_template, parameters)
    return None


def _build_description(entry: CatalogEntry, parameters: dict) -> str:
    """Build a human-readable description of the write operation."""
    desc = f"{entry.method} {entry.endpoint}"
    desc = _interpolate_placeholders(desc, parameters)
    return f"{entry.summary} -- {desc}"


def _interpolate_placeholders(template: str, parameters: dict) -> str:
    """Replace {param} placeholders in a string template with parameter values."""
    result = template
    for key, value in parameters.items():
        placeholder = "{" + key + "}"
        if placeholder in result:
            result = result.replace(placeholder, str(value))
    return result


def _render_template_value(value: Any, parameters: dict) -> Any:
    """Recursively render a body template using parameter values."""
    if isinstance(value, str):
        # Exact-match: whole string is a single {param} -- substitute and preserve type.
        if value.startswith("{") and value.endswith("}") and value.count("{") == 1:
            param_name = value[1:-1]
            return parameters.get(param_name)
        # Inline substitution: replace all {param} occurrences with str(parameter).
        if "{" in value and "}" in value:
            return _interpolate_placeholders(value, parameters)
    if isinstance(value, dict):
        rendered: dict[str, Any] = {}
        for key, child in value.items():
            child_value = _render_template_value(child, parameters)
            if child_value is not None:
                rendered[key] = child_value
        return rendered
    if isinstance(value, list):
        return [
            child_value
            for child in value
            if (child_value := _render_template_value(child, parameters)) is not None
        ]
    return value


def _sanitize_preview_body(entry: CatalogEntry, body: dict | None) -> dict | None:
    """Redact sensitive fields before returning preview data to the CLI."""
    if not body:
        return body
    if entry.id != "users.reset_password":
        return body

    sanitized = json.loads(json.dumps(body))
    password_profile = sanitized.get("passwordProfile")
    if isinstance(password_profile, dict) and "password" in password_profile:
        password_profile["password"] = "***REDACTED***"
    return sanitized


def _coerce_parameter_value(name: str, value: Any, declared_type: str) -> Any:
    """Convert a raw CLI parameter into its declared catalog type."""
    if not isinstance(value, str):
        return value

    lowered = declared_type.lower()
    if lowered in ("boolean", "bool"):
        return _parse_bool_parameter(name, value)
    if lowered in ("integer", "int"):
        try:
            return int(value)
        except ValueError as exc:
            raise CliError(
                ErrorPayload(
                    code=ErrorCode.USAGE_ERROR,
                    message=f"Parameter '{name}' must be an integer.",
                    hint=f"Received: {value}",
                )
            ) from exc
    return value


def _parse_bool_parameter(name: str, value: str) -> bool:
    """Parse common CLI boolean spellings."""
    normalized = value.strip().lower()
    if normalized in {"true", "1", "yes", "y", "on"}:
        return True
    if normalized in {"false", "0", "no", "n", "off"}:
        return False
    raise CliError(
        ErrorPayload(
            code=ErrorCode.USAGE_ERROR,
            message=f"Parameter '{name}' must be a boolean.",
            hint="Use true/false, 1/0, yes/no, or on/off.",
        )
    )


async def _resolve_request_body(
    entry: CatalogEntry,
    parameters: dict,
    body: dict | None,
    *,
    correlation_id: str,
) -> dict | None:
    """Build request bodies, including helper-op bodies derived from current state."""
    if entry.id == "conditional_access.update_user_targets":
        return await _build_conditional_access_user_target_patch(
            parameters,
            correlation_id=correlation_id,
        )

    request_body = _build_body(entry, parameters, body)
    if entry.id == "users.reset_password":
        if body is None and "new_password" not in parameters:
            raise CliError(
                ErrorPayload(
                    code=ErrorCode.USAGE_ERROR,
                    message="users.reset_password requires --param new_password=... or --body.",
                    hint="Provide a password explicitly; no password is generated automatically.",
                )
            )
        request_body = request_body or {}
        password_profile = dict(request_body.get("passwordProfile") or {})
        if "password" not in password_profile and "new_password" in parameters:
            password_profile["password"] = parameters["new_password"]
        if "forceChangePasswordNextSignIn" not in password_profile:
            password_profile["forceChangePasswordNextSignIn"] = bool(
                parameters.get("force_change_next_sign_in", True)
            )
        request_body["passwordProfile"] = password_profile
    return request_body


def _attach_query(url: str, query_params: dict[str, str] | None) -> str:
    if not query_params:
        return url
    # Preserve `()`, `=`, and `;` in query values so nested OData like
    # `$expand=members($select=id,displayName)` round-trips verbatim. `=` in values
    # is unambiguous because urlencode formats each pair as key=value from a dict.
    return f"{url}?{urlencode(query_params, safe='$,();=')}"


def _compose_full_url(url: str, api_version: str, query_params: dict[str, str] | None = None) -> str:
    """Compose a fully-qualified Graph URL from the relative path and query parameters."""
    return _attach_query(f"https://graph.microsoft.com/{api_version}{url}", query_params)


def _audit_url(url: str, query_params: dict[str, str] | None) -> str:
    """Relative Graph URL with query string attached, for audit log reproduction."""
    return _attach_query(url, query_params)


async def _resolve_preview_lookup(
    entry: CatalogEntry,
    parameters: dict,
    *,
    correlation_id: str,
) -> dict[str, Any]:
    """Fetch preview target state when the catalog declares a lookup endpoint."""
    if not entry.preview_lookup_endpoint:
        return {
            "http_status": None,
            "affected_resources": [],
            "warnings": [],
            "fingerprint": None,
        }

    resource, _, http_status = await _fetch_single_resource(
        _interpolate_placeholders(entry.preview_lookup_endpoint, parameters),
        entry.api_version.value,
        correlation_id=correlation_id,
        select=entry.preview_lookup_select,
    )

    affected_resources = []
    if resource and any(
        key in resource for key in ("id", "displayName", "name", "deviceName", "userPrincipalName")
    ):
        affected_resources.append(_format_affected_resource(resource))
    warnings: list[str] = []
    if entry.execute_fingerprint_fields:
        warnings.append("Execution will revalidate the target against the preview snapshot.")
    return {
        "http_status": http_status,
        "affected_resources": affected_resources,
        "warnings": warnings,
        "fingerprint": _compute_resource_fingerprint(resource, entry.execute_fingerprint_fields),
    }


async def _validate_resource_fingerprint(
    entry: CatalogEntry,
    parameters: dict,
    expected_fingerprint: str | None,
    *,
    correlation_id: str,
) -> None:
    """Block execution when a previewed resource changed since the token was issued."""
    if (
        not entry.execute_fingerprint_fields
        or not entry.preview_lookup_endpoint
        or expected_fingerprint is None
    ):
        return

    current_state = await _resolve_preview_lookup(
        entry,
        parameters,
        correlation_id=correlation_id,
    )
    if current_state["fingerprint"] != expected_fingerprint:
        raise CliError(
            ErrorPayload(
                code=ErrorCode.CONFLICT,
                message="Target resource changed since preview.",
                hint="Run the command again without --execute to capture a fresh preview.",
                correlation_id=correlation_id,
            )
        )


async def _build_conditional_access_user_target_patch(
    parameters: dict,
    *,
    correlation_id: str,
) -> dict[str, Any]:
    """Merge a single include/exclude user into a CA policy without resending the full body."""
    policy_id = parameters.get("policy_id")
    target_list = parameters.get("target_list")
    action = parameters.get("action")
    user_id = parameters.get("user_id")

    if not policy_id or not target_list or not action or not user_id:
        raise CliError(
            ErrorPayload(
                code=ErrorCode.USAGE_ERROR,
                message=(
                    "conditional_access.update_user_targets requires policy_id, "
                    "target_list, action, and user_id."
                ),
                hint="Example: --param policy_id=<id> --param target_list=excludeUsers --param action=remove --param user_id=<user-id>",
            )
        )
    if target_list not in {"includeUsers", "excludeUsers"}:
        raise CliError(
            ErrorPayload(
                code=ErrorCode.USAGE_ERROR,
                message=f"Unsupported target_list for conditional_access.update_user_targets: {target_list}",
                hint="Use target_list=includeUsers or target_list=excludeUsers.",
            )
        )

    policy, _, _ = await _fetch_single_resource(
        f"/identity/conditionalAccess/policies/{policy_id}",
        "v1.0",
        correlation_id=correlation_id,
    )
    users_block = dict(((policy or {}).get("conditions") or {}).get("users") or {})
    current_members = list(users_block.get(target_list) or [])

    if action == "add":
        if user_id not in current_members:
            current_members.append(user_id)
    elif action == "remove":
        current_members = [member for member in current_members if member != user_id]
    else:
        raise CliError(
            ErrorPayload(
                code=ErrorCode.USAGE_ERROR,
                message=f"Unsupported action for conditional_access.update_user_targets: {action}",
                hint="Use action=add or action=remove.",
            )
        )

    users_block[target_list] = current_members
    return {"conditions": {"users": users_block}}


async def _fetch_single_resource(
    url: str,
    api_version: str,
    *,
    correlation_id: str,
    select: list[str] | None = None,
) -> tuple[dict[str, Any] | None, int, int | None]:
    """Fetch one resource for preview or merge helpers."""
    query_params: dict[str, str] = {}
    if select:
        query_params["$select"] = ",".join(select)
    data, _, _, bytes_read, http_status = await _execute_get(
        url,
        api_version,
        query_params,
        top=1,
        singleton=True,
        headers={"client-request-id": correlation_id},
    )
    return (data[0] if data else None), bytes_read, http_status


def _compute_resource_fingerprint(resource: dict[str, Any] | None, field_paths: list[str]) -> str | None:
    """Hash the selected resource fields for execute-time drift detection."""
    if not resource or not field_paths:
        return None
    projection = {path: _extract_field_path(resource, path) for path in field_paths}
    payload = json.dumps(projection, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


@functools.lru_cache(maxsize=256)
def _split_field_path(path: str) -> tuple[str, ...]:
    """Split a dotted path, preserving @odata.* keys as single segments.

    Graph responses use OData annotations like `@odata.type`, `@odata.context`.
    Naive split on "." would break `target.@odata.type` into three segments and
    fail to find the nested annotation. A token starting with "@" consumes the
    next token so `@odata.type` stays atomic.
    """
    raw = path.split(".")
    out: list[str] = []
    i = 0
    while i < len(raw):
        tok = raw[i]
        if tok.startswith("@") and i + 1 < len(raw):
            out.append(tok + "." + raw[i + 1])
            i += 2
        else:
            out.append(tok)
            i += 1
    return tuple(out)


def _extract_field_path(data: Any, path: str) -> Any:
    """Read a dotted field path from a JSON-like structure."""
    current = data
    for segment in _split_field_path(path):
        if isinstance(current, dict):
            current = current.get(segment)
        else:
            return None
    return current


def _format_affected_resource(resource: dict[str, Any]) -> str:
    """Build a short resource label for preview output."""
    label = (
        resource.get("displayName")
        or resource.get("name")
        or resource.get("deviceName")
        or resource.get("userPrincipalName")
        or resource.get("id")
        or "resource"
    )
    resource_id = resource.get("id")
    if resource_id and resource_id != label:
        return f"{label} ({resource_id})"
    return str(label)


async def _paginate_graph_response(
    fetch: Callable[[str], Awaitable[tuple[dict[str, Any], int, int]]],
    first_url: str,
    top: int,
) -> tuple[list[dict], int | None, bool, int, int]:
    """Walk @odata.nextLink pages up to `top` items, summing raw payload bytes from each fetch.

    Pass top<=0 for unbounded pagination (fetch every page).

    PowerShell's Invoke-MgGraphRequest injects @odata.count = page length on every
    response regardless of $count=true, so only trust the field when the caller
    actually requested $count (i.e., Graph is returning a real server-side total).
    """
    unbounded = top <= 0
    response_data, bytes_seen, http_status = await fetch(first_url)
    trust_odata_count = "$count=true" in first_url or "%24count=true" in first_url
    total_count = response_data.get("@odata.count") if trust_odata_count else None
    next_link = response_data.get("@odata.nextLink")
    collected = list(response_data.get("value", []))
    while next_link and (unbounded or len(collected) < top):
        response_data, page_bytes, _ = await fetch(next_link)
        collected.extend(response_data.get("value", []))
        next_link = response_data.get("@odata.nextLink")
        bytes_seen += page_bytes
    if unbounded:
        return collected, total_count, False, bytes_seen, http_status
    has_more = len(collected) > top or next_link is not None
    return collected[:top], total_count, has_more, bytes_seen, http_status


async def _execute_get(
    url: str,
    api_version: str,
    query_params: dict[str, str],
    top: int,
    singleton: bool = False,
    headers: dict[str, str] | None = None,
) -> tuple[list[dict], int | None, bool, int, int | None]:
    """Execute a GET against Microsoft Graph, returning (data, total, has_more, bytes, status)."""
    from graphconnect.auth import get_auth_context, get_client, invoke_graph_powershell_request

    full_url = _compose_full_url(url, api_version, query_params)
    request_headers = headers or {}

    if get_auth_context().auth_method == AuthMethod.GRAPH_POWERSHELL:
        # PS path hides raw bytes; fall back to serialized size.
        async def fetch(target_url: str) -> tuple[dict[str, Any], int, int]:
            response = await asyncio.to_thread(
                invoke_graph_powershell_request,
                method="GET",
                url=target_url,
                headers=request_headers,
            )
            data, http_status = _unwrap_graph_response(response, default_status=200)
            return data, len(json.dumps(data, default=str)) if data else 0, http_status
    else:
        from kiota_abstractions.method import Method
        from kiota_abstractions.request_information import RequestInformation

        adapter = get_client().request_adapter

        async def fetch(target_url: str) -> tuple[dict[str, Any], int, int]:
            request_info = RequestInformation()
            request_info.http_method = Method.GET
            request_info.url = target_url
            for header_name, header_value in request_headers.items():
                request_info.headers.add(header_name, header_value)
            native_response = await adapter.send_primitive_async(request_info, "bytes", {})
            if not native_response:
                return {}, 0, 200
            return json.loads(native_response), len(native_response), 200

    if singleton:
        response, size, http_status = await fetch(full_url)
        return ([response] if response else []), None, False, size, http_status

    return await _paginate_graph_response(fetch, full_url, top)


async def _execute_mutation(
    method: str,
    url: str,
    api_version: str,
    body: dict | None,
    headers: dict[str, str] | None = None,
    expected_status: int = 204,
) -> tuple[dict[str, Any] | None, int, int | None]:
    """Execute a POST/PATCH/DELETE/PUT returning (body, bytes, status)."""
    from graphconnect.auth import get_auth_context, get_client, invoke_graph_powershell_request

    full_url = _compose_full_url(url, api_version)
    request_headers = headers or {}

    if get_auth_context().auth_method == AuthMethod.GRAPH_POWERSHELL:
        response = await asyncio.to_thread(
            invoke_graph_powershell_request,
            method=method,
            url=full_url,
            body=body,
            headers=request_headers,
        )
        data, http_status = _unwrap_graph_response(
            response,
            default_status=expected_status,
        )
        if isinstance(data, dict):
            return data, len(json.dumps(data, default=str)), http_status
        return None, 0, http_status

    from kiota_abstractions.method import Method
    from kiota_abstractions.request_information import RequestInformation

    method_map = {
        "POST": Method.POST,
        "PATCH": Method.PATCH,
        "DELETE": Method.DELETE,
        "PUT": Method.PUT,
    }

    request_info = RequestInformation()
    request_info.http_method = method_map.get(method, Method.POST)
    request_info.url = full_url
    for header_name, header_value in request_headers.items():
        request_info.headers.add(header_name, header_value)
    if body:
        request_info.headers.add("Content-Type", "application/json")
        request_info.set_stream_content(json.dumps(body).encode("utf-8"))

    adapter = get_client().request_adapter
    native_response = await adapter.send_primitive_async(request_info, "bytes", {})
    if not native_response:
        return None, 0, expected_status
    try:
        return json.loads(native_response), len(native_response), expected_status
    except json.JSONDecodeError:
        return None, len(native_response), expected_status


def _truncate_rows(rows: list[dict[str, Any]], top: int) -> tuple[list[dict[str, Any]], int, bool]:
    """Slice rows for return; return (rows, total_count, has_more). top<=0 means no limit."""
    total_count = len(rows)
    if top > 0:
        return rows[:top], total_count, total_count > top
    return rows, total_count, False


def _export_cache_key(url: str, api_version: str, request_body: dict[str, Any]) -> str:
    """Hash a report export request into a stable cache key.

    Includes the active principal so two operators (or two tenants after re-auth)
    sharing the same machine cannot read each other's report rows.
    """
    payload = json.dumps(
        {
            "principal": peek_user_principal(),
            "url": url,
            "api_version": api_version,
            "request_body": request_body,
        },
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _load_cached_export_rows(
    *,
    url: str,
    api_version: str,
    request_body: dict[str, Any],
    ttl_seconds: int = _EXPORT_CACHE_TTL_SECONDS,
) -> tuple[list[dict[str, Any]], int] | None:
    """Return cached Intune export rows when the request body matches and the cache is fresh."""
    cache_file = _EXPORT_CACHE_DIR / f"{_export_cache_key(url, api_version, request_body)}.json"
    try:
        raw = cache_file.read_bytes()
        payload = json.loads(raw.decode("utf-8"))
        saved_dt = datetime.fromisoformat(str(payload["saved_at"]).replace("Z", "+00:00"))
        rows = payload["rows"]
        assert isinstance(rows, list)
    except (OSError, ValueError, UnicodeDecodeError, KeyError, TypeError, AssertionError):
        return None
    if (datetime.now(timezone.utc) - saved_dt).total_seconds() > ttl_seconds:
        return None
    return [row for row in rows if isinstance(row, dict)], len(raw)


def _store_cached_export_rows(
    *,
    url: str,
    api_version: str,
    request_body: dict[str, Any],
    rows: list[dict[str, Any]],
) -> None:
    """Persist Intune export rows for short-term reuse inside repeated troubleshooting loops."""
    cache_file = _EXPORT_CACHE_DIR / f"{_export_cache_key(url, api_version, request_body)}.json"
    payload = {
        "saved_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "rows": rows,
    }
    try:
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        cache_file.write_text(json.dumps(payload, default=str), encoding="utf-8")
    except OSError:
        return


async def _execute_export_job_read(
    *,
    url: str,
    api_version: str,
    request_body: dict[str, Any],
    headers: dict[str, str] | None,
    top: int,
    correlation_id: str,
) -> tuple[list[dict[str, Any]], int | None, bool, int, int | None]:
    """Create an Intune export job, poll it to completion, and download rows."""
    cached = _load_cached_export_rows(url=url, api_version=api_version, request_body=request_body)
    if cached is not None:
        rows, bytes_read = cached
        sliced, total_count, has_more = _truncate_rows(rows, top)
        return sliced, total_count, has_more, bytes_read, 200

    job, bytes_read, http_status = await _execute_mutation(
        method="POST",
        url=url,
        api_version=api_version,
        body=request_body,
        headers=headers,
        expected_status=201,
    )
    if not isinstance(job, dict):
        raise RuntimeError("Export job creation returned no payload.")

    job_status = job
    job_id = job_status.get("id")
    if not job_id:
        raise RuntimeError("Export job creation did not return an id.")

    deadline = time.monotonic() + _EXPORT_JOB_DEADLINE_SECONDS
    poll_status = http_status

    while True:
        status = str(job_status.get("status") or "").lower()
        download_url = job_status.get("url")
        if status == "completed" and download_url:
            rows, download_bytes = await _download_export_rows(str(download_url))
            bytes_read += download_bytes
            _store_cached_export_rows(url=url, api_version=api_version, request_body=request_body, rows=rows)
            sliced, total_count, has_more = _truncate_rows(rows, top)
            return sliced, total_count, has_more, bytes_read, poll_status
        if status in {"failed", "failure", "cancelled", "unknown"}:
            raise RuntimeError(f"Export job {job_id} ended in status '{job_status.get('status')}'.")
        if time.monotonic() >= deadline:
            raise RuntimeError(
                f"Export job {job_id} did not complete within {_EXPORT_JOB_DEADLINE_SECONDS} seconds."
            )

        await asyncio.sleep(_EXPORT_JOB_POLL_INTERVAL_SECONDS)
        job_status, poll_bytes, poll_status = await _fetch_single_resource(
            f"{url}/{job_id}",
            api_version,
            correlation_id=correlation_id,
        )
        bytes_read += poll_bytes
        if job_status is None:
            raise RuntimeError(f"Export job {job_id} could not be read after creation.")


async def _download_export_rows(download_url: str) -> tuple[list[dict[str, Any]], int]:
    """Download an Intune export artifact and return normalized row dicts."""
    return await asyncio.to_thread(_download_export_rows_sync, download_url)


def _download_export_rows_sync(download_url: str) -> tuple[list[dict[str, Any]], int]:
    """Blocking half of export download and payload normalization."""
    with urlopen(download_url, timeout=60) as response:  # nosec B310: Graph returns a signed blob URL
        payload = response.read()
    return _parse_export_payload(payload), len(payload)


def _parse_export_payload(payload: bytes) -> list[dict[str, Any]]:
    """Parse a zipped Intune export artifact into normalized row dicts."""
    if zipfile.is_zipfile(io.BytesIO(payload)):
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            names = [name for name in archive.namelist() if not name.endswith("/")]
            if not names:
                return []
            first_name = names[0]
            raw = archive.read(first_name)
        return _parse_export_document(raw, first_name)
    return _parse_export_document(payload, "export.json")


def _parse_export_document(raw: bytes, name: str) -> list[dict[str, Any]]:
    """Parse a single export file based on its extension."""
    lowered = name.lower()
    if lowered.endswith(".json"):
        document = json.loads(raw.decode("utf-8-sig"))
        return _normalize_export_rows(document)
    if lowered.endswith(".csv"):
        text = raw.decode("utf-8-sig")
        return list(csv.DictReader(io.StringIO(text)))
    raise RuntimeError(f"Unsupported Intune export format: {name}")


def _normalize_export_rows(document: Any) -> list[dict[str, Any]]:
    """Normalize common Intune export JSON shapes into row dicts."""
    if isinstance(document, list):
        return [row for row in document if isinstance(row, dict)]
    if not isinstance(document, dict):
        return []

    values = document.get("values")
    columns = document.get("columns")
    if isinstance(values, list):
        if values and isinstance(values[0], dict):
            return [row for row in values if isinstance(row, dict)]
        if isinstance(columns, list):
            out: list[dict[str, Any]] = []
            for row in values:
                if isinstance(row, list):
                    out.append({str(columns[i]): row[i] for i in range(min(len(columns), len(row)))})
            return out

    for key in ("Results", "results", "Rows", "rows", "value"):
        child = document.get(key)
        if isinstance(child, list):
            return [row for row in child if isinstance(row, dict)]
    return []


def _normalize_post_read_response(
    raw: dict | None,
    top: int,
) -> tuple[list[dict], int | None, bool]:
    """Normalize an Intune reports {Schema, Values} response into row dicts."""
    if not raw or not isinstance(raw, dict):
        return [], 0, False
    schema = raw.get("Schema")
    values = raw.get("Values")
    if not schema or not isinstance(values, list):
        return [], 0, False
    columns = [c["Column"] for c in schema]
    rows = [{columns[i]: row[i] for i in range(len(columns))} for row in values]
    total = raw.get("TotalRowCount") or len(rows)
    has_more = bool(top and len(rows) >= top and total > len(rows))
    return rows, total, has_more


def _unwrap_graph_response(response: Any, default_status: int) -> tuple[dict[str, Any], int]:
    """Normalize Graph PowerShell responses into (body, status_code)."""
    if isinstance(response, dict) and "body" in response and "status_code" in response:
        body = response.get("body")
        if isinstance(body, dict):
            data = body
        elif body is None:
            data = {}
        else:
            data = {"value": body}
        return data, int(response.get("status_code") or default_status)
    if isinstance(response, dict):
        return response, default_status
    return {}, default_status


def _expected_success_status(method: str) -> int:
    """Return the default success status code for a mutation."""
    return 204


_MS_DATE_RE = re.compile(r"^/Date\((-?\d+)\)/$")

# Graph uses year-0001 and year-9999 as "never" sentinels for never-reported /
# no-expiry fields. Anything beyond these thresholds is emitted as None.
_MS_DATE_SENTINEL_NEG = -60_000_000_000_000  # ~year 0070
_MS_DATE_SENTINEL_POS = 253_000_000_000_000  # ~year 9990


def _post_process_rows(
    rows: list[dict[str, Any]],
    projections: list[CatalogProjection],
    drop_paths: list[str] | None = None,
    operation_id: str | None = None,
) -> list[dict[str, Any]]:
    """Apply response post-processing: date normalization, projections, drops, op-specific fixups."""
    if not rows:
        return rows
    for row in rows:
        _normalize_values(row)
        if projections:
            _apply_projections(row, projections)
        if drop_paths:
            for path in drop_paths:
                _drop_path(row, path)
    if operation_id:
        _apply_operation_specific_postprocess(operation_id, rows)
    return rows


# Field name fragments that commonly carry a user identity. When Graph/Intune
# returns the literal string "None" on one of these, it means "no user" and
# should be null. Scoped narrowly so we don't touch legitimate string values.
_USER_IDENTITY_FIELD_FRAGMENTS = ("userprincipalname", "username", "useremail", "upn")


def _drop_path(obj: dict[str, Any], path: str) -> None:
    """Remove a field from a dict, honoring `array[].subfield` and dotted paths.

    A literal key match takes precedence over dotted traversal so paths whose
    key names embed a dot (e.g. `@odata.type`, `assignments@odata.context`) work
    without escaping.
    """
    if "[]" in path:
        head, _, rest = path.partition("[]")
        array_key = head.rstrip(".")
        sub_path = rest.lstrip(".")
        target = obj.get(array_key) if array_key else obj
        if not isinstance(target, list):
            return
        for item in target:
            if isinstance(item, dict) and sub_path:
                _drop_path(item, sub_path)
        return
    if path in obj:
        obj.pop(path, None)
        return
    if "." in path:
        head, _, rest = path.partition(".")
        child = obj.get(head)
        if isinstance(child, dict):
            _drop_path(child, rest)


def _apply_operation_specific_postprocess(operation_id: str, rows: list[dict[str, Any]]) -> None:
    """Per-op response shape fixups that can't be expressed via generic projections."""
    if operation_id == "audit.directory_logs":
        # modifiedProperties.oldValue/newValue are JSON-encoded strings
        # (e.g. '[]', '["Pilot Ring 1"]'). Consumers always re-parse, so do it
        # once here and emit structured values instead.
        for row in rows:
            for target in row.get("targetResources") or []:
                for prop in (target or {}).get("modifiedProperties") or []:
                    for field in ("oldValue", "newValue"):
                        value = prop.get(field)
                        if isinstance(value, str) and value and (value[0] in "[{" or value in ('"', "null")):
                            try:
                                prop[field] = json.loads(value)
                            except (ValueError, TypeError):
                                pass
    elif operation_id == "users.list_privileged":
        # Full user objects ship under `members` — flatten a UPN roster + count
        # so callers don't have to dive into the nested blob for common queries.
        for row in rows:
            members = row.get("members") or []
            if isinstance(members, list):
                row["memberUPNs"] = [
                    (m or {}).get("userPrincipalName")
                    for m in members
                    if isinstance(m, dict)
                ]
                row["memberCount"] = len(members)
    elif operation_id in {"devices.policy_setting_statuses", "devices.explain_policy_failure"}:
        for row in rows:
            row["SettingLabel"] = _humanize_setting_name(row.get("SettingName") or row.get("SettingNm"))
            error_code = row.get("ErrorCode")
            if isinstance(error_code, int) and error_code in _INTUNE_ERROR_HINTS:
                row["ErrorHint"] = _INTUNE_ERROR_HINTS[error_code]
            elif row.get("StateDetails_loc"):
                row["ErrorHint"] = row.get("StateDetails_loc")


def _humanize_setting_name(value: Any) -> str | None:
    """Convert Intune setting identifiers into a label operators can scan quickly."""
    if not isinstance(value, str) or not value:
        return None
    parts = [part for part in value.split("_") if part]
    humanized = [_humanize_setting_token(part) for part in parts]
    return " - ".join(part for part in humanized if part)


def _humanize_setting_token(token: str) -> str:
    """Expand CamelCase and numeric suffixes in one setting-name token."""
    token = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", token)
    token = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", token)
    token = re.sub(r"([A-Za-z])(\d+)", r"\1 \2", token)
    return token.strip()


def _normalize_values(value: Any) -> Any:
    """Single-pass normalization: /Date(ms)/ → ISO 8601, strip @odata.context, coerce 'None' → null on user-identity columns."""
    if isinstance(value, dict):
        for k in [k for k in value if k == "@odata.context" or k.endswith("@odata.context")]:
            value.pop(k, None)
        for k, v in list(value.items()):
            if isinstance(v, str) and v == "None":
                kl = k.lower()
                if any(frag in kl for frag in _USER_IDENTITY_FIELD_FRAGMENTS):
                    value[k] = None
                    continue
            value[k] = _normalize_values(v)
        return value
    if isinstance(value, list):
        for i, v in enumerate(value):
            value[i] = _normalize_values(v)
        return value
    if isinstance(value, str) and value.startswith("/Date("):
        match = _MS_DATE_RE.match(value)
        if match:
            try:
                ms = int(match.group(1))
            except ValueError:
                return value
            if ms <= _MS_DATE_SENTINEL_NEG or ms >= _MS_DATE_SENTINEL_POS:
                return None
            try:
                return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).isoformat().replace("+00:00", "Z")
            except (OverflowError, OSError):
                return value
    return value


def _dedupe_rows(rows: list[dict[str, Any]], fields: list[str]) -> list[dict[str, Any]]:
    """Drop rows whose tuple of `fields` values matches a prior row. Keeps first occurrence.

    Used for Graph endpoints that return the same logical row once per associated
    user on multi-user devices (e.g. compliancePolicyStates, configurationStates).
    """
    parsed = [_split_field_path(f) for f in fields]
    seen: set[tuple] = set()
    out: list[dict[str, Any]] = []
    for row in rows:
        key_parts: list[Any] = []
        for segments in parsed:
            current: Any = row
            for segment in segments:
                if isinstance(current, dict):
                    current = current.get(segment)
                else:
                    current = None
                    break
            key_parts.append(current)
        key = tuple(key_parts)
        if key in seen:
            continue
        seen.add(key)
        out.append(row)
    return out


def _apply_projections(row: dict[str, Any], projections: list[CatalogProjection]) -> None:
    """Flatten declared nested paths into top-level columns on the row."""
    for proj in projections:
        raw = _extract_field_path(row, proj.path)
        if proj.enum_map and raw is not None:
            row[proj.name] = proj.enum_map.get(str(raw), raw)
        else:
            row[proj.name] = raw


_HTTP_STATUS_RE = re.compile(r"HTTP/1\.\d\s+(\d{3})")
_GRAPH_CODE_RE = re.compile(r'"code"\s*:\s*"([^"]*)"')
_REASON_PHRASE_RE = re.compile(r"does not indicate success:\s*(\w+)", re.IGNORECASE)

# PS Invoke-MgGraphRequest surfaces the .NET reason phrase (e.g. "BadRequest"); resolve via stdlib.
_PS_REASON_TO_STATUS = {
    status.phrase.replace(" ", "").lower(): status.value for status in HTTPStatus
}


_MANAGED_DEVICE_UNSELECTABLE = (
    "joinType",
    "chassisType",
    "autopilotEnrolled",
    "deviceType",
    "deviceCategoryDisplayName",
)

# Graph 404/ResourceNotFound responses point at a parent collection; map each
# collection segment to the catalog op that lists valid IDs for it so the hint
# tells the operator what to run next instead of saying "check the ID".
_PARENT_COLLECTION_TO_LIST_OP = (
    ("/configurationPolicies/", "policies.list_settings_catalog"),
    ("/deviceConfigurations/", "policies.list_config_profiles"),
    ("/deviceCompliancePolicies/", "policies.list_compliance_policies"),
    ("/compliancePolicies/", "policies.list_modern_compliance"),
    ("/intents/", "policies.list_intent_profiles"),
    ("/templates/", "policies.list_baseline_templates"),
    ("/managedDevices/", "devices.list_managed"),
    ("/devices/", "devices.list_entra"),
    ("/groups/", "groups.list_all"),
    ("/users/", "users.list_all"),
    ("/identity/conditionalAccess/policies/", "conditional_access.list_policies"),
)


def _list_op_for_missing_resource(message: str) -> str | None:
    """Pick the catalog list op whose collection matches the failing path segment."""
    for segment, op in _PARENT_COLLECTION_TO_LIST_OP:
        if segment in message:
            return op
    return None


def _specialized_hint(
    message: str,
    http_status: int | None,
    graph_error_code: str | None = None,
) -> str | None:
    """Return a focused hint for known Graph quirks. None if nothing matches.

    Keep this list short and empirical — hints are loud, and a wrong hint
    ("known Graph issue — retry later") is worse than no hint because it
    sends the operator on a retry loop instead of examining the request.
    """
    if http_status == 500 and "/deviceConfigurations/" in message and "$select=" in message:
        return (
            "Graph 500s on $select against polymorphic deviceConfiguration subtypes. "
            "Drop default_select from the op or query without --select."
        )
    if (
        http_status == 400
        and "/managedDevices" in message
        and "$select=" in message
    ):
        for field in _MANAGED_DEVICE_UNSELECTABLE:
            if field in message:
                return (
                    f"Field `{field}` is not $select-able on /deviceManagement/managedDevices "
                    "in v1.0 — Microsoft documents it but the OData schema rejects it. "
                    "Drop it from your --select list."
                )
    # Intune wraps missing-collection-segment errors as 400 BadRequest with an
    # inner ResourceNotFound code; treat both shapes the same here.
    if graph_error_code == "ResourceNotFound" or (
        http_status == 404 and "ResourceNotFound" in message
    ):
        list_op = _list_op_for_missing_resource(message)
        if list_op:
            return (
                f"Resource id not found. Run `graphconnect read {list_op}` "
                "to find valid IDs (tenant or scope mismatch is the other common cause)."
            )
        return "Resource id not found. Run `graphconnect catalog search <keyword>` to find the list op that enumerates valid IDs for this path."
    return None


def _map_graph_exception(exc: Exception, correlation_id: str | None = None) -> ErrorPayload:
    """Best-effort translation of raw Graph/PS errors into a structured ErrorPayload."""
    message = str(exc)
    status_match = _HTTP_STATUS_RE.search(message)
    code_match = _GRAPH_CODE_RE.search(message)
    http_status = int(status_match.group(1)) if status_match else None
    if http_status is None:
        reason_match = _REASON_PHRASE_RE.search(message)
        if reason_match:
            http_status = _PS_REASON_TO_STATUS.get(reason_match.group(1).lower())
    graph_error_code = code_match.group(1) if code_match else None

    if (
        "Not authenticated" in message
        or "not_authenticated" in message
        or "No usable authentication source found" in message
    ):
        return ErrorPayload(
            code=ErrorCode.AUTH_REQUIRED,
            message="Not authenticated with Microsoft Graph.",
            hint="Run: graphconnect auth login",
            correlation_id=correlation_id,
        )

    specialized = _specialized_hint(message, http_status, graph_error_code)

    if http_status is None:
        return ErrorPayload(
            code=ErrorCode.UPSTREAM_ERROR,
            message=message.strip().splitlines()[0] if message else "Upstream Graph call failed.",
            hint=specialized or "Check audit.jsonl for the full trace.",
            correlation_id=correlation_id,
            graph_error_code=graph_error_code,
        )

    code_map = {
        400: ErrorCode.BAD_REQUEST,
        401: ErrorCode.AUTH_REQUIRED,
        403: ErrorCode.PERMISSION_DENIED,
        404: ErrorCode.NOT_FOUND,
        409: ErrorCode.CONFLICT,
        429: ErrorCode.THROTTLED,
    }
    code = code_map.get(http_status, ErrorCode.UPSTREAM_ERROR)
    # Intune wraps missing-resource errors as 400 BadRequest with inner
    # ResourceNotFound; reclassify so scripts get the NOT_FOUND exit code.
    if graph_error_code == "ResourceNotFound":
        code = ErrorCode.NOT_FOUND

    hints = {
        ErrorCode.PERMISSION_DENIED: "Missing Graph scope. Re-run `graphconnect auth login` and grant the required permission.",
        ErrorCode.NOT_FOUND: "Resource does not exist — check IDs and tenant.",
        ErrorCode.THROTTLED: "Graph is throttling. Back off and retry.",
        ErrorCode.BAD_REQUEST: "Graph rejected the query. Run `graphconnect catalog detail <op>` and check parameter shapes.",
    }

    first_line = next((ln for ln in message.splitlines() if ln.strip()), message)
    return ErrorPayload(
        code=code,
        message=first_line,
        hint=specialized or hints.get(code),
        retryable=code in (ErrorCode.THROTTLED, ErrorCode.UPSTREAM_ERROR),
        http_status=http_status,
        graph_error_code=graph_error_code,
        correlation_id=correlation_id,
    )
