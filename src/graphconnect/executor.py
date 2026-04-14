"""Builds and executes Graph API requests from catalog entries."""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
import uuid
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from typing import Any, Awaitable, Callable
from urllib.parse import urlencode

from graphconnect.audit import log_operation
from graphconnect.safety import check_rate_limit, generate_token, validate_token
from graphconnect.types import (
    AuthMethod,
    CatalogEntry,
    CliError,
    ErrorCode,
    ErrorPayload,
    OperationResult,
    SafetyTier,
    WritePreview,
)


async def execute_read(
    entry: CatalogEntry,
    parameters: dict | None = None,
    top: int = 100,
    select: list[str] | None = None,
    filter_expr: str | None = None,
    expand: str | None = None,
    order_by: str | None = None,
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
    request_id = _new_id()
    correlation_id = _new_id()
    start_time = time.monotonic()

    url = _build_url(entry, parameters)
    query_params = _build_query_params(entry, parameters, top, select, filter_expr, expand, order_by)
    headers = _build_headers(entry, correlation_id=correlation_id)

    try:
        data, total_count, has_more, bytes_read, http_status = await _execute_get(
            url,
            entry.api_version.value,
            query_params,
            top,
            singleton=entry.singleton,
            headers=headers,
        )
    except Exception as exc:
        elapsed = int((time.monotonic() - start_time) * 1000)
        payload = _map_graph_exception(exc, correlation_id=correlation_id)
        log_operation(
            operation_id=entry.id,
            safety_tier=entry.safety_tier,
            method="GET",
            graph_url=url,
            parameters=parameters,
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
        method="GET",
        graph_url=url,
        parameters=parameters,
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
        has_more=has_more,
        data=data,
        execution_time_ms=elapsed,
        graph_url=url,
        request_id=request_id,
        correlation_id=correlation_id,
    )


async def preview_write(
    entry: CatalogEntry,
    parameters: dict | None = None,
    body: dict | None = None,
) -> WritePreview:
    """Generate a dry-run preview for a write operation."""
    parameters = _apply_parameter_defaults(entry, parameters or {})
    parameters = _normalize_parameter_types(entry, parameters)
    url = _build_url(entry, parameters)

    correlation_id = _new_id()
    idempotency_key = _new_id()
    start_time = time.monotonic()

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
    correlation_seed = _new_id()
    try:
        request_body = await _resolve_request_body(
            entry,
            parameters,
            body,
            correlation_id=correlation_seed,
        )
    except CliError:
        raise
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
    top: int = 50,
) -> list[OperationResult]:
    """Execute read operations concurrently (Graph $batch endpoint can be added later)."""
    return list(await asyncio.gather(*(execute_read(entry=entry, top=top) for entry in entries)))


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

    if entry.supports_top:
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
        if param.maps_to_filter and param.name in parameters:
            mapped = param.maps_to_filter.replace("{value}", str(parameters[param.name]))
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
    if isinstance(value, str) and value.startswith("{") and value.endswith("}"):
        param_name = value[1:-1]
        return parameters.get(param_name)
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
    if lowered == "number":
        try:
            return float(value)
        except ValueError as exc:
            raise CliError(
                ErrorPayload(
                    code=ErrorCode.USAGE_ERROR,
                    message=f"Parameter '{name}' must be a number.",
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


def _compose_full_url(url: str, api_version: str, query_params: dict[str, str] | None = None) -> str:
    """Compose a fully-qualified Graph URL from the relative path and query parameters."""
    full_url = f"https://graph.microsoft.com/{api_version}{url}"
    if query_params:
        query_string = urlencode(query_params, safe="$,")
        if query_string:
            full_url += f"?{query_string}"
    return full_url


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


def _extract_field_path(data: Any, path: str) -> Any:
    """Read a dotted field path from a JSON-like structure."""
    current = data
    for segment in path.split("."):
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
    """Walk @odata.nextLink pages up to `top` items, summing raw payload bytes from each fetch."""
    response_data, bytes_seen, http_status = await fetch(first_url)
    total_count = response_data.get("@odata.count")
    next_link = response_data.get("@odata.nextLink")
    collected = list(response_data.get("value", []))
    while next_link and len(collected) < top:
        response_data, page_bytes, _ = await fetch(next_link)
        collected.extend(response_data.get("value", []))
        next_link = response_data.get("@odata.nextLink")
        bytes_seen += page_bytes
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
    """Return the default success status code for a successful mutation."""
    if method == "POST":
        return 204
    if method in ("PATCH", "DELETE", "PUT"):
        return 204
    return 200


_HTTP_STATUS_RE = re.compile(r"HTTP/1\.\d\s+(\d{3})")
_GRAPH_CODE_RE = re.compile(r'"code"\s*:\s*"([^"]*)"')
_REASON_PHRASE_RE = re.compile(r"does not indicate success:\s*(\w+)", re.IGNORECASE)

# PS Invoke-MgGraphRequest surfaces the .NET reason phrase (e.g. "BadRequest"); resolve via stdlib.
_PS_REASON_TO_STATUS = {
    status.phrase.replace(" ", "").lower(): status.value for status in HTTPStatus
}


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

    if http_status is None:
        return ErrorPayload(
            code=ErrorCode.UPSTREAM_ERROR,
            message=message.strip().splitlines()[0] if message else "Upstream Graph call failed.",
            hint="Check audit.jsonl for the full trace.",
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
        hint=hints.get(code),
        retryable=code in (ErrorCode.THROTTLED, ErrorCode.UPSTREAM_ERROR),
        http_status=http_status,
        graph_error_code=graph_error_code,
        correlation_id=correlation_id,
    )
