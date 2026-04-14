"""Builds and executes Graph API requests from catalog entries."""

from __future__ import annotations

import asyncio
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
    request_id = _new_id()
    correlation_id = _new_id()
    start_time = time.monotonic()

    url = _build_url(entry, parameters)
    query_params = _build_query_params(entry, parameters, top, select, filter_expr, expand, order_by)
    headers = _build_headers(entry, correlation_id=correlation_id)

    try:
        data, total_count, has_more, bytes_read = await _execute_get(
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
    parameters = parameters or {}

    url = _build_url(entry, parameters)
    request_body = _build_body(entry, parameters, body)

    correlation_id = _new_id()
    idempotency_key = _new_id()

    token = generate_token(
        operation_id=entry.id,
        safety_tier=entry.safety_tier,
        parameters=parameters,
        body=request_body,
        correlation_id=correlation_id,
        idempotency_key=idempotency_key,
    )

    warnings: list[str] = []
    if entry.safety_tier == SafetyTier.DESTRUCTIVE:
        warnings.append("DESTRUCTIVE: This operation cannot be undone.")
        warnings.append("You MUST confirm this action explicitly before proceeding.")

    description = _build_description(entry, parameters)

    log_operation(
        operation_id=entry.id,
        safety_tier=entry.safety_tier,
        method=entry.method,
        graph_url=url,
        parameters=parameters,
        status="preview",
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
        body=request_body,
        description=description,
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
    parameters = parameters or {}
    request_body = _build_body(entry, parameters, body)

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
        result, bytes_written = await _execute_mutation(
            entry.method, url, entry.api_version.value, request_body, headers=headers
        )
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
    url = entry.endpoint
    for key, value in parameters.items():
        placeholder = "{" + key + "}"
        if placeholder in url:
            url = url.replace(placeholder, str(value))
    return url


def _apply_parameter_defaults(entry: CatalogEntry, parameters: dict) -> dict:
    """Fill in declared default values for parameters the caller didn't provide."""
    merged = dict(parameters)
    for param in entry.parameters:
        if param.name not in merged and param.default is not None:
            merged[param.name] = param.default
    return merged


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
        if expand:
            query["$expand"] = expand
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

    if expand:
        query["$expand"] = expand

    return query


def _build_body(entry: CatalogEntry, parameters: dict, body: dict | None) -> dict | None:
    """Build request body from template and parameters."""
    if body is not None:
        return body
    if entry.body_template:
        result = {}
        for key, value in entry.body_template.items():
            if isinstance(value, str) and value.startswith("{") and value.endswith("}"):
                param_name = value[1:-1]
                if param_name in parameters:
                    result[key] = parameters[param_name]
                else:
                    result[key] = value
            else:
                result[key] = value
        return result
    return None


def _build_description(entry: CatalogEntry, parameters: dict) -> str:
    """Build a human-readable description of the write operation."""
    desc = f"{entry.method} {entry.endpoint}"
    for key, value in parameters.items():
        placeholder = "{" + key + "}"
        desc = desc.replace(placeholder, str(value))
    return f"{entry.summary} -- {desc}"


def _compose_full_url(url: str, api_version: str, query_params: dict[str, str] | None = None) -> str:
    """Compose a fully-qualified Graph URL from the relative path and query parameters."""
    full_url = f"https://graph.microsoft.com/{api_version}{url}"
    if query_params:
        query_string = urlencode(query_params, safe="$,")
        if query_string:
            full_url += f"?{query_string}"
    return full_url


async def _paginate_graph_response(
    fetch: Callable[[str], Awaitable[tuple[dict[str, Any], int]]],
    first_url: str,
    top: int,
) -> tuple[list[dict], int | None, bool, int]:
    """Walk @odata.nextLink pages up to `top` items, summing raw payload bytes from each fetch."""
    response_data, bytes_seen = await fetch(first_url)
    total_count = response_data.get("@odata.count")
    next_link = response_data.get("@odata.nextLink")
    collected = list(response_data.get("value", []))
    while next_link and len(collected) < top:
        response_data, page_bytes = await fetch(next_link)
        collected.extend(response_data.get("value", []))
        next_link = response_data.get("@odata.nextLink")
        bytes_seen += page_bytes
    has_more = len(collected) > top or next_link is not None
    return collected[:top], total_count, has_more, bytes_seen


async def _execute_get(
    url: str,
    api_version: str,
    query_params: dict[str, str],
    top: int,
    singleton: bool = False,
    headers: dict[str, str] | None = None,
) -> tuple[list[dict], int | None, bool, int]:
    """Execute a GET against Microsoft Graph, returning (data, total, has_more, bytes)."""
    from graphconnect.auth import get_auth_context, get_client, invoke_graph_powershell_request

    full_url = _compose_full_url(url, api_version, query_params)
    request_headers = headers or {}

    if get_auth_context().auth_method == AuthMethod.GRAPH_POWERSHELL:
        # PS path hides raw bytes; fall back to serialized size.
        async def fetch(target_url: str) -> tuple[dict[str, Any], int]:
            response = await asyncio.to_thread(
                invoke_graph_powershell_request,
                method="GET",
                url=target_url,
                headers=request_headers,
            )
            data = response if isinstance(response, dict) else {}
            return data, len(json.dumps(data, default=str)) if data else 0
    else:
        from kiota_abstractions.method import Method
        from kiota_abstractions.request_information import RequestInformation

        adapter = get_client().request_adapter

        async def fetch(target_url: str) -> tuple[dict[str, Any], int]:
            request_info = RequestInformation()
            request_info.http_method = Method.GET
            request_info.url = target_url
            for header_name, header_value in request_headers.items():
                request_info.headers.add(header_name, header_value)
            native_response = await adapter.send_primitive_async(request_info, "bytes", {})
            if not native_response:
                return {}, 0
            return json.loads(native_response), len(native_response)

    if singleton:
        response, size = await fetch(full_url)
        return ([response] if response else []), None, False, size

    return await _paginate_graph_response(fetch, full_url, top)


async def _execute_mutation(
    method: str,
    url: str,
    api_version: str,
    body: dict | None,
    headers: dict[str, str] | None = None,
) -> tuple[dict[str, Any] | None, int]:
    """Execute a POST/PATCH/DELETE/PUT returning (body, bytes)."""
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
        if isinstance(response, dict):
            return response, len(json.dumps(response, default=str))
        return None, 0

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
        return None, 0
    try:
        return json.loads(native_response), len(native_response)
    except json.JSONDecodeError:
        return None, len(native_response)


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

    if "Not authenticated" in message or "not_authenticated" in message:
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
