"""Builds and executes Graph API requests from catalog entries."""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Any

from graph_cli.audit import log_operation
from graph_cli.safety import check_rate_limit, generate_token, validate_token
from graph_cli.types import CatalogEntry, OperationResult, SafetyTier, WritePreview


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
    from graph_cli.auth import ensure_authenticated

    # Rate limit check
    retry_after = check_rate_limit(SafetyTier.READ)
    if retry_after is not None:
        raise RuntimeError(f"Rate limited. Retry after {retry_after:.0f} seconds.")

    parameters = parameters or {}
    start_time = time.monotonic()

    # Build the URL and query parameters
    url = _build_url(entry, parameters)
    query_params = _build_query_params(entry, parameters, top, select, filter_expr, expand, order_by)

    client = ensure_authenticated()

    # Execute via httpx through the Graph SDK's request adapter
    try:
        data, total_count, has_more = await _execute_get(client, url, entry.api_version.value, query_params, top)
    except Exception as e:
        elapsed = int((time.monotonic() - start_time) * 1000)
        log_operation(
            operation_id=entry.id,
            safety_tier=entry.safety_tier,
            method="GET",
            graph_url=url,
            parameters=parameters,
            status="error",
            execution_time_ms=elapsed,
            error=str(e),
        )
        raise

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
    )

    return OperationResult(
        operation_id=entry.id,
        item_count=len(data),
        has_more=has_more,
        data=data,
        execution_time_ms=elapsed,
        graph_url=url,
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

    token = generate_token(
        operation_id=entry.id,
        safety_tier=entry.safety_tier,
        parameters=parameters,
        body=request_body,
    )

    warnings = []
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
    )


async def execute_write(
    entry: CatalogEntry,
    parameters: dict | None = None,
    body: dict | None = None,
    confirm_token: str = "",
) -> dict[str, Any] | None:
    """Execute a write operation after validating the confirmation token."""
    from graph_cli.auth import ensure_authenticated

    parameters = parameters or {}
    request_body = _build_body(entry, parameters, body)

    # Validate token (raises on failure)
    token = validate_token(
        confirm_token=confirm_token,
        operation_id=entry.id,
        parameters=parameters,
        body=request_body,
    )

    # Rate limit check
    retry_after = check_rate_limit(entry.safety_tier)
    if retry_after is not None:
        raise RuntimeError(f"Rate limited. Retry after {retry_after:.0f} seconds.")

    url = _build_url(entry, parameters)
    client = ensure_authenticated()
    start_time = time.monotonic()

    try:
        result = await _execute_mutation(client, entry.method, url, entry.api_version.value, request_body)
    except Exception as e:
        elapsed = int((time.monotonic() - start_time) * 1000)
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
            error=str(e),
        )
        raise

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
    )

    return result


async def execute_batch(
    entries: list[CatalogEntry],
    top: int = 50,
) -> list[OperationResult]:
    """Execute multiple read operations. Uses sequential calls (Graph $batch can be added later)."""
    results = []
    for entry in entries:
        result = await execute_read(entry=entry, top=top)
        results.append(result)
    return results


# -- Internal helpers -------------------------------------------------------


def _build_url(entry: CatalogEntry, parameters: dict) -> str:
    """Build the Graph API URL from the catalog entry endpoint and parameters."""
    url = entry.endpoint
    for key, value in parameters.items():
        placeholder = "{" + key + "}"
        if placeholder in url:
            url = url.replace(placeholder, str(value))
    return url


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

    # Top
    query["$top"] = str(min(top, 999))

    # Select
    select_fields = select or entry.default_select
    if select_fields:
        query["$select"] = ",".join(select_fields)

    # Filter: combine default + parameter-mapped + user-provided
    filters = []
    if entry.default_filter:
        filters.append(entry.default_filter)

    # Apply computed_filter with parameter substitution
    if entry.computed_filter:
        computed = entry.computed_filter
        for param in entry.parameters:
            if param.name in parameters:
                if "{cutoff_datetime}" in computed and param.name == "days_inactive":
                    days = int(parameters[param.name])
                    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
                    computed = computed.replace("{cutoff_datetime}", cutoff.strftime("%Y-%m-%dT%H:%M:%SZ"))
        filters.append(computed)

    # Apply maps_to_filter from parameters
    for param in entry.parameters:
        if param.maps_to_filter and param.name in parameters:
            mapped = param.maps_to_filter.replace("{value}", str(parameters[param.name]))
            filters.append(mapped)

    if filter_expr:
        filters.append(filter_expr)

    if filters:
        query["$filter"] = " and ".join(filters)

    # OrderBy
    order = order_by or entry.default_orderby
    if order:
        query["$orderby"] = order

    # Expand
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


async def _execute_get(
    client: Any,
    url: str,
    api_version: str,
    query_params: dict[str, str],
    top: int,
) -> tuple[list[dict], int | None, bool]:
    """Execute a GET request against the Graph API with pagination support."""
    from kiota_abstractions.request_information import RequestInformation
    from kiota_http.middleware.options import ResponseHandlerOption
    from kiota_abstractions.method import Method

    # Build query string
    qs_parts = [f"{k}={v}" for k, v in query_params.items()]
    query_string = "&".join(qs_parts)
    full_url = f"https://graph.microsoft.com/{api_version}{url}"
    if query_string:
        full_url += f"?{query_string}"

    adapter = client.request_adapter

    request_info = RequestInformation()
    request_info.http_method = Method.GET
    request_info.url = full_url

    # Send raw request and parse JSON
    import httpx

    native_response = await adapter.send_primitive_async(request_info, "bytes", {})
    import json
    response_data = json.loads(native_response) if native_response else {}

    items = response_data.get("value", [])
    next_link = response_data.get("@odata.nextLink")
    total_count = response_data.get("@odata.count")

    # Follow pagination up to the requested top
    collected = list(items)
    while next_link and len(collected) < top:
        request_info = RequestInformation()
        request_info.http_method = Method.GET
        request_info.url = next_link
        native_response = await adapter.send_primitive_async(request_info, "bytes", {})
        response_data = json.loads(native_response) if native_response else {}
        page_items = response_data.get("value", [])
        collected.extend(page_items)
        next_link = response_data.get("@odata.nextLink")

    has_more = len(collected) > top or next_link is not None
    return collected[:top], total_count, has_more


async def _execute_mutation(
    client: Any,
    method: str,
    url: str,
    api_version: str,
    body: dict | None,
) -> dict[str, Any] | None:
    """Execute a POST/PATCH/DELETE request against the Graph API."""
    from kiota_abstractions.request_information import RequestInformation
    from kiota_abstractions.method import Method
    from kiota_abstractions.headers_collection import HeadersCollection
    import json

    full_url = f"https://graph.microsoft.com/{api_version}{url}"

    method_map = {
        "POST": Method.POST,
        "PATCH": Method.PATCH,
        "DELETE": Method.DELETE,
        "PUT": Method.PUT,
    }

    request_info = RequestInformation()
    request_info.http_method = method_map.get(method, Method.POST)
    request_info.url = full_url

    if body:
        request_info.headers.add("Content-Type", "application/json")
        request_info.set_stream_content(json.dumps(body).encode("utf-8"))

    adapter = client.request_adapter
    native_response = await adapter.send_primitive_async(request_info, "bytes", {})

    if native_response:
        try:
            return json.loads(native_response)
        except json.JSONDecodeError:
            return None
    return None
