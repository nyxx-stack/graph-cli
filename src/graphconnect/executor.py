"""Builds and executes Graph API requests from catalog entries."""

from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable
from urllib.parse import urlencode

from graphconnect.audit import log_operation
from graphconnect.safety import check_rate_limit, generate_token, validate_token
from graphconnect.types import AuthMethod, CatalogEntry, OperationResult, SafetyTier, WritePreview


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
        raise RuntimeError(f"Rate limited. Retry after {retry_after:.0f} seconds.")

    parameters = _apply_parameter_defaults(entry, parameters or {})
    start_time = time.monotonic()

    url = _build_url(entry, parameters)
    query_params = _build_query_params(entry, parameters, top, select, filter_expr, expand, order_by)
    headers = _build_headers(entry)

    try:
        data, total_count, has_more = await _execute_get(
            url,
            entry.api_version.value,
            query_params,
            top,
            singleton=entry.singleton,
            headers=headers,
        )
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
    parameters = parameters or {}
    request_body = _build_body(entry, parameters, body)

    validate_token(
        confirm_token=confirm_token,
        operation_id=entry.id,
        parameters=parameters,
        body=request_body,
    )

    retry_after = check_rate_limit(entry.safety_tier)
    if retry_after is not None:
        raise RuntimeError(f"Rate limited. Retry after {retry_after:.0f} seconds.")

    url = _build_url(entry, parameters)
    start_time = time.monotonic()

    try:
        result = await _execute_mutation(entry.method, url, entry.api_version.value, request_body)
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


def _apply_parameter_defaults(entry: CatalogEntry, parameters: dict) -> dict:
    """Fill in declared default values for parameters the caller didn't provide."""
    merged = dict(parameters)
    for param in entry.parameters:
        if param.name not in merged and param.default is not None:
            merged[param.name] = param.default
    return merged


def _build_headers(entry: CatalogEntry) -> dict[str, str]:
    """Build request headers required by the catalog entry."""
    headers: dict[str, str] = {}
    if entry.advanced_query:
        headers["ConsistencyLevel"] = "eventual"
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
        # Singletons don't support $top/$orderby/$filter; $select is still fine.
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
    fetch: Callable[[str], Awaitable[dict[str, Any]]],
    first_url: str,
    top: int,
) -> tuple[list[dict], int | None, bool]:
    """Walk @odata.nextLink pages up to `top` items using the provided fetch callable."""
    response_data = await fetch(first_url)
    total_count = response_data.get("@odata.count")
    next_link = response_data.get("@odata.nextLink")
    collected = list(response_data.get("value", []))
    while next_link and len(collected) < top:
        response_data = await fetch(next_link)
        collected.extend(response_data.get("value", []))
        next_link = response_data.get("@odata.nextLink")
    has_more = len(collected) > top or next_link is not None
    return collected[:top], total_count, has_more


async def _execute_get(
    url: str,
    api_version: str,
    query_params: dict[str, str],
    top: int,
    singleton: bool = False,
    headers: dict[str, str] | None = None,
) -> tuple[list[dict], int | None, bool]:
    """Execute a GET against Microsoft Graph, dispatching to the active auth backend."""
    from graphconnect.auth import get_auth_context, get_client, invoke_graph_powershell_request

    full_url = _compose_full_url(url, api_version, query_params)
    request_headers = headers or {}

    if get_auth_context().auth_method == AuthMethod.GRAPH_POWERSHELL:
        async def fetch(target_url: str) -> dict[str, Any]:
            response = await asyncio.to_thread(
                invoke_graph_powershell_request,
                method="GET",
                url=target_url,
                headers=request_headers,
            )
            return response if isinstance(response, dict) else {}
    else:
        from kiota_abstractions.method import Method
        from kiota_abstractions.request_information import RequestInformation

        adapter = get_client().request_adapter

        async def fetch(target_url: str) -> dict[str, Any]:
            request_info = RequestInformation()
            request_info.http_method = Method.GET
            request_info.url = target_url
            for header_name, header_value in request_headers.items():
                request_info.headers.add(header_name, header_value)
            native_response = await adapter.send_primitive_async(request_info, "bytes", {})
            return json.loads(native_response) if native_response else {}

    if singleton:
        response = await fetch(full_url)
        return ([response] if response else []), None, False

    return await _paginate_graph_response(fetch, full_url, top)


async def _execute_mutation(
    method: str,
    url: str,
    api_version: str,
    body: dict | None,
) -> dict[str, Any] | None:
    """Execute a POST/PATCH/DELETE/PUT against Microsoft Graph, dispatching to the active auth backend."""
    from graphconnect.auth import get_auth_context, get_client, invoke_graph_powershell_request

    full_url = _compose_full_url(url, api_version)

    if get_auth_context().auth_method == AuthMethod.GRAPH_POWERSHELL:
        response = await asyncio.to_thread(
            invoke_graph_powershell_request,
            method=method,
            url=full_url,
            body=body,
        )
        return response if isinstance(response, dict) else None

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
    if body:
        request_info.headers.add("Content-Type", "application/json")
        request_info.set_stream_content(json.dumps(body).encode("utf-8"))

    adapter = get_client().request_adapter
    native_response = await adapter.send_primitive_async(request_info, "bytes", {})
    if native_response:
        try:
            return json.loads(native_response)
        except json.JSONDecodeError:
            return None
    return None

