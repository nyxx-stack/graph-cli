"""Graph HTTP client with throttle, consistency, pagination, deadline."""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Literal
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

from .consistency import apply_advanced_query, needs_advanced_query
from .national_cloud import get_endpoint_base
from .pagination import paginate as _paginate
from .throttle import ThrottleState, sleep_for_retry


class DeadlineExceeded(TimeoutError):
    pass


class GraphTransportError(RuntimeError):
    def __init__(self, message: str, *, status_code: int | None = None, body: Any = None):
        super().__init__(message)
        self.status_code = status_code
        self.body = body


@dataclass
class GraphResponse:
    status_code: int
    headers: dict[str, str]
    body: Any
    request_id: str
    trace_id: str
    attempts: int = 1
    throttle_wait_s: float = 0.0
    pages: int = 1


def _split_path(path: str) -> tuple[str, dict[str, str]]:
    parts = urlsplit(path)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    cleaned = urlunsplit((parts.scheme, parts.netloc, parts.path, "", parts.fragment))
    return cleaned, query


def _compose_url(
    base: str, api_version: str, path: str, query: dict[str, str]
) -> str:
    if path.startswith("http://") or path.startswith("https://"):
        full = path
    else:
        segment = path if path.startswith("/") else f"/{path}"
        if segment.startswith(f"/{api_version}/") or segment.startswith(f"/{api_version}"):
            full = f"{base}{segment}"
        else:
            full = f"{base}/{api_version}{segment}"
    if not query:
        return full
    parts = urlsplit(full)
    merged = dict(parse_qsl(parts.query, keep_blank_values=True))
    merged.update(query)
    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urlencode(merged, doseq=True), parts.fragment)
    )


def _resolve_auth_context(profile: str) -> Any:
    from graphconnect.auth import get_auth_context

    return get_auth_context(profile=profile)


async def _acquire_token(context: Any, profile: str) -> str:
    cred = getattr(context, "credential", None)
    if cred is None:
        raise GraphTransportError(
            f"no credential configured for profile '{profile}' — run `graphconnect auth login`"
        )
    scopes = list(getattr(context, "scopes", []) or ["https://graph.microsoft.com/.default"])
    token_obj = cred.get_token(*scopes)
    if asyncio.iscoroutine(token_obj):
        token_obj = await token_obj
    return getattr(token_obj, "token", "STUB")


def _coerce_header_map(headers: Any) -> dict[str, str]:
    if not isinstance(headers, dict):
        return {}
    out: dict[str, str] = {}
    for key, value in headers.items():
        if value is None:
            continue
        if isinstance(value, list):
            out[str(key)] = ",".join(str(item) for item in value)
        else:
            out[str(key)] = str(value)
    return out


def _unwrap_powershell_response(
    response: Any,
    *,
    default_status: int,
) -> tuple[Any, int, dict[str, str]]:
    if isinstance(response, dict) and "body" in response:
        return (
            response.get("body"),
            int(response.get("status_code") or default_status),
            _coerce_header_map(response.get("headers") or {}),
        )
    return response, default_status, {}


def _retry_response(status_code: int, headers: dict[str, str], body: Any) -> httpx.Response:
    content = b""
    if body is not None:
        if isinstance(body, (dict, list)):
            content = json.dumps(body, default=str).encode("utf-8")
        else:
            content = str(body).encode("utf-8")
    return httpx.Response(status_code=status_code, headers=headers, content=content)


_http_client_ref: dict[str, httpx.AsyncClient] = {}


def set_http_client(client: httpx.AsyncClient | None) -> None:
    """Install a custom AsyncClient (for tests with MockTransport)."""
    if client is None:
        _http_client_ref.pop("client", None)
    else:
        _http_client_ref["client"] = client


def _get_http_client() -> httpx.AsyncClient:
    client = _http_client_ref.get("client")
    if client is None:
        client = httpx.AsyncClient(timeout=httpx.Timeout(30.0))
        _http_client_ref["client"] = client
    return client


@dataclass
class _Exchange:
    body: Any
    status_code: int
    headers: dict[str, str]


_Sender = Callable[[str, str, "dict | bytes | None", dict[str, str], float], Awaitable[_Exchange]]


async def _send_httpx(
    method: str,
    url: str,
    body: dict | bytes | None,
    headers: dict[str, str],
    timeout: float,
) -> _Exchange:
    if isinstance(body, bytes):
        content: bytes | None = body
    elif isinstance(body, dict):
        content = json.dumps(body).encode("utf-8")
    else:
        content = None
    response = await asyncio.wait_for(
        _get_http_client().request(method, url, headers=headers, content=content),
        timeout=timeout,
    )
    return _Exchange(
        body=_safe_json(response),
        status_code=response.status_code,
        headers=dict(response.headers),
    )


async def _send_powershell(
    method: str,
    url: str,
    body: dict | bytes | None,
    headers: dict[str, str],
    timeout: float,
) -> _Exchange:
    from graphconnect.auth import invoke_graph_powershell_request

    response = await asyncio.wait_for(
        asyncio.to_thread(
            invoke_graph_powershell_request,
            method=method,
            url=url,
            body=body if isinstance(body, dict) else None,
            headers=headers,
        ),
        timeout=timeout,
    )
    body_out, status_code, headers_out = _unwrap_powershell_response(response, default_status=200)
    return _Exchange(body=body_out, status_code=status_code, headers=headers_out)


async def _run_request_loop(
    *,
    send: _Sender,
    method: str,
    url: str,
    body: dict | bytes | None,
    headers: dict[str, str],
    deadline: float,
    deadline_s: float,
    paginate: bool,
    top: int | None,
    max_items: int | None,
    trace_id: str,
) -> GraphResponse:
    state = ThrottleState()
    attempt = 0
    while True:
        attempt += 1
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise DeadlineExceeded(
                f"deadline of {deadline_s:.1f}s exceeded after {attempt - 1} attempts"
            )
        try:
            exchange = await send(method, url, body, headers, remaining)
        except asyncio.TimeoutError as exc:
            raise DeadlineExceeded(
                f"deadline of {deadline_s:.1f}s exceeded during request"
            ) from exc

        if exchange.status_code in (429, 503):
            wait_s = await sleep_for_retry(
                _retry_response(exchange.status_code, exchange.headers, exchange.body),
                attempt,
            )
            if wait_s is None:
                raise GraphTransportError(
                    f"throttled (status {exchange.status_code}); exhausted {attempt} attempts",
                    status_code=exchange.status_code,
                    body=exchange.body,
                )
            remaining = deadline - time.monotonic()
            if wait_s >= remaining:
                raise DeadlineExceeded(
                    f"retry wait {wait_s:.2f}s exceeds remaining deadline {remaining:.2f}s"
                )
            state.record(wait_s)
            await asyncio.sleep(wait_s)
            continue
        break

    parsed = exchange.body
    pages = 1
    if paginate and isinstance(parsed, dict) and parsed.get("@odata.nextLink"):

        async def fetch_next(next_url: str) -> dict[str, Any]:
            nonlocal pages
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise DeadlineExceeded("deadline exceeded during pagination")
            try:
                ex = await send("GET", next_url, None, headers, remaining)
            except asyncio.TimeoutError as exc:
                raise DeadlineExceeded("deadline exceeded during pagination") from exc
            if ex.status_code >= 400:
                raise GraphTransportError(
                    f"Graph returned {ex.status_code}",
                    status_code=ex.status_code,
                    body=ex.body,
                )
            pages += 1
            return ex.body if isinstance(ex.body, dict) else {}

        items = await _paginate(parsed, request_fn=fetch_next, top=top, max_items=max_items)
        parsed = dict(parsed)
        parsed["value"] = items
        parsed.pop("@odata.nextLink", None)

    if exchange.status_code >= 400:
        raise GraphTransportError(
            f"Graph returned {exchange.status_code}",
            status_code=exchange.status_code,
            body=parsed,
        )

    request_id = exchange.headers.get("request-id") or exchange.headers.get("x-ms-request-id") or ""
    return GraphResponse(
        status_code=exchange.status_code,
        headers=exchange.headers,
        body=parsed,
        request_id=request_id,
        trace_id=trace_id,
        attempts=attempt,
        throttle_wait_s=state.total_wait_s,
        pages=pages,
    )


async def _graph_request_via_powershell(
    method: str,
    url: str,
    *,
    body: dict | bytes | None,
    headers: dict[str, str],
    deadline_s: float,
    deadline: float,
    paginate: bool,
    top: int | None,
    max_items: int | None,
    trace_id: str,
) -> GraphResponse:
    return await _run_request_loop(
        send=_send_powershell,
        method=method,
        url=url,
        body=body,
        headers=headers,
        deadline=deadline,
        deadline_s=deadline_s,
        paginate=paginate,
        top=top,
        max_items=max_items,
        trace_id=trace_id,
    )


async def graph_request(
    method: str,
    path: str,
    *,
    profile: str = "default",
    body: dict | bytes | None = None,
    api_version: Literal["v1.0", "beta"] = "v1.0",
    extra_headers: dict[str, str] | None = None,
    deadline_s: float = 30.0,
    paginate: bool = False,
    top: int | None = None,
    national_cloud: str = "commercial",
    max_items: int | None = None,
) -> GraphResponse:
    """Issue a Graph request with retries, consistency headers, optional pagination."""
    trace_id = uuid.uuid4().hex
    deadline = time.monotonic() + max(0.0, deadline_s)
    base = get_endpoint_base(national_cloud)
    cleaned_path, path_query = _split_path(path)
    query: dict[str, str] = dict(path_query)
    headers: dict[str, str] = dict(extra_headers or {})

    if top is not None and "$top" not in query:
        query["$top"] = str(top)
    if needs_advanced_query(cleaned_path, query):
        headers, query = apply_advanced_query(headers, query)

    headers.setdefault("client-request-id", trace_id)
    headers.setdefault("Accept", "application/json")
    if isinstance(body, dict):
        headers.setdefault("Content-Type", "application/json")

    url = _compose_url(base, api_version, cleaned_path, query)
    context = _resolve_auth_context(profile)

    if getattr(context, "credential", None) is None:
        return await _graph_request_via_powershell(
            method,
            url,
            body=body,
            headers=headers,
            deadline_s=deadline_s,
            deadline=deadline,
            paginate=paginate,
            top=top,
            max_items=max_items,
            trace_id=trace_id,
        )

    token = await _acquire_token(context, profile)
    headers.setdefault("Authorization", f"Bearer {token}")

    return await _run_request_loop(
        send=_send_httpx,
        method=method,
        url=url,
        body=body,
        headers=headers,
        deadline=deadline,
        deadline_s=deadline_s,
        paginate=paginate,
        top=top,
        max_items=max_items,
        trace_id=trace_id,
    )


def _safe_json(response: httpx.Response) -> Any:
    if not response.content:
        return None
    ctype = response.headers.get("content-type", "")
    if "json" not in ctype.lower():
        try:
            return response.json()
        except Exception:
            return response.text
    try:
        return response.json()
    except Exception:
        return response.text
