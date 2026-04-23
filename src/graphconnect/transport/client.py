"""Graph HTTP client with throttle, consistency, pagination, deadline."""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Literal
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

from .consistency import apply_advanced_query, needs_advanced_query
from .national_cloud import get_endpoint_base
from .pagination import paginate
from .throttle import ThrottleState, sleep_for_retry

try:  # pragma: no cover - auth is owned by another agent
    from graphconnect.auth import get_credential  # type: ignore
except Exception:  # pragma: no cover
    async def get_credential(profile: str = "default"):  # type: ignore
        # TODO(merge): replace with real impl from auth-builder
        class _StubCredential:
            async def get_token(self, *scopes: str):
                class _T:
                    token = "STUB"
                    expires_on = int(time.time()) + 3600
                return _T()
        return _StubCredential()


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


_DEFAULT_SCOPE = "https://graph.microsoft.com/.default"


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


async def _acquire_token(profile: str) -> str:
    cred = get_credential(profile)
    if asyncio.iscoroutine(cred):
        cred = await cred
    if cred is None:
        raise GraphTransportError(
            f"no credential configured for profile '{profile}' — run `graphconnect auth login`"
        )
    token_obj = cred.get_token(_DEFAULT_SCOPE)
    if asyncio.iscoroutine(token_obj):
        token_obj = await token_obj
    return getattr(token_obj, "token", "STUB")


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

    token = await _acquire_token(profile)
    headers.setdefault("Authorization", f"Bearer {token}")
    headers.setdefault("client-request-id", trace_id)
    headers.setdefault("Accept", "application/json")

    payload_bytes: bytes | None = None
    if body is not None:
        if isinstance(body, bytes):
            payload_bytes = body
        else:
            payload_bytes = json.dumps(body).encode("utf-8")
            headers.setdefault("Content-Type", "application/json")

    url = _compose_url(base, api_version, cleaned_path, query)

    state = ThrottleState()
    attempt = 0
    client = _get_http_client()

    while True:
        attempt += 1
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise DeadlineExceeded(
                f"deadline of {deadline_s:.1f}s exceeded after {attempt - 1} attempts"
            )
        try:
            response = await asyncio.wait_for(
                client.request(
                    method,
                    url,
                    headers=headers,
                    content=payload_bytes,
                ),
                timeout=remaining,
            )
        except asyncio.TimeoutError as exc:
            raise DeadlineExceeded(
                f"deadline of {deadline_s:.1f}s exceeded during request"
            ) from exc

        if response.status_code in (429, 503):
            wait_s = await sleep_for_retry(response, attempt)
            if wait_s is None:
                raise GraphTransportError(
                    f"throttled (status {response.status_code}); exhausted {attempt} attempts",
                    status_code=response.status_code,
                    body=_safe_json(response),
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

    parsed = _safe_json(response)
    request_id = response.headers.get("request-id") or response.headers.get("x-ms-request-id") or ""

    pages = 1
    if paginate and isinstance(parsed, dict) and parsed.get("@odata.nextLink"):
        async def fetch_next(next_url: str) -> dict[str, Any]:
            nonlocal pages
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise DeadlineExceeded("deadline exceeded during pagination")
            resp = await asyncio.wait_for(
                client.request("GET", next_url, headers=headers),
                timeout=remaining,
            )
            pages += 1
            return _safe_json(resp) or {}

        from .pagination import paginate as _paginate
        items = await _paginate(
            parsed,
            request_fn=fetch_next,
            top=top,
            max_items=max_items,
        )
        parsed = dict(parsed)
        parsed["value"] = items
        parsed.pop("@odata.nextLink", None)

    if response.status_code >= 400:
        raise GraphTransportError(
            f"Graph returned {response.status_code}",
            status_code=response.status_code,
            body=parsed,
        )

    return GraphResponse(
        status_code=response.status_code,
        headers=dict(response.headers),
        body=parsed,
        request_id=request_id,
        trace_id=trace_id,
        attempts=attempt,
        throttle_wait_s=state.total_wait_s,
        pages=pages,
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
