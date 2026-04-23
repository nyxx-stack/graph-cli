"""Transport shim for the explain package.

The four sub-commands go through one function here so tests can monkey-patch a
single symbol. At merge time this will resolve to
`graphconnect.transport.graph_request` unconditionally.

TODO(merge): drop the ImportError fallback once transport is guaranteed to be
present on PYTHONPATH.
"""

from __future__ import annotations

from typing import Any, Literal

try:
    from graphconnect.transport import graph_request as _graph_request  # type: ignore
except Exception:  # pragma: no cover
    _graph_request = None  # type: ignore[assignment]


async def graph_get(
    path: str,
    *,
    profile: str = "default",
    api_version: Literal["v1.0", "beta"] = "v1.0",
    paginate: bool = True,
) -> Any:
    """GET a Graph path and return the parsed body."""
    if _graph_request is None:
        raise RuntimeError(
            "graphconnect.transport is unavailable; tests should monkey-patch "
            "graphconnect.explain._transport.graph_get"
        )
    resp = await _graph_request(
        "GET", path, profile=profile, api_version=api_version, paginate=paginate
    )
    return resp.body


async def graph_post(
    path: str,
    body: dict[str, Any],
    *,
    profile: str = "default",
    api_version: Literal["v1.0", "beta"] = "v1.0",
) -> Any:
    if _graph_request is None:
        raise RuntimeError(
            "graphconnect.transport is unavailable; tests should monkey-patch "
            "graphconnect.explain._transport.graph_post"
        )
    resp = await _graph_request(
        "POST", path, body=body, profile=profile, api_version=api_version
    )
    return resp.body


def _values(body: Any) -> list[dict[str, Any]]:
    if isinstance(body, dict):
        val = body.get("value")
        if isinstance(val, list):
            return [r for r in val if isinstance(r, dict)]
    if isinstance(body, list):
        return [r for r in body if isinstance(r, dict)]
    return []
