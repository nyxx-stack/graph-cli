"""Transport shim for the explain package.

The four sub-commands go through one function here so tests can monkey-patch a
single symbol.
"""

from __future__ import annotations

from typing import Any, Literal

from graphconnect.selectors import value_list as _values
from graphconnect.transport import graph_request

__all__ = ["graph_get", "graph_post", "_values"]


async def graph_get(
    path: str,
    *,
    profile: str = "default",
    api_version: Literal["v1.0", "beta"] = "v1.0",
    paginate: bool = True,
) -> Any:
    """GET a Graph path and return the parsed body."""
    resp = await graph_request(
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
    resp = await graph_request(
        "POST", path, body=body, profile=profile, api_version=api_version
    )
    return resp.body


