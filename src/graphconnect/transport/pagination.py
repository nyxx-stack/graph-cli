"""Follow @odata.nextLink pages up to a configured cap."""

from __future__ import annotations

from typing import Any, Awaitable, Callable


async def paginate(
    first_response: dict[str, Any],
    *,
    request_fn: Callable[[str], Awaitable[dict[str, Any]]],
    top: int | None = None,
    max_items: int | None = None,
) -> list[dict[str, Any]]:
    """Walk @odata.nextLink pages, returning the concatenated `value` list.

    - `max_items` hard-caps the collected items.
    - `top` is treated as a hint equivalent to max_items if max_items is unset.
    """
    cap = max_items if max_items is not None else top
    collected: list[dict[str, Any]] = list(first_response.get("value", []) or [])
    next_link = first_response.get("@odata.nextLink")
    while next_link:
        if cap is not None and len(collected) >= cap:
            break
        page = await request_fn(next_link)
        collected.extend(page.get("value", []) or [])
        next_link = page.get("@odata.nextLink")
    if cap is not None:
        return collected[:cap]
    return collected
