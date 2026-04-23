"""Internal Locator model split out to avoid circular imports."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel

EntityType = Literal["device", "user", "group", "policy", "assignment"]


class Locator(BaseModel):
    type: EntityType
    id: str
    display_name: str | None = None
    upn: str | None = None
    kind: str | None = None


class NotFound(Exception):
    """No match found for the supplied query."""


class AmbiguousMatch(Exception):
    """Multiple candidates matched; caller must disambiguate."""

    def __init__(self, query: str, candidates: list[Locator]):
        self.query = query
        self.candidates = candidates
        preview = ", ".join(
            f"{c.display_name or c.id} ({c.type})" for c in candidates[:5]
        )
        super().__init__(f"multiple matches for {query!r}: {preview}")
