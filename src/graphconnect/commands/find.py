"""`find` verb — search for devices / users / groups / policies / assignments."""

from __future__ import annotations

import asyncio
import uuid
from typing import Optional

import typer

from graphconnect.selectors import (
    AmbiguousMatch,
    Locator,
    NotFound,
    find as selector_find,
)
from graphconnect.types import Envelope

try:  # pragma: no cover
    from graphconnect.output import emit  # type: ignore
except Exception:  # pragma: no cover
    # TODO(merge): replace with real import from envelope-builder.
    def emit(env: Envelope, *, bare: bool | None = None, format: str = "json") -> None:
        import json
        import sys

        print(json.dumps(env.model_dump(), default=str), file=sys.stdout)


_VALID_TYPES = ("device", "user", "group", "policy", "assignment")


def _next_actions_for(locator: Locator) -> list[str]:
    match locator.type:
        case "device":
            return [
                f"show device {locator.id}",
                f"explain policy-failure --device-id {locator.id}",
            ]
        case "user":
            return [f"show user {locator.id}"]
        case "group":
            return [
                f"show group {locator.id}",
                f"hunt assignment --group-id {locator.id}",
            ]
        case "policy":
            return [f"show policy {locator.id}"]
        case "assignment":
            return [f"show group {locator.id}"]
    return []


def _to_row(locator: Locator) -> dict:
    row = locator.model_dump()
    row["next_actions"] = _next_actions_for(locator)
    return row


def register(app: typer.Typer) -> None:
    @app.command("find", help="Find entities (devices, users, groups, policies) by name or id.")
    def _find_cmd(
        query: str = typer.Argument(..., help="Name, UPN, or id to look up."),
        type: Optional[str] = typer.Option(
            None,
            "--type",
            help=f"Restrict search to one of: {', '.join(_VALID_TYPES)}.",
        ),
        profile: str = typer.Option("default", "--profile", help="Auth profile name."),
        limit: int = typer.Option(10, "--limit", min=1, max=100),
        bare: bool = typer.Option(False, "--bare", help="Emit legacy bare output."),
    ) -> None:
        if type is not None and type not in _VALID_TYPES:
            raise typer.BadParameter(
                f"--type must be one of {', '.join(_VALID_TYPES)}",
                param_hint="--type",
            )

        trace_id = uuid.uuid4().hex

        from graphconnect.transport import GraphTransportError
        from graphconnect.types import ErrorCode, ErrorPayload

        try:
            locators = asyncio.run(
                selector_find(query, type=type, profile=profile, limit=limit)
            )
        except GraphTransportError as exc:
            env = Envelope.err(
                summary=f"transport error: {exc}",
                error=ErrorPayload(
                    code=ErrorCode.UPSTREAM_ERROR,
                    message=str(exc),
                    hint="Run `graphconnect auth login --profile <name>` to configure credentials.",
                ),
                trace_id=trace_id,
            )
            emit(env, bare=bare)
            return
        except NotFound as exc:
            env = Envelope(
                ok=True,
                trace_id=trace_id,
                mode="read",
                summary=str(exc),
                data=[],
                next_actions=[],
            )
            emit(env, bare=bare)
            return
        except AmbiguousMatch as exc:
            data = [_to_row(c) for c in exc.candidates]
            env = Envelope(
                ok=True,
                trace_id=trace_id,
                mode="read",
                summary=f"multiple matches for {query!r}; use --type or a more specific query",
                data=data,
                warnings=[str(exc)],
                next_actions=[row["next_actions"][0] for row in data if row["next_actions"]][:5],
            )
            emit(env, bare=bare)
            return

        data = [_to_row(loc) for loc in locators]
        summary = (
            f"found {len(data)} match(es) for {query!r}"
            if data
            else f"no matches for {query!r}"
        )
        next_actions: list[str] = []
        for row in data:
            next_actions.extend(row["next_actions"])
        env = Envelope.ok_read(
            summary,
            data,
            trace_id=trace_id,
            next_actions=next_actions[:10],
        )
        emit(env, bare=bare)


__all__ = ["register"]
