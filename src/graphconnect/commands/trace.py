"""`trace` verb — read historical audit records and render step history."""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime
from typing import Any

import typer

from graphconnect.audit_reader import (
    AuditRecord,
    find_by_trace_id,
    latest as latest_trace,
    list_recent,
)
from graphconnect.types import Envelope, ErrorCode, ErrorPayload

app = typer.Typer(name="trace", help="Replay audit step history.", no_args_is_help=True)


def _new_trace_id() -> str:
    return uuid.uuid4().hex


def _parse_since(value: str | None) -> datetime | None:
    if value is None:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise typer.BadParameter(f"invalid ISO-8601 timestamp: {value!r}") from exc


def _step_from_record(rec: AuditRecord, seq: int, *, raw: bool) -> dict[str, Any]:
    step: dict[str, Any] = {
        "seq": seq,
        "timestamp": rec.timestamp.isoformat(),
        "verb": rec.verb or rec.operation_id,
        "method": rec.method,
        "path": rec.graph_url,
        "status": rec.http_status if rec.http_status is not None else rec.status,
        "duration_ms": rec.execution_time_ms,
    }
    if rec.error:
        step["error"] = rec.error
    if raw and rec.http_requests is not None:
        step["http_requests"] = rec.http_requests
    return step


def _summary_from_record(rec: AuditRecord) -> dict[str, Any]:
    return {
        "trace_id": rec.trace_id,
        "timestamp": rec.timestamp.isoformat(),
        "verb": rec.verb or rec.operation_id,
        "method": rec.method,
        "path": rec.graph_url,
        "status": rec.http_status if rec.http_status is not None else rec.status,
        "ok": rec.ok if rec.ok is not None else (rec.status == "success" and not rec.error),
        "error": rec.error,
    }


def _emit(env: Envelope) -> None:
    typer.echo(env.model_dump_json(exclude_none=True))


@app.command("show")
def trace_show(
    trace_id: str = typer.Argument(..., help="Trace id to replay."),
    raw: bool = typer.Option(False, "--raw", help="Include raw HTTP requests/responses."),
) -> None:
    _emit(asyncio.run(_trace_show_async(trace_id, raw=raw)))


async def _trace_show_async(trace_id: str, *, raw: bool) -> Envelope:
    out_trace = _new_trace_id()
    records = await find_by_trace_id(trace_id)
    if not records:
        return Envelope.err(
            summary=f"no audit records for trace_id '{trace_id}'",
            error=ErrorPayload(
                code=ErrorCode.NOT_FOUND, message=f"trace_id '{trace_id}' not found"
            ),
            trace_id=out_trace,
        )
    data = [_step_from_record(r, i + 1, raw=raw) for i, r in enumerate(records)]
    next_actions: list[str] = []
    if not raw:
        next_actions.append(f"trace show {trace_id} --raw")
    return Envelope.ok_read(
        summary=f"trace {trace_id}: {len(data)} step{'s' if len(data) != 1 else ''}",
        data=data,
        trace_id=out_trace,
        next_actions=next_actions,
    )


@app.command("list")
def trace_list(
    since: str = typer.Option(None, "--since", help="Only include records at/after this ISO-8601 timestamp."),
    limit: int = typer.Option(50, "--limit", min=1, help="Max number of runs to return."),
    verb: str = typer.Option(None, "--verb", help="Filter by verb name."),
    ok_only: bool = typer.Option(False, "--ok", help="Only successful runs."),
    failed_only: bool = typer.Option(False, "--failed", help="Only failed runs."),
) -> None:
    _emit(
        asyncio.run(
            _trace_list_async(
                since=since, limit=limit, verb=verb, ok_only=ok_only, failed_only=failed_only
            )
        )
    )


async def _trace_list_async(
    *,
    since: str | None,
    limit: int,
    verb: str | None,
    ok_only: bool,
    failed_only: bool,
) -> Envelope:
    out_trace = _new_trace_id()
    if ok_only and failed_only:
        return Envelope.err(
            summary="cannot combine --ok and --failed",
            error=ErrorPayload(
                code=ErrorCode.BAD_REQUEST,
                message="--ok and --failed are mutually exclusive",
            ),
            trace_id=out_trace,
        )
    ok_filter: bool | None = None
    if ok_only:
        ok_filter = True
    elif failed_only:
        ok_filter = False

    since_dt = _parse_since(since)
    records = await list_recent(since=since_dt, limit=limit, verb=verb, ok=ok_filter)
    data = [_summary_from_record(r) for r in records]
    next_actions = [f"trace show {r.trace_id}" for r in records if r.trace_id][:5]
    return Envelope.ok_read(
        summary=f"{len(data)} run{'s' if len(data) != 1 else ''}",
        data=data,
        trace_id=out_trace,
        next_actions=next_actions,
    )


@app.command("latest")
def trace_latest(
    raw: bool = typer.Option(False, "--raw", help="Include raw HTTP requests/responses."),
) -> None:
    _emit(asyncio.run(_trace_latest_async(raw=raw)))


async def _trace_latest_async(*, raw: bool) -> Envelope:
    out_trace = _new_trace_id()
    tid = await latest_trace()
    if tid is None:
        return Envelope.err(
            summary="no audit records found",
            error=ErrorPayload(code=ErrorCode.NOT_FOUND, message="no trace records available"),
            trace_id=out_trace,
        )
    return await _trace_show_async(tid, raw=raw)


def register(parent: typer.Typer) -> None:
    """Attach the `trace` command group to a parent Typer app."""
    parent.add_typer(app, name="trace")


__all__ = ["app", "register"]
