"""Read-only indexer over `~/.graphconnect/audit/*.ndjson` trace records."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from graphconnect import audit as audit_mod


class AuditRecord(BaseModel):
    timestamp: datetime
    operation_id: str | None = None
    verb: str | None = None
    method: str | None = None
    graph_url: str | None = None
    status: str | None = None
    http_status: int | None = None
    item_count: int | None = None
    execution_time_ms: int | None = None
    user_principal: str | None = None
    profile: str | None = None
    mode: str | None = None
    ok: bool | None = None
    error: str | None = None
    error_code: str | None = None
    request_id: str | None = None
    correlation_id: str | None = None
    trace_id: str | None = None
    breakglass: bool | None = None
    reason: str | None = None
    http_requests: list[dict[str, Any]] | None = None
    raw: dict[str, Any] = Field(default_factory=dict)


def _trace_dir() -> Path:
    return audit_mod.AUDIT_TRACE_DIR


def _iter_ndjson_files() -> list[Path]:
    trace_dir = _trace_dir()
    if not trace_dir.exists():
        return []
    return sorted(trace_dir.glob("*.ndjson"))


def _parse_line(line: str) -> AuditRecord | None:
    line = line.strip()
    if not line:
        return None
    try:
        payload = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    known = {
        "timestamp",
        "operation_id",
        "verb",
        "method",
        "graph_url",
        "status",
        "http_status",
        "item_count",
        "execution_time_ms",
        "user_principal",
        "profile",
        "mode",
        "ok",
        "error",
        "error_code",
        "request_id",
        "correlation_id",
        "trace_id",
        "breakglass",
        "reason",
        "http_requests",
    }
    fields = {k: payload[k] for k in known if k in payload}
    try:
        return AuditRecord(**fields, raw=payload)
    except Exception:
        return None


def _load_all() -> list[AuditRecord]:
    records: list[AuditRecord] = []
    for path in _iter_ndjson_files():
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                rec = _parse_line(line)
                if rec is not None:
                    records.append(rec)
    return records


def _inferred_ok(rec: AuditRecord) -> bool:
    if rec.ok is not None:
        return rec.ok
    return rec.status == "success" and rec.error is None


async def find_by_trace_id(trace_id: str) -> list[AuditRecord]:
    records = [r for r in _load_all() if r.trace_id == trace_id]
    records.sort(key=lambda r: r.timestamp)
    return records


async def list_recent(
    *,
    since: datetime | None = None,
    limit: int = 50,
    verb: str | None = None,
    ok: bool | None = None,
) -> list[AuditRecord]:
    records = _load_all()
    if since is not None:
        records = [r for r in records if r.timestamp >= since]
    if verb is not None:
        records = [r for r in records if r.verb == verb]
    if ok is not None:
        records = [r for r in records if _inferred_ok(r) == ok]
    records.sort(key=lambda r: r.timestamp, reverse=True)
    seen: set[str] = set()
    unique: list[AuditRecord] = []
    for r in records:
        key = r.trace_id or f"__rec__{id(r)}"
        if key in seen:
            continue
        seen.add(key)
        unique.append(r)
        if len(unique) >= limit:
            break
    return unique


async def latest() -> str | None:
    recent = await list_recent(limit=1)
    if not recent:
        return None
    return recent[0].trace_id
