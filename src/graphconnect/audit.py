"""Append-only JSONL audit log for all Graph operations."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from graphconnect.types import AuditEntry, SafetyTier

AUDIT_DIR = Path.home() / ".graphconnect"
AUDIT_FILE = AUDIT_DIR / "audit.jsonl"
AUDIT_TRACE_DIR = AUDIT_DIR / "audit"

_audit_dir_ready = False
_audit_trace_dir_ready = False


def log_operation(
    operation_id: str,
    safety_tier: SafetyTier,
    method: str,
    graph_url: str,
    parameters: dict | None = None,
    status: str = "success",
    http_status: int | None = None,
    item_count: int | None = None,
    execution_time_ms: int = 0,
    user_principal: str | None = None,
    confirm_token: str | None = None,
    preview_shown: bool | None = None,
    confirmed_at: datetime | None = None,
    error: str | None = None,
    error_code: str | None = None,
    request_id: str | None = None,
    correlation_id: str | None = None,
    idempotency_key: str | None = None,
    response_bytes: int | None = None,
    *,
    trace_id: str | None = None,
    breakglass: bool | None = None,
    reason: str | None = None,
    http_requests: list[dict[str, Any]] | None = None,
    verb: str | None = None,
    profile: str | None = None,
    mode: str | None = None,
    ok: bool | None = None,
) -> None:
    """Append an audit entry to the JSONL log.

    v2 extras (`trace_id`, `breakglass`, `reason`, `http_requests`, `verb`,
    `profile`, `mode`, `ok`) are written alongside the legacy `AuditEntry`
    fields in the per-day NDJSON file and, when present, inline in the
    legacy `audit.jsonl`. All new kwargs are optional and keyword-only so
    existing callers continue to work unchanged.
    """
    timestamp = datetime.now(timezone.utc)
    entry = AuditEntry(
        timestamp=timestamp,
        operation_id=operation_id,
        safety_tier=safety_tier,
        user_principal=user_principal,
        method=method,
        graph_url=graph_url,
        parameters=parameters or {},
        status=status,
        http_status=http_status,
        item_count=item_count,
        execution_time_ms=execution_time_ms,
        confirm_token=confirm_token,
        preview_shown=preview_shown,
        confirmed_at=confirmed_at,
        error=error,
        error_code=error_code,
        request_id=request_id,
        correlation_id=correlation_id,
        idempotency_key=idempotency_key,
        response_bytes=response_bytes,
    )

    record: dict[str, Any] = json.loads(entry.model_dump_json())
    if trace_id is not None:
        record["trace_id"] = trace_id
    if breakglass is not None:
        record["breakglass"] = breakglass
    if reason is not None:
        record["reason"] = reason
    if http_requests is not None:
        record["http_requests"] = http_requests
    if verb is not None:
        record["verb"] = verb
    if profile is not None:
        record["profile"] = profile
    if mode is not None:
        record["mode"] = mode
    if ok is not None:
        record["ok"] = ok

    line = json.dumps(record, separators=(",", ":")) + "\n"

    global _audit_dir_ready
    if not _audit_dir_ready:
        AUDIT_DIR.mkdir(parents=True, exist_ok=True)
        _audit_dir_ready = True
    with open(AUDIT_FILE, "a", encoding="utf-8") as f:
        f.write(line)

    if trace_id is not None:
        global _audit_trace_dir_ready
        trace_dir = AUDIT_TRACE_DIR
        if not _audit_trace_dir_ready:
            trace_dir.mkdir(parents=True, exist_ok=True)
            _audit_trace_dir_ready = True
        day = timestamp.strftime("%Y-%m-%d")
        with open(trace_dir / f"{day}.ndjson", "a", encoding="utf-8") as f:
            f.write(line)
