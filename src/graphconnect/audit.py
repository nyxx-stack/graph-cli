"""Append-only JSONL audit log for all Graph operations."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from graphconnect.types import AuditEntry, SafetyTier

AUDIT_DIR = Path.home() / ".graphconnect"
AUDIT_FILE = AUDIT_DIR / "audit.jsonl"

_audit_dir_ready = False


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
) -> None:
    """Append an audit entry to the JSONL log."""
    entry = AuditEntry(
        timestamp=datetime.now(timezone.utc),
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

    global _audit_dir_ready
    if not _audit_dir_ready:
        AUDIT_DIR.mkdir(parents=True, exist_ok=True)
        _audit_dir_ready = True
    with open(AUDIT_FILE, "a", encoding="utf-8") as f:
        f.write(entry.model_dump_json() + "\n")
