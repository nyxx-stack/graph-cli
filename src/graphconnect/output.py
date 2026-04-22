"""Output formatters for table, JSON, and CSV modes, plus TTY-gated defaults."""

from __future__ import annotations

import csv
import io
import json
import sys
from typing import Any

from rich.console import Console
from rich.table import Table

from graphconnect.types import ErrorCode, ErrorPayload

# Rich Console honors NO_COLOR automatically; force_terminal=False keeps it off when piped.
console = Console()
stderr_console = Console(stderr=True)

_QUIET = False


def set_quiet(value: bool) -> None:
    """Enable/disable chatter suppression for the process."""
    global _QUIET
    _QUIET = value


def is_quiet() -> bool:
    return _QUIET


def is_tty() -> bool:
    """True when stdout is attached to a terminal."""
    try:
        return sys.stdout.isatty()
    except (AttributeError, ValueError):
        return False


def resolve_format(explicit: str | None, *, default_tty: str = "table") -> str:
    """Return 'json' when piped unless caller passed --format explicitly."""
    if explicit:
        return explicit
    return default_tty if is_tty() else "json"


# -- Renderers --------------------------------------------------------------


def print_table(data: list[dict[str, Any]], title: str | None = None) -> None:
    """Render a Rich table to stdout. Empty data prints a dim placeholder."""
    if not data:
        console.print("[dim]No results.[/dim]")
        return

    table = Table(title=title, show_lines=False, pad_edge=False)
    columns = list(data[0].keys())
    for col in columns:
        table.add_column(col, overflow="fold")
    for row in data:
        table.add_row(*[_format_value(row.get(col)) for col in columns])
    console.print(table)


def print_json(data: Any) -> None:
    """Print data as formatted JSON to stdout."""
    print(json.dumps(data, indent=2, default=str))


def print_ndjson(data: list[dict[str, Any]]) -> None:
    """Print data as newline-delimited JSON (one compact row per line)."""
    for row in data:
        print(json.dumps(row, default=str, separators=(",", ":")))


def print_csv(data: list[dict[str, Any]]) -> None:
    """Print data as CSV to stdout."""
    if not data:
        return
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=list(data[0].keys()))
    writer.writeheader()
    writer.writerows(data)
    print(buf.getvalue(), end="")


def print_result(
    data: list[dict[str, Any]],
    output_format: str = "table",
    title: str | None = None,
    total: int | None = None,
    has_more: bool = False,
    envelope_extras: dict[str, Any] | None = None,
    envelope: bool = False,
) -> None:
    """Render operation results; pagination hints go to stderr (chatter, not payload).

    In JSON mode, stdout is the data array directly so callers don't need to
    unwrap `.data` — envelope metadata (count, has_more, correlation_id, etc.)
    goes to stderr as a single chatter line. Pass `envelope=True` to restore
    the wrapped `{data, count, has_more, ...}` shape for scripts.
    """
    if output_format == "json":
        if envelope:
            wrapped: dict[str, Any] = {
                "data": data,
                "count": len(data),
                "total": total,
                "has_more": has_more,
            }
            if envelope_extras:
                wrapped.update(envelope_extras)
            print_json(wrapped)
            return
        print_json(data)
        _emit_envelope_chatter(len(data), total=total, has_more=has_more, extras=envelope_extras)
        return
    if output_format == "compact":
        print_ndjson(data)
        _emit_envelope_chatter(len(data), total=total, has_more=has_more, extras=envelope_extras)
        return
    if output_format == "csv":
        print_csv(data)
        return

    print_table(data, title=title)
    if has_more and not is_quiet():
        if total and total > len(data):
            stderr_note(f"[showing {len(data)} of {total} — pass -n 0 for all]")
        else:
            stderr_note(f"[showing {len(data)}, more pages available — pass -n 0 for all]")


def _emit_envelope_chatter(
    count: int,
    *,
    total: int | None,
    has_more: bool,
    extras: dict[str, Any] | None,
) -> None:
    """Single stderr line summarizing the envelope metadata stripped from stdout."""
    if _QUIET:
        return
    parts = [f"{count} rows"]
    if has_more:
        if total and total > count:
            parts.append(f"of {total} total — pass -n 0 for all")
        else:
            parts.append("more pages — pass -n 0 for all")
    if extras:
        if cid := extras.get("correlation_id"):
            parts.append(f"correlation_id={cid}")
        if ms := extras.get("execution_time_ms"):
            parts.append(f"{ms}ms")
    stderr_note("[" + " | ".join(parts) + "]")


# -- Chatter / stderr -------------------------------------------------------


def stderr_note(message: str, *, style: str = "dim") -> None:
    """Non-payload status lines; suppressed under --quiet."""
    if _QUIET:
        return
    stderr_console.print(f"[{style}]{message}[/{style}]")


# -- Errors -----------------------------------------------------------------


_EXIT_CODES: dict[ErrorCode, int] = {
    ErrorCode.USAGE_ERROR: 2,
    ErrorCode.NOT_FOUND: 3,
    ErrorCode.WRONG_TIER: 2,
    ErrorCode.PERMISSION_DENIED: 4,
    ErrorCode.AUTH_REQUIRED: 4,
    ErrorCode.CONFLICT: 5,
    ErrorCode.THROTTLED: 6,
    ErrorCode.BAD_REQUEST: 2,
    ErrorCode.TOKEN_INVALID: 2,
    ErrorCode.TOKEN_EXPIRED: 2,
    ErrorCode.UPSTREAM_ERROR: 1,
    ErrorCode.UNKNOWN: 1,
}


def exit_for_code(code: ErrorCode) -> int:
    """Map an ErrorCode to its POSIX-style exit status."""
    return _EXIT_CODES.get(code, 1)


def emit_error(payload: ErrorPayload, output_format: str | None = None) -> int:
    """Render a structured error to stderr; return the exit code to raise with."""
    fmt = output_format or ("json" if not is_tty() else "table")
    if fmt == "json":
        # Use plain stdlib print to stderr (Rich markup would pollute JSON).
        print(
            json.dumps({"error": payload.model_dump(exclude_none=True)}, indent=2, default=str),
            file=sys.stderr,
        )
    else:
        stderr_console.print(f"[red]Error:[/red] {payload.message}")
        if payload.hint:
            stderr_console.print(f"  [dim]hint:[/dim] {payload.hint}")
        if payload.graph_error_code:
            stderr_console.print(
                f"  [dim]graph:[/dim] {payload.graph_error_code}"
                + (f" (HTTP {payload.http_status})" if payload.http_status else "")
            )
        if payload.correlation_id:
            stderr_console.print(f"  [dim]correlation_id:[/dim] {payload.correlation_id}")
    return exit_for_code(payload.code)


# -- Internal ---------------------------------------------------------------


def _format_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, dict):
        return json.dumps(value, default=str)
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    return str(value)
