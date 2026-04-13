"""Output formatters for table, JSON, and CSV output modes."""

from __future__ import annotations

import csv
import io
import json
from typing import Any

from rich.console import Console
from rich.table import Table

console = Console()


def print_table(data: list[dict[str, Any]], title: str | None = None) -> None:
    """Print data as a Rich table."""
    if not data:
        console.print("[dim]No results.[/dim]")
        return

    table = Table(title=title, show_lines=False, pad_edge=False)

    # Use keys from first row as columns
    columns = list(data[0].keys())
    for col in columns:
        table.add_column(col, overflow="fold")

    for row in data:
        table.add_row(*[_format_value(row.get(col)) for col in columns])

    console.print(table)


def print_json(data: Any) -> None:
    """Print data as formatted JSON."""
    print(json.dumps(data, indent=2, default=str))


def print_csv(data: list[dict[str, Any]]) -> None:
    """Print data as CSV to stdout."""
    if not data:
        return

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=list(data[0].keys()))
    writer.writeheader()
    writer.writerows(data)
    print(output.getvalue(), end="")


def print_result(
    data: list[dict[str, Any]],
    output_format: str = "table",
    title: str | None = None,
    total: int | None = None,
    has_more: bool = False,
) -> None:
    """Print results in the requested format with optional pagination info."""
    if output_format == "json":
        print_json({"data": data, "count": len(data), "total": total, "has_more": has_more})
    elif output_format == "csv":
        print_csv(data)
    else:
        print_table(data, title=title)
        if has_more and total:
            console.print(f"\n[dim][showing {len(data)} of {total}, use --top {total} for all][/dim]")
        elif has_more:
            console.print(f"\n[dim][showing {len(data)}, more results available -- increase --top][/dim]")


def _format_value(value: Any) -> str:
    """Format a value for table display."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, dict):
        # Flatten nested dicts for display
        return json.dumps(value, default=str)
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    return str(value)
