"""GraphConnect CLI entrypoint."""

from __future__ import annotations

import json as json_lib
from pathlib import Path
from typing import Annotated, Any, NoReturn

import typer

from graphconnect.output import (
    console,
    emit_error,
    print_csv,
    print_json,
    print_result,
    print_table,
    resolve_format,
    set_quiet,
    stderr_console,
)
from graphconnect.types import CliError, ErrorCode, ErrorPayload, SafetyTier


def _fail(
    code: ErrorCode,
    message: str,
    *,
    hint: str | None = None,
    fmt: str,
    cause: Exception | None = None,
) -> NoReturn:
    """Emit a structured error and raise typer.Exit with the mapped status code."""
    _fail_payload(ErrorPayload(code=code, message=message, hint=hint), fmt=fmt, cause=cause)


def _fail_payload(
    payload: ErrorPayload,
    *,
    fmt: str,
    cause: Exception | None = None,
) -> NoReturn:
    exit_code = emit_error(payload, output_format=fmt)
    if cause is not None:
        raise typer.Exit(exit_code) from cause
    raise typer.Exit(exit_code)


def _global_callback(
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="Suppress chatter on stderr.")] = False,
) -> None:
    """Top-level callback; applies --quiet for every subcommand."""
    if quiet:
        set_quiet(True)


app = typer.Typer(
    name="graphconnect",
    help=(
        "GraphConnect helps operators query and manage Intune and Entra "
        "through a curated Microsoft Graph catalog."
    ),
    no_args_is_help=True,
    callback=_global_callback,
)

auth_app = typer.Typer(help="Manage Microsoft Graph authentication.")
app.add_typer(auth_app, name="auth")


# -- auth commands ---------------------------------------------------------


@auth_app.command("login")
def auth_login(
    output_format: Annotated[str | None, typer.Option("--format", "-f", help="table|json")] = None,
) -> None:
    """Start device code flow to authenticate with Microsoft Graph."""
    from graphconnect.auth import login

    fmt = resolve_format(output_format)
    try:
        result = login()
    except RuntimeError as exc:
        hint = "Install Microsoft.Graph.Authentication or configure MSGRAPH_TENANT_ID / MSGRAPH_CLIENT_ID."
        message = str(exc)
        if "sign-in window exited" in message or "Graph context became visible" in message:
            hint = (
                "If the separate sign-in window reported success, wait a few seconds and run "
                "`graphconnect auth status`. If it still shows unauthenticated, rerun "
                "`graphconnect auth login` and leave the sign-in window open briefly after success."
            )
        _fail(
            ErrorCode.AUTH_REQUIRED,
            message,
            hint=hint,
            fmt=fmt,
            cause=exc,
        )

    if fmt == "json":
        print_json(result.model_dump())
        return
    if not result.authenticated:
        _fail(ErrorCode.AUTH_REQUIRED, "Authentication failed.", fmt=fmt)
    stderr_console.print("[green]Authenticated successfully.[/green]")
    if result.auth_method:
        stderr_console.print(f"Auth method: {result.auth_method.value}")
    if result.user_principal:
        stderr_console.print(f"User: {result.user_principal}")
    if result.token_expires:
        stderr_console.print(f"Token expires: {result.token_expires.isoformat()}")


@auth_app.command("status")
def auth_status(
    output_format: Annotated[str | None, typer.Option("--format", "-f", help="table|json")] = None,
) -> None:
    """Show current authentication status."""
    from graphconnect.auth import status

    fmt = resolve_format(output_format)
    result = status()
    if fmt == "json":
        print_json(result.model_dump())
        return
    if result.authenticated:
        console.print("[green]Authenticated[/green]")
        if result.auth_method:
            console.print(f"Auth method: {result.auth_method}")
        if result.user_principal:
            console.print(f"User: {result.user_principal}")
        if result.display_name:
            console.print(f"Name: {result.display_name}")
        if result.token_expires:
            console.print(f"Token expires: {result.token_expires.isoformat()}")
        console.print(f"Scopes: {len(result.scopes)} granted")
        return
    console.print("[yellow]Not authenticated.[/yellow] Run: graphconnect auth login")


@auth_app.command("logout")
def auth_logout(
    output_format: Annotated[str | None, typer.Option("--format", "-f", help="table|json")] = None,
) -> None:
    """Clear cached authentication credentials."""
    from graphconnect.auth import logout

    fmt = resolve_format(output_format)
    logout()
    if fmt == "json":
        print_json({"status": "logged_out"})
        return
    console.print("[green]Logged out.[/green]")


@auth_app.command("config")
def auth_config(
    tenant_id: Annotated[str, typer.Option("--tenant-id", help="Entra tenant ID")],
    client_id: Annotated[str, typer.Option("--client-id", help="App registration client ID")],
    output_format: Annotated[str | None, typer.Option("--format", "-f", help="table|json")] = None,
) -> None:
    """Save auth configuration (tenant ID and client ID)."""
    from graphconnect.auth import save_config

    fmt = resolve_format(output_format)
    save_config(tenant_id, client_id)
    if fmt == "json":
        print_json({"status": "saved", "tenant_id": tenant_id, "client_id": client_id})


# -- catalog commands ------------------------------------------------------

catalog_app = typer.Typer(help="Search and browse the operation catalog.")
app.add_typer(catalog_app, name="catalog")


@catalog_app.command("search")
def catalog_search(
    query: Annotated[str, typer.Argument(help="Natural language search query")],
    top: Annotated[int, typer.Option("--top", "-n", help="Max results")] = 10,
    output_format: Annotated[str | None, typer.Option("--format", "-f", help="table|json")] = None,
) -> None:
    """Fuzzy-search the catalog by keyword or natural language."""
    from graphconnect.catalog import search_catalog

    fmt = resolve_format(output_format)
    results = search_catalog(query, top=top)
    data = [
        {
            "operation_id": result["entry"].id,
            "summary": result["entry"].summary,
            "domain": result["entry"].domain,
            "tier": result["entry"].safety_tier.value,
            "score": f"{result['score']:.0f}",
        }
        for result in results
    ]
    if fmt == "json":
        print_json(data)
    else:
        print_table(data, title=f"Catalog search: '{query}'")


@catalog_app.command("list")
def catalog_list(
    domain: Annotated[str | None, typer.Option("--domain", "-d", help="Filter by domain")] = None,
    tier: Annotated[str | None, typer.Option("--tier", "-t", help="Filter by safety tier")] = None,
    output_format: Annotated[str | None, typer.Option("--format", "-f", help="table|json")] = None,
) -> None:
    """List all catalog operations, optionally filtered."""
    from graphconnect.catalog import list_catalog

    fmt = resolve_format(output_format)
    entries = list_catalog(domain=domain, tier=tier)
    data = [
        {
            "operation_id": entry.id,
            "summary": entry.summary,
            "domain": entry.domain,
            "tier": entry.safety_tier.value,
            "method": entry.method,
        }
        for entry in entries
    ]
    if fmt == "json":
        print_json(data)
    else:
        title = f"Catalog: {domain}" if domain else "All catalog operations"
        print_table(data, title=title)


@catalog_app.command("detail")
def catalog_detail(
    operation_id: Annotated[str, typer.Argument(help="Operation ID (e.g., devices.list_managed)")],
    output_format: Annotated[str | None, typer.Option("--format", "-f", help="table|json")] = None,
) -> None:
    """Show full details for a specific catalog operation."""
    from graphconnect.catalog import get_entry, get_schema

    fmt = resolve_format(output_format)
    entry = get_entry(operation_id)
    if not entry:
        _fail(
            ErrorCode.NOT_FOUND,
            f"Operation not found: {operation_id}",
            hint="Run: graphconnect catalog search <keyword>",
            fmt=fmt,
        )

    if fmt == "json":
        response_schema = get_schema(entry.response_schema) if entry.response_schema else None
        print_json(
            {
                "operation_id": entry.id,
                "aliases": entry.aliases,
                "summary": entry.summary,
                "description": entry.description.strip() if entry.description else "",
                "method": entry.method,
                "endpoint": entry.endpoint,
                "api_version": entry.api_version.value,
                "beta": entry.beta,
                "domain": entry.domain,
                "safety_tier": entry.safety_tier.value,
                "annotations": entry.annotations(),
                "parameters": _parameters_to_jsonschema(entry),
                "default_select": entry.default_select,
                "default_filter": entry.default_filter,
                "default_orderby": entry.default_orderby,
                "graph_permissions": entry.graph_permissions,
                "rate_limit_class": entry.rate_limit_class,
                "response_schema_key": entry.response_schema,
                "response_schema": response_schema,
                "cmmc_controls": entry.cmmc_controls,
                "tags": entry.tags,
                "examples": [ex.model_dump(exclude_none=True) for ex in entry.examples],
            }
        )
        return

    console.print(f"[bold]{entry.id}[/bold]  [{entry.safety_tier.value}]")
    if entry.aliases:
        console.print(f"[dim]aliases:[/dim] {', '.join(entry.aliases)}")
    console.print(f"{entry.summary}\n")
    if entry.description:
        console.print(entry.description.strip())
        console.print()
    console.print(f"Method:   {entry.method}")
    console.print(f"Endpoint: {entry.endpoint}")
    console.print(f"API:      {entry.api_version.value}")
    if entry.beta:
        console.print("[yellow]Note: Uses beta API, may break without notice[/yellow]")

    annotations = entry.annotations()
    hint_labels = [name for name, val in annotations.items() if val]
    if hint_labels:
        console.print(f"Hints:    {', '.join(hint_labels)}")
    if entry.rate_limit_class:
        console.print(f"Rate:     {entry.rate_limit_class}")
    if entry.parameters:
        console.print("\nParameters:")
        for param in entry.parameters:
            required = " (required)" if param.required else ""
            default = f" [default: {param.default}]" if param.default is not None else ""
            console.print(f"  {param.name}: {param.type}{required}{default}")
            if param.description:
                console.print(f"    {param.description}")
            if param.enum:
                console.print(f"    Values: {', '.join(param.enum)}")
    if entry.default_select:
        console.print(f"\nDefault fields: {', '.join(entry.default_select)}")
    if entry.graph_permissions:
        console.print(f"Permissions: {', '.join(entry.graph_permissions)}")
    if entry.cmmc_controls:
        console.print(f"CMMC controls: {', '.join(entry.cmmc_controls)}")
    if entry.response_schema:
        console.print(f"Response:  {entry.response_schema}")
    if entry.examples:
        console.print("\nExamples:")
        for example in entry.examples:
            params = " ".join(
                f"--param {key}={value}" for key, value in (example.parameters or {}).items()
            )
            console.print(f"  graphconnect read {entry.id} {params}".strip())
            console.print(f"    {example.description}")


# -- read / write / batch / schema / doctor --------------------------------


@app.command("read")
def read_operation(
    operation_id: Annotated[str, typer.Argument(help="Catalog operation ID")],
    param: Annotated[list[str] | None, typer.Option("--param", "-p", help="key=value (values split on FIRST '='); use --params-json for values containing '='")] = None,
    params_json: Annotated[str | None, typer.Option("--params-json", help="JSON object of parameters; merged over --param entries")] = None,
    top: Annotated[int, typer.Option("--top", "-n", help="Max items to return")] = 100,
    select: Annotated[str | None, typer.Option("--select", "-s", help="Comma-separated fields")] = None,
    filter_expr: Annotated[str | None, typer.Option("--filter", help="OData filter expression")] = None,
    expand: Annotated[str | None, typer.Option("--expand", help="OData expand expression")] = None,
    order_by: Annotated[str | None, typer.Option("--orderby", help="OData orderby expression")] = None,
    output_format: Annotated[str | None, typer.Option("--format", "-f", help="table|json|csv")] = None,
) -> None:
    """Execute a read-only catalog operation against Microsoft Graph."""
    import asyncio

    from graphconnect.catalog import get_entry
    from graphconnect.executor import execute_read

    fmt = resolve_format(output_format)
    entry = get_entry(operation_id)
    if not entry:
        _fail(
            ErrorCode.NOT_FOUND,
            f"Operation not found: {operation_id}",
            hint="Run: graphconnect catalog search <keyword>",
            fmt=fmt,
        )
    if entry.safety_tier != SafetyTier.READ:
        _fail(
            ErrorCode.WRONG_TIER,
            f"Operation '{operation_id}' is a {entry.safety_tier.value} operation.",
            hint=f"Use: graphconnect write {operation_id}",
            fmt=fmt,
        )

    parameters = _merge_params(param, params_json, fmt=fmt)
    parameters, select, filter_expr, expand, order_by = _extract_read_query_controls(
        parameters,
        select=select,
        filter_expr=filter_expr,
        expand=expand,
        order_by=order_by,
    )
    select_fields = [field.strip() for field in select.split(",")] if select else None
    try:
        result = asyncio.run(
            execute_read(
                entry=entry,
                parameters=parameters,
                top=top,
                select=select_fields,
                filter_expr=filter_expr,
                expand=expand,
                order_by=order_by,
            )
        )
    except CliError as exc:
        _fail_payload(exc.payload, fmt=fmt, cause=exc)
    except RuntimeError as exc:
        _fail(ErrorCode.UNKNOWN, str(exc), fmt=fmt, cause=exc)

    print_result(
        data=result.data,
        output_format=fmt,
        title=f"{operation_id} ({result.item_count} items, {result.execution_time_ms}ms)",
        total=result.item_count if result.has_more else None,
        has_more=result.has_more,
        envelope_extras={
            "operation_id": result.operation_id,
            "request_id": result.request_id,
            "correlation_id": result.correlation_id,
            "execution_time_ms": result.execution_time_ms,
        },
    )


@app.command("write")
def write_operation(
    operation_id: Annotated[str, typer.Argument(help="Catalog operation ID")],
    param: Annotated[list[str] | None, typer.Option("--param", "-p", help="key=value (splits on first '=')")] = None,
    params_json: Annotated[str | None, typer.Option("--params-json", help="JSON object of parameters")] = None,
    body: Annotated[str | None, typer.Option("--body", help="JSON request body")] = None,
    execute: Annotated[bool, typer.Option("--execute", help="Execute (requires --token)")] = False,
    token: Annotated[str | None, typer.Option("--token", help="Confirmation token from dry-run")] = None,
    output_format: Annotated[str | None, typer.Option("--format", "-f", help="table|json")] = None,
) -> None:
    """Execute a write operation. Dry-run by default; use --execute --token to apply."""
    import asyncio

    from graphconnect.catalog import get_entry
    from graphconnect.executor import execute_write, preview_write

    fmt = resolve_format(output_format)
    entry = get_entry(operation_id)
    if not entry:
        _fail(
            ErrorCode.NOT_FOUND,
            f"Operation not found: {operation_id}",
            hint="Run: graphconnect catalog search <keyword>",
            fmt=fmt,
        )
    if entry.safety_tier == SafetyTier.READ:
        _fail(
            ErrorCode.WRONG_TIER,
            f"Operation '{operation_id}' is read-only.",
            hint=f"Use: graphconnect read {operation_id}",
            fmt=fmt,
        )

    parameters = _merge_params(param, params_json, fmt=fmt)
    body_data = _parse_json_arg(body, flag="--body", fmt=fmt)

    if execute:
        if not token:
            _fail(
                ErrorCode.USAGE_ERROR,
                "--execute requires --token from a prior dry-run.",
                hint=f"First run: graphconnect write {operation_id} (without --execute)",
                fmt=fmt,
            )
        try:
            result = asyncio.run(
                execute_write(
                    entry=entry,
                    parameters=parameters,
                    body=body_data,
                    confirm_token=token,
                )
            )
        except CliError as exc:
            _fail_payload(exc.payload, fmt=fmt, cause=exc)
        except RuntimeError as exc:
            _fail(ErrorCode.UNKNOWN, str(exc), fmt=fmt, cause=exc)

        if fmt == "json":
            print_json({"status": "executed", "operation_id": operation_id, "result": result})
        else:
            console.print(f"[green]Executed:[/green] {operation_id}")
            if result:
                console.print(f"Result: {result}")
        return

    try:
        preview = asyncio.run(preview_write(entry=entry, parameters=parameters, body=body_data))
    except CliError as exc:
        _fail_payload(exc.payload, fmt=fmt, cause=exc)

    if fmt == "json":
        print_json(preview.model_dump())
        return

    tier_color = "red" if preview.safety_tier == SafetyTier.DESTRUCTIVE else "yellow"
    console.print(f"[bold {tier_color}]PREVIEW[/bold {tier_color}] [{preview.safety_tier.value}]")
    console.print(f"  {preview.method} {preview.url}")
    if preview.body:
        console.print(f"  Body: {json_lib.dumps(preview.body, indent=2)}")
    console.print(f"\n  {preview.description}")
    if preview.affected_resources:
        console.print(f"  Affects: {', '.join(preview.affected_resources)}")
    if not preview.reversible:
        console.print("  [red]This operation CANNOT be undone.[/red]")
    elif preview.reverse_operation:
        console.print(f"  Reverse: graphconnect write {preview.reverse_operation}")
    for warning in preview.warnings:
        console.print(f"  [red]WARNING: {warning}[/red]")
    console.print(f"\n  Token: {preview.confirm_token}")
    console.print(f"  Expires: {preview.expires_at.isoformat()}")
    console.print(f"  Correlation: {preview.correlation_id}")
    console.print(
        f"\n  To execute: graphconnect write {operation_id} "
        + " ".join(f"--param {key}={value}" for key, value in parameters.items())
        + f" --execute --token {preview.confirm_token}"
    )


@app.command("batch")
def batch_read(
    operation_ids: Annotated[list[str], typer.Argument(help="Operation IDs to batch")],
    top: Annotated[int, typer.Option("--top", "-n", help="Max items per operation")] = 50,
    output_format: Annotated[str | None, typer.Option("--format", "-f", help="table|json|csv")] = None,
) -> None:
    """Execute multiple read operations in a single batch."""
    import asyncio

    from graphconnect.catalog import get_entry
    from graphconnect.executor import execute_batch

    fmt = resolve_format(output_format)
    if len(operation_ids) > 10:
        _fail(ErrorCode.USAGE_ERROR, "Maximum 10 operations per batch.", fmt=fmt)

    entries = []
    for op_id in operation_ids:
        entry = get_entry(op_id)
        if not entry:
            _fail(ErrorCode.NOT_FOUND, f"Operation not found: {op_id}", fmt=fmt)
        if entry.safety_tier != SafetyTier.READ:
            _fail(
                ErrorCode.WRONG_TIER,
                f"Batch only supports read operations; '{op_id}' is {entry.safety_tier.value}.",
                fmt=fmt,
            )
        entries.append(entry)

    try:
        results = asyncio.run(execute_batch(entries, top=top))
    except CliError as exc:
        _fail_payload(exc.payload, fmt=fmt, cause=exc)

    if fmt == "json":
        print_json([r.model_dump() for r in results])
        return
    if fmt == "csv":
        merged: list[dict[str, Any]] = []
        for r in results:
            for row in r.data:
                merged.append({"operation_id": r.operation_id, **row})
        print_csv(merged)
        return
    for result in results:
        stderr_console.print(f"\n[bold]{result.operation_id}[/bold] ({result.item_count} items)")
        print_result(data=result.data, output_format="table", title=None, has_more=result.has_more)


@app.command("schema")
def schema_inspect(
    resource_type: Annotated[str, typer.Argument(help="Graph resource type (e.g., managedDevice)")],
    relationships: Annotated[bool, typer.Option("--relationships", "-r", help="Show relationships")] = False,
    output_format: Annotated[str | None, typer.Option("--format", "-f", help="table|json")] = None,
) -> None:
    """Inspect the Graph schema for a resource type."""
    from graphconnect.catalog import get_schema

    fmt = resolve_format(output_format)
    schema = get_schema(resource_type)
    if not schema:
        _fail(
            ErrorCode.NOT_FOUND,
            f"Unknown resource type: {resource_type}",
            hint="Known: managedDevice, user, group, deviceCompliancePolicy, …",
            fmt=fmt,
        )
    if fmt == "json":
        print_json(schema)
        return

    console.print(f"[bold]{resource_type}[/bold]")
    if "properties" in schema:
        props = [
            {"name": key, "type": value.get("type", ""), "description": value.get("description", "")}
            for key, value in schema["properties"].items()
        ]
        print_table(props, title="Properties")
    if relationships and "relationships" in schema:
        rels = [
            {"name": key, "type": value.get("type", ""), "target": value.get("target", "")}
            for key, value in schema["relationships"].items()
        ]
        print_table(rels, title="Relationships")


@app.command("doctor")
def doctor(
    output_format: Annotated[str | None, typer.Option("--format", "-f", help="table|json")] = None,
) -> None:
    """Validate first-run prerequisites and auth state."""
    from graphconnect.doctor import run_doctor

    fmt = resolve_format(output_format)
    raise typer.Exit(run_doctor(output_format=fmt))


# -- helpers ---------------------------------------------------------------


def _parse_kv_params(param: list[str] | None, fmt: str) -> dict[str, Any]:
    if not param:
        return {}
    result: dict[str, Any] = {}
    for item in param:
        if "=" not in item:
            _fail(
                ErrorCode.USAGE_ERROR,
                f"Invalid parameter format: {item!r}",
                hint="Use --param key=value (splits on first '='); for values containing '=', use --params-json.",
                fmt=fmt,
            )
        key, value = item.split("=", 1)
        result[key.strip()] = value.strip()
    return result


def _parse_json_arg(raw: str | None, *, flag: str, fmt: str) -> Any:
    """Parse an optional JSON flag value, failing the CLI with a usage error on bad JSON."""
    if raw is None:
        return None
    payload = raw
    if raw.startswith("@"):
        path = Path(raw[1:]).expanduser()
        if not path.is_file():
            _fail(
                ErrorCode.USAGE_ERROR,
                f"{flag} file not found: {path}",
                hint=f"Use {flag} @<path-to-json-file>",
                fmt=fmt,
            )
        payload = path.read_text(encoding="utf-8")
    try:
        return json_lib.loads(payload)
    except json_lib.JSONDecodeError as exc:
        _fail(ErrorCode.USAGE_ERROR, f"{flag} is not valid JSON: {exc}", fmt=fmt, cause=exc)


def _merge_params(
    param: list[str] | None,
    params_json: str | None,
    fmt: str,
) -> dict[str, Any]:
    merged = _parse_kv_params(param, fmt=fmt)
    parsed = _parse_json_arg(params_json, flag="--params-json", fmt=fmt)
    if parsed is not None:
        if not isinstance(parsed, dict):
            _fail(
                ErrorCode.USAGE_ERROR,
                "--params-json must be a JSON object (e.g. '{\"key\":\"value\"}')",
                fmt=fmt,
            )
        merged.update(parsed)
    return merged


def _extract_read_query_controls(
    parameters: dict[str, Any],
    *,
    select: str | None,
    filter_expr: str | None,
    expand: str | None,
    order_by: str | None,
) -> tuple[dict[str, Any], str | None, str | None, str | None, str | None]:
    """Promote reserved query controls from --param/--params-json into read() options.

    This makes shell and agent usage less brittle because callers often pass
    `filter=...` or `orderby=...` through the generic parameter surface instead
    of dedicated Typer flags.
    """
    remaining = dict(parameters)

    if select is None and "select" in remaining:
        select = str(remaining.pop("select"))
    if filter_expr is None and "filter" in remaining:
        filter_expr = str(remaining.pop("filter"))
    if expand is None and "expand" in remaining:
        expand = str(remaining.pop("expand"))
    if order_by is None:
        if "orderby" in remaining:
            order_by = str(remaining.pop("orderby"))
        elif "order_by" in remaining:
            order_by = str(remaining.pop("order_by"))

    return remaining, select, filter_expr, expand, order_by


def _parameters_to_jsonschema(entry: Any) -> dict[str, Any]:
    """Convert CatalogEntry parameters into a JSON Schema object for agent consumers."""
    properties: dict[str, Any] = {}
    required: list[str] = []
    type_map = {
        "string": "string",
        "integer": "integer",
        "int": "integer",
        "number": "number",
        "boolean": "boolean",
        "bool": "boolean",
    }
    for p in entry.parameters:
        schema: dict[str, Any] = {
            "type": type_map.get(p.type, "string"),
            "description": p.description or "",
        }
        if p.enum:
            schema["enum"] = list(p.enum)
        if p.default is not None:
            schema["default"] = p.default
        properties[p.name] = schema
        if p.required:
            required.append(p.name)

    obj: dict[str, Any] = {"type": "object", "properties": properties, "additionalProperties": False}
    if required:
        obj["required"] = required
    return obj
