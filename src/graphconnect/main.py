"""GraphConnect CLI entrypoint."""

from __future__ import annotations

from typing import Annotated

import typer

from graphconnect.output import console
from graphconnect.types import SafetyTier

app = typer.Typer(
    name="graphconnect",
    help=(
        "GraphConnect helps operators query and manage Intune and Entra "
        "through a curated Microsoft Graph catalog."
    ),
    no_args_is_help=True,
)

auth_app = typer.Typer(help="Manage Microsoft Graph authentication.")
app.add_typer(auth_app, name="auth")


@auth_app.command("login")
def auth_login() -> None:
    """Start device code flow to authenticate with Microsoft Graph."""
    from graphconnect.auth import login

    try:
        result = login()
        if result.authenticated:
            console.print("[green]Authenticated successfully.[/green]")
            if result.auth_method:
                console.print(f"Auth method: {result.auth_method.value}")
            if result.user_principal:
                console.print(f"User: {result.user_principal}")
            if result.token_expires:
                console.print(f"Token expires: {result.token_expires.isoformat()}")
        else:
            console.print("[red]Authentication failed.[/red]")
            raise typer.Exit(1)
    except RuntimeError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1) from exc


@auth_app.command("status")
def auth_status(
    output_format: Annotated[str, typer.Option("--format", "-f", help="Output format")] = "table",
) -> None:
    """Show current authentication status."""
    from graphconnect.auth import status
    from graphconnect.output import print_json

    result = status()
    if output_format == "json":
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
def auth_logout() -> None:
    """Clear cached authentication credentials."""
    from graphconnect.auth import logout

    logout()
    console.print("[green]Logged out.[/green]")


@auth_app.command("config")
def auth_config(
    tenant_id: Annotated[str, typer.Option("--tenant-id", help="Entra tenant ID")],
    client_id: Annotated[str, typer.Option("--client-id", help="App registration client ID")],
) -> None:
    """Save auth configuration (tenant ID and client ID)."""
    from graphconnect.auth import save_config

    save_config(tenant_id, client_id)


catalog_app = typer.Typer(help="Search and browse the operation catalog.")
app.add_typer(catalog_app, name="catalog")


@catalog_app.command("search")
def catalog_search(
    query: Annotated[str, typer.Argument(help="Natural language search query")],
    top: Annotated[int, typer.Option("--top", "-n", help="Max results")] = 10,
    output_format: Annotated[str, typer.Option("--format", "-f", help="Output format")] = "table",
) -> None:
    """Fuzzy-search the catalog by keyword or natural language."""
    from graphconnect.catalog import search_catalog
    from graphconnect.output import print_json, print_table

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
    if output_format == "json":
        print_json(data)
    else:
        print_table(data, title=f"Catalog search: '{query}'")


@catalog_app.command("list")
def catalog_list(
    domain: Annotated[str | None, typer.Option("--domain", "-d", help="Filter by domain")] = None,
    tier: Annotated[str | None, typer.Option("--tier", "-t", help="Filter by safety tier")] = None,
    output_format: Annotated[str, typer.Option("--format", "-f", help="Output format")] = "table",
) -> None:
    """List all catalog operations, optionally filtered."""
    from graphconnect.catalog import list_catalog
    from graphconnect.output import print_json, print_table

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
    if output_format == "json":
        print_json(data)
    else:
        title = f"Catalog: {domain}" if domain else "All catalog operations"
        print_table(data, title=title)


@catalog_app.command("detail")
def catalog_detail(
    operation_id: Annotated[str, typer.Argument(help="Operation ID (e.g., devices.list_managed)")],
    output_format: Annotated[str, typer.Option("--format", "-f", help="Output format")] = "table",
) -> None:
    """Show full details for a specific catalog operation."""
    from graphconnect.catalog import get_entry
    from graphconnect.output import print_json

    entry = get_entry(operation_id)
    if not entry:
        console.print(f"[red]Operation not found:[/red] {operation_id}")
        raise typer.Exit(1)
    if output_format == "json":
        print_json(entry.model_dump())
        return

    console.print(f"[bold]{entry.id}[/bold]  [{entry.safety_tier.value}]")
    console.print(f"{entry.summary}\n")
    if entry.description:
        console.print(entry.description.strip())
        console.print()
    console.print(f"Method:   {entry.method}")
    console.print(f"Endpoint: {entry.endpoint}")
    console.print(f"API:      {entry.api_version.value}")
    if entry.beta:
        console.print("[yellow]Note: Uses beta API, may break without notice[/yellow]")
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
    if entry.examples:
        console.print("\nExamples:")
        for example in entry.examples:
            params = " ".join(
                f"--param {key}={value}" for key, value in (example.parameters or {}).items()
            )
            console.print(f"  graphconnect read {entry.id} {params}".strip())
            console.print(f"    {example.description}")


@app.command("read")
def read_operation(
    operation_id: Annotated[str, typer.Argument(help="Catalog operation ID")],
    param: Annotated[list[str] | None, typer.Option("--param", "-p", help="key=value parameters")] = None,
    top: Annotated[int, typer.Option("--top", "-n", help="Max items to return")] = 100,
    select: Annotated[str | None, typer.Option("--select", "-s", help="Comma-separated fields")] = None,
    filter_expr: Annotated[str | None, typer.Option("--filter", help="OData filter expression")] = None,
    expand: Annotated[str | None, typer.Option("--expand", help="OData expand expression")] = None,
    order_by: Annotated[str | None, typer.Option("--orderby", help="OData orderby expression")] = None,
    output_format: Annotated[str, typer.Option("--format", "-f", help="table, json, or csv")] = "table",
) -> None:
    """Execute a read-only catalog operation against Microsoft Graph."""
    import asyncio

    from graphconnect.catalog import get_entry
    from graphconnect.executor import execute_read
    from graphconnect.output import print_result

    entry = get_entry(operation_id)
    if not entry:
        console.print(f"[red]Operation not found:[/red] {operation_id}")
        console.print("Run: graphconnect catalog search <keyword>")
        raise typer.Exit(1)
    if entry.safety_tier != SafetyTier.READ:
        console.print(f"[red]Operation '{operation_id}' is a {entry.safety_tier.value} operation.[/red]")
        console.print("Use: graphconnect write <operation-id>")
        raise typer.Exit(1)

    parameters = _parse_params(param)
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
    except RuntimeError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1) from exc

    print_result(
        data=result.data,
        output_format=output_format,
        title=f"{operation_id} ({result.item_count} items, {result.execution_time_ms}ms)",
        total=result.item_count if result.has_more else None,
        has_more=result.has_more,
    )


@app.command("write")
def write_operation(
    operation_id: Annotated[str, typer.Argument(help="Catalog operation ID")],
    param: Annotated[list[str] | None, typer.Option("--param", "-p", help="key=value parameters")] = None,
    body: Annotated[str | None, typer.Option("--body", help="JSON request body")] = None,
    execute: Annotated[bool, typer.Option("--execute", help="Execute the operation (requires --token)")] = False,
    token: Annotated[str | None, typer.Option("--token", help="Confirmation token from dry-run")] = None,
    output_format: Annotated[str, typer.Option("--format", "-f", help="table, json, or csv")] = "table",
) -> None:
    """Execute a write operation. Dry-run by default; use --execute --token to apply."""
    import asyncio
    import json as json_lib

    from graphconnect.catalog import get_entry
    from graphconnect.executor import execute_write, preview_write
    from graphconnect.output import print_json

    entry = get_entry(operation_id)
    if not entry:
        console.print(f"[red]Operation not found:[/red] {operation_id}")
        raise typer.Exit(1)
    if entry.safety_tier == SafetyTier.READ:
        console.print(f"[yellow]Operation '{operation_id}' is read-only.[/yellow]")
        console.print("Use: graphconnect read <operation-id>")
        raise typer.Exit(1)

    parameters = _parse_params(param)
    body_data = json_lib.loads(body) if body else None

    if execute:
        if not token:
            console.print("[red]--execute requires --token from a prior dry-run.[/red]")
            console.print(f"First run: graphconnect write {operation_id} (without --execute)")
            raise typer.Exit(1)
        try:
            result = asyncio.run(
                execute_write(
                    entry=entry,
                    parameters=parameters,
                    body=body_data,
                    confirm_token=token,
                )
            )
        except (ValueError, RuntimeError) as exc:
            console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(1) from exc

        if output_format == "json":
            print_json({"status": "executed", "operation_id": operation_id, "result": result})
        else:
            console.print(f"[green]Executed:[/green] {operation_id}")
            if result:
                console.print(f"Result: {result}")
        return

    preview = asyncio.run(preview_write(entry=entry, parameters=parameters, body=body_data))
    if output_format == "json":
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
    console.print(
        f"\n  To execute: graphconnect write {operation_id} "
        + " ".join(f"--param {key}={value}" for key, value in parameters.items())
        + f" --execute --token {preview.confirm_token}"
    )


@app.command("batch")
def batch_read(
    operation_ids: Annotated[list[str], typer.Argument(help="Operation IDs to batch")],
    top: Annotated[int, typer.Option("--top", "-n", help="Max items per operation")] = 50,
    output_format: Annotated[str, typer.Option("--format", "-f", help="table, json, or csv")] = "table",
) -> None:
    """Execute multiple read operations in a single batch."""
    import asyncio

    from graphconnect.catalog import get_entry
    from graphconnect.executor import execute_batch
    from graphconnect.output import print_json, print_result

    if len(operation_ids) > 10:
        console.print("[red]Maximum 10 operations per batch.[/red]")
        raise typer.Exit(1)

    entries = []
    for operation_id in operation_ids:
        entry = get_entry(operation_id)
        if not entry:
            console.print(f"[red]Operation not found:[/red] {operation_id}")
            raise typer.Exit(1)
        if entry.safety_tier != SafetyTier.READ:
            console.print(
                f"[red]Batch only supports read operations. '{operation_id}' is {entry.safety_tier.value}.[/red]"
            )
            raise typer.Exit(1)
        entries.append(entry)

    results = asyncio.run(execute_batch(entries, top=top))

    if output_format == "json":
        print_json([result.model_dump() for result in results])
        return
    for result in results:
        console.print(f"\n[bold]{result.operation_id}[/bold] ({result.item_count} items)")
        print_result(data=result.data, output_format="table", title=None, has_more=result.has_more)


@app.command("schema")
def schema_inspect(
    resource_type: Annotated[str, typer.Argument(help="Graph resource type (e.g., managedDevice)")],
    relationships: Annotated[bool, typer.Option("--relationships", "-r", help="Show relationships")] = False,
    output_format: Annotated[str, typer.Option("--format", "-f", help="Output format")] = "table",
) -> None:
    """Inspect the Graph schema for a resource type."""
    from graphconnect.catalog import get_schema
    from graphconnect.output import print_json, print_table

    schema = get_schema(resource_type)
    if not schema:
        console.print(f"[red]Unknown resource type:[/red] {resource_type}")
        console.print("Supported: managedDevice, user, group, deviceCompliancePolicy, ...")
        raise typer.Exit(1)
    if output_format == "json":
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
    output_format: Annotated[str, typer.Option("--format", "-f", help="Output format")] = "table",
) -> None:
    """Validate first-run prerequisites and auth state."""
    from graphconnect.doctor import run_doctor

    raise typer.Exit(run_doctor(output_format=output_format))


def _parse_params(param: list[str] | None) -> dict[str, str]:
    """Parse --param key=value pairs into a dict."""
    if not param:
        return {}
    result: dict[str, str] = {}
    for item in param:
        if "=" not in item:
            console.print(f"[red]Invalid parameter format:[/red] {item}")
            console.print("Use: --param key=value")
            raise typer.Exit(1)
        key, value = item.split("=", 1)
        result[key.strip()] = value.strip()
    return result
