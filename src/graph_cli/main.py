"""DAF Graph CLI - Microsoft Graph CLI for CMMC L2 Intune/Entra management."""

from __future__ import annotations

from typing import Annotated, Optional

import typer

from graph_cli.output import console

app = typer.Typer(
    name="graph",
    help="Microsoft Graph CLI for CMMC L2 Intune/Entra management.",
    no_args_is_help=True,
)

# -- Auth commands ----------------------------------------------------------

auth_app = typer.Typer(help="Manage Microsoft Graph authentication.")
app.add_typer(auth_app, name="auth")


@auth_app.command("login")
def auth_login() -> None:
    """Start device code flow to authenticate with Microsoft Graph."""
    from graph_cli.auth import login

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
    except RuntimeError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)


@auth_app.command("status")
def auth_status(
    output_format: Annotated[str, typer.Option("--format", "-f", help="Output format")] = "table",
) -> None:
    """Show current authentication status."""
    from graph_cli.auth import status
    from graph_cli.output import print_json

    result = status()
    if output_format == "json":
        print_json(result.model_dump())
    elif result.authenticated:
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
    else:
        console.print("[yellow]Not authenticated.[/yellow] Run: graph auth login")


@auth_app.command("logout")
def auth_logout() -> None:
    """Clear cached authentication credentials."""
    from graph_cli.auth import logout

    logout()
    console.print("[green]Logged out.[/green]")


@auth_app.command("config")
def auth_config(
    tenant_id: Annotated[str, typer.Option("--tenant-id", help="Entra tenant ID")],
    client_id: Annotated[str, typer.Option("--client-id", help="App registration client ID")],
) -> None:
    """Save auth configuration (tenant ID and client ID)."""
    from graph_cli.auth import save_config

    save_config(tenant_id, client_id)


# -- Catalog commands -------------------------------------------------------

catalog_app = typer.Typer(help="Search and browse the operation catalog.")
app.add_typer(catalog_app, name="catalog")


@catalog_app.command("search")
def catalog_search(
    query: Annotated[str, typer.Argument(help="Natural language search query")],
    top: Annotated[int, typer.Option("--top", "-n", help="Max results")] = 10,
    output_format: Annotated[str, typer.Option("--format", "-f", help="Output format")] = "table",
) -> None:
    """Fuzzy-search the catalog by keyword or natural language."""
    from graph_cli.catalog import search_catalog
    from graph_cli.output import print_json, print_table

    results = search_catalog(query, top=top)
    data = [
        {
            "operation_id": r["entry"].id,
            "summary": r["entry"].summary,
            "domain": r["entry"].domain,
            "tier": r["entry"].safety_tier.value,
            "score": f"{r['score']:.0f}",
        }
        for r in results
    ]
    if output_format == "json":
        print_json(data)
    else:
        print_table(data, title=f"Catalog search: '{query}'")


@catalog_app.command("list")
def catalog_list(
    domain: Annotated[Optional[str], typer.Option("--domain", "-d", help="Filter by domain")] = None,
    tier: Annotated[Optional[str], typer.Option("--tier", "-t", help="Filter by safety tier")] = None,
    output_format: Annotated[str, typer.Option("--format", "-f", help="Output format")] = "table",
) -> None:
    """List all catalog operations, optionally filtered."""
    from graph_cli.catalog import list_catalog
    from graph_cli.output import print_json, print_table

    entries = list_catalog(domain=domain, tier=tier)
    data = [
        {
            "operation_id": e.id,
            "summary": e.summary,
            "domain": e.domain,
            "tier": e.safety_tier.value,
            "method": e.method,
        }
        for e in entries
    ]
    if output_format == "json":
        print_json(data)
    else:
        title = "All catalog operations"
        if domain:
            title = f"Catalog: {domain}"
        print_table(data, title=title)


@catalog_app.command("detail")
def catalog_detail(
    operation_id: Annotated[str, typer.Argument(help="Operation ID (e.g., devices.list_managed)")],
    output_format: Annotated[str, typer.Option("--format", "-f", help="Output format")] = "table",
) -> None:
    """Show full details for a specific catalog operation."""
    from graph_cli.catalog import get_entry
    from graph_cli.output import print_json

    entry = get_entry(operation_id)
    if not entry:
        console.print(f"[red]Operation not found:[/red] {operation_id}")
        raise typer.Exit(1)

    if output_format == "json":
        print_json(entry.model_dump())
    else:
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
            for p in entry.parameters:
                req = " (required)" if p.required else ""
                default = f" [default: {p.default}]" if p.default is not None else ""
                console.print(f"  {p.name}: {p.type}{req}{default}")
                if p.description:
                    console.print(f"    {p.description}")
                if p.enum:
                    console.print(f"    Values: {', '.join(p.enum)}")
        if entry.default_select:
            console.print(f"\nDefault fields: {', '.join(entry.default_select)}")
        if entry.graph_permissions:
            console.print(f"Permissions: {', '.join(entry.graph_permissions)}")
        if entry.cmmc_controls:
            console.print(f"CMMC controls: {', '.join(entry.cmmc_controls)}")
        if entry.examples:
            console.print("\nExamples:")
            for ex in entry.examples:
                params = " ".join(f"--param {k}={v}" for k, v in (ex.parameters or {}).items())
                console.print(f"  graph read {entry.id} {params}".strip())
                console.print(f"    {ex.description}")


# -- Read command -----------------------------------------------------------


@app.command("read")
def read_operation(
    operation_id: Annotated[str, typer.Argument(help="Catalog operation ID")],
    param: Annotated[Optional[list[str]], typer.Option("--param", "-p", help="key=value parameters")] = None,
    top: Annotated[int, typer.Option("--top", "-n", help="Max items to return")] = 100,
    select: Annotated[Optional[str], typer.Option("--select", "-s", help="Comma-separated fields")] = None,
    filter_expr: Annotated[Optional[str], typer.Option("--filter", help="OData filter expression")] = None,
    expand: Annotated[Optional[str], typer.Option("--expand", help="OData expand expression")] = None,
    order_by: Annotated[Optional[str], typer.Option("--orderby", help="OData orderby expression")] = None,
    output_format: Annotated[str, typer.Option("--format", "-f", help="table, json, or csv")] = "table",
) -> None:
    """Execute a read-only catalog operation against Microsoft Graph."""
    import asyncio

    from graph_cli.catalog import get_entry
    from graph_cli.executor import execute_read
    from graph_cli.output import print_result

    entry = get_entry(operation_id)
    if not entry:
        console.print(f"[red]Operation not found:[/red] {operation_id}")
        console.print("Run: graph catalog search <keyword>")
        raise typer.Exit(1)

    if entry.safety_tier.value != "read":
        console.print(f"[red]Operation '{operation_id}' is a {entry.safety_tier.value} operation.[/red]")
        console.print("Use: graph write <operation-id>")
        raise typer.Exit(1)

    parameters = _parse_params(param)
    select_fields = [s.strip() for s in select.split(",")] if select else None

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
    except RuntimeError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)

    print_result(
        data=result.data,
        output_format=output_format,
        title=f"{operation_id} ({result.item_count} items, {result.execution_time_ms}ms)",
        total=result.item_count if result.has_more else None,
        has_more=result.has_more,
    )


# -- Write command ----------------------------------------------------------


@app.command("write")
def write_operation(
    operation_id: Annotated[str, typer.Argument(help="Catalog operation ID")],
    param: Annotated[Optional[list[str]], typer.Option("--param", "-p", help="key=value parameters")] = None,
    body: Annotated[Optional[str], typer.Option("--body", help="JSON request body")] = None,
    execute: Annotated[bool, typer.Option("--execute", help="Execute the operation (requires --token)")] = False,
    token: Annotated[Optional[str], typer.Option("--token", help="Confirmation token from dry-run")] = None,
    output_format: Annotated[str, typer.Option("--format", "-f", help="table, json, or csv")] = "table",
) -> None:
    """Execute a write operation. Dry-run by default; use --execute --token to apply."""
    import asyncio
    import json as json_lib

    from graph_cli.catalog import get_entry
    from graph_cli.executor import execute_write, preview_write
    from graph_cli.output import print_json

    entry = get_entry(operation_id)
    if not entry:
        console.print(f"[red]Operation not found:[/red] {operation_id}")
        raise typer.Exit(1)

    if entry.safety_tier.value == "read":
        console.print(f"[yellow]Operation '{operation_id}' is read-only.[/yellow]")
        console.print("Use: graph read <operation-id>")
        raise typer.Exit(1)

    parameters = _parse_params(param)
    body_data = json_lib.loads(body) if body else None

    if execute:
        if not token:
            console.print("[red]--execute requires --token from a prior dry-run.[/red]")
            console.print(f"First run: graph write {operation_id} (without --execute)")
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
        except (ValueError, RuntimeError) as e:
            console.print(f"[red]Error:[/red] {e}")
            raise typer.Exit(1)

        if output_format == "json":
            print_json({"status": "executed", "operation_id": operation_id, "result": result})
        else:
            console.print(f"[green]Executed:[/green] {operation_id}")
            if result:
                console.print(f"Result: {result}")
    else:
        # Dry-run: show preview
        preview = asyncio.run(
            preview_write(
                entry=entry,
                parameters=parameters,
                body=body_data,
            )
        )

        if output_format == "json":
            print_json(preview.model_dump())
        else:
            tier_color = "red" if preview.safety_tier.value == "destructive" else "yellow"
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
                console.print(f"  Reverse: graph write {preview.reverse_operation}")
            for warning in preview.warnings:
                console.print(f"  [red]WARNING: {warning}[/red]")
            console.print(f"\n  Token: {preview.confirm_token}")
            console.print(f"  Expires: {preview.expires_at.isoformat()}")
            console.print(
                f"\n  To execute: graph write {operation_id} "
                + " ".join(f"--param {k}={v}" for k, v in parameters.items())
                + f" --execute --token {preview.confirm_token}"
            )


# -- Batch command ----------------------------------------------------------


@app.command("batch")
def batch_read(
    operation_ids: Annotated[list[str], typer.Argument(help="Operation IDs to batch")],
    top: Annotated[int, typer.Option("--top", "-n", help="Max items per operation")] = 50,
    output_format: Annotated[str, typer.Option("--format", "-f", help="table, json, or csv")] = "table",
) -> None:
    """Execute multiple read operations in a single batch."""
    import asyncio

    from graph_cli.catalog import get_entry
    from graph_cli.executor import execute_batch
    from graph_cli.output import print_json, print_result

    if len(operation_ids) > 10:
        console.print("[red]Maximum 10 operations per batch.[/red]")
        raise typer.Exit(1)

    entries = []
    for op_id in operation_ids:
        entry = get_entry(op_id)
        if not entry:
            console.print(f"[red]Operation not found:[/red] {op_id}")
            raise typer.Exit(1)
        if entry.safety_tier.value != "read":
            console.print(f"[red]Batch only supports read operations. '{op_id}' is {entry.safety_tier.value}.[/red]")
            raise typer.Exit(1)
        entries.append(entry)

    results = asyncio.run(execute_batch(entries, top=top))

    if output_format == "json":
        print_json([r.model_dump() for r in results])
    else:
        for result in results:
            console.print(f"\n[bold]{result.operation_id}[/bold] ({result.item_count} items)")
            print_result(
                data=result.data,
                output_format="table",
                title=None,
                has_more=result.has_more,
            )


# -- Schema command ---------------------------------------------------------


@app.command("schema")
def schema_inspect(
    resource_type: Annotated[str, typer.Argument(help="Graph resource type (e.g., managedDevice)")],
    relationships: Annotated[bool, typer.Option("--relationships", "-r", help="Show relationships")] = False,
    enums: Annotated[bool, typer.Option("--enums", "-e", help="Show enum values")] = False,
    output_format: Annotated[str, typer.Option("--format", "-f", help="Output format")] = "table",
) -> None:
    """Inspect the Graph schema for a resource type."""
    from graph_cli.catalog import get_schema
    from graph_cli.output import print_json, print_table

    schema = get_schema(resource_type)
    if not schema:
        console.print(f"[red]Unknown resource type:[/red] {resource_type}")
        console.print("Supported: managedDevice, user, group, deviceCompliancePolicy, ...")
        raise typer.Exit(1)

    if output_format == "json":
        print_json(schema)
    else:
        console.print(f"[bold]{resource_type}[/bold]")
        if "properties" in schema:
            props = [
                {"name": k, "type": v.get("type", ""), "description": v.get("description", "")}
                for k, v in schema["properties"].items()
            ]
            print_table(props, title="Properties")
        if relationships and "relationships" in schema:
            rels = [
                {"name": k, "type": v.get("type", ""), "target": v.get("target", "")}
                for k, v in schema["relationships"].items()
            ]
            print_table(rels, title="Relationships")


# -- Helpers ----------------------------------------------------------------


def _parse_params(param: list[str] | None) -> dict:
    """Parse --param key=value pairs into a dict."""
    if not param:
        return {}
    result = {}
    for p in param:
        if "=" not in p:
            console.print(f"[red]Invalid parameter format:[/red] {p}")
            console.print("Use: --param key=value")
            raise typer.Exit(1)
        key, value = p.split("=", 1)
        result[key.strip()] = value.strip()
    return result


if __name__ == "__main__":
    app()
