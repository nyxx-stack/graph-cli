"""`show` verb — fetch a single entity by id or name and emit an Envelope."""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

import typer

from graphconnect.output import emit
from graphconnect.selectors import Locator, resolve
from graphconnect.transport import graph_request
from graphconnect.types import Envelope, ErrorCode, ErrorPayload


app = typer.Typer(name="show", help="Fetch a single entity by id or name.", no_args_is_help=True)


# --- helpers ----------------------------------------------------------------


def _new_trace_id() -> str:
    return uuid.uuid4().hex


async def _resolve_or_id(query: str, *, type: str, profile: str) -> Locator | None:
    """Accept an id or a name. Delegates to `selectors.resolve`.

    Any recognized "no match" signal from the resolver (LookupError, or a class
    named NotFound / AmbiguousMatch — we match by name to avoid depending on
    the selector agent's public exception shape during merge) returns None.
    """
    try:
        return await resolve(query, type=type, profile=profile)
    except LookupError:
        return None
    except Exception as exc:  # noqa: BLE001
        if exc.__class__.__name__ in {"NotFound", "AmbiguousMatch"}:
            return None
        raise


async def _get_json(
    path: str, *, profile: str, api_version: str = "v1.0"
) -> dict[str, Any] | None:
    resp = await graph_request("GET", path, profile=profile, api_version=api_version)
    if resp.status_code == 404:
        return None
    if resp.status_code >= 400:
        raise RuntimeError(f"graph {resp.status_code}: {resp.body}")
    body = resp.body
    return body if isinstance(body, dict) else None


def _not_found(entity: str, query: str, trace_id: str) -> Envelope:
    return Envelope.err(
        summary=f"{entity} not found for '{query}'",
        error=ErrorPayload(code=ErrorCode.NOT_FOUND, message=f"{entity} '{query}' not found"),
        trace_id=trace_id,
    )


def _run(coro) -> Envelope:
    """Run an async show helper; convert transport auth errors to envelopes."""
    from graphconnect.transport import GraphTransportError

    try:
        return asyncio.run(coro)
    except GraphTransportError as exc:
        return Envelope.err(
            summary=f"transport error: {exc}",
            error=ErrorPayload(
                code=ErrorCode.UPSTREAM_ERROR,
                message=str(exc),
                hint="Run `graphconnect auth login --profile <name>` to configure credentials.",
            ),
            trace_id=_new_trace_id(),
        )


def _pol_kind_path(kind: str | None, policy_id: str) -> str:
    """Map a policy Locator.kind to the primary GET-by-id endpoint."""
    match kind:
        case "settingsCatalog":
            return f"/deviceManagement/configurationPolicies/{policy_id}"
        case "configurationProfile":
            return f"/deviceManagement/deviceConfigurations/{policy_id}"
        case "compliance":
            return f"/deviceManagement/deviceCompliancePolicies/{policy_id}"
        case "conditionalAccess":
            return f"/identity/conditionalAccess/policies/{policy_id}"
        case _:
            # Default guess — settings catalog is the most common in v2 flows.
            return f"/deviceManagement/configurationPolicies/{policy_id}"


def _pol_assignments_path(kind: str | None, policy_id: str) -> str:
    match kind:
        case "settingsCatalog":
            return f"/deviceManagement/configurationPolicies/{policy_id}/assignments"
        case "configurationProfile":
            return f"/deviceManagement/deviceConfigurations/{policy_id}/assignments"
        case "compliance":
            return f"/deviceManagement/deviceCompliancePolicies/{policy_id}/assignments"
        case "conditionalAccess":
            # CA policies embed targets in the policy document; no separate endpoint.
            return f"/identity/conditionalAccess/policies/{policy_id}"
        case _:
            return f"/deviceManagement/configurationPolicies/{policy_id}/assignments"


def _pol_status_path(kind: str | None, policy_id: str) -> str | None:
    match kind:
        case "settingsCatalog":
            return f"/deviceManagement/configurationPolicies/{policy_id}/deviceStatuses"
        case "configurationProfile":
            return f"/deviceManagement/deviceConfigurations/{policy_id}/deviceStatuses"
        case "compliance":
            return f"/deviceManagement/deviceCompliancePolicies/{policy_id}/deviceStatuses"
        case _:
            return None


# --- subcommands ------------------------------------------------------------


@app.command("device")
def show_device(
    query: str = typer.Argument(..., help="Device id or name."),
    profile: str = typer.Option("default", "--profile"),
    include_apps: bool = typer.Option(False, "--include-apps"),
    include_compliance: bool = typer.Option(False, "--include-compliance"),
) -> None:
    env = _run(
        _show_device_async(query, profile=profile, include_apps=include_apps, include_compliance=include_compliance)
    )
    emit(env)


async def _show_device_async(
    query: str, *, profile: str, include_apps: bool, include_compliance: bool
) -> Envelope:
    trace_id = _new_trace_id()
    loc = await _resolve_or_id(query, type="device", profile=profile)
    if loc is None:
        return _not_found("Device", query, trace_id)

    base_path = f"/deviceManagement/managedDevices/{loc.id}"
    tasks: dict[str, Any] = {"device": _get_json(base_path, profile=profile)}
    if include_apps:
        tasks["apps"] = _get_json(f"{base_path}/detectedApps", profile=profile)
    if include_compliance:
        tasks["compliance"] = _get_json(f"{base_path}/deviceCompliancePolicyStates", profile=profile)

    results = dict(zip(tasks.keys(), await asyncio.gather(*tasks.values()), strict=True))
    device = results.get("device")
    if device is None:
        return _not_found("Device", query, trace_id)

    data: list[dict[str, Any]] = [{"entity": "device", **device}]
    if include_apps:
        data.append({"entity": "detectedApps", "items": _unwrap_value(results["apps"])})
    if include_compliance:
        data.append({"entity": "compliance", "items": _unwrap_value(results["compliance"])})

    return Envelope.ok_read(
        summary=f"device {loc.display_name or loc.id}",
        data=data,
        trace_id=trace_id,
        next_actions=[
            f"explain device-compliance --device-id {loc.id}",
            f"show user {device.get('userPrincipalName')}" if device.get("userPrincipalName") else "",
        ],
    )


@app.command("user")
def show_user(
    query: str = typer.Argument(..., help="User id or UPN or display name."),
    profile: str = typer.Option("default", "--profile"),
    include_licenses: bool = typer.Option(False, "--include-licenses"),
    include_groups: bool = typer.Option(False, "--include-groups"),
) -> None:
    env = _run(
        _show_user_async(query, profile=profile, include_licenses=include_licenses, include_groups=include_groups)
    )
    emit(env)


async def _show_user_async(
    query: str, *, profile: str, include_licenses: bool, include_groups: bool
) -> Envelope:
    trace_id = _new_trace_id()
    loc = await _resolve_or_id(query, type="user", profile=profile)
    if loc is None:
        return _not_found("User", query, trace_id)

    base_path = f"/users/{loc.id}"
    tasks: dict[str, Any] = {"user": _get_json(base_path, profile=profile)}
    if include_licenses:
        tasks["licenses"] = _get_json(f"{base_path}/licenseDetails", profile=profile)
    if include_groups:
        tasks["groups"] = _get_json(f"{base_path}/memberOf", profile=profile)

    results = dict(zip(tasks.keys(), await asyncio.gather(*tasks.values()), strict=True))
    user = results.get("user")
    if user is None:
        return _not_found("User", query, trace_id)

    data: list[dict[str, Any]] = [{"entity": "user", **user}]
    if include_licenses:
        data.append({"entity": "licenses", "items": _unwrap_value(results["licenses"])})
    if include_groups:
        data.append({"entity": "groups", "items": _unwrap_value(results["groups"])})

    return Envelope.ok_read(
        summary=f"user {loc.upn or loc.display_name or loc.id}",
        data=data,
        trace_id=trace_id,
        next_actions=[
            f"show device --user-id {loc.id}",
            f"hunt signins --user-id {loc.id}",
        ],
    )


@app.command("group")
def show_group(
    query: str = typer.Argument(..., help="Group id or name."),
    profile: str = typer.Option("default", "--profile"),
    include_members: bool = typer.Option(False, "--include-members"),
    include_assignments: bool = typer.Option(False, "--include-assignments"),
) -> None:
    env = _run(
        _show_group_async(query, profile=profile, include_members=include_members, include_assignments=include_assignments)
    )
    emit(env)


async def _show_group_async(
    query: str, *, profile: str, include_members: bool, include_assignments: bool
) -> Envelope:
    trace_id = _new_trace_id()
    loc = await _resolve_or_id(query, type="group", profile=profile)
    if loc is None:
        return _not_found("Group", query, trace_id)

    base_path = f"/groups/{loc.id}"
    tasks: dict[str, Any] = {"group": _get_json(base_path, profile=profile)}
    if include_members:
        tasks["members"] = _get_json(f"{base_path}/members", profile=profile)
    if include_assignments:
        # "Assignments *on* a group" = policies targeting this group. There's no
        # single Graph endpoint; the selector agent or hunt verb resolves it.
        # For show, we return the group's assignments via transitiveMemberOf targets
        # as a best-effort pointer. Consumers who need the full fanout use `hunt`.
        tasks["assignments"] = _get_json(f"{base_path}/transitiveMemberOf", profile=profile)

    results = dict(zip(tasks.keys(), await asyncio.gather(*tasks.values()), strict=True))
    group = results.get("group")
    if group is None:
        return _not_found("Group", query, trace_id)

    data: list[dict[str, Any]] = [{"entity": "group", **group}]
    if include_members:
        data.append({"entity": "members", "items": _unwrap_value(results["members"])})
    if include_assignments:
        data.append({"entity": "assignments", "items": _unwrap_value(results["assignments"])})

    return Envelope.ok_read(
        summary=f"group {loc.display_name or loc.id}",
        data=data,
        trace_id=trace_id,
        next_actions=[
            f"hunt assignment-drift --group-id {loc.id}",
        ],
    )


@app.command("policy")
def show_policy(
    query: str = typer.Argument(..., help="Policy id or name."),
    profile: str = typer.Option("default", "--profile"),
    include_assignments: bool = typer.Option(False, "--include-assignments"),
    include_status: bool = typer.Option(False, "--include-status"),
) -> None:
    env = _run(
        _show_policy_async(query, profile=profile, include_assignments=include_assignments, include_status=include_status)
    )
    emit(env)


async def _show_policy_async(
    query: str, *, profile: str, include_assignments: bool, include_status: bool
) -> Envelope:
    trace_id = _new_trace_id()
    loc = await _resolve_or_id(query, type="policy", profile=profile)
    if loc is None:
        return _not_found("Policy", query, trace_id)

    kind = loc.kind
    tasks: dict[str, Any] = {"policy": _get_json(_pol_kind_path(kind, loc.id), profile=profile)}
    if include_assignments and kind != "conditionalAccess":
        tasks["assignments"] = _get_json(_pol_assignments_path(kind, loc.id), profile=profile)
    if include_status:
        status_path = _pol_status_path(kind, loc.id)
        if status_path is not None:
            tasks["status"] = _get_json(status_path, profile=profile)

    results = dict(zip(tasks.keys(), await asyncio.gather(*tasks.values()), strict=True))
    policy = results.get("policy")
    if policy is None:
        return _not_found("Policy", query, trace_id)

    data: list[dict[str, Any]] = [{"entity": "policy", "kind": kind, **policy}]
    if "assignments" in results:
        data.append({"entity": "assignments", "items": _unwrap_value(results["assignments"])})
    if "status" in results:
        data.append({"entity": "status", "items": _unwrap_value(results["status"])})

    return Envelope.ok_read(
        summary=f"policy {loc.display_name or loc.id}",
        data=data,
        trace_id=trace_id,
        next_actions=[
            f"explain policy-failure --policy-id {loc.id}",
        ],
    )


@app.command("assignment")
def show_assignment(
    id: str = typer.Argument(..., help="Assignment id (policy-id_group-id format)."),
    profile: str = typer.Option("default", "--profile"),
) -> None:
    env = _run(_show_assignment_async(id, profile=profile))
    emit(env)


async def _show_assignment_async(id: str, *, profile: str) -> Envelope:
    trace_id = _new_trace_id()
    # Assignment ids in Intune are composite: <policy-id>_<group-id>. We try the
    # settings-catalog endpoint first since it's the dominant modern shape.
    if "_" not in id:
        return Envelope.err(
            summary=f"assignment id '{id}' is malformed",
            error=ErrorPayload(
                code=ErrorCode.BAD_REQUEST,
                message="assignment id must be <policy-id>_<group-id>",
            ),
            trace_id=trace_id,
        )
    policy_id, _, _ = id.partition("_")

    for path in (
        f"/deviceManagement/configurationPolicies/{policy_id}/assignments/{id}",
        f"/deviceManagement/deviceConfigurations/{policy_id}/assignments/{id}",
        f"/deviceManagement/deviceCompliancePolicies/{policy_id}/assignments/{id}",
    ):
        record = await _get_json(path, profile=profile)
        if record is not None:
            return Envelope.ok_read(
                summary=f"assignment {id}",
                data=[{"entity": "assignment", **record}],
                trace_id=trace_id,
                next_actions=[f"show policy {policy_id}"],
            )
    return _not_found("Assignment", id, trace_id)


def _unwrap_value(body: dict[str, Any] | None) -> list[Any]:
    """Graph collection responses wrap rows in `value`."""
    if body is None:
        return []
    if isinstance(body, dict) and "value" in body and isinstance(body["value"], list):
        return body["value"]
    return [body] if isinstance(body, dict) else []


# --- registration -----------------------------------------------------------


def register(parent: typer.Typer) -> None:
    """Attach the `show` command group to a parent Typer app."""
    parent.add_typer(app, name="show")
