"""`change` verb — plan/apply mutation operations with confirmation tokens.

Each subcommand wraps a catalog write/destructive entry through
`executor.preview_write` / `executor.execute_write`. Default flow is `--plan`
(dry-run → Envelope mode="plan" with a token and preview); `--apply --token <t>`
executes. `--breakglass --reason "<text>"` enables emergency application on
entries flagged `emergency_safe: true` with a reduced 60s token TTL and an
audit record tagged `breakglass=true`.
"""

from __future__ import annotations

import asyncio
import shlex
import uuid
from datetime import datetime, timezone
from typing import Any, NamedTuple

import typer

from graphconnect.audit import log_operation
from graphconnect.catalog import get_entry
from graphconnect.executor import execute_write, preview_write
from graphconnect.output import emit
from graphconnect.selectors import (
    AmbiguousMatch,
    Locator,
    NotFound,
    resolve,
    value_list,
)
from graphconnect.transport import GraphTransportError, graph_request
from graphconnect.types import (
    CatalogEntry,
    CliError,
    Envelope,
    ErrorCode,
    ErrorPayload,
    SafetyTier,
    WritePreview,
)

app = typer.Typer(
    name="change",
    help="Plan and apply state-mutating operations with token-gated confirmation.",
    no_args_is_help=True,
)


BREAKGLASS_TTL_S = 60


def _new_trace_id() -> str:
    return uuid.uuid4().hex


async def _resolve_id(query: str, *, type: str, profile: str) -> Locator | None:
    try:
        return await resolve(query, type=type, profile=profile)
    except (NotFound, AmbiguousMatch, LookupError):
        return None


async def _resolve_or_transport_err(
    query: str, *, type: str, profile: str, trace_id: str
) -> tuple[Locator | None, Envelope | None]:
    try:
        loc = await _resolve_id(query, type=type, profile=profile)
    except GraphTransportError as exc:
        return None, Envelope.err(
            summary=f"{type} lookup failed: {exc}",
            error=ErrorPayload(
                code=ErrorCode.UPSTREAM_ERROR,
                message=str(exc),
                hint="Run `graphconnect auth login --profile <name>` to configure credentials.",
            ),
            trace_id=trace_id,
            mode="plan",
        )
    return loc, None


def _err_envelope(
    summary: str,
    code: ErrorCode,
    message: str,
    *,
    trace_id: str,
    mode: str = "plan",
    hint: str | None = None,
) -> Envelope:
    return Envelope.err(
        summary=summary,
        error=ErrorPayload(code=code, message=message, hint=hint),
        trace_id=trace_id,
        mode=mode,  # type: ignore[arg-type]
    )


def _plan_dict(preview: WritePreview, *, ttl_s: int) -> dict[str, Any]:
    return {
        "token": preview.confirm_token,
        "method": preview.method,
        "url": preview.url,
        "body": preview.body,
        "affected_resources": list(preview.affected_resources),
        "reversible": preview.reversible,
        "reverse_operation": preview.reverse_operation,
        "ttl_s": ttl_s,
    }


def _ttl_seconds(entry: CatalogEntry, *, breakglass: bool) -> int:
    if breakglass:
        return BREAKGLASS_TTL_S
    if entry.safety_tier == SafetyTier.DESTRUCTIVE:
        return 60
    return 120


def _apply_command(
    verb: str,
    *,
    profile: str,
    positional: list[str] | None = None,
    options: dict[str, str | None] | None = None,
    breakglass: bool = False,
    reason: str | None = None,
) -> str:
    """Render a `change <verb>` apply invocation with a `{token}` placeholder."""
    parts: list[str] = ["change", verb]
    if positional:
        parts.extend(positional)
    for key, value in (options or {}).items():
        if not value:
            continue
        parts.extend([f"--{key}", value])
    parts.extend(["--profile", profile, "--apply", "--token", "{token}"])
    if breakglass:
        parts.append("--breakglass")
        if reason:
            parts.extend(["--reason", reason])
    return shlex.join(parts)


def _validate_breakglass(
    entry: CatalogEntry,
    *,
    breakglass: bool,
    reason: str | None,
    trace_id: str,
    mode: str,
) -> Envelope | None:
    if not breakglass:
        return None
    if not reason or not reason.strip():
        return _err_envelope(
            summary="--breakglass requires --reason",
            code=ErrorCode.USAGE_ERROR,
            message="--breakglass requires a non-empty --reason.",
            trace_id=trace_id,
            mode=mode,
            hint="Document why the normal plan→apply flow is being bypassed.",
        )
    if not entry.emergency_safe:
        return _err_envelope(
            summary=f"{entry.id} is not emergency_safe",
            code=ErrorCode.PERMISSION_DENIED,
            message=(
                f"Catalog entry '{entry.id}' is not flagged emergency_safe; "
                "--breakglass is refused."
            ),
            trace_id=trace_id,
            mode=mode,
            hint="Only operations marked emergency_safe=true accept --breakglass.",
        )
    return None


async def _run_plan(
    entry: CatalogEntry,
    parameters: dict[str, Any],
    body: dict[str, Any] | None,
    *,
    trace_id: str,
    profile: str,
    verb: str,
    summary: str,
    breakglass: bool,
    reason: str | None,
    apply_command: str | None,
) -> Envelope:
    bg_err = _validate_breakglass(
        entry, breakglass=breakglass, reason=reason, trace_id=trace_id, mode="plan"
    )
    if bg_err is not None:
        log_operation(
            operation_id=entry.id,
            safety_tier=entry.safety_tier,
            method=entry.method,
            graph_url=entry.endpoint,
            parameters=parameters,
            status="error",
            error=bg_err.error.message if bg_err.error else "",
            error_code=bg_err.error.code.value if bg_err.error else None,
            trace_id=trace_id,
            verb=verb,
            profile=profile,
            mode="plan",
            ok=False,
            breakglass=breakglass,
            reason=reason,
        )
        return bg_err

    try:
        preview = await preview_write(entry, parameters, body)
    except CliError as exc:
        return Envelope.err(
            summary=f"{summary} — preview failed",
            error=exc.payload,
            trace_id=trace_id,
            mode="plan",
        )

    ttl_s = _ttl_seconds(entry, breakglass=breakglass)
    plan = _plan_dict(preview, ttl_s=ttl_s)

    next_actions = [
        (apply_command or f"change {verb} --apply --token {{token}}").replace(
            "{token}",
            preview.confirm_token,
        ),
    ]
    return Envelope.ok_plan(
        summary=summary,
        plan=plan,
        trace_id=trace_id,
        warnings=list(preview.warnings),
        next_actions=next_actions,
    )


async def _run_apply(
    entry: CatalogEntry,
    parameters: dict[str, Any],
    body: dict[str, Any] | None,
    *,
    trace_id: str,
    profile: str,
    verb: str,
    summary: str,
    token: str,
    breakglass: bool,
    reason: str | None,
) -> Envelope:
    mode_for_err = "breakglass" if breakglass else "apply"
    bg_err = _validate_breakglass(
        entry,
        breakglass=breakglass,
        reason=reason,
        trace_id=trace_id,
        mode=mode_for_err,
    )
    if bg_err is not None:
        log_operation(
            operation_id=entry.id,
            safety_tier=entry.safety_tier,
            method=entry.method,
            graph_url=entry.endpoint,
            parameters=parameters,
            status="error",
            error=bg_err.error.message if bg_err.error else "",
            error_code=bg_err.error.code.value if bg_err.error else None,
            trace_id=trace_id,
            verb=verb,
            profile=profile,
            mode=mode_for_err,
            ok=False,
            breakglass=breakglass,
            reason=reason,
        )
        return bg_err

    if not token:
        err = ErrorPayload(
            code=ErrorCode.TOKEN_INVALID,
            message="--apply requires --token <t>.",
            hint="Run with --plan first to obtain a confirmation token.",
        )
        return Envelope.err(
            summary=f"{summary} — missing --token",
            error=err,
            trace_id=trace_id,
            mode=mode_for_err,  # type: ignore[arg-type]
        )

    try:
        result = await execute_write(entry, parameters, body, confirm_token=token)
    except CliError as exc:
        log_operation(
            operation_id=entry.id,
            safety_tier=entry.safety_tier,
            method=entry.method,
            graph_url=entry.endpoint,
            parameters=parameters,
            status="error",
            error=exc.payload.message,
            error_code=exc.payload.code.value,
            trace_id=trace_id,
            verb=verb,
            profile=profile,
            mode=mode_for_err,
            ok=False,
            breakglass=breakglass,
            reason=reason,
        )
        return Envelope.err(
            summary=f"{summary} — apply failed",
            error=exc.payload,
            trace_id=trace_id,
            mode=mode_for_err,  # type: ignore[arg-type]
        )

    log_operation(
        operation_id=entry.id,
        safety_tier=entry.safety_tier,
        method=entry.method,
        graph_url=entry.endpoint,
        parameters=parameters,
        status="success",
        confirm_token=token,
        confirmed_at=datetime.now(timezone.utc),
        trace_id=trace_id,
        verb=verb,
        profile=profile,
        mode=mode_for_err,
        ok=True,
        breakglass=breakglass,
        reason=reason,
    )

    data = [result] if isinstance(result, dict) else []
    return Envelope.ok_apply(
        summary=summary,
        data=data,
        trace_id=trace_id,
        breakglass=breakglass,
    )


async def _dispatch(
    entry_id: str,
    parameters: dict[str, Any],
    body: dict[str, Any] | None,
    *,
    plan: bool,
    apply: bool,
    token: str | None,
    breakglass: bool,
    reason: str | None,
    profile: str,
    verb: str,
    summary: str,
    trace_id: str,
    apply_command: str | None = None,
) -> Envelope:
    entry = get_entry(entry_id)
    if entry is None:
        return _err_envelope(
            summary=f"catalog entry '{entry_id}' not found",
            code=ErrorCode.NOT_FOUND,
            message=f"No catalog entry for operation id '{entry_id}'.",
            trace_id=trace_id,
            mode="plan",
        )

    if apply and plan:
        return _err_envelope(
            summary="--plan and --apply are mutually exclusive",
            code=ErrorCode.USAGE_ERROR,
            message="Pass either --plan or --apply, not both.",
            trace_id=trace_id,
            mode="plan",
        )

    if apply:
        return await _run_apply(
            entry,
            parameters,
            body,
            trace_id=trace_id,
            profile=profile,
            verb=verb,
            summary=summary,
            token=token or "",
            breakglass=breakglass,
            reason=reason,
        )

    return await _run_plan(
        entry,
        parameters,
        body,
        trace_id=trace_id,
        profile=profile,
        verb=verb,
        summary=summary,
        breakglass=breakglass,
        reason=reason,
        apply_command=apply_command,
    )


async def _resolve_or_literal(
    query: str, *, type: str, profile: str, trace_id: str
) -> tuple[str | None, Envelope | None]:
    loc, err = await _resolve_or_transport_err(query, type=type, profile=profile, trace_id=trace_id)
    if err is not None:
        return None, err
    if loc is None:
        return None, _err_envelope(
            summary=f"{type} '{query}' not found",
            code=ErrorCode.NOT_FOUND,
            message=f"Could not resolve {type}: {query!r}.",
            trace_id=trace_id,
            mode="plan",
        )
    return loc.id, None


# --- subcommands ------------------------------------------------------------


def _mode_flags(plan: bool, apply: bool) -> tuple[bool, bool]:
    if not plan and not apply:
        return True, False
    return plan, apply


class _AssignmentConfig(NamedTuple):
    create_entry_id: str
    delete_entry_id: str
    base_path: str
    api_version: str
    id_param: str


_ASSIGNMENT_CONFIG: dict[str, _AssignmentConfig] = {
    "settingsCatalog": _AssignmentConfig(
        create_entry_id="policies.create_settings_catalog_assignment",
        delete_entry_id="policies.delete_settings_catalog_assignment",
        base_path="/deviceManagement/configurationPolicies",
        api_version="beta",
        id_param="policy_id",
    ),
    "configurationProfile": _AssignmentConfig(
        create_entry_id="policies.create_config_profile_assignment",
        delete_entry_id="policies.delete_config_profile_assignment",
        base_path="/deviceManagement/deviceConfigurations",
        api_version="v1.0",
        id_param="profile_id",
    ),
    "compliance": _AssignmentConfig(
        create_entry_id="policies.create_compliance_policy_assignment",
        delete_entry_id="policies.delete_compliance_policy_assignment",
        base_path="/deviceManagement/deviceCompliancePolicies",
        api_version="v1.0",
        id_param="policy_id",
    ),
}


def _assignment_config(kind: str | None) -> _AssignmentConfig | None:
    return _ASSIGNMENT_CONFIG.get(kind or "")


async def _find_assignment_id_for_group(
    *,
    policy_id: str,
    config: _AssignmentConfig,
    group_id: str,
    profile: str,
    trace_id: str,
) -> tuple[str | None, Envelope | None]:
    try:
        response = await graph_request(
            "GET",
            f"{config.base_path}/{policy_id}/assignments?$select=id,target",
            profile=profile,
            api_version=config.api_version,  # type: ignore[arg-type]
            paginate=True,
        )
    except GraphTransportError as exc:
        return None, Envelope.err(
            summary=f"assignment lookup failed: {exc}",
            error=ErrorPayload(
                code=ErrorCode.UPSTREAM_ERROR,
                message=str(exc),
                hint="Run `graphconnect auth login --profile <name>` to configure credentials.",
            ),
            trace_id=trace_id,
        )

    for row in value_list(response.body):
        target = row.get("target") or {}
        if str(target.get("groupId") or "") == group_id and row.get("id"):
            return str(row["id"]), None

    return None, _err_envelope(
        summary=f"group '{group_id}' is not assigned",
        code=ErrorCode.NOT_FOUND,
        message=f"Could not find an assignment targeting group '{group_id}' on policy '{policy_id}'.",
        trace_id=trace_id,
    )


@app.command("assign")
def cmd_assign(
    policy: str = typer.Option(..., "--policy", help="Policy id or name."),
    to: str = typer.Option(..., "--to", help="Target group id or name."),
    plan: bool = typer.Option(False, "--plan"),
    apply: bool = typer.Option(False, "--apply"),
    token: str | None = typer.Option(None, "--token"),
    profile: str = typer.Option("default", "--profile"),
) -> None:
    env = asyncio.run(
        _assign_async(
            policy=policy, to=to, plan_flag=plan, apply_flag=apply, token=token, profile=profile
        )
    )
    emit(env)


async def _assign_async(
    *,
    policy: str,
    to: str,
    plan_flag: bool,
    apply_flag: bool,
    token: str | None,
    profile: str,
) -> Envelope:
    plan_flag, apply_flag = _mode_flags(plan_flag, apply_flag)
    trace_id = _new_trace_id()

    (pol_loc, pol_err), (grp_id, err) = await asyncio.gather(
        _resolve_or_transport_err(policy, type="policy", profile=profile, trace_id=trace_id),
        _resolve_or_literal(to, type="group", profile=profile, trace_id=trace_id),
    )
    if pol_err is not None:
        return pol_err
    if pol_loc is None:
        return _err_envelope(
            summary=f"policy '{policy}' not found",
            code=ErrorCode.NOT_FOUND,
            message=f"Could not resolve policy: {policy!r}.",
            trace_id=trace_id,
        )
    if err is not None:
        return err

    config = _assignment_config(pol_loc.kind)
    if config is None:
        return _err_envelope(
            summary=f"policy kind '{pol_loc.kind}' is not assignable via change assign",
            code=ErrorCode.USAGE_ERROR,
            message="Only classic config profiles, Settings Catalog policies, and compliance policies support change assign.",
            trace_id=trace_id,
        )

    parameters = {config.id_param: pol_loc.id, "group_id": grp_id}
    return await _dispatch(
        config.create_entry_id,
        parameters,
        None,
        plan=plan_flag,
        apply=apply_flag,
        token=token,
        breakglass=False,
        reason=None,
        profile=profile,
        verb="assign",
        summary=f"assign {pol_loc.display_name or pol_loc.id} → {to}",
        trace_id=trace_id,
        apply_command=_apply_command(
            "assign",
            profile=profile,
            options={"policy": policy, "to": to},
        ),
    )


@app.command("unassign")
def cmd_unassign(
    policy: str = typer.Option(..., "--policy"),
    from_: str = typer.Option(..., "--from"),
    plan: bool = typer.Option(False, "--plan"),
    apply: bool = typer.Option(False, "--apply"),
    token: str | None = typer.Option(None, "--token"),
    profile: str = typer.Option("default", "--profile"),
) -> None:
    env = asyncio.run(
        _unassign_async(
            policy=policy, from_=from_, plan_flag=plan, apply_flag=apply, token=token, profile=profile
        )
    )
    emit(env)


async def _unassign_async(
    *,
    policy: str,
    from_: str,
    plan_flag: bool,
    apply_flag: bool,
    token: str | None,
    profile: str,
) -> Envelope:
    plan_flag, apply_flag = _mode_flags(plan_flag, apply_flag)
    trace_id = _new_trace_id()

    (pol_loc, pol_err), (grp_id, err) = await asyncio.gather(
        _resolve_or_transport_err(policy, type="policy", profile=profile, trace_id=trace_id),
        _resolve_or_literal(from_, type="group", profile=profile, trace_id=trace_id),
    )
    if pol_err is not None:
        return pol_err
    if pol_loc is None:
        return _err_envelope(
            summary=f"policy '{policy}' not found",
            code=ErrorCode.NOT_FOUND,
            message=f"Could not resolve policy: {policy!r}.",
            trace_id=trace_id,
        )
    if err is not None:
        return err

    config = _assignment_config(pol_loc.kind)
    if config is None:
        return _err_envelope(
            summary=f"policy kind '{pol_loc.kind}' is not unassignable via change unassign",
            code=ErrorCode.USAGE_ERROR,
            message="Only classic config profiles, Settings Catalog policies, and compliance policies support change unassign.",
            trace_id=trace_id,
        )

    assignment_id, assignment_err = await _find_assignment_id_for_group(
        policy_id=pol_loc.id,
        config=config,
        group_id=grp_id,
        profile=profile,
        trace_id=trace_id,
    )
    if assignment_err is not None:
        return assignment_err

    parameters = {config.id_param: pol_loc.id, "assignment_id": assignment_id}
    return await _dispatch(
        config.delete_entry_id,
        parameters,
        None,
        plan=plan_flag,
        apply=apply_flag,
        token=token,
        breakglass=False,
        reason=None,
        profile=profile,
        verb="unassign",
        summary=f"unassign {pol_loc.display_name or pol_loc.id} from {from_}",
        trace_id=trace_id,
        apply_command=_apply_command(
            "unassign",
            profile=profile,
            options={"policy": policy, "from": from_},
        ),
    )


@app.command("sync")
def cmd_sync(
    device: str = typer.Option(..., "--device"),
    plan: bool = typer.Option(False, "--plan"),
    apply: bool = typer.Option(False, "--apply"),
    token: str | None = typer.Option(None, "--token"),
    profile: str = typer.Option("default", "--profile"),
) -> None:
    env = asyncio.run(
        _sync_async(device=device, plan_flag=plan, apply_flag=apply, token=token, profile=profile)
    )
    emit(env)


async def _sync_async(
    *, device: str, plan_flag: bool, apply_flag: bool, token: str | None, profile: str
) -> Envelope:
    plan_flag, apply_flag = _mode_flags(plan_flag, apply_flag)
    trace_id = _new_trace_id()
    dev_id, err = await _resolve_or_literal(device, type="device", profile=profile, trace_id=trace_id)
    if err is not None:
        return err
    return await _dispatch(
        "devices.sync_device",
        {"device_id": dev_id},
        None,
        plan=plan_flag,
        apply=apply_flag,
        token=token,
        breakglass=False,
        reason=None,
        profile=profile,
        verb="sync",
        summary=f"sync device {device}",
        trace_id=trace_id,
        apply_command=_apply_command(
            "sync",
            profile=profile,
            options={"device": device},
        ),
    )


@app.command("retire")
def cmd_retire(
    device: str = typer.Option(..., "--device"),
    plan: bool = typer.Option(False, "--plan"),
    apply: bool = typer.Option(False, "--apply"),
    token: str | None = typer.Option(None, "--token"),
    profile: str = typer.Option("default", "--profile"),
) -> None:
    env = asyncio.run(
        _retire_async(device=device, plan_flag=plan, apply_flag=apply, token=token, profile=profile)
    )
    emit(env)


async def _retire_async(
    *, device: str, plan_flag: bool, apply_flag: bool, token: str | None, profile: str
) -> Envelope:
    plan_flag, apply_flag = _mode_flags(plan_flag, apply_flag)
    trace_id = _new_trace_id()
    dev_id, err = await _resolve_or_literal(device, type="device", profile=profile, trace_id=trace_id)
    if err is not None:
        return err
    return await _dispatch(
        "devices.retire",
        {"device_id": dev_id},
        None,
        plan=plan_flag,
        apply=apply_flag,
        token=token,
        breakglass=False,
        reason=None,
        profile=profile,
        verb="retire",
        summary=f"retire device {device}",
        trace_id=trace_id,
        apply_command=_apply_command(
            "retire",
            profile=profile,
            options={"device": device},
        ),
    )


@app.command("wipe")
def cmd_wipe(
    device: str = typer.Option(..., "--device"),
    plan: bool = typer.Option(False, "--plan"),
    apply: bool = typer.Option(False, "--apply"),
    token: str | None = typer.Option(None, "--token"),
    breakglass: bool = typer.Option(False, "--breakglass"),
    reason: str | None = typer.Option(None, "--reason"),
    profile: str = typer.Option("default", "--profile"),
) -> None:
    env = asyncio.run(
        _wipe_async(
            device=device,
            plan_flag=plan,
            apply_flag=apply,
            token=token,
            breakglass=breakglass,
            reason=reason,
            profile=profile,
        )
    )
    emit(env)


async def _wipe_async(
    *,
    device: str,
    plan_flag: bool,
    apply_flag: bool,
    token: str | None,
    breakglass: bool,
    reason: str | None,
    profile: str,
) -> Envelope:
    plan_flag, apply_flag = _mode_flags(plan_flag, apply_flag)
    trace_id = _new_trace_id()
    dev_id, err = await _resolve_or_literal(device, type="device", profile=profile, trace_id=trace_id)
    if err is not None:
        return err
    return await _dispatch(
        "devices.wipe",
        {"device_id": dev_id},
        None,
        plan=plan_flag,
        apply=apply_flag,
        token=token,
        breakglass=breakglass,
        reason=reason,
        profile=profile,
        verb="wipe",
        summary=f"wipe device {device}",
        trace_id=trace_id,
        apply_command=_apply_command(
            "wipe",
            profile=profile,
            options={"device": device},
            breakglass=breakglass,
            reason=reason,
        ),
    )


@app.command("group-add")
def cmd_group_add(
    user: str = typer.Option(..., "--user"),
    group: str = typer.Option(..., "--group"),
    plan: bool = typer.Option(False, "--plan"),
    apply: bool = typer.Option(False, "--apply"),
    token: str | None = typer.Option(None, "--token"),
    profile: str = typer.Option("default", "--profile"),
) -> None:
    env = asyncio.run(
        _group_add_async(
            user=user, group=group, plan_flag=plan, apply_flag=apply, token=token, profile=profile
        )
    )
    emit(env)


async def _group_add_async(
    *,
    user: str,
    group: str,
    plan_flag: bool,
    apply_flag: bool,
    token: str | None,
    profile: str,
) -> Envelope:
    plan_flag, apply_flag = _mode_flags(plan_flag, apply_flag)
    trace_id = _new_trace_id()
    (usr_id, err_u), (grp_id, err_g) = await asyncio.gather(
        _resolve_or_literal(user, type="user", profile=profile, trace_id=trace_id),
        _resolve_or_literal(group, type="group", profile=profile, trace_id=trace_id),
    )
    if err_u is not None:
        return err_u
    if err_g is not None:
        return err_g
    return await _dispatch(
        "groups.add_member",
        {"group_id": grp_id, "member_id": usr_id},
        None,
        plan=plan_flag,
        apply=apply_flag,
        token=token,
        breakglass=False,
        reason=None,
        profile=profile,
        verb="group-add",
        summary=f"add {user} to group {group}",
        trace_id=trace_id,
        apply_command=_apply_command(
            "group-add",
            profile=profile,
            options={"user": user, "group": group},
        ),
    )


@app.command("group-remove")
def cmd_group_remove(
    user: str = typer.Option(..., "--user"),
    group: str = typer.Option(..., "--group"),
    plan: bool = typer.Option(False, "--plan"),
    apply: bool = typer.Option(False, "--apply"),
    token: str | None = typer.Option(None, "--token"),
    profile: str = typer.Option("default", "--profile"),
) -> None:
    env = asyncio.run(
        _group_remove_async(
            user=user, group=group, plan_flag=plan, apply_flag=apply, token=token, profile=profile
        )
    )
    emit(env)


async def _group_remove_async(
    *,
    user: str,
    group: str,
    plan_flag: bool,
    apply_flag: bool,
    token: str | None,
    profile: str,
) -> Envelope:
    plan_flag, apply_flag = _mode_flags(plan_flag, apply_flag)
    trace_id = _new_trace_id()
    (usr_id, err_u), (grp_id, err_g) = await asyncio.gather(
        _resolve_or_literal(user, type="user", profile=profile, trace_id=trace_id),
        _resolve_or_literal(group, type="group", profile=profile, trace_id=trace_id),
    )
    if err_u is not None:
        return err_u
    if err_g is not None:
        return err_g
    return await _dispatch(
        "groups.remove_member",
        {"group_id": grp_id, "member_id": usr_id},
        None,
        plan=plan_flag,
        apply=apply_flag,
        token=token,
        breakglass=False,
        reason=None,
        profile=profile,
        verb="group-remove",
        summary=f"remove {user} from group {group}",
        trace_id=trace_id,
        apply_command=_apply_command(
            "group-remove",
            profile=profile,
            options={"user": user, "group": group},
        ),
    )


# --- account <enable|disable|reset-password> --------------------------------


account_app = typer.Typer(
    name="account",
    help="User account state changes (enable, disable, reset-password).",
    no_args_is_help=True,
)


@account_app.command("enable")
def cmd_account_enable(
    user: str = typer.Option(..., "--user"),
    plan: bool = typer.Option(False, "--plan"),
    apply: bool = typer.Option(False, "--apply"),
    token: str | None = typer.Option(None, "--token"),
    breakglass: bool = typer.Option(False, "--breakglass"),
    reason: str | None = typer.Option(None, "--reason"),
    profile: str = typer.Option("default", "--profile"),
) -> None:
    env = asyncio.run(
        _account_async(
            action="enable",
            user=user,
            plan_flag=plan,
            apply_flag=apply,
            token=token,
            breakglass=breakglass,
            reason=reason,
            profile=profile,
        )
    )
    emit(env)


@account_app.command("disable")
def cmd_account_disable(
    user: str = typer.Option(..., "--user"),
    plan: bool = typer.Option(False, "--plan"),
    apply: bool = typer.Option(False, "--apply"),
    token: str | None = typer.Option(None, "--token"),
    breakglass: bool = typer.Option(False, "--breakglass"),
    reason: str | None = typer.Option(None, "--reason"),
    profile: str = typer.Option("default", "--profile"),
) -> None:
    env = asyncio.run(
        _account_async(
            action="disable",
            user=user,
            plan_flag=plan,
            apply_flag=apply,
            token=token,
            breakglass=breakglass,
            reason=reason,
            profile=profile,
        )
    )
    emit(env)


@account_app.command("reset-password")
def cmd_account_reset_password(
    user: str = typer.Option(..., "--user"),
    new_password: str | None = typer.Option(None, "--new-password"),
    plan: bool = typer.Option(False, "--plan"),
    apply: bool = typer.Option(False, "--apply"),
    token: str | None = typer.Option(None, "--token"),
    breakglass: bool = typer.Option(False, "--breakglass"),
    reason: str | None = typer.Option(None, "--reason"),
    profile: str = typer.Option("default", "--profile"),
) -> None:
    env = asyncio.run(
        _account_async(
            action="reset-password",
            user=user,
            new_password=new_password,
            plan_flag=plan,
            apply_flag=apply,
            token=token,
            breakglass=breakglass,
            reason=reason,
            profile=profile,
        )
    )
    emit(env)


async def _account_async(
    *,
    action: str,
    user: str,
    plan_flag: bool,
    apply_flag: bool,
    token: str | None,
    breakglass: bool,
    reason: str | None,
    profile: str,
    new_password: str | None = None,
) -> Envelope:
    plan_flag, apply_flag = _mode_flags(plan_flag, apply_flag)
    trace_id = _new_trace_id()
    usr_id, err = await _resolve_or_literal(user, type="user", profile=profile, trace_id=trace_id)
    if err is not None:
        return err

    parameters: dict[str, Any] = {"user_id": usr_id}
    body: dict[str, Any] | None = None

    if action == "enable":
        # TODO(merge): add users.enable_account catalog entry. For v2 we piggy-back
        # on users.disable_account with an explicit body override.
        entry_id = "users.disable_account"
        body = {"accountEnabled": True}
        summary = f"enable account {user}"
    elif action == "disable":
        entry_id = "users.disable_account"
        summary = f"disable account {user}"
    elif action == "reset-password":
        entry_id = "users.reset_password"
        if new_password:
            parameters["new_password"] = new_password
        summary = f"reset password for {user}"
    else:
        return _err_envelope(
            summary=f"unknown account action '{action}'",
            code=ErrorCode.USAGE_ERROR,
            message=f"Unknown account action: {action!r}.",
            trace_id=trace_id,
        )

    return await _dispatch(
        entry_id,
        parameters,
        body,
        plan=plan_flag,
        apply=apply_flag,
        token=token,
        breakglass=breakglass,
        reason=reason,
        profile=profile,
        verb=f"account-{action}",
        summary=summary,
        trace_id=trace_id,
        apply_command=_apply_command(
            "account",
            profile=profile,
            positional=[action],
            options={
                "user": user,
                "new-password": new_password if action == "reset-password" else None,
            },
            breakglass=breakglass,
            reason=reason,
        ),
    )


app.add_typer(account_app, name="account")


# --- registration -----------------------------------------------------------


def register(parent: typer.Typer) -> None:
    """Attach the `change` command group to a parent Typer app."""
    parent.add_typer(app, name="change")
