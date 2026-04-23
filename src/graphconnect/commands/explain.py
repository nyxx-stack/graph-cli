"""Typer subcommand group: `explain`.

Registers four subcommands: policy-failure, noncompliance, assignment-drift,
enrollment-failure. Each delegates to graphconnect.explain.<subcmd>.run(...)
and emits the returned Envelope.
"""

from __future__ import annotations

import asyncio
from typing import Optional

import typer

from ..explain import (
    assignment_drift as _assignment_drift,
    enrollment_failure as _enrollment_failure,
    noncompliance as _noncompliance,
    policy_failure as _policy_failure,
)
from ..output import emit
from ..selectors import looks_like_guid
from ..types import Envelope, ErrorCode, ErrorPayload


def _run(coro) -> Envelope:
    import uuid

    from ..transport import GraphTransportError

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
            trace_id=uuid.uuid4().hex,
        )


def register(app: typer.Typer) -> None:
    explain_app = typer.Typer(
        name="explain",
        help="Explain why something is failing: policy conflicts, compliance, assignment drift, enrollment failures.",
        no_args_is_help=True,
    )

    @explain_app.command("policy-failure")
    def policy_failure_cmd(
        device_name: Optional[str] = typer.Option(None, "--device-name"),
        device_id: Optional[str] = typer.Option(None, "--device-id"),
        policy_name: Optional[str] = typer.Option(None, "--policy-name"),
        policy_id: Optional[str] = typer.Option(None, "--policy-id"),
        include_compliant: bool = typer.Option(False, "--include-compliant"),
        no_overlap: bool = typer.Option(False, "--no-overlap-context"),
        top: int = typer.Option(0, "--top"),
        profile: str = typer.Option("default", "--profile"),
        bare: bool = typer.Option(False, "--bare"),
    ) -> None:
        env = _run(
            _policy_failure.run(
                device_id=device_id,
                device_name=device_name,
                policy_id=policy_id,
                policy_name=policy_name,
                include_compliant=include_compliant,
                include_overlap_context=not no_overlap,
                top=top,
                profile=profile,
            )
        )
        emit(env, bare=bare)

    @explain_app.command("noncompliance")
    def noncompliance_cmd(
        device: str = typer.Option(..., "--device", help="Managed device name or id"),
        profile: str = typer.Option("default", "--profile"),
        bare: bool = typer.Option(False, "--bare"),
    ) -> None:
        kwargs: dict = {"profile": profile}
        if looks_like_guid(device):
            kwargs["device_id"] = device
        else:
            kwargs["device_name"] = device
        env = _run(_noncompliance.run(**kwargs))
        emit(env, bare=bare)

    @explain_app.command("assignment-drift")
    def assignment_drift_cmd(
        policy: str = typer.Option(..., "--policy", help="Policy name or id"),
        include_groups: bool = typer.Option(False, "--include-groups"),
        profile: str = typer.Option("default", "--profile"),
        bare: bool = typer.Option(False, "--bare"),
    ) -> None:
        kwargs: dict = {"profile": profile, "include_groups": include_groups}
        if looks_like_guid(policy):
            kwargs["policy_id"] = policy
        else:
            kwargs["policy_name"] = policy
        env = _run(_assignment_drift.run(**kwargs))
        emit(env, bare=bare)

    @explain_app.command("enrollment-failure")
    def enrollment_failure_cmd(
        user: Optional[str] = typer.Option(None, "--user"),
        device: Optional[str] = typer.Option(None, "--device"),
        profile: str = typer.Option("default", "--profile"),
        bare: bool = typer.Option(False, "--bare"),
    ) -> None:
        env = _run(
            _enrollment_failure.run(user=user, device=device, profile=profile)
        )
        emit(env, bare=bare)

    app.add_typer(explain_app)
