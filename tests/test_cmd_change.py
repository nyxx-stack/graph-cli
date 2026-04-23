from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from graphconnect.commands import change as change_mod
from graphconnect.commands.change import (
    _account_async,
    _sync_async,
    _wipe_async,
    register,
)
from graphconnect.selectors import Locator
from graphconnect.types import (
    CliError,
    ErrorCode,
    ErrorPayload,
    SafetyTier,
    WritePreview,
)


# --- fakes ------------------------------------------------------------------


def _make_preview(
    *,
    op_id: str,
    tier: SafetyTier,
    method: str = "POST",
    url: str = "https://graph.microsoft.com/v1.0/x",
    body: dict[str, Any] | None = None,
    token: str = "wrt_deadbeef",
    affected: list[str] | None = None,
    reversible: bool = True,
) -> WritePreview:
    return WritePreview(
        operation_id=op_id,
        safety_tier=tier,
        method=method,
        url=url,
        body=body,
        description=f"preview {op_id}",
        affected_resources=affected or [],
        reversible=reversible,
        confirm_token=token,
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=60),
        warnings=[],
        correlation_id="corr-1",
        idempotency_key="idem-1",
    )


def _install_resolve(monkeypatch: pytest.MonkeyPatch, mapping: dict[tuple[str, str], Locator | None]) -> None:
    async def fake_resolve(query: str, *, type: str | None = None, profile: str = "default") -> Locator:
        key = (type or "", query)
        loc = mapping.get(key)
        if loc is None:
            from graphconnect.selectors import NotFound
            raise NotFound(query)
        return loc

    monkeypatch.setattr(change_mod, "resolve", fake_resolve)


def _install_preview_write(
    monkeypatch: pytest.MonkeyPatch,
    preview_factory: Any,
) -> list[tuple[str, dict, dict | None]]:
    calls: list[tuple[str, dict, dict | None]] = []

    async def fake_preview_write(entry, parameters=None, body=None):
        calls.append((entry.id, dict(parameters or {}), body))
        return preview_factory(entry)

    monkeypatch.setattr(change_mod, "preview_write", fake_preview_write)
    return calls


def _install_execute_write(
    monkeypatch: pytest.MonkeyPatch,
    *,
    valid_tokens: set[str],
    result: dict[str, Any] | None = None,
    force_error: CliError | None = None,
    fingerprint_mismatch: bool = False,
) -> list[tuple[str, str]]:
    calls: list[tuple[str, str]] = []

    async def fake_execute_write(entry, parameters=None, body=None, confirm_token: str = ""):
        calls.append((entry.id, confirm_token))
        if force_error is not None:
            raise force_error
        if fingerprint_mismatch:
            raise CliError(
                ErrorPayload(
                    code=ErrorCode.CONFLICT,
                    message="Target resource changed since preview.",
                )
            )
        if confirm_token not in valid_tokens:
            raise CliError(
                ErrorPayload(
                    code=ErrorCode.TOKEN_INVALID,
                    message="Invalid or expired confirmation token.",
                )
            )
        return result or {"ok": True}

    monkeypatch.setattr(change_mod, "execute_write", fake_execute_write)
    return calls


def _silence_audit(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    captured: list[dict[str, Any]] = []

    def fake_log(**kwargs):
        captured.append(kwargs)

    monkeypatch.setattr(change_mod, "log_operation", fake_log)
    return captured


# --- plan -------------------------------------------------------------------


def test_plan_emits_envelope_with_token(monkeypatch: pytest.MonkeyPatch) -> None:
    _silence_audit(monkeypatch)
    _install_resolve(
        monkeypatch,
        {("device", "LAPTOP-01"): Locator(type="device", id="dev-1", display_name="LAPTOP-01")},
    )
    _install_preview_write(
        monkeypatch,
        lambda entry: _make_preview(op_id=entry.id, tier=entry.safety_tier, token="wrt_abc123"),
    )

    env = asyncio.run(
        _sync_async(device="LAPTOP-01", plan_flag=True, apply_flag=False, token=None, profile="default")
    )

    assert env.ok is True
    assert env.mode == "plan"
    assert env.plan is not None
    assert env.plan["token"] == "wrt_abc123"
    assert env.plan["method"] == "POST"
    # devices.sync_device is write tier → ttl 120s for non-breakglass flow.
    assert env.plan["ttl_s"] == 120
    assert any("--apply" in na and "wrt_abc123" in na for na in env.next_actions)


def test_plan_ttl_for_write_tier(monkeypatch: pytest.MonkeyPatch) -> None:
    _silence_audit(monkeypatch)
    _install_resolve(
        monkeypatch,
        {("device", "dev-1"): Locator(type="device", id="dev-1", display_name="dev-1")},
    )
    _install_preview_write(
        monkeypatch,
        lambda entry: _make_preview(op_id=entry.id, tier=entry.safety_tier),
    )
    env = asyncio.run(
        _sync_async(device="dev-1", plan_flag=True, apply_flag=False, token=None, profile="default")
    )
    # devices.sync_device is write tier → ttl 120
    assert env.plan is not None
    assert env.plan["ttl_s"] == 120


# --- apply ------------------------------------------------------------------


def test_apply_with_valid_token_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    _silence_audit(monkeypatch)
    _install_resolve(
        monkeypatch,
        {("device", "dev-1"): Locator(type="device", id="dev-1", display_name="dev-1")},
    )
    _install_execute_write(monkeypatch, valid_tokens={"wrt_goodtoken"}, result={"ok": True})

    env = asyncio.run(
        _sync_async(
            device="dev-1", plan_flag=False, apply_flag=True, token="wrt_goodtoken", profile="default"
        )
    )
    assert env.ok is True
    assert env.mode == "apply"


def test_apply_with_wrong_token_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    _silence_audit(monkeypatch)
    _install_resolve(
        monkeypatch,
        {("device", "dev-1"): Locator(type="device", id="dev-1", display_name="dev-1")},
    )
    _install_execute_write(monkeypatch, valid_tokens={"wrt_correct"})

    env = asyncio.run(
        _sync_async(
            device="dev-1", plan_flag=False, apply_flag=True, token="wrt_wrong", profile="default"
        )
    )
    assert env.ok is False
    assert env.error is not None
    assert env.error.code == ErrorCode.TOKEN_INVALID


def test_apply_missing_token_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    _silence_audit(monkeypatch)
    _install_resolve(
        monkeypatch,
        {("device", "dev-1"): Locator(type="device", id="dev-1", display_name="dev-1")},
    )
    # No execute_write stub needed — we expect early refusal.
    env = asyncio.run(
        _sync_async(device="dev-1", plan_flag=False, apply_flag=True, token=None, profile="default")
    )
    assert env.ok is False
    assert env.error is not None
    assert env.error.code == ErrorCode.TOKEN_INVALID


def test_apply_token_expired(monkeypatch: pytest.MonkeyPatch) -> None:
    _silence_audit(monkeypatch)
    _install_resolve(
        monkeypatch,
        {("device", "dev-1"): Locator(type="device", id="dev-1", display_name="dev-1")},
    )
    err = CliError(
        ErrorPayload(
            code=ErrorCode.TOKEN_EXPIRED,
            message="Token expired.",
        )
    )
    _install_execute_write(monkeypatch, valid_tokens=set(), force_error=err)
    env = asyncio.run(
        _sync_async(
            device="dev-1", plan_flag=False, apply_flag=True, token="wrt_stale", profile="default"
        )
    )
    assert env.ok is False
    assert env.error is not None
    assert env.error.code == ErrorCode.TOKEN_EXPIRED


def test_apply_fingerprint_mismatch_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    _silence_audit(monkeypatch)
    _install_resolve(
        monkeypatch,
        {("device", "dev-1"): Locator(type="device", id="dev-1", display_name="dev-1")},
    )
    _install_execute_write(
        monkeypatch, valid_tokens={"wrt_anything"}, fingerprint_mismatch=True
    )
    env = asyncio.run(
        _sync_async(
            device="dev-1", plan_flag=False, apply_flag=True, token="wrt_anything", profile="default"
        )
    )
    assert env.ok is False
    assert env.error is not None
    assert env.error.code == ErrorCode.CONFLICT


# --- breakglass -------------------------------------------------------------


def test_breakglass_without_reason_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    _silence_audit(monkeypatch)
    _install_resolve(
        monkeypatch,
        {("device", "dev-1"): Locator(type="device", id="dev-1", display_name="dev-1")},
    )
    env = asyncio.run(
        _wipe_async(
            device="dev-1",
            plan_flag=True,
            apply_flag=False,
            token=None,
            breakglass=True,
            reason=None,
            profile="default",
        )
    )
    assert env.ok is False
    assert env.error is not None
    assert env.error.code == ErrorCode.USAGE_ERROR
    assert "reason" in env.error.message.lower()


def test_breakglass_on_emergency_safe_entry_tags_audit(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = _silence_audit(monkeypatch)
    _install_resolve(
        monkeypatch,
        {("device", "dev-1"): Locator(type="device", id="dev-1", display_name="dev-1")},
    )
    _install_execute_write(monkeypatch, valid_tokens={"dst_good"}, result={"wiped": True})

    env = asyncio.run(
        _wipe_async(
            device="dev-1",
            plan_flag=False,
            apply_flag=True,
            token="dst_good",
            breakglass=True,
            reason="stolen device — urgent",
            profile="default",
        )
    )
    assert env.ok is True
    assert env.mode == "breakglass"
    # Ensure the audit record captured breakglass + reason.
    bg_records = [r for r in captured if r.get("breakglass") is True]
    assert bg_records, "expected at least one breakglass audit record"
    assert bg_records[-1]["reason"] == "stolen device — urgent"
    assert bg_records[-1]["ok"] is True


def test_breakglass_ttl_reduced_in_plan(monkeypatch: pytest.MonkeyPatch) -> None:
    _silence_audit(monkeypatch)
    _install_resolve(
        monkeypatch,
        {("device", "dev-1"): Locator(type="device", id="dev-1", display_name="dev-1")},
    )
    _install_preview_write(
        monkeypatch,
        lambda entry: _make_preview(
            op_id=entry.id, tier=entry.safety_tier, token="dst_plan", affected=["dev-1 (LAPTOP-01)"]
        ),
    )
    env = asyncio.run(
        _wipe_async(
            device="dev-1",
            plan_flag=True,
            apply_flag=False,
            token=None,
            breakglass=True,
            reason="incident #1234",
            profile="default",
        )
    )
    assert env.ok is True
    assert env.mode == "plan"
    assert env.plan is not None
    assert env.plan["ttl_s"] == 60


def test_breakglass_on_non_emergency_safe_entry_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """--breakglass on an entry lacking emergency_safe=true is refused."""
    _silence_audit(monkeypatch)

    from graphconnect.types import CatalogEntry

    fake_entry = CatalogEntry(
        id="fake.not_safe",
        summary="fake",
        domain="test",
        safety_tier=SafetyTier.DESTRUCTIVE,
        method="POST",
        endpoint="/fake",
        emergency_safe=False,
    )
    monkeypatch.setattr(change_mod, "get_entry", lambda op_id: fake_entry)
    _install_resolve(
        monkeypatch,
        {("user", "alice@example.com"): Locator(type="user", id="u-1", upn="alice@example.com")},
    )

    env = asyncio.run(
        _account_async(
            action="disable",
            user="alice@example.com",
            plan_flag=True,
            apply_flag=False,
            token=None,
            breakglass=True,
            reason="test",
            profile="default",
        )
    )
    assert env.ok is False
    assert env.error is not None
    assert env.error.code == ErrorCode.PERMISSION_DENIED
    assert "emergency_safe" in env.error.message


# --- registration -----------------------------------------------------------


def test_register_attaches_to_parent() -> None:
    import typer

    parent = typer.Typer()
    register(parent)
    # Registration doesn't raise and attaches a sub-typer named "change".
    # Typer internally tracks sub-typers on the app's registered_groups attribute.
    names = [g.typer_instance.info.name for g in parent.registered_groups]
    assert "change" in names


def test_import_register() -> None:
    from graphconnect.commands.change import register as _r

    assert callable(_r)
