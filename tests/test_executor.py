from __future__ import annotations

import asyncio

import pytest

from graphconnect import audit, executor, safety
from graphconnect.catalog import get_entry
from graphconnect.executor import execute_read, execute_write, preview_write
from graphconnect.types import CatalogEntry, CliError, ErrorCode, SafetyTier


def _entry(**overrides) -> CatalogEntry:
    base = {
        "id": "test.op",
        "summary": "Test operation",
        "description": "Test description",
        "domain": "tests",
        "safety_tier": SafetyTier.READ,
        "method": "GET",
        "endpoint": "/test",
    }
    base.update(overrides)
    return CatalogEntry(**base)


@pytest.fixture
def isolated_graphconnect_state(tmp_path, monkeypatch):
    graph_dir = tmp_path / ".graphconnect"
    monkeypatch.setattr(safety, "TOKEN_DIR", graph_dir)
    monkeypatch.setattr(safety, "TOKEN_FILE", graph_dir / "pending_tokens.json")
    monkeypatch.setattr(audit, "AUDIT_DIR", graph_dir)
    monkeypatch.setattr(audit, "AUDIT_FILE", graph_dir / "audit.jsonl")
    monkeypatch.setattr(audit, "_audit_dir_ready", False)
    yield


def test_execute_read_logs_success_http_status(monkeypatch):
    captured: dict[str, object] = {}

    async def fake_execute_get(*args, **kwargs):
        return [{"id": "1"}], 1, False, 42, 200

    monkeypatch.setattr(executor, "_execute_get", fake_execute_get)
    monkeypatch.setattr(executor, "check_rate_limit", lambda tier: None)
    monkeypatch.setattr(executor, "log_operation", lambda **kwargs: captured.update(kwargs))

    result = asyncio.run(execute_read(_entry(), top=10))

    assert result.item_count == 1
    assert captured["http_status"] == 200
    assert captured["status"] == "success"


def test_preview_and_execute_detect_resource_drift(isolated_graphconnect_state, monkeypatch):
    lookup_calls = 0
    mutation_called = False

    async def fake_fetch_single_resource(url, api_version, *, correlation_id, select=None):
        nonlocal lookup_calls
        lookup_calls += 1
        resource = {
            "id": "device-1",
            "deviceName": "Workstation 1",
            "lastSyncDateTime": "2026-04-01T00:00:00Z" if lookup_calls == 1 else "2026-04-02T00:00:00Z",
        }
        return resource, 10, 200

    async def fake_execute_mutation(*args, **kwargs):
        nonlocal mutation_called
        mutation_called = True
        return None, 0, 204

    monkeypatch.setattr(executor, "_fetch_single_resource", fake_fetch_single_resource)
    monkeypatch.setattr(executor, "_execute_mutation", fake_execute_mutation)
    monkeypatch.setattr(executor, "check_rate_limit", lambda tier: None)

    entry = _entry(
        id="devices.delete_managed_device",
        domain="devices",
        safety_tier=SafetyTier.DESTRUCTIVE,
        method="DELETE",
        endpoint="/deviceManagement/managedDevices/{device_id}",
        preview_lookup_endpoint="/deviceManagement/managedDevices/{device_id}",
        preview_lookup_select=["id", "deviceName", "lastSyncDateTime"],
        execute_fingerprint_fields=["id", "deviceName", "lastSyncDateTime"],
    )

    preview = asyncio.run(preview_write(entry, {"device_id": "device-1"}))

    with pytest.raises(CliError) as exc:
        asyncio.run(
            execute_write(
                entry,
                {"device_id": "device-1"},
                confirm_token=preview.confirm_token,
            )
        )

    assert exc.value.payload.code == ErrorCode.CONFLICT
    assert mutation_called is False


def test_reset_password_preview_redacts_password_and_preserves_execute_body(
    isolated_graphconnect_state, monkeypatch
):
    async def fake_fetch_single_resource(url, api_version, *, correlation_id, select=None):
        return {
            "id": "user-1",
            "displayName": "Ada Lovelace",
            "userPrincipalName": "ada@example.com",
            "accountEnabled": True,
        }, 10, 200

    captured: dict[str, object] = {}

    async def fake_execute_mutation(method, url, api_version, body, headers=None, expected_status=204):
        captured["body"] = body
        return None, 0, expected_status

    monkeypatch.setattr(executor, "_fetch_single_resource", fake_fetch_single_resource)
    monkeypatch.setattr(executor, "_execute_mutation", fake_execute_mutation)
    monkeypatch.setattr(executor, "check_rate_limit", lambda tier: None)

    entry = get_entry("users.reset_password")
    assert entry is not None

    preview = asyncio.run(
        preview_write(
            entry,
            {"user_id": "user-1", "new_password": "Sup3rSecret!", "force_change_next_sign_in": "false"},
        )
    )

    assert preview.body == {
        "passwordProfile": {
            "password": "***REDACTED***",
            "forceChangePasswordNextSignIn": False,
        }
    }

    asyncio.run(
        execute_write(
            entry,
            {"user_id": "user-1", "new_password": "Sup3rSecret!", "force_change_next_sign_in": "false"},
            confirm_token=preview.confirm_token,
        )
    )

    assert captured["body"] == {
        "passwordProfile": {
            "password": "Sup3rSecret!",
            "forceChangePasswordNextSignIn": False,
        }
    }


def test_render_template_omits_missing_optional_placeholders():
    rendered = executor._render_template_value(
        {
            "membershipRule": "{membership_rule}",
            "membershipRuleProcessingState": "{membership_rule_processing_state}",
        },
        {"membership_rule_processing_state": "Paused"},
    )

    assert rendered == {"membershipRuleProcessingState": "Paused"}


def test_conditional_access_update_user_targets_merges_current_policy(
    isolated_graphconnect_state, monkeypatch
):
    async def fake_fetch_single_resource(url, api_version, *, correlation_id, select=None):
        resource = {
            "id": "ca-1",
            "displayName": "Block legacy auth",
            "state": "enabled",
            "modifiedDateTime": "2026-04-14T12:00:00Z",
            "conditions": {
                "users": {
                    "includeUsers": ["user-a"],
                    "excludeUsers": ["user-b"],
                    "includeGroups": [],
                    "excludeGroups": [],
                    "includeRoles": [],
                    "excludeRoles": [],
                }
            },
        }
        return resource, 10, 200

    monkeypatch.setattr(executor, "_fetch_single_resource", fake_fetch_single_resource)

    entry = get_entry("conditional_access.update_user_targets")
    assert entry is not None

    preview = asyncio.run(
        preview_write(
            entry,
            {
                "policy_id": "ca-1",
                "target_list": "excludeUsers",
                "action": "add",
                "user_id": "user-c",
            },
        )
    )

    assert preview.body == {
        "conditions": {
            "users": {
                "includeUsers": ["user-a"],
                "excludeUsers": ["user-b", "user-c"],
                "includeGroups": [],
                "excludeGroups": [],
                "includeRoles": [],
                "excludeRoles": [],
            }
        }
    }
    assert preview.affected_resources == ["Block legacy auth (ca-1)"]


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ('HTTP/1.1 400 Bad Request {"code":"BadRequest"}', ErrorCode.BAD_REQUEST),
        ('HTTP/1.1 403 Forbidden {"code":"Authorization_RequestDenied"}', ErrorCode.PERMISSION_DENIED),
        ('HTTP/1.1 404 Not Found {"code":"ResourceNotFound"}', ErrorCode.NOT_FOUND),
        ('HTTP/1.1 409 Conflict {"code":"Conflict"}', ErrorCode.CONFLICT),
        ('HTTP/1.1 429 Too Many Requests {"code":"TooManyRequests"}', ErrorCode.THROTTLED),
        ("Not authenticated with Microsoft Graph.", ErrorCode.AUTH_REQUIRED),
        ("No usable authentication source found.", ErrorCode.AUTH_REQUIRED),
    ],
)
def test_map_graph_exception_codes(message, expected):
    payload = executor._map_graph_exception(RuntimeError(message))
    assert payload.code == expected
