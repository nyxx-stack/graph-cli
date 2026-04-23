from __future__ import annotations

import asyncio

import pytest

from graphconnect import audit, executor, safety
from graphconnect.catalog import get_entry
from graphconnect.executor import execute_read, execute_write, preview_write
from graphconnect.types import (
    CatalogEntry,
    CatalogParameter,
    CatalogProjection,
    CliError,
    ErrorCode,
    SafetyTier,
)


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
        parameters=[CatalogParameter(name="device_id", type="string", required=True)],
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


def test_specialized_hint_returns_none_by_default():
    # Regression guard: future hints must be empirical (reproducible via probe)
    # and must not send operators on retry loops past a root-cause bug. The
    # previous "known Graph issue — retry in 10-15 min" for classic
    # /deviceStatuses 500 was wrong — the real bug was $select in our catalog.
    assert executor._specialized_hint("anything", 500) is None


def test_normalize_values_falls_back_on_out_of_range_timestamp():
    # Intune classic profiles emit /Date(-1)/ as a "never" sentinel; on Windows
    # this raises OSError [Errno 22] from datetime.fromtimestamp. The normalizer
    # must fall back to the literal string instead of crashing the whole op.
    row = {"complianceGracePeriodExpirationDateTime": "/Date(-1)/"}
    out = executor._normalize_values(row)
    # Either the literal sentinel or a valid ISO 8601 string is acceptable;
    # what's NOT acceptable is the call raising.
    assert out["complianceGracePeriodExpirationDateTime"] is not None


def test_normalize_values_converts_ms_date_strings_to_iso():
    row = {
        "lastSyncDateTime": "/Date(1776772080000)/",
        "nested": {"createdDateTime": "/Date(1635505590813)/"},
        "passthrough": "/Date(not-a-number)/",
        "normal": "2026-04-22T00:00:00Z",
    }
    out = executor._normalize_values(row)
    assert out["lastSyncDateTime"].startswith("2026-")
    assert out["lastSyncDateTime"].endswith("Z")
    assert out["nested"]["createdDateTime"].startswith("2021-")
    # Non-numeric content stays literal (still useful for debugging).
    assert out["passthrough"] == "/Date(not-a-number)/"
    assert out["normal"] == "2026-04-22T00:00:00Z"


def test_split_field_path_preserves_odata_annotations():
    assert executor._split_field_path("target.@odata.type") == ("target", "@odata.type")
    assert executor._split_field_path("settingInstance.@odata.type") == (
        "settingInstance",
        "@odata.type",
    )
    assert executor._split_field_path("a.b.c") == ("a", "b", "c")


def test_extract_field_path_reads_odata_annotation():
    row = {"target": {"@odata.type": "#microsoft.graph.groupAssignmentTarget"}}
    assert (
        executor._extract_field_path(row, "target.@odata.type")
        == "#microsoft.graph.groupAssignmentTarget"
    )


def test_apply_projections_flattens_and_maps_enum():
    projections = [
        CatalogProjection(name="groupId", path="target.groupId"),
        CatalogProjection(
            name="Status",
            path="PolicyStatus",
            enum_map={"5": "Error", "6": "Conflict"},
        ),
    ]
    row = {"target": {"groupId": "abc-123"}, "PolicyStatus": 5}
    executor._apply_projections(row, projections)
    assert row["groupId"] == "abc-123"
    assert row["Status"] == "Error"
    # Raw numeric column preserved.
    assert row["PolicyStatus"] == 5


def test_post_process_rows_handles_missing_paths_as_none():
    projections = [CatalogProjection(name="groupId", path="target.groupId")]
    out = executor._post_process_rows([{"id": "x"}], projections)
    assert out == [{"id": "x", "groupId": None}]


def test_execute_read_applies_projections_and_date_normalization(monkeypatch):
    async def fake_execute_get(*args, **kwargs):
        return (
            [
                {
                    "target": {"groupId": "group-1"},
                    "PolicyStatus": 6,
                    "lastSyncDateTime": "/Date(1635505590813)/",
                }
            ],
            1,
            False,
            64,
            200,
        )

    monkeypatch.setattr(executor, "_execute_get", fake_execute_get)
    monkeypatch.setattr(executor, "check_rate_limit", lambda tier: None)
    monkeypatch.setattr(executor, "log_operation", lambda **kwargs: None)

    entry = _entry(
        projections=[
            CatalogProjection(name="groupId", path="target.groupId"),
            CatalogProjection(
                name="Status",
                path="PolicyStatus",
                enum_map={"6": "Conflict"},
            ),
        ],
    )
    result = asyncio.run(execute_read(entry, top=10))
    row = result.data[0]
    assert row["groupId"] == "group-1"
    assert row["Status"] == "Conflict"
    assert row["lastSyncDateTime"].startswith("2021-")


def test_normalize_export_rows_handles_columns_and_dict_values():
    document = {
        "columns": ["DeviceId", "SettingName", "SettingStatus"],
        "values": [
            {"DeviceId": "dev-1", "SettingName": "PrivilegeUse_AuditSensitivePrivilegeUse", "SettingStatus": 6}
        ],
    }

    assert executor._normalize_export_rows(document) == document["values"]


def test_execute_read_downloads_export_job(monkeypatch):
    async def fake_execute_mutation(method, url, api_version, body, headers=None, expected_status=204):
        assert method == "POST"
        assert body["reportName"] == "DevicePolicySettingsComplianceReport"
        return {"id": "job-1", "status": "completed", "url": "https://example.invalid/export.zip"}, 12, 201

    async def fake_download_export_rows(download_url):
        assert download_url == "https://example.invalid/export.zip"
        return (
            [
                {"SettingName": "PrivilegeUse_AuditSensitivePrivilegeUse", "SettingStatus": 6},
                {"SettingName": "DetailedTracking_AuditPNPActivity", "SettingStatus": 2},
            ],
            20,
        )

    monkeypatch.setattr(executor, "_execute_mutation", fake_execute_mutation)
    monkeypatch.setattr(executor, "_download_export_rows", fake_download_export_rows)
    monkeypatch.setattr(executor, "check_rate_limit", lambda tier: None)
    monkeypatch.setattr(executor, "log_operation", lambda **kwargs: None)

    entry = _entry(
        method="POST",
        endpoint="/deviceManagement/reports/exportJobs",
        download_export=True,
        parameters=[
            CatalogParameter(name="device_id", type="string", required=True),
            CatalogParameter(name="policy_id", type="string", required=True),
        ],
        body_template={
            "reportName": "DevicePolicySettingsComplianceReport",
            "format": "json",
            "filter": "(DeviceId eq '{device_id}') and (PolicyId eq '{policy_id}')",
        },
        projections=[
            CatalogProjection(
                name="Status",
                path="SettingStatus",
                enum_map={"2": "Compliant", "6": "Conflict"},
            )
        ],
    )

    result = asyncio.run(
        execute_read(
            entry,
            parameters={"device_id": "dev-1", "policy_id": "policy-1"},
            top=1,
        )
    )

    assert result.item_count == 1
    assert result.total_count == 2
    assert result.has_more is True
    assert result.data[0]["SettingName"] == "PrivilegeUse_AuditSensitivePrivilegeUse"
    assert result.data[0]["Status"] == "Conflict"


def test_execute_export_job_read_uses_cache(monkeypatch):
    monkeypatch.setattr(
        executor,
        "_load_cached_export_rows",
        lambda **kwargs: ([{"SettingName": "CachedSetting"}], 33),
    )

    async def fail_execute_mutation(*args, **kwargs):
        raise AssertionError("cache hit should skip export job creation")

    monkeypatch.setattr(executor, "_execute_mutation", fail_execute_mutation)

    rows, total_count, has_more, bytes_read, http_status = asyncio.run(
        executor._execute_export_job_read(
            url="/deviceManagement/reports/exportJobs",
            api_version="beta",
            request_body={"reportName": "DevicePolicySettingsComplianceReport"},
            headers=None,
            top=10,
            correlation_id="corr-1",
        )
    )

    assert rows == [{"SettingName": "CachedSetting"}]
    assert total_count == 1
    assert has_more is False
    assert bytes_read == 33
    assert http_status == 200


def test_execute_read_policy_setting_statuses_resolves_names_filters_failures_and_adds_overlap(
    monkeypatch,
):
    async def fake_resolve_context(parameters, correlation_id, *, policy_lookup=None):
        return {
            "device_id": "dev-1",
            "device_name": "DANAEH-PC",
            "device_user_principal_name": None,
            "policy_id": "policy-1",
            "policy_name": "Audit and Event Logging",
            "policy_kind": "settings_catalog",
        }

    async def fake_fetch_policy_setting_rows(device_id, *, policy_id=None, correlation_id):
        all_rows = [
            {
                "DeviceId": "dev-1",
                "PolicyId": "policy-1",
                "SettingName": "PrivilegeUse_AuditSensitivePrivilegeUse",
                "SettingStatus": 6,
                "SettingStatus_loc": "Conflict",
                "ErrorCode": -2016281211,
            },
            {
                "DeviceId": "dev-1",
                "PolicyId": "policy-1",
                "SettingName": "DetailedTracking_AuditPNPActivity",
                "SettingStatus": 2,
                "SettingStatus_loc": "Compliant",
                "ErrorCode": None,
            },
            {
                "DeviceId": "dev-1",
                "PolicyId": "policy-2",
                "SettingName": "PrivilegeUse_AuditSensitivePrivilegeUse",
                "SettingStatus": 2,
                "SettingStatus_loc": "Compliant",
            },
        ]
        if policy_id is None:
            return all_rows, 44
        return [row for row in all_rows if row["PolicyId"] == policy_id], 44

    async def fake_list_policy_lookup(correlation_id):
        return {
            "policy-1": {"id": "policy-1", "name": "Audit and Event Logging", "kind": "settings_catalog"},
            "policy-2": {"id": "policy-2", "name": "Legacy Baseline", "kind": "config_profile"},
        }

    monkeypatch.setattr(executor, "_resolve_policy_setting_context", fake_resolve_context)
    monkeypatch.setattr(executor, "_fetch_policy_setting_rows", fake_fetch_policy_setting_rows)
    monkeypatch.setattr(executor, "_list_policy_lookup", fake_list_policy_lookup)
    monkeypatch.setattr(executor, "check_rate_limit", lambda tier: None)
    monkeypatch.setattr(executor, "log_operation", lambda **kwargs: None)

    entry = _entry(
        id="devices.policy_setting_statuses",
        method="POST",
        endpoint="/deviceManagement/reports/exportJobs",
        download_export=True,
        parameters=[
            CatalogParameter(name="device_name", type="string"),
            CatalogParameter(name="policy_name", type="string"),
            CatalogParameter(name="failures_only", type="boolean", default=False),
            CatalogParameter(name="include_overlap_context", type="boolean", default=False),
        ],
        projections=[
            CatalogProjection(name="Status", path="SettingStatus", enum_map={"2": "Compliant", "6": "Conflict"})
        ],
        dedupe_by=["DeviceId", "PolicyId", "SettingName", "SettingStatus"],
    )

    result = asyncio.run(
        execute_read(
            entry,
            parameters={
                "device_name": "DANAEH-PC",
                "policy_name": "Audit and Event Logging",
                "failures_only": "true",
                "include_overlap_context": "true",
            },
            top=10,
        )
    )

    assert result.item_count == 1
    row = result.data[0]
    assert row["Status"] == "Conflict"
    assert row["SettingLabel"] == "Privilege Use - Audit Sensitive Privilege Use"
    assert row["OtherPolicies"] == ["Legacy Baseline"]
    assert "Conflict" in row["ErrorHint"]


def test_execute_read_explain_policy_failure_postprocesses_operator_fields(monkeypatch):
    async def fake_explain(parameters, top, correlation_id):
        return (
            [
                {
                    "DeviceName": "DANAEH-PC",
                    "PolicyName": "Audit and Event Logging",
                    "SettingName": "PrivilegeUse_AuditSensitivePrivilegeUse",
                    "SettingStatus": 6,
                    "SettingStatus_loc": "Conflict",
                    "ErrorCode": -2016281211,
                    "OtherPolicies": ["Legacy Baseline"],
                    "ConflictHint": "Also set by: Legacy Baseline",
                }
            ],
            1,
            False,
            21,
            200,
        )

    monkeypatch.setattr(executor, "_execute_explain_policy_failure", fake_explain)
    monkeypatch.setattr(executor, "check_rate_limit", lambda tier: None)
    monkeypatch.setattr(executor, "log_operation", lambda **kwargs: None)

    entry = _entry(
        id="devices.explain_policy_failure",
        method="GET",
        endpoint="/internal/devices/explainPolicyFailure",
        parameters=[
            CatalogParameter(name="device_name", type="string"),
            CatalogParameter(name="policy_name", type="string"),
        ],
    )

    result = asyncio.run(
        execute_read(
            entry,
            parameters={"device_name": "DANAEH-PC", "policy_name": "Audit and Event Logging"},
            top=10,
        )
    )

    row = result.data[0]
    assert row["SettingLabel"] == "Privilege Use - Audit Sensitive Privilege Use"
    assert row["ErrorHint"] == "Conflict: another assigned policy is setting this value."
    assert row["ConflictHint"] == "Also set by: Legacy Baseline"


def test_multi_filter_expands_comma_list_to_odata_in(monkeypatch):
    captured: dict[str, object] = {}

    async def fake_execute_get(url, api_version, query_params, top, singleton=False, headers=None):
        captured["query_params"] = dict(query_params)
        return [], 0, False, 0, 200

    monkeypatch.setattr(executor, "_execute_get", fake_execute_get)
    monkeypatch.setattr(executor, "check_rate_limit", lambda tier: None)
    monkeypatch.setattr(executor, "log_operation", lambda **kwargs: None)

    entry = _entry(
        parameters=[
            CatalogParameter(
                name="group_ids",
                multi=True,
                maps_to_filter="id in ({value})",
            )
        ],
    )
    asyncio.run(execute_read(entry, parameters={"group_ids": "a,b,c"}, top=10))
    assert captured["query_params"]["$filter"] == "id in ('a','b','c')"


def test_value_map_selects_per_enum_filter_clause(monkeypatch):
    captured: dict[str, object] = {}

    async def fake_execute_get(url, api_version, query_params, top, singleton=False, headers=None):
        captured["query_params"] = dict(query_params)
        return [], 0, False, 0, 200

    monkeypatch.setattr(executor, "_execute_get", fake_execute_get)
    monkeypatch.setattr(executor, "check_rate_limit", lambda tier: None)
    monkeypatch.setattr(executor, "log_operation", lambda **kwargs: None)

    entry = _entry(
        endpoint="/auditLogs/signIns",
        parameters=[
            CatalogParameter(
                name="status_filter",
                enum=["success", "failure"],
                value_map={
                    "success": "status/errorCode eq 0",
                    "failure": "status/errorCode ne 0",
                },
            )
        ],
    )
    asyncio.run(execute_read(entry, parameters={"status_filter": "failure"}, top=10))
    assert captured["query_params"]["$filter"] == "status/errorCode ne 0"


def test_validate_parameters_rejects_unknown_key():
    entry = _entry(
        parameters=[CatalogParameter(name="device_id", type="string", required=True)],
        endpoint="/deviceManagement/managedDevices/{device_id}",
    )
    with pytest.raises(CliError) as exc:
        executor._validate_parameters(entry, {"device_id": "x", "bogus_key": "y"})
    assert exc.value.payload.code == ErrorCode.USAGE_ERROR
    assert "bogus_key" in exc.value.payload.message


def test_validate_parameters_rejects_missing_path_placeholder():
    entry = _entry(
        parameters=[CatalogParameter(name="device_id", type="string", required=True)],
        endpoint="/deviceManagement/managedDevices/{device_id}",
    )
    with pytest.raises(CliError) as exc:
        executor._validate_parameters(entry, {})
    assert exc.value.payload.code == ErrorCode.USAGE_ERROR
    assert "device_id" in exc.value.payload.message


def test_audit_url_attaches_query_string():
    assert executor._audit_url("/users", {"$top": "10", "$filter": "a eq 'b'"}).startswith("/users?")
    assert executor._audit_url("/users", {}) == "/users"
    assert executor._audit_url("/users", None) == "/users"


def test_audit_directory_logs_postprocess_parses_json_string_values():
    rows = [
        {
            "targetResources": [
                {
                    "modifiedProperties": [
                        {"displayName": "DisplayName", "oldValue": "[]", "newValue": '["Pilot Ring 1"]'},
                        {"displayName": "SecurityEnabled", "oldValue": "[]", "newValue": "[true]"},
                        {"displayName": "Other", "oldValue": None, "newValue": None},
                    ]
                }
            ]
        }
    ]
    executor._apply_operation_specific_postprocess("audit.directory_logs", rows)
    props = rows[0]["targetResources"][0]["modifiedProperties"]
    assert props[0]["oldValue"] == []
    assert props[0]["newValue"] == ["Pilot Ring 1"]
    assert props[1]["newValue"] == [True]
    assert props[2]["oldValue"] is None  # unchanged


def test_users_list_privileged_postprocess_flattens_member_upns():
    rows = [
        {
            "displayName": "Global Administrator",
            "members": [
                {"userPrincipalName": "a@x.com"},
                {"userPrincipalName": "b@x.com"},
                {"displayName": "no upn"},
            ],
        }
    ]
    executor._apply_operation_specific_postprocess("users.list_privileged", rows)
    assert rows[0]["memberUPNs"] == ["a@x.com", "b@x.com", None]
    assert rows[0]["memberCount"] == 3


def test_multi_filter_escapes_single_quotes(monkeypatch):
    captured: dict[str, object] = {}

    async def fake_execute_get(url, api_version, query_params, top, singleton=False, headers=None):
        captured["query_params"] = dict(query_params)
        return [], 0, False, 0, 200

    monkeypatch.setattr(executor, "_execute_get", fake_execute_get)
    monkeypatch.setattr(executor, "check_rate_limit", lambda tier: None)
    monkeypatch.setattr(executor, "log_operation", lambda **kwargs: None)

    entry = _entry(
        parameters=[
            CatalogParameter(
                name="names",
                multi=True,
                maps_to_filter="displayName in ({value})",
            )
        ],
    )
    asyncio.run(execute_read(entry, parameters={"names": "O'Brien,plain"}, top=10))
    assert captured["query_params"]["$filter"] == "displayName in ('O''Brien','plain')"
