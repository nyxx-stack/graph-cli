from __future__ import annotations

from typer.testing import CliRunner

from graphconnect.catalog import get_entry
from graphconnect.main import app
from graphconnect.types import CatalogEntry, SafetyTier


runner = CliRunner()


def test_help_exposes_graphconnect_command():
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "graphconnect" in result.stdout
    assert "doctor" in result.stdout


def test_doctor_json_output(monkeypatch):
    monkeypatch.setattr("graphconnect.doctor._check_python", lambda: _result("Python", "ok"))
    monkeypatch.setattr("graphconnect.doctor._check_powershell", lambda: _result("PowerShell", "ok"))
    monkeypatch.setattr("graphconnect.doctor._check_sdk", lambda: _result("msgraph-sdk", "ok"))
    monkeypatch.setattr("graphconnect.doctor._check_graph_module", lambda: _result("Microsoft.Graph module", "ok"))
    monkeypatch.setattr("graphconnect.doctor._check_auth", lambda: _result("Auth", "fail", "missing", "login"))

    result = runner.invoke(app, ["doctor", "--format", "json"])

    assert result.exit_code == 1
    assert '"name": "Auth"' in result.stdout
    assert '"status": "fail"' in result.stdout


def test_write_requires_token():
    result = runner.invoke(app, ["write", "devices.sync_device", "--execute"])

    assert result.exit_code == 2
    assert "--execute requires --token" in (result.stderr or result.output)


def test_write_rejects_invalid_json_body():
    result = runner.invoke(app, ["write", "devices.sync_device", "--body", "{nope"])

    assert result.exit_code == 2
    assert "--body is not valid JSON" in (result.stderr or result.output)


def test_write_accepts_json_body_from_file(tmp_path, monkeypatch):
    body_path = tmp_path / "body.json"
    body_path.write_text('{"keepUserData": true}', encoding="utf-8")

    class Preview:
        operation_id = "devices.sync_device"
        safety_tier = SafetyTier.WRITE
        method = "POST"
        url = "/deviceManagement/managedDevices/device-1/syncDevice"
        body = {"keepUserData": True}
        description = "preview"
        affected_resources = []
        reversible = True
        reverse_operation = None
        confirm_token = "token"
        expires_at = "never"
        warnings = []
        correlation_id = "corr"
        idempotency_key = "idem"

        def model_dump(self):
            return {
                "operation_id": self.operation_id,
                "safety_tier": self.safety_tier.value,
                "method": self.method,
                "url": self.url,
                "body": self.body,
                "description": self.description,
                "affected_resources": self.affected_resources,
                "reversible": self.reversible,
                "reverse_operation": self.reverse_operation,
                "confirm_token": self.confirm_token,
                "expires_at": self.expires_at,
                "warnings": self.warnings,
                "correlation_id": self.correlation_id,
                "idempotency_key": self.idempotency_key,
            }

    async def fake_preview_write(entry, parameters, body):
        assert body == {"keepUserData": True}
        return Preview()

    monkeypatch.setattr("graphconnect.executor.preview_write", fake_preview_write)

    result = runner.invoke(app, ["write", "devices.sync_device", "--body", f"@{body_path}", "--format", "json"])

    assert result.exit_code == 0
    assert '"keepUserData": true' in result.stdout


def test_catalog_exposes_contained_intune_assignment_and_state_ops():
    assert get_entry("devices.configuration_states") is not None
    assert get_entry("policies.create_config_profile_assignment") is not None
    assert get_entry("policies.delete_config_profile_assignment") is not None


def test_catalog_search_finds_new_write_surface():
    result = runner.invoke(app, ["catalog", "search", "conditional access state", "--format", "json"])

    assert result.exit_code == 0
    assert "conditional_access.set_policy_state" in result.stdout


def test_read_promotes_filter_from_param(monkeypatch):
    captured: dict[str, object] = {}

    entry = CatalogEntry(
        id="users.list_all",
        summary="List users",
        description="Test",
        domain="users",
        safety_tier=SafetyTier.READ,
        method="GET",
        endpoint="/users",
    )

    monkeypatch.setattr("graphconnect.catalog.get_entry", lambda operation_id: entry)

    async def fake_execute_read(entry, parameters, top, select, filter_expr, expand, order_by):
        captured["parameters"] = parameters
        captured["filter_expr"] = filter_expr
        captured["select"] = select
        captured["expand"] = expand
        captured["order_by"] = order_by

        class Result:
            operation_id = entry.id
            item_count = 0
            has_more = False
            data = []
            execution_time_ms = 1
            request_id = "req"
            correlation_id = "corr"

        return Result()

    monkeypatch.setattr("graphconnect.executor.execute_read", fake_execute_read)

    result = runner.invoke(
        app,
        [
            "read",
            "users.list_all",
            "-p",
            "filter=startswith(userPrincipalName,'DWilliams')",
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    assert captured["parameters"] == {}
    assert captured["filter_expr"] == "startswith(userPrincipalName,'DWilliams')"


def test_read_json_default_emits_rows_only(monkeypatch):
    _stub_read_response(monkeypatch, rows=[{"id": "a"}, {"id": "b"}])

    result = runner.invoke(app, ["read", "users.list_all", "--format", "json"])

    import json as _json

    assert result.exit_code == 0
    parsed = _json.loads(result.stdout)
    # Default stdout is the array — no unwrap needed.
    assert parsed == [{"id": "a"}, {"id": "b"}]
    # Envelope metadata lives on stderr as chatter.
    assert "rows" in (result.stderr or "")


def test_read_envelope_flag_restores_wrapper(monkeypatch):
    _stub_read_response(monkeypatch, rows=[{"id": "a"}])

    result = runner.invoke(
        app,
        ["read", "users.list_all", "--format", "json", "--envelope"],
    )

    import json as _json

    assert result.exit_code == 0
    parsed = _json.loads(result.stdout)
    assert isinstance(parsed, dict)
    assert parsed["data"] == [{"id": "a"}]
    assert "count" in parsed
    assert "correlation_id" in parsed


def _stub_read_response(monkeypatch, rows: list[dict]) -> None:
    entry = CatalogEntry(
        id="users.list_all",
        summary="List users",
        description="Test",
        domain="users",
        safety_tier=SafetyTier.READ,
        method="GET",
        endpoint="/users",
    )
    monkeypatch.setattr("graphconnect.catalog.get_entry", lambda operation_id: entry)

    async def fake_execute_read(entry, parameters, top, select, filter_expr, expand, order_by):
        class Result:
            operation_id = entry.id
            item_count = len(rows)
            has_more = False
            data = rows
            execution_time_ms = 1
            request_id = "req"
            correlation_id = "corr-xyz"

        return Result()

    monkeypatch.setattr("graphconnect.executor.execute_read", fake_execute_read)


def _result(name: str, status: str, detail: str = "ok", fix: str = ""):
    from graphconnect.doctor import CheckResult

    return CheckResult(name=name, status=status, detail=detail, fix=fix)
