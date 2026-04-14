from __future__ import annotations

from typer.testing import CliRunner

from graphconnect.main import app


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


def test_catalog_search_finds_new_write_surface():
    result = runner.invoke(app, ["catalog", "search", "conditional access state", "--format", "json"])

    assert result.exit_code == 0
    assert "conditional_access.set_policy_state" in result.stdout


def _result(name: str, status: str, detail: str = "ok", fix: str = ""):
    from graphconnect.doctor import CheckResult

    return CheckResult(name=name, status=status, detail=detail, fix=fix)
