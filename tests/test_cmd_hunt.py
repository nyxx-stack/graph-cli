from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from graphconnect.commands import hunt as hunt_mod


# ---------- fixtures ----------


class _StubResponse:
    def __init__(self, body: Any, status_code: int = 200):
        self.body = body
        self.status_code = status_code
        self.headers: dict[str, str] = {}
        self.request_id = "req-1"
        self.trace_id = "trace-1"
        self.attempts = 1
        self.throttle_wait_s = 0.0
        self.pages = 1


@pytest.fixture
def canned_results() -> dict[str, Any]:
    return {
        "schema": [
            {"Name": "Timestamp", "Type": "DateTime"},
            {"Name": "DeviceName", "Type": "String"},
        ],
        "results": [
            {"Timestamp": "2026-04-23T12:00:00Z", "DeviceName": "pc-01"},
            {"Timestamp": "2026-04-23T12:01:00Z", "DeviceName": "pc-02"},
        ],
    }


@pytest.fixture
def mock_transport(monkeypatch, canned_results):
    calls: list[dict[str, Any]] = []

    async def fake_graph_request(method, path, **kwargs):
        calls.append({"method": method, "path": path, **kwargs})
        return _StubResponse(canned_results)

    monkeypatch.setattr(hunt_mod, "graph_request", fake_graph_request)
    return calls


@pytest.fixture
def mock_no_profiles(monkeypatch):
    monkeypatch.setattr(hunt_mod, "list_profiles", lambda: [])


# ---------- tests ----------


def test_hunt_kql_string_returns_results(mock_transport, mock_no_profiles):
    env = hunt_mod.hunt_command(kql="DeviceEvents | take 2")
    assert env.ok is True
    assert env.mode == "read"
    assert env.data is not None
    assert len(env.data) == 2
    assert env.data[0]["DeviceName"] == "pc-01"
    assert mock_transport[0]["method"] == "POST"
    assert mock_transport[0]["path"] == "/security/runHuntingQuery"
    body = mock_transport[0]["body"]
    assert body["Query"] == "DeviceEvents | take 2"
    assert body["Timespan"] == "P7D"


def test_hunt_file_reads_from_disk(tmp_path: Path, mock_transport, mock_no_profiles):
    kql_file = tmp_path / "q.kql"
    kql_file.write_text("DeviceEvents | take 5", encoding="utf-8")
    env = hunt_mod.hunt_command(file=kql_file, timespan="P1D")
    assert env.ok is True
    body = mock_transport[0]["body"]
    assert body["Query"] == "DeviceEvents | take 5"
    assert body["Timespan"] == "P1D"


def test_hunt_snippet_loads_and_runs(mock_transport, mock_no_profiles):
    env = hunt_mod.hunt_command(snippet="recent_signins_from_new_country")
    assert env.ok is True
    body = mock_transport[0]["body"]
    assert "SigninLogs" in body["Query"]


def test_list_snippets_shows_titles():
    env = hunt_mod.hunt_command(list_snippets=True)
    assert env.ok is True
    assert env.data is not None
    names = {row["name"] for row in env.data}
    assert {
        "recent_signins_from_new_country",
        "device_compliance_failures",
        "risky_admin_activity",
    }.issubset(names)
    titled = {row["name"]: row["title"] for row in env.data}
    assert titled["recent_signins_from_new_country"].startswith("Recent sign-ins")


def test_delegated_profile_emits_warning(monkeypatch, mock_transport):
    class P:
        name = "corp"
        mode = "delegated"
        default = True

    monkeypatch.setattr(hunt_mod, "list_profiles", lambda: [P()])
    env = hunt_mod.hunt_command(kql="DeviceEvents | take 1", profile="corp")
    assert env.ok is True
    assert any("delegated" in w.lower() for w in env.warnings)


def test_app_only_profile_no_warning(monkeypatch, mock_transport):
    class P:
        name = "service"
        mode = "app-secret"
        default = True

    monkeypatch.setattr(hunt_mod, "list_profiles", lambda: [P()])
    env = hunt_mod.hunt_command(kql="DeviceEvents | take 1", profile="service")
    assert env.ok is True
    assert not any("delegated" in w.lower() for w in env.warnings)


def test_default_profile_selection_prefers_app_only(monkeypatch, mock_transport):
    class Delegated:
        name = "corp"
        mode = "delegated"
        default = True

    class App:
        name = "svc"
        mode = "app-cert"
        default = False

    monkeypatch.setattr(hunt_mod, "list_profiles", lambda: [Delegated(), App()])
    env = hunt_mod.hunt_command(kql="DeviceEvents | take 1")
    assert env.ok is True
    assert mock_transport[0]["profile"] == "svc"


def test_default_profile_falls_back_with_warning(monkeypatch, mock_transport):
    class Delegated:
        name = "corp"
        mode = "delegated"
        default = True

    monkeypatch.setattr(hunt_mod, "list_profiles", lambda: [Delegated()])
    env = hunt_mod.hunt_command(kql="DeviceEvents | take 1")
    assert env.ok is True
    assert mock_transport[0]["profile"] == "corp"
    assert any("app-only" in w.lower() or "delegated" in w.lower() for w in env.warnings)


def test_invalid_kql_returns_error_envelope(monkeypatch, mock_no_profiles):
    async def fake_request(method, path, **kwargs):
        raise hunt_mod.GraphTransportError(
            "Graph returned 400",
            status_code=400,
            body={"error": {"code": "BadRequest", "message": "Syntax error at line 1"}},
        )

    monkeypatch.setattr(hunt_mod, "graph_request", fake_request)
    env = hunt_mod.hunt_command(kql="bogus |||")
    assert env.ok is False
    assert env.error is not None
    assert "Syntax error" in env.error.message or "400" in env.error.message


def test_invalid_timespan_rejected(mock_transport, mock_no_profiles):
    import typer

    with pytest.raises(typer.BadParameter):
        hunt_mod.hunt_command(kql="DeviceEvents | take 1", timespan="7days")


def test_mutually_exclusive_sources(mock_no_profiles):
    env = hunt_mod.hunt_command(kql="x", file=Path("y.kql"))
    assert env.ok is False
    assert env.error is not None


def test_register_adds_command():
    import typer

    app = typer.Typer()
    hunt_mod.register(app)
    names = [cmd.name for cmd in app.registered_commands]
    assert "hunt" in names
