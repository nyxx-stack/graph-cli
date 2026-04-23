"""Tests for the `find` Typer verb."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import pytest
import typer
from typer.testing import CliRunner

from graphconnect.commands import find as cmd_find
from graphconnect.selectors import resolvers


@dataclass
class _StubResp:
    body: Any
    status_code: int = 200
    headers: dict = None  # type: ignore[assignment]
    request_id: str = "r"
    trace_id: str = "t"
    attempts: int = 1
    throttle_wait_s: float = 0.0
    pages: int = 1

    def __post_init__(self) -> None:
        if self.headers is None:
            self.headers = {}


def _install_stub(monkeypatch, rules):
    async def fake_graph_request(method, path, **kw):
        for needle, body in rules:
            if needle in path:
                return _StubResp(body=body)
        return _StubResp(body={"value": []})

    monkeypatch.setattr(resolvers, "graph_request", fake_graph_request)


def _build_app() -> typer.Typer:
    # Use a second dummy command so Typer keeps the 'find' subcommand name
    # instead of collapsing into a single-command app.
    app = typer.Typer()
    cmd_find.register(app)

    @app.command("_noop", hidden=True)
    def _noop() -> None:
        pass

    return app


def _last_stdout_envelope(stdout: str) -> dict:
    # `output.emit` writes to stdout; the last line should be JSON (or the only
    # line when format=json). Try parsing the entire stdout, then the last line.
    stripped = stdout.strip()
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        lines = [line for line in stripped.splitlines() if line.strip()]
        for line in reversed(lines):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue
        raise AssertionError(f"no JSON envelope in stdout: {stdout!r}")


GUID = "11111111-2222-3333-4444-555555555555"


def test_find_by_name_emits_envelope(monkeypatch):
    _install_stub(monkeypatch, [
        ("/deviceManagement/managedDevices", {"value": [{"id": GUID, "deviceName": "LAPTOP-01"}]}),
    ])
    runner = CliRunner()
    result = runner.invoke(_build_app(), ["find", "LAPTOP-01", "--type", "device"])
    assert result.exit_code == 0, result.output
    env = _last_stdout_envelope(result.stdout)
    assert env["ok"] is True
    assert env["mode"] == "read"
    assert env["data"]
    row = env["data"][0]
    assert row["id"] == GUID
    assert row["type"] == "device"
    assert any(a.startswith("show device ") for a in env["next_actions"])


def test_find_no_match_returns_empty_data(monkeypatch):
    _install_stub(monkeypatch, [
        ("/users", {"value": []}),
    ])
    runner = CliRunner()
    result = runner.invoke(_build_app(), ["find", "ghost", "--type", "user"])
    assert result.exit_code == 0, result.output
    env = _last_stdout_envelope(result.stdout)
    assert env["ok"] is True
    assert env["data"] == []


def test_find_invalid_type_errors(monkeypatch):
    _install_stub(monkeypatch, [])
    runner = CliRunner()
    result = runner.invoke(_build_app(), ["find", "x", "--type", "bogus"])
    assert result.exit_code != 0


def test_find_ambiguous_surfaces_candidates(monkeypatch):
    _install_stub(monkeypatch, [
        (
            "/deviceManagement/managedDevices",
            {
                "value": [
                    {"id": GUID, "deviceName": "LAPTOP-01"},
                    {"id": "22222222-2222-3333-4444-555555555555", "deviceName": "LAPTOP-02"},
                ]
            },
        ),
    ])
    runner = CliRunner()
    # Query "LAPTOP" is a prefix for both — not exact for either, so find()
    # should return both candidates (ambiguity is the UX of find, not an
    # exception).
    result = runner.invoke(_build_app(), ["find", "LAPTOP", "--type", "device"])
    assert result.exit_code == 0, result.output
    env = _last_stdout_envelope(result.stdout)
    assert len(env["data"]) == 2
    assert {row["id"] for row in env["data"]} == {
        GUID,
        "22222222-2222-3333-4444-555555555555",
    }


def test_find_guid_short_circuits_without_list_call(monkeypatch):
    calls: list[str] = []

    async def recording_graph_request(method, path, **kw):
        calls.append(path)
        if path == f"/deviceManagement/managedDevices/{GUID}":
            return _StubResp(body={"id": GUID, "deviceName": "LAPTOP-01"})
        return _StubResp(body={"value": []})

    monkeypatch.setattr(resolvers, "graph_request", recording_graph_request)

    runner = CliRunner()
    result = runner.invoke(_build_app(), ["find", GUID, "--type", "device"])
    assert result.exit_code == 0, result.output
    assert len(calls) == 1


def test_find_profile_forwarded_to_selector(monkeypatch):
    seen_profiles: list[str] = []

    async def recording_graph_request(method, path, **kw):
        seen_profiles.append(kw.get("profile"))
        return _StubResp(body={"value": [{"id": GUID, "deviceName": "DEV"}]})

    monkeypatch.setattr(resolvers, "graph_request", recording_graph_request)

    runner = CliRunner()
    result = runner.invoke(
        _build_app(),
        ["find", "DEV", "--type", "device", "--profile", "prod"],
    )
    assert result.exit_code == 0, result.output
    assert seen_profiles, "no transport calls were made"
    assert all(p == "prod" for p in seen_profiles), seen_profiles
