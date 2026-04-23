from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from graphconnect.commands import raw as raw_module
from graphconnect.commands.raw import register
from graphconnect.types import Envelope


# --- fixtures ---------------------------------------------------------------


class _FakeResponse:
    def __init__(self, *, status_code: int = 200, body: Any = None, headers: dict | None = None):
        self.status_code = status_code
        self.body = body
        self.headers = headers or {}
        self.request_id = "req-123"
        self.trace_id = "trace-abc"
        self.attempts = 1
        self.throttle_wait_s = 0.0


@pytest.fixture
def isolated_state(tmp_path, monkeypatch):
    """Isolate token + audit file locations so tests don't touch real home dir."""
    monkeypatch.setattr(raw_module, "_TOKEN_DIR", tmp_path)
    monkeypatch.setattr(raw_module, "_TOKEN_FILE", tmp_path / "tokens.json")
    monkeypatch.setattr(raw_module, "_AUDIT_DIR", tmp_path / "audit")
    yield tmp_path


def _mock_graph_request(response: _FakeResponse | Exception):
    calls: list[dict[str, Any]] = []

    async def _fake(method, path, **kwargs):
        calls.append({"method": method, "path": path, **kwargs})
        if isinstance(response, Exception):
            raise response
        return response

    return _fake, calls


def _read_audit_records(audit_dir: Path) -> list[dict[str, Any]]:
    records = []
    if not audit_dir.exists():
        return records
    for ndjson in audit_dir.glob("*.ndjson"):
        for line in ndjson.read_text(encoding="utf-8").splitlines():
            if line.strip():
                records.append(json.loads(line))
    return records


# --- register ---------------------------------------------------------------


def test_register_attaches_raw_subcommand():
    import typer

    parent = typer.Typer()
    register(parent)
    # raw is registered as a single command on the parent (not a sub-app) so
    # that option-after-positional parsing works cleanly under Typer/Click.
    names = [c.name for c in parent.registered_commands]
    assert "raw" in names


def test_register_symbol_importable():
    from graphconnect.commands.raw import register as r

    assert callable(r)


# --- GET --------------------------------------------------------------------


def test_raw_get_users_emits_read_envelope(isolated_state):
    response = _FakeResponse(body={"value": [{"id": "u1", "displayName": "Alice"}]})
    fake, calls = _mock_graph_request(response)

    with patch.object(raw_module, "graph_request", fake):
        env: Envelope = raw_module.raw_cmd(
            method="GET",
            path="/users",
            body=None,
            body_file=None,
            plan=False,
            apply=False,
            token=None,
            profile="default",
            query_params="$top=1",
            api_version="v1.0",
            force_allow_delete=False,
        )

    assert env.ok is True
    assert env.mode == "read"
    assert env.data == [{"id": "u1", "displayName": "Alice"}]
    assert calls[0]["method"] == "GET"
    assert "/users" in calls[0]["path"]
    assert "$top=1" in calls[0]["path"]


def test_raw_get_single_object_wraps_as_row(isolated_state):
    response = _FakeResponse(body={"id": "u1", "displayName": "Alice"})
    fake, _ = _mock_graph_request(response)

    with patch.object(raw_module, "graph_request", fake):
        env = raw_module.raw_cmd(
            method="GET",
            path="/users/u1",
            body=None,
            body_file=None,
            plan=False,
            apply=False,
            token=None,
            profile="default",
            query_params=None,
            api_version="v1.0",
            force_allow_delete=False,
        )

    assert env.ok is True
    assert env.data == [{"id": "u1", "displayName": "Alice"}]


# --- non-GET without --plan/--apply refuses ---------------------------------


def test_raw_post_without_plan_or_apply_refuses(isolated_state, tmp_path):
    body_file = tmp_path / "body.json"
    body_file.write_text(json.dumps({"displayName": "Test Group"}), encoding="utf-8")

    fake, calls = _mock_graph_request(_FakeResponse())

    with patch.object(raw_module, "graph_request", fake):
        env = raw_module.raw_cmd(
            method="POST",
            path="/groups",
            body=None,
            body_file=body_file,
            plan=False,
            apply=False,
            token=None,
            profile="default",
            query_params=None,
            api_version="v1.0",
            force_allow_delete=False,
        )

    assert env.ok is False
    assert env.error is not None
    assert "plan" in env.error.message.lower() or "apply" in env.error.message.lower()
    assert calls == []  # no live call was made


# --- --plan mints token -----------------------------------------------------


def test_raw_post_plan_returns_plan_envelope_with_token(isolated_state, tmp_path):
    body_file = tmp_path / "body.json"
    body_file.write_text(json.dumps({"displayName": "Test Group"}), encoding="utf-8")

    fake, calls = _mock_graph_request(_FakeResponse())

    with patch.object(raw_module, "graph_request", fake):
        env = raw_module.raw_cmd(
            method="POST",
            path="/groups",
            body=None,
            body_file=body_file,
            plan=True,
            apply=False,
            token=None,
            profile="default",
            query_params=None,
            api_version="v1.0",
            force_allow_delete=False,
        )

    assert env.ok is True
    assert env.mode == "plan"
    assert env.plan is not None
    assert env.plan["method"] == "POST"
    assert env.plan["path"] == "/groups"
    assert env.plan["body"] == {"displayName": "Test Group"}
    assert env.plan.get("token")
    assert env.plan.get("ttl_s") == 120
    assert calls == []  # plan never executes


# --- --apply with token executes --------------------------------------------


def test_raw_post_apply_with_valid_token_executes(isolated_state, tmp_path):
    body_file = tmp_path / "body.json"
    body_file.write_text(json.dumps({"displayName": "Test Group"}), encoding="utf-8")

    with patch.object(raw_module, "graph_request", _mock_graph_request(_FakeResponse())[0]):
        plan_env = raw_module.raw_cmd(
            method="POST",
            path="/groups",
            body=None,
            body_file=body_file,
            plan=True,
            apply=False,
            token=None,
            profile="default",
            query_params=None,
            api_version="v1.0",
            force_allow_delete=False,
        )
    token = plan_env.plan["token"]

    response = _FakeResponse(status_code=201, body={"id": "g99", "displayName": "Test Group"})
    fake, calls = _mock_graph_request(response)

    with patch.object(raw_module, "graph_request", fake):
        env = raw_module.raw_cmd(
            method="POST",
            path="/groups",
            body=None,
            body_file=body_file,
            plan=False,
            apply=True,
            token=token,
            profile="default",
            query_params=None,
            api_version="v1.0",
            force_allow_delete=False,
        )

    assert env.ok is True
    assert env.mode == "apply"
    assert env.data == [{"id": "g99", "displayName": "Test Group"}]
    assert len(calls) == 1
    assert calls[0]["method"] == "POST"
    assert calls[0]["path"] == "/groups"
    assert calls[0]["body"] == {"displayName": "Test Group"}


def test_raw_apply_with_bad_token_refuses(isolated_state, tmp_path):
    body_file = tmp_path / "body.json"
    body_file.write_text(json.dumps({"displayName": "X"}), encoding="utf-8")

    fake, calls = _mock_graph_request(_FakeResponse())

    with patch.object(raw_module, "graph_request", fake):
        env = raw_module.raw_cmd(
            method="POST",
            path="/groups",
            body=None,
            body_file=body_file,
            plan=False,
            apply=True,
            token="raw_deadbeef",
            profile="default",
            query_params=None,
            api_version="v1.0",
            force_allow_delete=False,
        )

    assert env.ok is False
    assert env.error is not None
    assert calls == []


# --- DELETE safety ----------------------------------------------------------


def test_raw_delete_without_token_refuses(isolated_state):
    fake, calls = _mock_graph_request(_FakeResponse())

    with patch.object(raw_module, "graph_request", fake):
        env = raw_module.raw_cmd(
            method="DELETE",
            path="/users/some-id",
            body=None,
            body_file=None,
            plan=False,
            apply=False,
            token=None,
            profile="default",
            query_params=None,
            api_version="v1.0",
            force_allow_delete=False,
        )

    assert env.ok is False
    assert calls == []


def test_raw_delete_apply_without_force_flag_refuses(isolated_state):
    # Mint a plan first.
    with patch.object(raw_module, "graph_request", _mock_graph_request(_FakeResponse())[0]):
        plan_env = raw_module.raw_cmd(
            method="DELETE",
            path="/users/some-id",
            body=None,
            body_file=None,
            plan=True,
            apply=False,
            token=None,
            profile="default",
            query_params=None,
            api_version="v1.0",
            force_allow_delete=False,
        )
    token = plan_env.plan["token"]

    fake, calls = _mock_graph_request(_FakeResponse(status_code=204))

    with patch.object(raw_module, "graph_request", fake):
        env = raw_module.raw_cmd(
            method="DELETE",
            path="/users/some-id",
            body=None,
            body_file=None,
            plan=False,
            apply=True,
            token=token,
            profile="default",
            query_params=None,
            api_version="v1.0",
            force_allow_delete=False,
        )

    assert env.ok is False
    assert "force-allow-delete" in env.error.message.lower() or "delete" in env.error.message.lower()
    assert calls == []


def test_raw_delete_apply_with_force_flag_executes(isolated_state):
    with patch.object(raw_module, "graph_request", _mock_graph_request(_FakeResponse())[0]):
        plan_env = raw_module.raw_cmd(
            method="DELETE",
            path="/users/some-id",
            body=None,
            body_file=None,
            plan=True,
            apply=False,
            token=None,
            profile="default",
            query_params=None,
            api_version="v1.0",
            force_allow_delete=False,
        )
    token = plan_env.plan["token"]

    fake, calls = _mock_graph_request(_FakeResponse(status_code=204, body=None))

    with patch.object(raw_module, "graph_request", fake):
        env = raw_module.raw_cmd(
            method="DELETE",
            path="/users/some-id",
            body=None,
            body_file=None,
            plan=False,
            apply=True,
            token=token,
            profile="default",
            query_params=None,
            api_version="v1.0",
            force_allow_delete=True,
        )

    assert env.ok is True
    assert env.mode == "apply"
    assert len(calls) == 1
    assert calls[0]["method"] == "DELETE"


# --- out-of-scope -----------------------------------------------------------


def test_raw_refuses_out_of_scope_path(isolated_state):
    fake, calls = _mock_graph_request(_FakeResponse())

    with patch.object(raw_module, "graph_request", fake):
        env = raw_module.raw_cmd(
            method="GET",
            path="/foo/bar",
            body=None,
            body_file=None,
            plan=False,
            apply=False,
            token=None,
            profile="default",
            query_params=None,
            api_version="v1.0",
            force_allow_delete=False,
        )

    assert env.ok is False
    assert env.error is not None
    assert "allowed prefixes" in (env.error.hint or "").lower() or "/users" in (env.error.hint or "")
    assert calls == []


def test_raw_accepts_prefixed_api_version_in_path(isolated_state):
    fake, calls = _mock_graph_request(_FakeResponse(body={"value": []}))

    with patch.object(raw_module, "graph_request", fake):
        env = raw_module.raw_cmd(
            method="GET",
            path="/v1.0/users",
            body=None,
            body_file=None,
            plan=False,
            apply=False,
            token=None,
            profile="default",
            query_params=None,
            api_version="v1.0",
            force_allow_delete=False,
        )

    assert env.ok is True
    assert len(calls) == 1


# --- audit record -----------------------------------------------------------


def test_raw_writes_audit_record_with_verb_raw_and_trace_id(isolated_state):
    response = _FakeResponse(body={"value": []})
    fake, _ = _mock_graph_request(response)

    with patch.object(raw_module, "graph_request", fake):
        env = raw_module.raw_cmd(
            method="GET",
            path="/users",
            body=None,
            body_file=None,
            plan=False,
            apply=False,
            token=None,
            profile="default",
            query_params=None,
            api_version="v1.0",
            force_allow_delete=False,
        )

    records = _read_audit_records(isolated_state / "audit")
    assert len(records) == 1
    rec = records[0]
    assert rec["verb"] == "raw"
    assert rec["trace_id"] == env.trace_id
    assert rec["args_redacted"]["method"] == "GET"
    assert rec["args_redacted"]["path"] == "/users"
    assert rec["ok"] is True


def test_raw_plan_writes_plan_audit_record(isolated_state, tmp_path):
    body_file = tmp_path / "body.json"
    body_file.write_text(json.dumps({"displayName": "x"}), encoding="utf-8")

    with patch.object(raw_module, "graph_request", _mock_graph_request(_FakeResponse())[0]):
        env = raw_module.raw_cmd(
            method="POST",
            path="/groups",
            body=None,
            body_file=body_file,
            plan=True,
            apply=False,
            token=None,
            profile="default",
            query_params=None,
            api_version="v1.0",
            force_allow_delete=False,
        )

    records = _read_audit_records(isolated_state / "audit")
    assert len(records) >= 1
    plan_rec = [r for r in records if r["mode"] == "plan"][0]
    assert plan_rec["verb"] == "raw"
    assert plan_rec["trace_id"] == env.trace_id
    assert plan_rec["args_redacted"]["method"] == "POST"
    assert plan_rec["args_redacted"]["has_body"] is True


# --- body handling edge cases -----------------------------------------------


def test_raw_body_inline_json_is_accepted(isolated_state):
    fake, calls = _mock_graph_request(_FakeResponse(status_code=200, body={"id": "g1"}))

    with patch.object(raw_module, "graph_request", fake):
        plan_env = raw_module.raw_cmd(
            method="POST",
            path="/groups",
            body='{"displayName": "inline"}',
            body_file=None,
            plan=True,
            apply=False,
            token=None,
            profile="default",
            query_params=None,
            api_version="v1.0",
            force_allow_delete=False,
        )

    assert plan_env.ok is True
    assert plan_env.plan["body"] == {"displayName": "inline"}


def test_raw_body_and_body_file_mutually_exclusive(isolated_state, tmp_path):
    body_file = tmp_path / "body.json"
    body_file.write_text("{}", encoding="utf-8")

    fake, _ = _mock_graph_request(_FakeResponse())

    with patch.object(raw_module, "graph_request", fake):
        env = raw_module.raw_cmd(
            method="POST",
            path="/groups",
            body="{}",
            body_file=body_file,
            plan=True,
            apply=False,
            token=None,
            profile="default",
            query_params=None,
            api_version="v1.0",
            force_allow_delete=False,
        )

    assert env.ok is False
