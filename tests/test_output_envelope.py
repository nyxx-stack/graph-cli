from __future__ import annotations

import json

import pytest

from graphconnect.output import EnvelopeEmitError, emit, set_bare, set_quiet
from graphconnect.types import Envelope, ErrorCode, ErrorPayload


@pytest.fixture(autouse=True)
def _reset_output_state():
    set_bare(False)
    set_quiet(False)
    yield
    set_bare(False)
    set_quiet(False)


def test_emit_json_contains_expected_envelope_keys(capsys):
    env = Envelope.ok_read("2 rows", [{"id": "a"}, {"id": "b"}], trace_id="t-json")
    emit(env)
    out = capsys.readouterr().out
    parsed = json.loads(out)
    assert parsed["ok"] is True
    assert parsed["mode"] == "read"
    assert parsed["trace_id"] == "t-json"
    assert parsed["summary"] == "2 rows"
    assert parsed["data"] == [{"id": "a"}, {"id": "b"}]


def test_emit_bare_read_returns_bare_array(capsys):
    env = Envelope.ok_read("2", [{"id": "a"}, {"id": "b"}], trace_id="t-bare")
    emit(env, bare=True)
    out = capsys.readouterr().out
    parsed = json.loads(out)
    assert parsed == [{"id": "a"}, {"id": "b"}]


def test_emit_bare_plan_returns_plan_object(capsys):
    plan = {"token": "tok", "steps": [{"op": "assign"}]}
    env = Envelope.ok_plan("dry-run", plan, trace_id="t-plan")
    emit(env, bare=True)
    out = capsys.readouterr().out
    parsed = json.loads(out)
    assert parsed == plan


def test_emit_table_renders_data_and_sends_warnings_to_stderr(capsys):
    env = Envelope(
        ok=True,
        trace_id="t-table",
        mode="read",
        summary="devices",
        data=[{"id": "a", "name": "laptop"}],
        warnings=["took 2s"],
        next_actions=["graphconnect show device:a"],
    )
    emit(env, format="table")
    captured = capsys.readouterr()
    # table content (Rich) goes to stdout
    assert "laptop" in captured.out
    # chatter goes to stderr
    assert "took 2s" in captured.err
    assert "graphconnect show device:a" in captured.err


def test_emit_error_envelope_default_writes_to_stdout(capsys):
    env = Envelope.err(
        "not found",
        ErrorPayload(code=ErrorCode.NOT_FOUND, message="device not found"),
        trace_id="t-err",
    )
    emit(env)
    out = capsys.readouterr().out
    parsed = json.loads(out)
    assert parsed["ok"] is False
    assert parsed["error"]["code"] == "not_found"


def test_emit_error_envelope_bare_raises_with_exit_code(capsys):
    env = Envelope.err(
        "not found",
        ErrorPayload(code=ErrorCode.NOT_FOUND, message="device not found"),
        trace_id="t-err-bare",
    )
    with pytest.raises(EnvelopeEmitError) as exc_info:
        emit(env, bare=True, format="json")
    # NOT_FOUND maps to exit code 3 (see output._EXIT_CODES).
    assert exc_info.value.exit_code == 3
    # The error went to stderr (emit_error writes there in json mode).
    err = capsys.readouterr().err
    assert "device not found" in err


def test_emit_global_bare_flag_is_honored(capsys):
    set_bare(True)
    env = Envelope.ok_read("1", [{"id": "a"}], trace_id="t-flag")
    emit(env)
    out = capsys.readouterr().out
    assert json.loads(out) == [{"id": "a"}]


def test_emit_quiet_suppresses_warnings_on_stderr(capsys):
    set_quiet(True)
    env = Envelope(
        ok=True,
        trace_id="t-q",
        mode="read",
        summary="s",
        data=[{"id": "a"}],
        warnings=["noisy"],
    )
    emit(env)
    assert "noisy" not in capsys.readouterr().err


def test_emit_compact_ndjson(capsys):
    env = Envelope.ok_read("two", [{"id": "a"}, {"id": "b"}], trace_id="t-nd")
    emit(env, bare=True, format="compact")
    out = capsys.readouterr().out.strip().splitlines()
    assert [json.loads(line) for line in out] == [{"id": "a"}, {"id": "b"}]
