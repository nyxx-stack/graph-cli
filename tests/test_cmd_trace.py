from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone

import pytest
import typer
from typer.testing import CliRunner

from graphconnect import audit as audit_mod
from graphconnect.audit_reader import find_by_trace_id, latest, list_recent
from graphconnect.commands import trace as cmd_trace


@pytest.fixture
def audit_dir(tmp_path, monkeypatch):
    graph_dir = tmp_path / ".graphconnect"
    trace_dir = graph_dir / "audit"
    monkeypatch.setattr(audit_mod, "AUDIT_DIR", graph_dir)
    monkeypatch.setattr(audit_mod, "AUDIT_FILE", graph_dir / "audit.jsonl")
    monkeypatch.setattr(audit_mod, "AUDIT_TRACE_DIR", trace_dir)
    monkeypatch.setattr(audit_mod, "_audit_dir_ready", False)
    monkeypatch.setattr(audit_mod, "_audit_trace_dir_ready", False)
    return trace_dir


def _write_records(trace_dir, records):
    trace_dir.mkdir(parents=True, exist_ok=True)
    by_day: dict[str, list[dict]] = {}
    for r in records:
        day = r["timestamp"][:10]
        by_day.setdefault(day, []).append(r)
    for day, rows in by_day.items():
        path = trace_dir / f"{day}.ndjson"
        with open(path, "a", encoding="utf-8") as f:
            for row in rows:
                f.write(json.dumps(row) + "\n")


def _base_record(ts: datetime, trace_id: str, **extras):
    rec = {
        "timestamp": ts.isoformat(),
        "operation_id": "devices.list",
        "safety_tier": "read",
        "method": "GET",
        "graph_url": "/deviceManagement/managedDevices",
        "parameters": {},
        "status": "success",
        "http_status": 200,
        "execution_time_ms": 42,
        "trace_id": trace_id,
        "verb": "read",
        "ok": True,
    }
    rec.update(extras)
    return rec


def _invoke(command_obj, args):
    runner = CliRunner()
    app = typer.Typer()
    cmd_trace.register(app)
    return runner.invoke(app, ["trace", *args])


def test_trace_show_returns_sorted_step_list(audit_dir):
    t0 = datetime(2026, 4, 23, 10, 0, 0, tzinfo=timezone.utc)
    tid = "trace-alpha"
    recs = [
        _base_record(t0 + timedelta(seconds=2), tid, method="GET", graph_url="/step-c", http_status=200),
        _base_record(t0, tid, method="GET", graph_url="/step-a", http_status=200),
        _base_record(t0 + timedelta(seconds=1), tid, method="POST", graph_url="/step-b", http_status=201),
    ]
    _write_records(audit_dir, recs)

    result = _invoke(cmd_trace.app, ["show", tid])
    assert result.exit_code == 0, result.output
    env = json.loads(result.output)
    assert env["ok"] is True
    assert env["mode"] == "read"
    data = env["data"]
    assert [row["seq"] for row in data] == [1, 2, 3]
    assert [row["path"] for row in data] == ["/step-a", "/step-b", "/step-c"]
    assert [row["method"] for row in data] == ["GET", "POST", "GET"]
    assert all("http_requests" not in row for row in data)
    assert f"trace show {tid} --raw" in env["next_actions"]


def test_trace_list_limit_returns_most_recent(audit_dir):
    t0 = datetime(2026, 4, 23, 10, 0, 0, tzinfo=timezone.utc)
    recs = [
        _base_record(t0, "trace-old", verb="read"),
        _base_record(t0 + timedelta(seconds=10), "trace-mid", verb="read"),
        _base_record(t0 + timedelta(seconds=20), "trace-new", verb="read"),
    ]
    _write_records(audit_dir, recs)

    result = _invoke(cmd_trace.app, ["list", "--limit", "2"])
    assert result.exit_code == 0, result.output
    env = json.loads(result.output)
    assert len(env["data"]) == 2
    assert [row["trace_id"] for row in env["data"]] == ["trace-new", "trace-mid"]


def test_trace_list_accepts_naive_since_timestamp(audit_dir):
    t0 = datetime(2026, 4, 23, 10, 0, 0, tzinfo=timezone.utc)
    recs = [
        _base_record(t0 - timedelta(days=1), "trace-old"),
        _base_record(t0, "trace-new"),
    ]
    _write_records(audit_dir, recs)

    result = _invoke(cmd_trace.app, ["list", "--since", "2026-04-23T00:00:00"])
    assert result.exit_code == 0, result.output
    env = json.loads(result.output)
    assert [row["trace_id"] for row in env["data"]] == ["trace-new"]


def test_trace_latest_returns_newest_trace_id(audit_dir):
    t0 = datetime(2026, 4, 23, 10, 0, 0, tzinfo=timezone.utc)
    recs = [
        _base_record(t0, "trace-old"),
        _base_record(t0 + timedelta(seconds=30), "trace-new"),
    ]
    _write_records(audit_dir, recs)

    result = _invoke(cmd_trace.app, ["latest"])
    assert result.exit_code == 0, result.output
    env = json.loads(result.output)
    assert env["ok"] is True
    assert env["data"]
    assert env["summary"].startswith("trace trace-new")


def test_trace_show_raw_includes_http_requests(audit_dir):
    t0 = datetime(2026, 4, 23, 10, 0, 0, tzinfo=timezone.utc)
    http_requests = [{"method": "GET", "url": "/x", "status": 200, "body": {"ok": True}}]
    recs = [
        _base_record(t0, "trace-raw", http_requests=http_requests),
    ]
    _write_records(audit_dir, recs)

    plain = _invoke(cmd_trace.app, ["show", "trace-raw"])
    plain_env = json.loads(plain.output)
    assert "http_requests" not in plain_env["data"][0]

    raw = _invoke(cmd_trace.app, ["show", "trace-raw", "--raw"])
    raw_env = json.loads(raw.output)
    assert raw_env["data"][0]["http_requests"] == http_requests


def test_trace_show_renders_raw_audit_rows_with_standard_fields(audit_dir):
    t0 = datetime(2026, 4, 23, 10, 0, 0, tzinfo=timezone.utc)
    recs = [
        {
            "timestamp": t0.isoformat(),
            "trace_id": "trace-raw-schema",
            "operation_id": "raw",
            "verb": "raw",
            "mode": "apply",
            "profile": "default",
            "method": "PATCH",
            "graph_url": "/users/u1",
            "status": "success",
            "http_status": 204,
            "ok": True,
        }
    ]
    _write_records(audit_dir, recs)

    result = _invoke(cmd_trace.app, ["show", "trace-raw-schema"])
    assert result.exit_code == 0, result.output
    env = json.loads(result.output)
    assert env["data"][0]["method"] == "PATCH"
    assert env["data"][0]["path"] == "/users/u1"
    assert env["data"][0]["status"] == 204


def test_trace_list_filter_by_verb_and_failed(audit_dir):
    t0 = datetime(2026, 4, 23, 10, 0, 0, tzinfo=timezone.utc)
    recs = [
        _base_record(t0, "t1", verb="read", ok=True, status="success"),
        _base_record(
            t0 + timedelta(seconds=5),
            "t2",
            verb="change",
            ok=False,
            status="error",
            http_status=403,
            error="forbidden",
        ),
        _base_record(t0 + timedelta(seconds=10), "t3", verb="change", ok=True),
    ]
    _write_records(audit_dir, recs)

    by_verb = _invoke(cmd_trace.app, ["list", "--verb", "change"])
    verb_env = json.loads(by_verb.output)
    assert {r["trace_id"] for r in verb_env["data"]} == {"t2", "t3"}

    failed = _invoke(cmd_trace.app, ["list", "--failed"])
    failed_env = json.loads(failed.output)
    assert [r["trace_id"] for r in failed_env["data"]] == ["t2"]


def test_trace_show_not_found(audit_dir):
    result = _invoke(cmd_trace.app, ["show", "missing"])
    assert result.exit_code == 0
    env = json.loads(result.output)
    assert env["ok"] is False
    assert env["error"]["code"] == "not_found"


def test_log_operation_writes_daily_ndjson_when_trace_id_set(audit_dir):
    from graphconnect.types import SafetyTier

    audit_mod.log_operation(
        operation_id="devices.list",
        safety_tier=SafetyTier.READ,
        method="GET",
        graph_url="/deviceManagement/managedDevices",
        status="success",
        http_status=200,
        execution_time_ms=17,
        trace_id="trace-extended",
        verb="read",
        profile="default",
        mode="read",
        ok=True,
        http_requests=[{"method": "GET", "url": "/deviceManagement/managedDevices", "status": 200}],
    )

    files = list(audit_dir.glob("*.ndjson"))
    assert len(files) == 1
    line = files[0].read_text(encoding="utf-8").strip()
    row = json.loads(line)
    assert row["trace_id"] == "trace-extended"
    assert row["verb"] == "read"
    assert row["profile"] == "default"
    assert row["http_requests"][0]["url"].endswith("/managedDevices")


def test_log_operation_without_trace_id_skips_daily_ndjson(audit_dir):
    from graphconnect.types import SafetyTier

    audit_mod.log_operation(
        operation_id="devices.list",
        safety_tier=SafetyTier.READ,
        method="GET",
        graph_url="/deviceManagement/managedDevices",
        status="success",
        http_status=200,
    )
    assert not list(audit_dir.glob("*.ndjson")) if audit_dir.exists() else True
    assert (audit_mod.AUDIT_FILE).exists()


def test_audit_reader_find_by_trace_id(audit_dir):
    t0 = datetime(2026, 4, 23, 10, 0, 0, tzinfo=timezone.utc)
    recs = [
        _base_record(t0 + timedelta(seconds=1), "X"),
        _base_record(t0, "X"),
        _base_record(t0, "Y"),
    ]
    _write_records(audit_dir, recs)
    found = asyncio.run(find_by_trace_id("X"))
    assert len(found) == 2
    assert found[0].timestamp < found[1].timestamp


def test_audit_reader_latest_empty(audit_dir):
    assert asyncio.run(latest()) is None


def test_audit_reader_list_recent_since_filter(audit_dir):
    t0 = datetime(2026, 4, 23, 10, 0, 0, tzinfo=timezone.utc)
    recs = [
        _base_record(t0 - timedelta(days=2), "old"),
        _base_record(t0, "fresh"),
    ]
    _write_records(audit_dir, recs)
    cutoff = t0 - timedelta(hours=1)
    recent = asyncio.run(list_recent(since=cutoff))
    assert [r.trace_id for r in recent] == ["fresh"]
