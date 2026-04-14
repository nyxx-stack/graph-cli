from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path

from graphconnect._ps_host import GraphPowerShellHost
from graphconnect._ps_host import _build_host_script


FAKE_HOST_SCRIPT = """
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.stdout.write(json.dumps({"type": "ready", "authenticated": True}) + "\\n")
sys.stdout.flush()

close_once_marker = Path(sys.argv[1]) if len(sys.argv) > 1 else None

for raw in sys.stdin:
    if not raw.strip():
        continue
    cmd = json.loads(raw)
    op = cmd.get("op")
    if op == "disconnect":
        sys.stdout.write(json.dumps({"id": cmd["id"], "ok": True, "disconnected": True}) + "\\n")
        sys.stdout.flush()
        break
    if cmd.get("url") == "close-once":
        if close_once_marker is not None and not close_once_marker.exists():
            close_once_marker.write_text("1", encoding="utf-8")
            sys.stdout.flush()
            sys.exit(0)
    payload = {
        "body": {
            "method": cmd.get("method"),
            "url": cmd.get("url"),
            "body": cmd.get("body"),
            "headers": cmd.get("headers"),
        },
        "status_code": 204 if cmd.get("method") != "GET" else 200,
        "headers": {"request-id": "fake-request"},
    }
    sys.stdout.write(json.dumps({"id": cmd["id"], "ok": True, "data": payload}, ensure_ascii=False) + "\\n")
    sys.stdout.flush()
"""


def _make_process_factory(tmp_path: Path):
    script_path = tmp_path / "fake_ps_host.py"
    marker_path = tmp_path / "close-once.marker"
    script_path.write_text(textwrap.dedent(FAKE_HOST_SCRIPT), encoding="utf-8")

    def factory() -> subprocess.Popen[str]:
        return subprocess.Popen(
            [sys.executable, "-u", str(script_path), str(marker_path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            bufsize=1,
        )

    return factory


def test_host_round_trip_and_unicode(tmp_path):
    host = GraphPowerShellHost(required_scopes=[], process_factory=_make_process_factory(tmp_path))
    body = {"displayName": "Ren\u00e9e Dupont", "city": "\u4e1c\u4eac"}

    result = host.invoke(
        method="POST",
        url="users",
        body=body,
        headers={"ConsistencyLevel": "eventual"},
    )

    assert result == {
        "body": {
            "method": "POST",
            "url": "users",
            "body": body,
            "headers": {"ConsistencyLevel": "eventual"},
        },
        "status_code": 204,
        "headers": {"request-id": "fake-request"},
    }
    host.close()


def test_host_large_body_round_trip(tmp_path):
    host = GraphPowerShellHost(required_scopes=[], process_factory=_make_process_factory(tmp_path))
    large_value = "x" * 150_000

    result = host.invoke(method="PATCH", url="policies", body={"payload": large_value})

    assert result["body"]["body"]["payload"] == large_value
    host.close()


def test_host_respawns_once_after_broken_pipe(tmp_path):
    spawn_count = 0
    base_factory = _make_process_factory(tmp_path)

    def factory() -> subprocess.Popen[str]:
        nonlocal spawn_count
        spawn_count += 1
        return base_factory()

    host = GraphPowerShellHost(required_scopes=[], process_factory=factory)

    result = host.invoke(method="GET", url="close-once")

    assert result["body"]["url"] == "close-once"
    assert spawn_count == 2
    host.close()


def test_host_disconnect_and_close_cleanup(tmp_path):
    host = GraphPowerShellHost(required_scopes=[], process_factory=_make_process_factory(tmp_path))
    host.invoke(method="GET", url="users")

    process = host._process
    assert process is not None

    host.disconnect()

    assert host._process is None
    assert process.poll() is not None
    host.close()


def test_host_close_stops_process(tmp_path):
    host = GraphPowerShellHost(required_scopes=[], process_factory=_make_process_factory(tmp_path))
    host.invoke(method="GET", url="users")

    process = host._process
    assert process is not None

    host.close()

    assert host._process is None
    assert process.poll() is not None


def test_host_script_serializes_body_to_json_for_graph_requests():
    script = _build_host_script(required_scopes=[])

    assert "ConvertTo-Json -Compress -Depth 64" in script
    assert "$params.ContentType = 'application/json'" in script
