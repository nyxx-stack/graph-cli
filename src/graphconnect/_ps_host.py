"""Persistent Windows PowerShell host for Microsoft Graph requests."""

from __future__ import annotations

import collections
import json
import subprocess
import threading
from typing import Any, Callable, Iterable


class _HostEOFError(RuntimeError):
    """Raised when the host exits before sending a framed response."""


class _HostProtocolError(RuntimeError):
    """Raised when the host emits an unexpected frame."""


_READY_ERROR = (
    "Not authenticated with Microsoft Graph PowerShell. "
    "Run graphconnect auth login or Connect-MgGraph -UseDeviceCode."
)


def _build_host_script(required_scopes: Iterable[str]) -> str:
    scopes_json = json.dumps(list(required_scopes))
    return f"""
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
[Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
$requiredScopes = ConvertFrom-Json @'
{scopes_json}
'@
$ctx = Get-MgContext -ErrorAction SilentlyContinue
if (-not $ctx) {{
    Connect-MgGraph -ContextScope CurrentUser -Scopes $requiredScopes -NoWelcome | Out-Null
    $ctx = Get-MgContext -ErrorAction SilentlyContinue
}}
if (-not $ctx) {{
    [Console]::Out.WriteLine('{{"type":"ready","authenticated":false,"error":"not_authenticated"}}')
    [Console]::Out.Flush()
    exit 2
}}
[Console]::Out.WriteLine('{{"type":"ready","authenticated":true}}')
[Console]::Out.Flush()
try {{
    while (($line = [Console]::In.ReadLine()) -ne $null) {{
        if ([string]::IsNullOrWhiteSpace($line)) {{ continue }}
        $cmd = $null
        $id = -1
        try {{
            $cmd = $line | ConvertFrom-Json
            if ($null -ne $cmd.id) {{ $id = $cmd.id }}
            switch ($cmd.op) {{
                'disconnect' {{
                    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
                    $env = @{{ id = $id; ok = $true; disconnected = $true }}
                    [Console]::Out.WriteLine(($env | ConvertTo-Json -Compress -Depth 32))
                    [Console]::Out.Flush()
                    break
                }}
                'request' {{
                    $statusCode = $null
                    $responseHeaders = $null
                    $params = @{{
                        Method = $cmd.method
                        Uri = $cmd.url
                        OutputType = 'PSObject'
                        StatusCodeVariable = 'statusCode'
                        ResponseHeadersVariable = 'responseHeaders'
                    }}
                    if ($null -ne $cmd.body) {{ $params.Body = $cmd.body }}
                    if ($null -ne $cmd.headers) {{
                        $ht = @{{}}
                        foreach ($p in $cmd.headers.PSObject.Properties) {{ $ht[$p.Name] = $p.Value }}
                        $params.Headers = $ht
                    }}
                    $resp = Invoke-MgGraphRequest @params
                    $headerMap = @{{}}
                    if ($null -ne $responseHeaders) {{
                        foreach ($entry in $responseHeaders.GetEnumerator()) {{
                            $headerMap[$entry.Key] = $entry.Value
                        }}
                    }}
                    $env = @{{
                        id = $id
                        ok = $true
                        data = @{{
                            body = $resp
                            status_code = $statusCode
                            headers = $headerMap
                        }}
                    }}
                    [Console]::Out.WriteLine(($env | ConvertTo-Json -Compress -Depth 32))
                    [Console]::Out.Flush()
                }}
                default {{
                    $env = @{{ id = $id; ok = $false; error = "unknown_op" }}
                    [Console]::Out.WriteLine(($env | ConvertTo-Json -Compress -Depth 32))
                    [Console]::Out.Flush()
                }}
            }}
        }} catch {{
            $env = @{{ id = $id; ok = $false; error = "$($_.Exception.Message)" }}
            [Console]::Out.WriteLine(($env | ConvertTo-Json -Compress -Depth 32))
            [Console]::Out.Flush()
        }}
    }}
}} catch {{
    [Console]::Out.WriteLine((@{{ id = -1; ok = $false; error = "$($_.Exception.Message)" }} | ConvertTo-Json -Compress -Depth 32))
    [Console]::Out.Flush()
    exit 1
}}
"""


class GraphPowerShellHost:
    """Persistent single-request-at-a-time Graph PowerShell host."""

    def __init__(
        self,
        *,
        required_scopes: Iterable[str],
        process_factory: Callable[[], subprocess.Popen[str]] | None = None,
        close_timeout: float = 5.0,
    ) -> None:
        self._script = _build_host_script(required_scopes)
        self._process_factory = process_factory
        self._close_timeout = close_timeout
        self._process: subprocess.Popen[str] | None = None
        self._lock = threading.Lock()
        self._next_id = 0
        self._stderr_buf: collections.deque[str] = collections.deque(maxlen=64)

    def invoke(
        self,
        *,
        method: str,
        url: str,
        body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> Any:
        """Send a Graph request through the persistent host."""
        with self._lock:
            for attempt in range(2):
                try:
                    return self._invoke_once_locked(
                        method=method,
                        url=url,
                        body=body,
                        headers=headers,
                    )
                except (BrokenPipeError, _HostEOFError) as exc:
                    self._close_locked()
                    if attempt == 1:
                        raise RuntimeError(self._format_comm_error("PowerShell host connection lost")) from exc

    def disconnect(self) -> None:
        """Disconnect the underlying Graph PowerShell session and stop the host."""
        with self._lock:
            process = self._process
            if process is None or process.poll() is not None:
                self._close_locked()
                return

            message_id = self._reserve_id_locked()
            try:
                self._send_message_locked({"id": message_id, "op": "disconnect"})
                response = self._read_message_locked()
            finally:
                self._close_locked()

            if response.get("id") != message_id:
                raise _HostProtocolError("disconnect response id mismatch")
            if not response.get("ok"):
                error = response.get("error") or "Disconnect-MgGraph failed."
                raise RuntimeError(self._format_comm_error(error))

    def close(self) -> None:
        """Stop the host process."""
        with self._lock:
            self._close_locked()

    def _invoke_once_locked(
        self,
        *,
        method: str,
        url: str,
        body: dict[str, Any] | None,
        headers: dict[str, str] | None,
    ) -> Any:
        self._ensure_process_locked()
        message_id = self._reserve_id_locked()
        self._send_message_locked(
            {
                "id": message_id,
                "op": "request",
                "method": method,
                "url": url,
                "body": body,
                "headers": headers,
            }
        )
        response = self._read_message_locked()
        if response.get("id") != message_id:
            raise _HostProtocolError("response id mismatch")
        if not response.get("ok"):
            error = response.get("error") or "PowerShell request failed."
            raise RuntimeError(self._format_comm_error(error))
        return response.get("data")

    def _ensure_process_locked(self) -> None:
        process = self._process
        if process is not None and process.poll() is None:
            return

        self._stderr_buf.clear()
        process = self._spawn_process()
        self._process = process
        threading.Thread(
            target=self._drain_stderr,
            args=(process.stderr,),
            daemon=True,
        ).start()

        ready = self._read_message_locked()
        if ready.get("type") != "ready":
            self._close_locked()
            raise _HostProtocolError("missing ready handshake")
        if not ready.get("authenticated"):
            self._close_locked()
            error = ready.get("error")
            if error == "not_authenticated":
                raise RuntimeError(_READY_ERROR)
            raise RuntimeError(self._format_comm_error(error or _READY_ERROR))

    def _spawn_process(self) -> subprocess.Popen[str]:
        if self._process_factory is not None:
            return self._process_factory()

        from graphconnect.auth import _build_powershell_invocation

        argv, env = _build_powershell_invocation(self._script)
        return subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            bufsize=1,
            env=env,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )

    def _send_message_locked(self, payload: dict[str, Any]) -> None:
        process = self._require_process_locked()
        stdin = process.stdin
        if stdin is None:
            raise _HostEOFError("PowerShell host stdin unavailable.")
        stdin.write(json.dumps(payload, ensure_ascii=False))
        stdin.write("\n")
        stdin.flush()

    def _read_message_locked(self) -> dict[str, Any]:
        process = self._require_process_locked()
        stdout = process.stdout
        if stdout is None:
            raise _HostEOFError("PowerShell host stdout unavailable.")
        line = stdout.readline()
        if line == "":
            raise _HostEOFError(self._format_comm_error("PowerShell host exited unexpectedly."))
        try:
            return json.loads(line)
        except json.JSONDecodeError as exc:
            raise _HostProtocolError(f"invalid host JSON: {line.strip()}") from exc

    def _require_process_locked(self) -> subprocess.Popen[str]:
        process = self._process
        if process is None:
            raise _HostEOFError("PowerShell host is not running.")
        return process

    def _reserve_id_locked(self) -> int:
        self._next_id += 1
        return self._next_id

    def _close_locked(self) -> None:
        process = self._process
        self._process = None
        if process is None:
            return

        try:
            if process.stdin is not None:
                process.stdin.close()
        except OSError:
            pass

        try:
            process.wait(timeout=self._close_timeout)
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=1)

        for stream_name in ("stdout", "stderr"):
            stream = getattr(process, stream_name)
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass

    def _drain_stderr(self, stream: Any) -> None:
        if stream is None:
            return
        try:
            for line in stream:
                text = line.strip()
                if text:
                    self._stderr_buf.append(text)
        finally:
            try:
                stream.close()
            except OSError:
                pass

    def _format_comm_error(self, message: str) -> str:
        if not self._stderr_buf:
            return message
        return f"{message} stderr: {' | '.join(self._stderr_buf)}"
