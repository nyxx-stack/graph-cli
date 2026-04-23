"""PowerShell-backed Graph authentication fallback.

Wraps Microsoft.Graph.Authentication so GraphConnect can operate against a
user-signed Graph PowerShell context without a dedicated app registration.
This module was lifted from the legacy ``graphconnect.auth`` module; behavior
is preserved so existing callers (doctor, executor, _ps_host) keep working.
"""

from __future__ import annotations

import atexit
import functools
import json
import os
import shutil
import subprocess
import sys
import time
from typing import TYPE_CHECKING, Any

from graphconnect.types import AuthMethod

if TYPE_CHECKING:
    from graphconnect._ps_host import GraphPowerShellHost


TOKEN_CACHE_NAME = "graphconnect"
GRAPH_RESOURCE_SCOPE = "https://graph.microsoft.com/.default"

DELEGATED_SCOPES = [
    "Application.Read.All",
    "DeviceManagementManagedDevices.Read.All",
    "DeviceManagementManagedDevices.ReadWrite.All",
    "DeviceManagementManagedDevices.PrivilegedOperations.All",
    "DeviceManagementConfiguration.Read.All",
    "DeviceManagementConfiguration.ReadWrite.All",
    "Directory.AccessAsUser.All",
    "Directory.Read.All",
    "User.Read.All",
    "User.EnableDisableAccount.All",
    "User-PasswordProfile.ReadWrite.All",
    "Device.Read.All",
    "Group.Read.All",
    "Group.ReadWrite.All",
    "GroupMember.Read.All",
    "GroupMember.ReadWrite.All",
    "AuditLog.Read.All",
    "Policy.Read.All",
    "Policy.ReadWrite.ConditionalAccess",
    "RoleManagement.Read.Directory",
]

_PS_PREAMBLE = """
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
"""

_GET_CONTEXT_TAIL = """
$ctx = Get-MgContext -ErrorAction SilentlyContinue
if (-not $ctx) {
    [Console]::Out.Write('null')
    exit 0
}
[pscustomobject]@{
    account = $ctx.Account
    app_name = $ctx.AppName
    auth_type = $ctx.AuthType
    context_scope = $ctx.ContextScope
    scopes = @($ctx.Scopes)
} | ConvertTo-Json -Compress -Depth 4
"""


_host: GraphPowerShellHost | None = None
_host_atexit_registered = False


@functools.lru_cache(maxsize=1)
def _powershell_executable() -> str | None:
    """Return the available Windows PowerShell executable, if present."""
    for candidate in ("powershell.exe", "powershell"):
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    return None


def _build_powershell_invocation(
    script: str,
    *,
    no_exit: bool = False,
    extra_env: dict[str, str] | None = None,
) -> tuple[list[str], dict[str, str]]:
    """Build the argv and environment for a PowerShell invocation."""
    powershell = _powershell_executable()
    if not powershell:
        raise RuntimeError("Windows PowerShell is not available on PATH.")
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)
    mode_flag = "-NoExit" if no_exit else "-NoProfile"
    return [powershell, "-NoLogo", mode_flag, "-Command", script], env


def _run_powershell(
    script: str,
    extra_env: dict[str, str] | None = None,
    timeout: float | None = 60,
) -> subprocess.CompletedProcess[str]:
    """Run a PowerShell script and return the completed process."""
    argv, env = _build_powershell_invocation(script, extra_env=extra_env)
    return subprocess.run(argv, capture_output=True, text=True, env=env, check=False, timeout=timeout)


def _launch_powershell_window(
    script: str,
    extra_env: dict[str, str] | None = None,
) -> subprocess.Popen[str]:
    """Launch a separate PowerShell window for interactive auth."""
    argv, env = _build_powershell_invocation(script, no_exit=True, extra_env=extra_env)
    creationflags = getattr(subprocess, "CREATE_NEW_CONSOLE", 0)
    return subprocess.Popen(argv, env=env, creationflags=creationflags)


def _run_powershell_json(
    script: str,
    extra_env: dict[str, str] | None = None,
    timeout: float | None = 60,
) -> Any:
    """Run a PowerShell script that emits JSON and parse the result."""
    result = _run_powershell(script, extra_env=extra_env, timeout=timeout)
    if result.returncode != 0:
        error = (result.stderr or result.stdout).strip()
        raise RuntimeError(error or "PowerShell command failed.")
    payload = result.stdout.strip()
    if not payload:
        return None
    return _parse_powershell_json_payload(payload)


def _parse_powershell_json_payload(payload: str) -> Any:
    """Parse JSON from PowerShell stdout, tolerating banner lines before the JSON."""
    try:
        return json.loads(payload)
    except json.JSONDecodeError:
        pass
    for line in reversed(payload.splitlines()):
        candidate = line.strip()
        if not candidate:
            continue
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            continue
    raise RuntimeError("PowerShell command did not emit valid JSON.")


def _scopes_block() -> str:
    scopes_json = json.dumps(DELEGATED_SCOPES)
    return f"$requiredScopes = ConvertFrom-Json @'\n{scopes_json}\n'@\n"


def _get_graph_powershell_context_data(
    connect: bool = False,
    *,
    use_device_code: bool = False,
    timeout: float | None = 60,
) -> dict[str, Any] | None:
    """Read the current Graph PowerShell context; optionally reconnect from cache first."""
    parts = [_PS_PREAMBLE]
    if connect:
        connect_cmd = "Connect-MgGraph -ContextScope CurrentUser -Scopes $requiredScopes -NoWelcome"
        if use_device_code:
            connect_cmd = "Connect-MgGraph -ContextScope CurrentUser -UseDeviceCode -Scopes $requiredScopes -NoWelcome"
        parts.append(f"{_scopes_block()}{connect_cmd} | Out-Null\n")
    parts.append(_GET_CONTEXT_TAIL)
    data = _run_powershell_json("".join(parts), timeout=timeout)
    return data if isinstance(data, dict) else None


def try_graph_powershell_context(force_login: bool = False) -> "PSContext | None":
    """Use Microsoft Graph PowerShell as the primary no-app auth backend."""
    if not _powershell_executable():
        return None

    try:
        data = _get_graph_powershell_context_data()
    except (RuntimeError, subprocess.TimeoutExpired):
        data = None

    if data is None:
        try:
            data = _get_graph_powershell_context_data(connect=True, use_device_code=True, timeout=15)
        except (RuntimeError, subprocess.TimeoutExpired):
            data = None

    current_scopes = set(data.get("scopes") or []) if data else set()
    missing_scopes = [scope for scope in DELEGATED_SCOPES if scope not in current_scopes]

    if force_login and (data is None or missing_scopes):
        login_script = (
            f"{_PS_PREAMBLE}{_scopes_block()}"
            "Connect-MgGraph -ContextScope CurrentUser -UseDeviceCode -Scopes $requiredScopes -NoWelcome\n"
            "Write-Host ''\n"
            "Write-Host 'Graph sign-in completed. You can close this window.'\n"
        )
        print("Launching Microsoft Graph PowerShell sign-in window...")
        process = _launch_powershell_window(login_script)

        deadline = time.monotonic() + 300
        exit_code: int | None = None
        exit_seen_at: float | None = None
        while time.monotonic() < deadline:
            try:
                data = _get_graph_powershell_context_data(connect=True, use_device_code=True, timeout=15)
            except (RuntimeError, subprocess.TimeoutExpired):
                data = None
            current_scopes = set(data.get("scopes") or []) if data else set()
            missing_scopes = [scope for scope in DELEGATED_SCOPES if scope not in current_scopes]
            if data is not None and not missing_scopes:
                break

            poll_result = process.poll()
            if poll_result is not None and exit_seen_at is None:
                exit_code = poll_result
                exit_seen_at = time.monotonic()

            if exit_seen_at is not None and time.monotonic() - exit_seen_at >= 15:
                break
            time.sleep(2)

        if (data is None or missing_scopes) and exit_code not in (None, 0):
            raise RuntimeError(
                f"Connect-MgGraph sign-in window exited with code {exit_code} "
                "before the Graph context became visible."
            )

    if data is None or missing_scopes:
        return None

    return PSContext(
        scopes=list(data.get("scopes") or []),
        user_principal=data.get("account"),
        auth_method=AuthMethod.GRAPH_POWERSHELL,
    )


class PSContext:
    """Lightweight struct describing a cached Graph PowerShell context."""

    __slots__ = ("scopes", "user_principal", "auth_method")

    def __init__(self, *, scopes: list[str], user_principal: str | None, auth_method: AuthMethod) -> None:
        self.scopes = scopes
        self.user_principal = user_principal
        self.auth_method = auth_method


def invoke_graph_powershell_request(
    *,
    method: str,
    url: str,
    body: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> Any:
    """Execute a Graph request through Microsoft Graph PowerShell."""
    try:
        return _get_graph_powershell_host().invoke(
            method=method,
            url=url,
            body=body,
            headers=headers,
        )
    except RuntimeError:
        _close_graph_powershell_host()
        return _get_graph_powershell_host().invoke(
            method=method,
            url=url,
            body=body,
            headers=headers,
        )


def _get_graph_powershell_host() -> "GraphPowerShellHost":
    global _host, _host_atexit_registered

    if _host is None:
        from graphconnect._ps_host import GraphPowerShellHost

        _host = GraphPowerShellHost(required_scopes=DELEGATED_SCOPES)
        if not _host_atexit_registered:
            atexit.register(_close_graph_powershell_host)
            _host_atexit_registered = True
    return _host


def _close_graph_powershell_host() -> None:
    global _host
    if _host is not None:
        _host.close()
        _host = None


def peek_display_name_via_powershell() -> str | None:
    """Best-effort /me GET through Graph PowerShell to populate display_name."""
    try:
        response = invoke_graph_powershell_request(
            method="GET",
            url="https://graph.microsoft.com/v1.0/me?$select=displayName",
            headers={},
        )
    except Exception:
        return None
    if not isinstance(response, dict):
        return None
    body = response.get("body") if "body" in response else response
    if isinstance(body, dict):
        value = body.get("displayName")
        if isinstance(value, str) and value.strip():
            return value
    return None


def disconnect_graph_powershell() -> bool:
    """Best-effort disconnect of the persistent PowerShell host + Graph session."""
    global _host
    if not _powershell_executable():
        if _host is not None:
            _host.close()
            _host = None
        return False

    host_disconnected = False
    if _host is not None:
        try:
            _host.disconnect()
            host_disconnected = True
        except (RuntimeError, subprocess.TimeoutExpired, OSError):
            pass
        finally:
            _host.close()
            _host = None

    if not host_disconnected:
        try:
            _run_powershell(
                "Import-Module Microsoft.Graph.Authentication -ErrorAction SilentlyContinue; "
                "Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null"
            )
        except (RuntimeError, subprocess.TimeoutExpired, OSError):
            pass
    return True


# Re-exported so legacy callers keep working during the v2 transition.
__all__ = [
    "DELEGATED_SCOPES",
    "GRAPH_RESOURCE_SCOPE",
    "TOKEN_CACHE_NAME",
    "PSContext",
    "_build_powershell_invocation",
    "_parse_powershell_json_payload",
    "_powershell_executable",
    "_run_powershell",
    "disconnect_graph_powershell",
    "invoke_graph_powershell_request",
    "peek_display_name_via_powershell",
    "try_graph_powershell_context",
]


# Deprecated alias — keeps the print-to-stdout behavior used by CLI.
def log_logout_hint() -> None:
    print("Cleared in-memory credentials. You may need to clear Windows Credential Manager")
    print(f"for full token removal (look for entries matching '{TOKEN_CACHE_NAME}').", file=sys.stderr)
