"""Authentication helpers for Microsoft Graph CLI."""

from __future__ import annotations

import functools
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from azure.identity import (
    AzureCliCredential,
    AzurePowerShellCredential,
    DeviceCodeCredential,
    TokenCachePersistenceOptions,
)
from msgraph import GraphServiceClient

from graph_cli.types import AuthConfig, AuthMethod, AuthStatus

CONFIG_DIR = Path.home() / ".daf-graph"
CONFIG_FILE = CONFIG_DIR / "config.yaml"
TOKEN_CACHE_NAME = "daf-cmmc-graph-cli"
GRAPH_RESOURCE_SCOPE = "https://graph.microsoft.com/.default"

# Delegated permissions for CMMC Intune/Entra management
DELEGATED_SCOPES = [
    "DeviceManagementManagedDevices.Read.All",
    "DeviceManagementManagedDevices.ReadWrite.All",
    "DeviceManagementManagedDevices.PrivilegedOperations.All",
    "DeviceManagementConfiguration.Read.All",
    "DeviceManagementConfiguration.ReadWrite.All",
    "Directory.Read.All",
    "User.Read.All",
    "Device.Read.All",
    "Group.Read.All",
    "GroupMember.Read.All",
    "GroupMember.ReadWrite.All",
    "AuditLog.Read.All",
    "Policy.Read.All",
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


@dataclass
class CredentialContext:
    credential: Any
    scopes: list[str]
    auth_method: AuthMethod
    user_principal: str | None = None


_cached_context: CredentialContext | None = None
_client: GraphServiceClient | None = None


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
    script: str, extra_env: dict[str, str] | None = None, timeout: float | None = 60
) -> subprocess.CompletedProcess[str]:
    """Run a PowerShell script and return the completed process."""
    argv, env = _build_powershell_invocation(script, extra_env=extra_env)
    return subprocess.run(argv, capture_output=True, text=True, env=env, check=False, timeout=timeout)


def _launch_powershell_window(
    script: str, extra_env: dict[str, str] | None = None
) -> subprocess.Popen[str]:
    """Launch a separate PowerShell window for interactive auth."""
    argv, env = _build_powershell_invocation(script, no_exit=True, extra_env=extra_env)
    creationflags = getattr(subprocess, "CREATE_NEW_CONSOLE", 0)
    return subprocess.Popen(argv, env=env, creationflags=creationflags)


def _run_powershell_json(script: str, extra_env: dict[str, str] | None = None) -> Any:
    """Run a PowerShell script that emits JSON and parse the result."""
    result = _run_powershell(script, extra_env=extra_env)
    if result.returncode != 0:
        error = (result.stderr or result.stdout).strip()
        raise RuntimeError(error or "PowerShell command failed.")
    payload = result.stdout.strip()
    if not payload:
        return None
    return json.loads(payload)


def _scopes_block() -> str:
    """Return a PowerShell snippet that binds $requiredScopes to the CLI's scope list."""
    scopes_json = json.dumps(DELEGATED_SCOPES)
    return f"$requiredScopes = ConvertFrom-Json @'\n{scopes_json}\n'@\n"


def _get_graph_powershell_context_data(connect: bool = False) -> dict[str, Any] | None:
    """Read the current Graph PowerShell context; optionally reconnect from MSAL cache first."""
    parts = [_PS_PREAMBLE]
    if connect:
        parts.append(
            f"{_scopes_block()}"
            "Connect-MgGraph -ContextScope CurrentUser -Scopes $requiredScopes -NoWelcome | Out-Null\n"
        )
    parts.append(_GET_CONTEXT_TAIL)
    data = _run_powershell_json("".join(parts))
    return data if isinstance(data, dict) else None


def _resolve_device_code_config() -> AuthConfig | None:
    """Load device-code auth config from file or environment variables."""
    tenant_id = os.environ.get("MSGRAPH_TENANT_ID")
    client_id = os.environ.get("MSGRAPH_CLIENT_ID")

    if not (tenant_id and client_id):
        try:
            with open(CONFIG_FILE) as f:
                data = yaml.safe_load(f) or {}
            tenant_id = tenant_id or data.get("tenant_id")
            client_id = client_id or data.get("client_id")
        except FileNotFoundError:
            pass

    if not tenant_id or not client_id:
        return None

    return AuthConfig(tenant_id=tenant_id, client_id=client_id)


def _device_code_callback(verification_uri: str, user_code: str, expires_on: object) -> None:
    """Print device code prompt for the user."""
    print(f"\nTo sign in, open: {verification_uri}")
    print(f"Enter code: {user_code}\n")
    print("Waiting for authentication...", file=sys.stderr)


def _build_device_code_credential(config: AuthConfig) -> DeviceCodeCredential:
    """Create the configured device-code credential with persistent caching."""
    cache_options = TokenCachePersistenceOptions(
        name=TOKEN_CACHE_NAME,
        allow_unencrypted_storage=False,
    )
    return DeviceCodeCredential(
        tenant_id=config.tenant_id,
        client_id=config.client_id,
        cache_persistence_options=cache_options,
        prompt_callback=_device_code_callback,
    )


def _try_graph_powershell_context(force_login: bool = False) -> CredentialContext | None:
    """Use Microsoft Graph PowerShell as the primary no-app auth backend."""
    if not _powershell_executable():
        return None

    try:
        data = _get_graph_powershell_context_data()
    except (RuntimeError, subprocess.TimeoutExpired):
        data = None

    if data is None:
        try:
            data = _get_graph_powershell_context_data(connect=True)
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
        while time.monotonic() < deadline:
            data = _get_graph_powershell_context_data()
            current_scopes = set(data.get("scopes") or []) if data else set()
            missing_scopes = [scope for scope in DELEGATED_SCOPES if scope not in current_scopes]
            if data is not None and not missing_scopes:
                break
            if process.poll() is not None and process.returncode not in (None, 0):
                raise RuntimeError("Connect-MgGraph failed in the sign-in window.")
            time.sleep(2)

    if data is None or missing_scopes:
        return None

    return CredentialContext(
        credential=None,
        scopes=list(data.get("scopes") or []),
        auth_method=AuthMethod.GRAPH_POWERSHELL,
        user_principal=data.get("account"),
    )


def _try_tool_credentials() -> CredentialContext | None:
    """Try existing Microsoft developer-tool sign-ins before app-based auth."""
    for auth_method, builder in (
        (AuthMethod.AZURE_CLI, AzureCliCredential),
        (AuthMethod.AZURE_POWERSHELL, AzurePowerShellCredential),
    ):
        try:
            credential = builder()
            credential.get_token(GRAPH_RESOURCE_SCOPE)
            return CredentialContext(
                credential=credential,
                scopes=[GRAPH_RESOURCE_SCOPE],
                auth_method=auth_method,
            )
        except Exception:
            continue
    return None


def _get_credential(force_new: bool = False) -> CredentialContext:
    """Get or create the active credential context."""
    global _cached_context

    if _cached_context is not None and not force_new:
        return _cached_context

    context = _try_graph_powershell_context(force_login=force_new)

    if context is None:
        config = _resolve_device_code_config()
        if config is not None:
            context = CredentialContext(
                credential=_build_device_code_credential(config),
                scopes=list(DELEGATED_SCOPES),
                auth_method=AuthMethod.DEVICE_CODE,
            )

    if context is None:
        context = _try_tool_credentials()

    if context is None:
        raise RuntimeError(
            "No usable authentication source found. Recommended: use Microsoft Graph PowerShell "
            "(`Connect-MgGraph -UseDeviceCode`). Optional: sign in with Azure CLI (`az login`) "
            "or Azure PowerShell (`Connect-AzAccount`). Fallback: set MSGRAPH_TENANT_ID and "
            f"MSGRAPH_CLIENT_ID, or create {CONFIG_FILE} with tenant_id and client_id."
        )

    _cached_context = context
    return context


def get_client(force_new: bool = False) -> GraphServiceClient:
    """Get or create the Graph client with cached auth."""
    global _client

    if _client is not None and not force_new:
        return _client

    context = _get_credential(force_new=force_new)
    if context.credential is None:
        raise RuntimeError(
            f"Auth method '{context.auth_method.value}' does not provide a Graph SDK credential."
        )
    _client = GraphServiceClient(credentials=context.credential, scopes=context.scopes)
    return _client


def login() -> AuthStatus:
    """Authenticate and return status after auth completes."""
    context = _get_credential(force_new=True)

    if context.credential is None:
        return AuthStatus(
            authenticated=True,
            auth_method=context.auth_method,
            user_principal=context.user_principal,
            scopes=list(context.scopes),
        )

    token = context.credential.get_token(*context.scopes)

    return AuthStatus(
        authenticated=True,
        auth_method=context.auth_method,
        user_principal=context.user_principal,
        token_expires=datetime.fromtimestamp(token.expires_on, tz=timezone.utc) if token.expires_on else None,
        scopes=list(context.scopes),
    )


def logout() -> None:
    """Clear cached credentials."""
    global _cached_context, _client
    prior_method = _cached_context.auth_method if _cached_context else None
    _cached_context = None
    _client = None
    if prior_method == AuthMethod.GRAPH_POWERSHELL and _powershell_executable():
        try:
            _run_powershell(
                "Import-Module Microsoft.Graph.Authentication -ErrorAction SilentlyContinue; "
                "Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null"
            )
        except (RuntimeError, subprocess.TimeoutExpired, OSError):
            pass
    # The persistent token cache is managed by azure-identity.
    # To fully clear it, we'd need to access the MSAL cache directly.
    # For now, clearing the in-memory references forces re-auth on next use.
    print("Cleared in-memory credentials. You may need to clear Windows Credential Manager")
    print(f"for full token removal (look for entries matching '{TOKEN_CACHE_NAME}').")


def status() -> AuthStatus:
    """Check current authentication status without triggering login."""
    try:
        context = _get_credential()
        if context.credential is None:
            return AuthStatus(
                authenticated=True,
                auth_method=context.auth_method,
                user_principal=context.user_principal,
                scopes=list(context.scopes),
            )
        token = context.credential.get_token(*context.scopes)
        expires = datetime.fromtimestamp(token.expires_on, tz=timezone.utc) if token.expires_on else None

        return AuthStatus(
            authenticated=True,
            auth_method=context.auth_method,
            user_principal=context.user_principal,
            token_expires=expires,
            scopes=list(context.scopes),
        )
    except Exception:
        return AuthStatus(authenticated=False)


def get_auth_context(force_new: bool = False) -> CredentialContext:
    """Expose the active authentication context to request execution helpers."""
    return _get_credential(force_new=force_new)


def invoke_graph_powershell_request(
    *,
    method: str,
    url: str,
    body: dict[str, Any] | None = None,
) -> Any:
    """Execute a Graph request through Microsoft Graph PowerShell."""
    body_json = json.dumps(body) if body is not None else ""
    script = f"""{_PS_PREAMBLE}
$ctx = Get-MgContext -ErrorAction SilentlyContinue
if (-not $ctx) {{
{_scopes_block()}Connect-MgGraph -ContextScope CurrentUser -Scopes $requiredScopes -NoWelcome | Out-Null
    $ctx = Get-MgContext -ErrorAction SilentlyContinue
}}
if (-not $ctx) {{
    throw 'Not authenticated with Microsoft Graph PowerShell. Run graph auth login or Connect-MgGraph -UseDeviceCode.'
}}
$params = @{{
    Method = $env:GRAPHCLI_METHOD
    Uri = $env:GRAPHCLI_URL
    OutputType = 'Json'
}}
if ($env:GRAPHCLI_BODY) {{
    $params.Body = $env:GRAPHCLI_BODY | ConvertFrom-Json
}}
$response = Invoke-MgGraphRequest @params
if ($null -ne $response) {{
    [Console]::Out.Write($response)
}}
"""
    env = {
        "GRAPHCLI_METHOD": method,
        "GRAPHCLI_URL": url,
        "GRAPHCLI_BODY": body_json,
    }
    return _run_powershell_json(script, extra_env=env)


def save_config(tenant_id: str, client_id: str) -> None:
    """Save auth configuration to disk."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        yaml.safe_dump(
            {"tenant_id": tenant_id, "client_id": client_id},
            f,
            default_flow_style=False,
        )
    print(f"Config saved to {CONFIG_FILE}")
