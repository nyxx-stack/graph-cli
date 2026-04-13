"""Device code flow authentication with DPAPI-encrypted token caching."""

from __future__ import annotations

import sys
from pathlib import Path

import yaml
from azure.identity import DeviceCodeCredential, TokenCachePersistenceOptions
from msgraph import GraphServiceClient

from graph_cli.types import AuthConfig, AuthStatus

CONFIG_DIR = Path.home() / ".daf-graph"
CONFIG_FILE = CONFIG_DIR / "config.yaml"
TOKEN_CACHE_NAME = "daf-cmmc-graph-cli"

# Delegated permissions for CMMC Intune/Entra management
SCOPES = [
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

_credential: DeviceCodeCredential | None = None
_client: GraphServiceClient | None = None


def _load_config() -> AuthConfig:
    """Load auth config from file or environment variables."""
    import os

    tenant_id = os.environ.get("MSGRAPH_TENANT_ID")
    client_id = os.environ.get("MSGRAPH_CLIENT_ID")

    if not (tenant_id and client_id):
        if CONFIG_FILE.exists():
            with open(CONFIG_FILE) as f:
                data = yaml.safe_load(f) or {}
            tenant_id = tenant_id or data.get("tenant_id")
            client_id = client_id or data.get("client_id")

    if not tenant_id or not client_id:
        raise RuntimeError(
            f"Missing tenant_id or client_id. Set MSGRAPH_TENANT_ID and MSGRAPH_CLIENT_ID "
            f"env vars, or create {CONFIG_FILE} with tenant_id and client_id."
        )

    return AuthConfig(tenant_id=tenant_id, client_id=client_id)


def _device_code_callback(verification_uri: str, user_code: str, expires_on: object) -> None:
    """Print device code prompt for the user."""
    print(f"\nTo sign in, open: {verification_uri}")
    print(f"Enter code: {user_code}\n")
    print("Waiting for authentication...", file=sys.stderr)


def _get_credential(force_new: bool = False) -> DeviceCodeCredential:
    """Get or create the device code credential with persistent caching."""
    global _credential

    if _credential is not None and not force_new:
        return _credential

    config = _load_config()

    cache_options = TokenCachePersistenceOptions(
        name=TOKEN_CACHE_NAME,
        allow_unencrypted_storage=False,
    )

    _credential = DeviceCodeCredential(
        tenant_id=config.tenant_id,
        client_id=config.client_id,
        cache_persistence_options=cache_options,
        prompt_callback=_device_code_callback,
    )

    return _credential


def get_client(force_new: bool = False) -> GraphServiceClient:
    """Get or create the Graph client with cached auth."""
    global _client

    if _client is not None and not force_new:
        return _client

    credential = _get_credential(force_new=force_new)
    _client = GraphServiceClient(credentials=credential, scopes=SCOPES)
    return _client


def login() -> AuthStatus:
    """Initiate device code flow and return status after auth completes."""
    credential = _get_credential(force_new=True)

    # Force a token acquisition to trigger the device code prompt
    token = credential.get_token(*SCOPES)

    return AuthStatus(
        authenticated=True,
        token_expires=None,  # token.expires_on is a unix timestamp
        scopes=list(SCOPES),
    )


def logout() -> None:
    """Clear cached credentials."""
    global _credential, _client
    _credential = None
    _client = None
    # The persistent token cache is managed by azure-identity.
    # To fully clear it, we'd need to access the MSAL cache directly.
    # For now, clearing the in-memory references forces re-auth on next use.
    print("Cleared in-memory credentials. You may need to clear Windows Credential Manager")
    print(f"for full token removal (look for entries matching '{TOKEN_CACHE_NAME}').")


def status() -> AuthStatus:
    """Check current authentication status without triggering login."""
    try:
        credential = _get_credential()
        # Try to get a token silently (from cache)
        token = credential.get_token(*SCOPES)
        from datetime import datetime, timezone

        expires = datetime.fromtimestamp(token.expires_on, tz=timezone.utc) if token.expires_on else None

        return AuthStatus(
            authenticated=True,
            token_expires=expires,
            scopes=list(SCOPES),
        )
    except Exception:
        return AuthStatus(authenticated=False)


def ensure_authenticated() -> GraphServiceClient:
    """Get the Graph client, raising a clear error if not authenticated."""
    try:
        client = get_client()
        # Verify we can get a token
        credential = _get_credential()
        credential.get_token(*SCOPES)
        return client
    except Exception as e:
        raise RuntimeError(
            f"Not authenticated. Run: graph auth login\nError: {e}"
        ) from e


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
