"""Delegated (device code) credential factory for auth profiles."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

import yaml

from graphconnect.auth.powershell import DELEGATED_SCOPES, TOKEN_CACHE_NAME
from graphconnect.types import AuthConfig


def _device_code_callback(verification_uri: str, user_code: str, expires_on: object) -> None:
    del expires_on
    print(f"\nTo sign in, open: {verification_uri}", file=sys.stderr)
    print(f"Enter code: {user_code}\n", file=sys.stderr)
    print("Waiting for authentication...", file=sys.stderr)


def resolve_device_code_config(legacy_config_file: Path | None = None) -> AuthConfig | None:
    """Load device-code auth config from environment or the legacy yaml file."""
    tenant_id = os.environ.get("MSGRAPH_TENANT_ID")
    client_id = os.environ.get("MSGRAPH_CLIENT_ID")

    if (not tenant_id or not client_id) and legacy_config_file is not None:
        try:
            with open(legacy_config_file, encoding="utf-8") as handle:
                data = yaml.safe_load(handle) or {}
            tenant_id = tenant_id or data.get("tenant_id")
            client_id = client_id or data.get("client_id")
        except FileNotFoundError:
            pass

    if not tenant_id or not client_id:
        return None

    return AuthConfig(tenant_id=tenant_id, client_id=client_id)


def build_device_code_credential(
    *,
    tenant_id: str,
    client_id: str,
    authority: str | None = None,
    cache_name: str = TOKEN_CACHE_NAME,
) -> Any:
    """Create a DeviceCodeCredential with persistent token cache when available."""
    from azure.identity import DeviceCodeCredential

    kwargs: dict[str, Any] = {
        "tenant_id": tenant_id,
        "client_id": client_id,
        "prompt_callback": _device_code_callback,
    }
    if authority:
        kwargs["authority"] = authority

    try:
        from azure.identity import TokenCachePersistenceOptions

        kwargs["cache_persistence_options"] = TokenCachePersistenceOptions(
            name=cache_name,
            allow_unencrypted_storage=False,
        )
    except ImportError:
        pass

    return DeviceCodeCredential(**kwargs)


__all__ = [
    "DELEGATED_SCOPES",
    "build_device_code_credential",
    "resolve_device_code_config",
]
