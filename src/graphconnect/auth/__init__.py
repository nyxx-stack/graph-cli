"""GraphConnect auth profiles — public API.

Contract §3. Splits the legacy ``auth.py`` module into:
- profiles.py — on-disk profile registry + token cache paths.
- delegated.py — DeviceCodeCredential flow.
- app_only.py — ClientSecretCredential / CertificateCredential.
- powershell.py — Microsoft.Graph.Authentication fallback.

The legacy public surface used by executor / doctor / main / _ps_host is
re-exported from this module so the v2 rewrite is a drop-in replacement.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

import yaml
from msgraph import GraphServiceClient

from graphconnect.auth.app_only import (
    build_certificate_credential,
    build_client_secret_credential,
)
from graphconnect.auth.delegated import (
    build_device_code_credential,
    resolve_device_code_config,
)
from graphconnect.auth.powershell import (
    DELEGATED_SCOPES,
    GRAPH_RESOURCE_SCOPE,
    TOKEN_CACHE_NAME,
    PSContext,
    _build_powershell_invocation,
    _parse_powershell_json_payload,
    _powershell_executable,
    _run_powershell,
    disconnect_graph_powershell,
    invoke_graph_powershell_request,
    log_logout_hint,
    peek_display_name_via_powershell,
    try_graph_powershell_context,
)
from graphconnect.auth.profiles import (
    AuthMode,
    AuthProfile,
    AuthProfileStatus,
    LEGACY_CONFIG_DIR,
    LEGACY_CONFIG_FILE,
    PROFILES_DIR,
    clear_token_cache,
    delete_profile,
    get_profile,
    list_profiles,
    resolve_profile_name,
    save_profile,
    token_cache_path,
    use_profile,
)
from graphconnect.transport.national_cloud import (
    NationalCloud,
    get_authority,
    get_endpoint_base,
)
from graphconnect.types import AuthConfig, AuthMethod, AuthStatus

# Legacy aliases kept for callers that import these names directly.
CONFIG_DIR = LEGACY_CONFIG_DIR
CONFIG_FILE = LEGACY_CONFIG_FILE


@dataclass
class CredentialContext:
    """Legacy-shaped credential context used by executor."""

    credential: Any
    scopes: list[str] = field(default_factory=list)
    auth_method: AuthMethod = AuthMethod.DEVICE_CODE
    user_principal: str | None = None
    profile: str = "default"


# Per-profile in-memory caches: credential + GraphServiceClient instances.
_credential_cache: dict[str, CredentialContext] = {}
_client_cache: dict[str, GraphServiceClient] = {}


# ---------------------------------------------------------------------------
# Core: profile -> credential resolution
# ---------------------------------------------------------------------------


def _authority_for(profile: AuthProfile) -> str | None:
    try:
        return get_authority(profile.national_cloud)
    except ValueError:
        return None


def _build_credential_context(profile: AuthProfile, *, force_new: bool = False) -> CredentialContext:
    match profile.mode:
        case "delegated-ps":
            ctx = try_graph_powershell_context(force_login=force_new)
            if ctx is None:
                # Fall through to device code if PowerShell isn't usable.
                return _build_delegated_context(profile)
            return CredentialContext(
                credential=None,
                scopes=list(ctx.scopes),
                auth_method=AuthMethod.GRAPH_POWERSHELL,
                user_principal=ctx.user_principal,
                profile=profile.name,
            )
        case "delegated":
            return _build_delegated_context(profile)
        case "app-secret":
            if not profile.tenant_id or not profile.client_id:
                raise RuntimeError(
                    f"profile '{profile.name}' (app-secret) missing tenant_id/client_id."
                )
            # Secret not stored on disk — pulled from env at build time.
            import os

            secret = os.environ.get("MSGRAPH_CLIENT_SECRET")
            if not secret:
                raise RuntimeError(
                    f"profile '{profile.name}' (app-secret) requires MSGRAPH_CLIENT_SECRET env var."
                )
            credential = build_client_secret_credential(
                tenant_id=profile.tenant_id,
                client_id=profile.client_id,
                client_secret=secret,
                authority=_authority_for(profile),
            )
            return CredentialContext(
                credential=credential,
                scopes=[GRAPH_RESOURCE_SCOPE],
                auth_method=AuthMethod.DEVICE_CODE,
                profile=profile.name,
            )
        case "app-cert":
            if not profile.tenant_id or not profile.client_id or not profile.cert_path:
                raise RuntimeError(
                    f"profile '{profile.name}' (app-cert) missing tenant_id/client_id/cert_path."
                )
            credential = build_certificate_credential(
                tenant_id=profile.tenant_id,
                client_id=profile.client_id,
                cert_path=profile.cert_path,
                authority=_authority_for(profile),
            )
            return CredentialContext(
                credential=credential,
                scopes=[GRAPH_RESOURCE_SCOPE],
                auth_method=AuthMethod.DEVICE_CODE,
                profile=profile.name,
            )
        case _:
            raise RuntimeError(f"unknown auth mode '{profile.mode}'")


def _build_delegated_context(profile: AuthProfile) -> CredentialContext:
    """Fall back to DeviceCodeCredential for a 'delegated' profile or legacy path."""
    tenant_id = profile.tenant_id
    client_id = profile.client_id
    if not tenant_id or not client_id:
        legacy = resolve_device_code_config(LEGACY_CONFIG_FILE if profile.name == "default" else None)
        if legacy is not None:
            tenant_id = tenant_id or legacy.tenant_id
            client_id = client_id or legacy.client_id

    if not tenant_id or not client_id:
        raise RuntimeError(
            f"profile '{profile.name}' (delegated) missing tenant_id/client_id. "
            "Set MSGRAPH_TENANT_ID / MSGRAPH_CLIENT_ID, or re-run `auth login`."
        )

    credential = build_device_code_credential(
        tenant_id=tenant_id,
        client_id=client_id,
        authority=_authority_for(profile),
        cache_name=f"{TOKEN_CACHE_NAME}-{profile.name}" if profile.name != "default" else TOKEN_CACHE_NAME,
    )
    return CredentialContext(
        credential=credential,
        scopes=list(DELEGATED_SCOPES),
        auth_method=AuthMethod.DEVICE_CODE,
        profile=profile.name,
    )


def get_credential(profile: str = "default", *, force_new: bool = False) -> Any:
    """Return a credential object (or None for PowerShell mode) for the profile.

    Per contract §3. Returns an ``azure.identity`` TokenCredential, or ``None`` when
    the profile uses the PowerShell-backed session.
    """
    context = get_auth_context(profile=profile, force_new=force_new)
    return context.credential


def get_auth_context(profile: str | None = None, *, force_new: bool = False) -> CredentialContext:
    """Return a CredentialContext for the named profile, cached per-profile."""
    resolved = resolve_profile_name(profile)
    if not force_new and resolved in _credential_cache:
        return _credential_cache[resolved]

    prof = get_profile(resolved)
    context = _build_credential_context(prof, force_new=force_new)
    _credential_cache[resolved] = context
    return context


def get_client(profile: str | None = None, *, force_new: bool = False) -> GraphServiceClient:
    """Return a GraphServiceClient for the profile; legacy callers pass no args."""
    resolved = resolve_profile_name(profile)
    if not force_new and resolved in _client_cache:
        return _client_cache[resolved]

    context = get_auth_context(profile=resolved, force_new=force_new)
    if context.credential is None:
        raise RuntimeError(
            f"Auth method '{context.auth_method.value}' does not provide a Graph SDK credential."
        )
    client = GraphServiceClient(credentials=context.credential, scopes=context.scopes)
    _client_cache[resolved] = client
    return client


def peek_user_principal(profile: str | None = None) -> str | None:
    resolved = resolve_profile_name(profile)
    ctx = _credential_cache.get(resolved)
    return ctx.user_principal if ctx else None


# ---------------------------------------------------------------------------
# v2 public API
# ---------------------------------------------------------------------------


async def login(
    profile: str,
    *,
    mode: Literal["delegated", "app-secret", "app-cert"],
    tenant_id: str | None = None,
    client_id: str | None = None,
    client_secret: str | None = None,
    cert_path: str | None = None,
    national_cloud: str = "commercial",
    make_default: bool = False,
) -> AuthProfile:
    """Create (or overwrite) a profile and trigger an initial credential build."""
    del client_secret  # secret stays in env, not on disk
    prof = AuthProfile(
        name=profile,
        mode=mode,
        tenant_id=tenant_id or "",
        client_id=client_id or "",
        national_cloud=national_cloud,
        cert_path=cert_path,
        default=make_default,
    )
    save_profile(prof)
    _credential_cache.pop(profile, None)
    _client_cache.pop(profile, None)
    # Eagerly resolve a credential so misconfig shows up now, not on first use.
    get_auth_context(profile=profile, force_new=True)
    return prof


async def status(profile: str | None = None) -> list[AuthProfileStatus]:
    """Return token state for one profile, or all profiles when name is None."""
    names: list[str]
    if profile is None:
        names = [p.name for p in list_profiles()]
    else:
        names = [resolve_profile_name(profile)]

    out: list[AuthProfileStatus] = []
    for name in names:
        prof = get_profile(name)
        base = AuthProfileStatus(
            name=prof.name,
            mode=prof.mode,
            tenant_id=prof.tenant_id,
            national_cloud=prof.national_cloud,
            default=prof.default,
        )
        try:
            ctx = get_auth_context(profile=name)
        except Exception as exc:
            base.error = str(exc)
            out.append(base)
            continue

        base.scopes = list(ctx.scopes)
        base.user_principal = ctx.user_principal

        if ctx.credential is None:
            base.authenticated = ctx.user_principal is not None
        else:
            try:
                scopes = ctx.scopes if ctx.scopes else [GRAPH_RESOURCE_SCOPE]
                token = ctx.credential.get_token(*scopes)
                base.authenticated = True
                if token.expires_on:
                    base.token_expires = datetime.fromtimestamp(token.expires_on, tz=timezone.utc)
            except Exception as exc:
                base.authenticated = False
                base.error = str(exc)
        out.append(base)
    return out


def logout(profile: str | None = None) -> None:
    """Clear credential cache and remove the profile's token cache file."""
    resolved = resolve_profile_name(profile)
    prior = _credential_cache.pop(resolved, None)
    _client_cache.pop(resolved, None)
    clear_token_cache(resolved)

    if prior is not None and prior.auth_method == AuthMethod.GRAPH_POWERSHELL:
        disconnect_graph_powershell()
    log_logout_hint()


# ---------------------------------------------------------------------------
# Legacy compatibility shims (main.py + tests + doctor)
# ---------------------------------------------------------------------------


def legacy_login_default() -> AuthStatus:
    """Legacy ``login()`` behavior preserved for the existing CLI subcommand.

    Uses the default profile; triggers an interactive sign-in when needed.
    """
    context = get_auth_context(profile=None, force_new=True)

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


def legacy_status_default() -> AuthStatus:
    """Legacy ``status()`` behavior — never triggers a login."""
    try:
        context = get_auth_context(profile=None)
        if context.credential is None:
            display_name = peek_display_name_via_powershell()
            return AuthStatus(
                authenticated=True,
                auth_method=context.auth_method,
                user_principal=context.user_principal,
                display_name=display_name,
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


def legacy_logout() -> None:
    """Legacy ``logout()`` behavior — clears default profile credentials."""
    logout(profile=None)


def save_config(tenant_id: str, client_id: str) -> None:
    """Save legacy auth config (tenant + client) and sync to default profile."""
    LEGACY_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(LEGACY_CONFIG_FILE, "w", encoding="utf-8") as handle:
        yaml.safe_dump(
            {"tenant_id": tenant_id, "client_id": client_id},
            handle,
            default_flow_style=False,
        )
    print(f"Config saved to {LEGACY_CONFIG_FILE}")

    try:
        default_name = resolve_profile_name(None)
        prof = get_profile(default_name)
        prof.tenant_id = tenant_id
        prof.client_id = client_id
        save_profile(prof)
        _credential_cache.pop(default_name, None)
        _client_cache.pop(default_name, None)
    except Exception:
        pass


__all__ = [
    # v2 public API
    "AuthMode",
    "AuthProfile",
    "AuthProfileStatus",
    "get_credential",
    "list_profiles",
    "login",
    "logout",
    "status",
    "use_profile",
    # Shared / legacy surface used elsewhere in the codebase
    "CONFIG_DIR",
    "CONFIG_FILE",
    "CredentialContext",
    "DELEGATED_SCOPES",
    "GRAPH_RESOURCE_SCOPE",
    "NationalCloud",
    "TOKEN_CACHE_NAME",
    "_build_powershell_invocation",
    "_parse_powershell_json_payload",
    "_powershell_executable",
    "_run_powershell",
    "get_auth_context",
    "get_client",
    "get_profile",
    "invoke_graph_powershell_request",
    "legacy_login_default",
    "legacy_logout",
    "legacy_status_default",
    "peek_user_principal",
    "save_config",
    "save_profile",
    "token_cache_path",
]
