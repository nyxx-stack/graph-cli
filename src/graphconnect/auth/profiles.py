"""Auth profile registry on disk (~/.graphconnect/profiles/)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

# The legacy single-user dir; we keep using it for the implicit "default"
# profile's token cache so existing signed-in users do not have to re-auth.
LEGACY_CONFIG_DIR = Path.home() / ".graphconnect"
LEGACY_CONFIG_FILE = LEGACY_CONFIG_DIR / "config.yaml"

PROFILES_DIR = LEGACY_CONFIG_DIR / "profiles"
DEFAULT_POINTER_FILE = PROFILES_DIR / "_default.txt"

AuthMode = Literal["delegated", "app-secret", "app-cert", "delegated-ps"]
NationalCloudName = Literal["commercial", "USGov", "USGovHigh", "DoD", "China"]


class AuthProfile(BaseModel):
    name: str
    mode: AuthMode
    tenant_id: str = ""
    client_id: str = ""
    national_cloud: str = "commercial"
    cert_path: str | None = None
    default: bool = False


class AuthProfileStatus(BaseModel):
    name: str
    mode: AuthMode
    tenant_id: str = ""
    national_cloud: str = "commercial"
    default: bool = False
    authenticated: bool = False
    user_principal: str | None = None
    token_expires: datetime | None = None
    scopes: list[str] = Field(default_factory=list)
    error: str | None = None


def _ensure_profiles_dir() -> Path:
    PROFILES_DIR.mkdir(parents=True, exist_ok=True)
    return PROFILES_DIR


def profile_dir(name: str) -> Path:
    return PROFILES_DIR / name


def profile_config_path(name: str) -> Path:
    return profile_dir(name) / "config.json"


def token_cache_path(name: str) -> Path:
    return profile_dir(name) / "token_cache.bin"


def _profile_exists(name: str) -> bool:
    return profile_config_path(name).exists()


def _write_profile(profile: AuthProfile) -> None:
    _ensure_profiles_dir()
    profile_dir(profile.name).mkdir(parents=True, exist_ok=True)
    path = profile_config_path(profile.name)
    path.write_text(
        json.dumps(profile.model_dump(), indent=2, sort_keys=True),
        encoding="utf-8",
    )


def _read_profile(name: str) -> AuthProfile:
    path = profile_config_path(name)
    if not path.exists():
        raise FileNotFoundError(f"profile '{name}' not found at {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    return AuthProfile(**data)


def _read_default_pointer() -> str | None:
    if not DEFAULT_POINTER_FILE.exists():
        return None
    name = DEFAULT_POINTER_FILE.read_text(encoding="utf-8").strip()
    return name or None


def _write_default_pointer(name: str) -> None:
    _ensure_profiles_dir()
    DEFAULT_POINTER_FILE.write_text(name, encoding="utf-8")


def _bootstrap_default_if_missing() -> None:
    """Seed a 'default' profile on first use so legacy users keep working."""
    _ensure_profiles_dir()
    if _profile_exists("default"):
        if _read_default_pointer() is None:
            _write_default_pointer("default")
        return

    # Pull tenant/client from the legacy yaml if present; otherwise fall back
    # to env values that the device-code resolver will consult at login time.
    tenant_id = ""
    client_id = ""
    if LEGACY_CONFIG_FILE.exists():
        try:
            import yaml

            data = yaml.safe_load(LEGACY_CONFIG_FILE.read_text(encoding="utf-8")) or {}
            tenant_id = data.get("tenant_id", "") or ""
            client_id = data.get("client_id", "") or ""
        except Exception:
            pass

    profile = AuthProfile(
        name="default",
        mode="delegated-ps",
        tenant_id=tenant_id,
        client_id=client_id,
        national_cloud="commercial",
        default=True,
    )
    _write_profile(profile)
    _write_default_pointer("default")


def list_profiles() -> list[AuthProfile]:
    _bootstrap_default_if_missing()
    profiles: list[AuthProfile] = []
    default_name = _read_default_pointer()
    for child in sorted(PROFILES_DIR.iterdir()):
        if not child.is_dir():
            continue
        cfg = child / "config.json"
        if not cfg.exists():
            continue
        try:
            profile = _read_profile(child.name)
        except Exception:
            continue
        profile.default = profile.name == default_name
        profiles.append(profile)
    return profiles


def get_profile(name: str) -> AuthProfile:
    _bootstrap_default_if_missing()
    profile = _read_profile(name)
    default_name = _read_default_pointer()
    profile.default = profile.name == default_name
    return profile


def resolve_profile_name(name: str | None) -> str:
    _bootstrap_default_if_missing()
    if name:
        return name
    return _read_default_pointer() or "default"


def use_profile(name: str) -> None:
    _bootstrap_default_if_missing()
    if not _profile_exists(name):
        raise FileNotFoundError(f"profile '{name}' not found")
    _write_default_pointer(name)


def save_profile(profile: AuthProfile) -> AuthProfile:
    """Create or update a profile's on-disk config."""
    _ensure_profiles_dir()
    existing_default = _read_default_pointer()
    _write_profile(profile)
    if profile.default or existing_default is None:
        _write_default_pointer(profile.name)
    return profile


def delete_profile(name: str) -> None:
    path = profile_config_path(name)
    if path.exists():
        path.unlink()
    cache = token_cache_path(name)
    if cache.exists():
        cache.unlink()
    pdir = profile_dir(name)
    if pdir.exists() and not any(pdir.iterdir()):
        pdir.rmdir()
    if _read_default_pointer() == name:
        remaining = [p for p in PROFILES_DIR.iterdir() if p.is_dir() and (p / "config.json").exists()]
        if remaining:
            _write_default_pointer(remaining[0].name)
        else:
            DEFAULT_POINTER_FILE.unlink(missing_ok=True)


def clear_token_cache(name: str) -> bool:
    cache = token_cache_path(name)
    if cache.exists():
        cache.unlink()
        return True
    return False


def utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


__all__ = [
    "AuthMode",
    "AuthProfile",
    "AuthProfileStatus",
    "DEFAULT_POINTER_FILE",
    "LEGACY_CONFIG_DIR",
    "LEGACY_CONFIG_FILE",
    "NationalCloudName",
    "PROFILES_DIR",
    "clear_token_cache",
    "delete_profile",
    "get_profile",
    "list_profiles",
    "profile_config_path",
    "profile_dir",
    "resolve_profile_name",
    "save_profile",
    "token_cache_path",
    "use_profile",
]
