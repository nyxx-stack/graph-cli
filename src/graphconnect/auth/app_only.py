"""App-only credential factories (client secret + certificate)."""

from __future__ import annotations

from pathlib import Path
from typing import Any


def build_client_secret_credential(
    *,
    tenant_id: str,
    client_id: str,
    client_secret: str,
    authority: str | None = None,
) -> Any:
    from azure.identity import ClientSecretCredential

    kwargs: dict[str, Any] = {
        "tenant_id": tenant_id,
        "client_id": client_id,
        "client_secret": client_secret,
    }
    if authority:
        kwargs["authority"] = authority
    return ClientSecretCredential(**kwargs)


def build_certificate_credential(
    *,
    tenant_id: str,
    client_id: str,
    cert_path: str | Path,
    cert_password: str | None = None,
    authority: str | None = None,
) -> Any:
    from azure.identity import CertificateCredential

    path = Path(cert_path)
    if not path.exists():
        raise FileNotFoundError(f"certificate file not found: {path}")

    kwargs: dict[str, Any] = {
        "tenant_id": tenant_id,
        "client_id": client_id,
        "certificate_path": str(path),
    }
    if cert_password:
        kwargs["password"] = cert_password
    if authority:
        kwargs["authority"] = authority
    return CertificateCredential(**kwargs)


__all__ = [
    "build_certificate_credential",
    "build_client_secret_credential",
]
