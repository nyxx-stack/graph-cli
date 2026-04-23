from __future__ import annotations

import asyncio
import importlib
import sys
from pathlib import Path
from unittest.mock import patch

import pytest


@pytest.fixture()
def fresh_auth(tmp_path, monkeypatch):
    """Reload auth subpackage so it picks up a temp-home ~/.graphconnect dir."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))

    # Pydantic + module caches — drop anything already imported so Path.home()
    # is re-evaluated against our tmp HOME/USERPROFILE.
    for name in list(sys.modules):
        if name == "graphconnect.auth" or name.startswith("graphconnect.auth."):
            del sys.modules[name]

    auth = importlib.import_module("graphconnect.auth")
    profiles_mod = importlib.import_module("graphconnect.auth.profiles")

    # Sanity check — make sure Path.home() actually resolved into tmp_path.
    assert str(profiles_mod.PROFILES_DIR).startswith(str(tmp_path)), (
        f"profiles dir leaked outside tmp: {profiles_mod.PROFILES_DIR}"
    )
    return auth, profiles_mod


def test_create_and_list_profile(fresh_auth):
    auth, _ = fresh_auth
    profile = auth.AuthProfile(
        name="contoso",
        mode="app-secret",
        tenant_id="t-1",
        client_id="c-1",
    )
    auth.save_profile(profile)

    names = [p.name for p in auth.list_profiles()]
    assert "contoso" in names
    got = auth.get_profile("contoso")
    assert got.tenant_id == "t-1"
    assert got.mode == "app-secret"


def test_use_profile_changes_default(fresh_auth):
    auth, profiles_mod = fresh_auth

    auth.save_profile(auth.AuthProfile(name="a", mode="delegated-ps"))
    auth.save_profile(auth.AuthProfile(name="b", mode="delegated-ps"))

    auth.use_profile("b")
    assert profiles_mod._read_default_pointer() == "b"

    listed = {p.name: p.default for p in auth.list_profiles()}
    assert listed["b"] is True
    assert listed["a"] is False


def test_get_credential_app_secret_returns_credential(fresh_auth, monkeypatch):
    auth, _ = fresh_auth
    auth.save_profile(
        auth.AuthProfile(
            name="svc",
            mode="app-secret",
            tenant_id="tenant",
            client_id="client",
        )
    )
    monkeypatch.setenv("MSGRAPH_CLIENT_SECRET", "shhh")

    sentinel = object()
    with patch(
        "graphconnect.auth.build_client_secret_credential", return_value=sentinel
    ) as builder:
        cred = auth.get_credential("svc", force_new=True)

    assert cred is sentinel
    builder.assert_called_once()
    kwargs = builder.call_args.kwargs
    assert kwargs["tenant_id"] == "tenant"
    assert kwargs["client_secret"] == "shhh"


def test_get_credential_app_cert_reads_file(fresh_auth, tmp_path):
    auth, _ = fresh_auth
    cert = tmp_path / "cert.pem"
    cert.write_bytes(b"-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n")

    auth.save_profile(
        auth.AuthProfile(
            name="cert-svc",
            mode="app-cert",
            tenant_id="tenant",
            client_id="client",
            cert_path=str(cert),
        )
    )

    sentinel = object()
    with patch(
        "graphconnect.auth.build_certificate_credential", return_value=sentinel
    ) as builder:
        cred = auth.get_credential("cert-svc", force_new=True)

    assert cred is sentinel
    kwargs = builder.call_args.kwargs
    assert kwargs["cert_path"] == str(cert)


def test_get_credential_delegated_builds_device_code(fresh_auth, monkeypatch):
    auth, _ = fresh_auth
    auth.save_profile(
        auth.AuthProfile(
            name="dev",
            mode="delegated",
            tenant_id="tenant",
            client_id="client",
        )
    )

    sentinel = object()
    with patch(
        "graphconnect.auth.build_device_code_credential", return_value=sentinel
    ) as builder:
        cred = auth.get_credential("dev", force_new=True)

    assert cred is sentinel
    assert builder.call_args.kwargs["tenant_id"] == "tenant"


def test_bootstrap_default_profile_created_on_first_use(fresh_auth):
    auth, profiles_mod = fresh_auth

    assert not profiles_mod.PROFILES_DIR.exists() or not list(profiles_mod.PROFILES_DIR.iterdir())

    # Any entry point into the registry should bootstrap a 'default' profile.
    profiles = auth.list_profiles()
    names = [p.name for p in profiles]
    assert "default" in names
    default = auth.get_profile("default")
    assert default.default is True


def test_get_credential_for_default_does_not_raise_when_bootstrapping(fresh_auth):
    auth, _ = fresh_auth

    # Fresh home => no profile yet. A delegated-ps default is bootstrapped; we
    # stub out the PowerShell probe so we don't spawn a real process. When the
    # PS probe returns None, the module falls back to device-code, which needs
    # tenant/client — we provide those via env so the fallback succeeds too.
    with patch(
        "graphconnect.auth.try_graph_powershell_context", return_value=None
    ), patch(
        "graphconnect.auth.build_device_code_credential", return_value=object()
    ):
        import os

        os.environ["MSGRAPH_TENANT_ID"] = "t"
        os.environ["MSGRAPH_CLIENT_ID"] = "c"
        try:
            ctx = auth.get_auth_context(profile="default", force_new=True)
        finally:
            os.environ.pop("MSGRAPH_TENANT_ID", None)
            os.environ.pop("MSGRAPH_CLIENT_ID", None)

    assert ctx is not None
    assert ctx.profile == "default"


def test_logout_removes_token_cache(fresh_auth):
    auth, profiles_mod = fresh_auth

    auth.save_profile(
        auth.AuthProfile(
            name="cached",
            mode="app-secret",
            tenant_id="t",
            client_id="c",
        )
    )
    cache = profiles_mod.token_cache_path("cached")
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_bytes(b"fake-token-blob")
    assert cache.exists()

    with patch("graphconnect.auth.log_logout_hint", return_value=None):
        auth.logout("cached")

    assert not cache.exists()


def test_status_reports_profile_metadata(fresh_auth, monkeypatch):
    auth, _ = fresh_auth
    auth.save_profile(
        auth.AuthProfile(
            name="cert-svc",
            mode="app-cert",
            tenant_id="tenant",
            client_id="client",
            cert_path=str(Path(__file__).parent / "test_auth_profiles.py"),
        )
    )

    # Stub the credential so token probe succeeds deterministically.
    class _Tok:
        expires_on = 0

    class _Cred:
        def get_token(self, *scopes):
            return _Tok()

    with patch(
        "graphconnect.auth.build_certificate_credential", return_value=_Cred()
    ):
        statuses = asyncio.run(auth.status("cert-svc"))

    assert len(statuses) == 1
    s = statuses[0]
    assert s.name == "cert-svc"
    assert s.mode == "app-cert"
    assert s.authenticated is True
