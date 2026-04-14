from __future__ import annotations

from pathlib import Path
from unittest.mock import Mock

from graphconnect.auth import _try_tool_credentials
from graphconnect.types import AuthMethod


def test_try_tool_credentials_skips_azure_cli_without_marker(tmp_path, monkeypatch):
    monkeypatch.setenv("AZURE_CONFIG_DIR", str(tmp_path))

    cli_builder = Mock()
    azps_builder = Mock()
    monkeypatch.setattr("graphconnect.auth.AzureCliCredential", cli_builder)
    monkeypatch.setattr("graphconnect.auth.AzurePowerShellCredential", azps_builder)

    result = _try_tool_credentials()

    assert result is None
    cli_builder.assert_not_called()
    azps_builder.assert_not_called()


def test_try_tool_credentials_attempts_azure_cli_with_marker_then_continues(tmp_path, monkeypatch):
    monkeypatch.setenv("AZURE_CONFIG_DIR", str(tmp_path))
    (tmp_path / "azureProfile.json").write_text("{}", encoding="utf-8")

    cli_credential = Mock()
    cli_credential.get_token.side_effect = RuntimeError("no token")
    cli_builder = Mock(return_value=cli_credential)

    azps_builder = Mock()

    monkeypatch.setattr("graphconnect.auth.AzureCliCredential", cli_builder)
    monkeypatch.setattr("graphconnect.auth.AzurePowerShellCredential", azps_builder)

    result = _try_tool_credentials()

    assert result is None
    cli_builder.assert_called_once_with()
    cli_credential.get_token.assert_called_once()
    azps_builder.assert_not_called()


def test_try_tool_credentials_attempts_azure_powershell_with_marker(tmp_path, monkeypatch):
    home = tmp_path / "home"
    az_dir = home / ".Azure"
    az_dir.mkdir(parents=True)
    (az_dir / "AzureRmContext.json").write_text("{}", encoding="utf-8")

    monkeypatch.delenv("AZURE_CONFIG_DIR", raising=False)
    monkeypatch.setattr("graphconnect.auth.Path.home", lambda: home)

    azps_credential = Mock()
    azps_credential.get_token.return_value = object()
    azps_builder = Mock(return_value=azps_credential)

    monkeypatch.setattr("graphconnect.auth.AzureCliCredential", Mock())
    monkeypatch.setattr("graphconnect.auth.AzurePowerShellCredential", azps_builder)

    result = _try_tool_credentials()

    assert result is not None
    assert result.auth_method == AuthMethod.AZURE_POWERSHELL
    azps_builder.assert_called_once_with()
    azps_credential.get_token.assert_called_once()
