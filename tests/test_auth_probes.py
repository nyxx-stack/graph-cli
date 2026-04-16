from __future__ import annotations

import pytest

from graphconnect.auth import _parse_powershell_json_payload


def test_parse_powershell_json_payload_accepts_banner_before_json():
    payload = "Welcome to Microsoft Graph PowerShell!\n{\"account\":\"user@contoso.com\",\"scopes\":[\"User.Read.All\"]}"

    result = _parse_powershell_json_payload(payload)

    assert result == {"account": "user@contoso.com", "scopes": ["User.Read.All"]}


def test_parse_powershell_json_payload_accepts_trailing_json_after_multiline_output():
    payload = "Connecting to Microsoft Graph...\nPlease wait.\nnull"

    result = _parse_powershell_json_payload(payload)

    assert result is None


def test_parse_powershell_json_payload_raises_on_non_json_output():
    with pytest.raises(RuntimeError, match="did not emit valid JSON"):
        _parse_powershell_json_payload("Authentication failed before emitting context.")
