from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

import pytest
import typer
from typer.testing import CliRunner

from graphconnect.commands import show as show_mod
from graphconnect.commands.show import (
    _show_assignment_async,
    _show_device_async,
    _show_group_async,
    _show_policy_async,
    _show_user_async,
    register,
)
from graphconnect.selectors import Locator
from graphconnect.transport import GraphTransportError


@dataclass
class FakeResp:
    status_code: int
    body: Any


def _install_transport(monkeypatch: pytest.MonkeyPatch, responses: dict[str, FakeResp]) -> list[str]:
    """Route graph_request to a path-indexed table; records call order."""
    calls: list[str] = []

    async def fake_graph_request(method: str, path: str, **kw: Any) -> FakeResp:
        calls.append(path)
        return responses.get(path, FakeResp(404, {"error": {"message": "not found"}}))

    monkeypatch.setattr(show_mod, "graph_request", fake_graph_request)
    return calls


def _install_resolve(monkeypatch: pytest.MonkeyPatch, locators: dict[str, Locator | None]) -> None:
    async def fake_resolve(query: str, *, type: str | None = None, profile: str = "default") -> Locator:
        loc = locators.get(query)
        if loc is None:
            raise LookupError(query)
        return loc

    monkeypatch.setattr(show_mod, "resolve", fake_resolve)


# --- device -----------------------------------------------------------------


def test_show_device_basic(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_resolve(monkeypatch, {"LAPTOP-01": Locator(type="device", id="dev-1", display_name="LAPTOP-01")})
    _install_transport(
        monkeypatch,
        {
            "/deviceManagement/managedDevices/dev-1": FakeResp(
                200, {"id": "dev-1", "deviceName": "LAPTOP-01", "userPrincipalName": "alice@example.com"}
            ),
        },
    )
    env = asyncio.run(_show_device_async("LAPTOP-01", profile="default", include_apps=False, include_compliance=False))
    assert env.ok is True
    assert env.mode == "read"
    assert env.data is not None
    assert env.data[0]["entity"] == "device"
    assert env.data[0]["id"] == "dev-1"
    assert "LAPTOP-01" in env.summary
    assert "explain noncompliance --device dev-1" in env.next_actions


def test_show_device_include_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_resolve(monkeypatch, {"dev-1": Locator(type="device", id="dev-1", display_name="dev-1")})
    _install_transport(
        monkeypatch,
        {
            "/deviceManagement/managedDevices/dev-1": FakeResp(200, {"id": "dev-1", "deviceName": "dev-1"}),
            "/deviceManagement/managedDevices/dev-1/detectedApps": FakeResp(200, {"value": [{"id": "a1"}]}),
            "/deviceManagement/managedDevices/dev-1/deviceCompliancePolicyStates": FakeResp(200, {"value": [{"id": "c1"}]}),
        },
    )
    env = asyncio.run(_show_device_async("dev-1", profile="default", include_apps=True, include_compliance=True))
    assert env.ok is True
    entities = [d["entity"] for d in env.data]
    assert entities == ["device", "detectedApps", "compliance"]
    apps_row = next(d for d in env.data if d["entity"] == "detectedApps")
    assert apps_row["items"] == [{"id": "a1"}]


def test_show_device_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_resolve(monkeypatch, {})  # resolve raises LookupError
    _install_transport(monkeypatch, {})
    env = asyncio.run(_show_device_async("ghost", profile="default", include_apps=False, include_compliance=False))
    assert env.ok is False
    assert env.error is not None
    assert env.error.code.value == "not_found"
    assert "ghost" in env.summary


# --- user -------------------------------------------------------------------


def test_show_user_basic(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_resolve(
        monkeypatch,
        {"alice@example.com": Locator(type="user", id="u-1", upn="alice@example.com", display_name="Alice")},
    )
    _install_transport(
        monkeypatch,
        {"/users/u-1": FakeResp(200, {"id": "u-1", "displayName": "Alice"})},
    )
    env = asyncio.run(_show_user_async("alice@example.com", profile="default", include_licenses=False, include_groups=False))
    assert env.ok is True
    assert env.data[0]["entity"] == "user"
    assert env.data[0]["id"] == "u-1"
    assert "alice@example.com" in env.summary


def test_show_user_includes(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_resolve(monkeypatch, {"u-1": Locator(type="user", id="u-1", upn="alice@example.com")})
    _install_transport(
        monkeypatch,
        {
            "/users/u-1": FakeResp(200, {"id": "u-1"}),
            "/users/u-1/licenseDetails": FakeResp(200, {"value": [{"skuId": "E5"}]}),
            "/users/u-1/memberOf": FakeResp(200, {"value": [{"id": "g-1"}]}),
        },
    )
    env = asyncio.run(_show_user_async("u-1", profile="default", include_licenses=True, include_groups=True))
    assert env.ok is True
    entities = [d["entity"] for d in env.data]
    assert entities == ["user", "licenses", "groups"]
    assert next(d for d in env.data if d["entity"] == "licenses")["items"] == [{"skuId": "E5"}]


def test_show_user_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_resolve(monkeypatch, {})
    _install_transport(monkeypatch, {})
    env = asyncio.run(_show_user_async("nobody", profile="default", include_licenses=False, include_groups=False))
    assert env.ok is False
    assert env.error.code.value == "not_found"


# --- group ------------------------------------------------------------------


def test_show_group_basic(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_resolve(monkeypatch, {"Admins": Locator(type="group", id="g-1", display_name="Admins")})
    _install_transport(
        monkeypatch,
        {"/groups/g-1": FakeResp(200, {"id": "g-1", "displayName": "Admins"})},
    )
    env = asyncio.run(_show_group_async("Admins", profile="default", include_members=False, include_assignments=False))
    assert env.ok is True
    assert env.data[0]["entity"] == "group"
    assert env.data[0]["id"] == "g-1"


def test_show_group_include_members(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_resolve(monkeypatch, {"g-1": Locator(type="group", id="g-1", display_name="G")})
    _install_transport(
        monkeypatch,
        {
            "/groups/g-1": FakeResp(200, {"id": "g-1"}),
            "/groups/g-1/members": FakeResp(200, {"value": [{"id": "u-1"}, {"id": "u-2"}]}),
        },
    )
    env = asyncio.run(_show_group_async("g-1", profile="default", include_members=True, include_assignments=False))
    entities = [d["entity"] for d in env.data]
    assert entities == ["group", "members"]
    members = next(d for d in env.data if d["entity"] == "members")["items"]
    assert len(members) == 2


def test_show_group_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_resolve(monkeypatch, {})
    _install_transport(monkeypatch, {})
    env = asyncio.run(_show_group_async("ghost-group", profile="default", include_members=False, include_assignments=False))
    assert env.ok is False


# --- policy -----------------------------------------------------------------


def test_show_policy_settings_catalog(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_resolve(
        monkeypatch,
        {"Win-Baseline": Locator(type="policy", id="p-1", display_name="Win-Baseline", kind="settingsCatalog")},
    )
    _install_transport(
        monkeypatch,
        {
            "/deviceManagement/configurationPolicies/p-1": FakeResp(200, {"id": "p-1", "name": "Win-Baseline"}),
        },
    )
    env = asyncio.run(_show_policy_async("Win-Baseline", profile="default", include_assignments=False, include_status=False))
    assert env.ok is True
    row = env.data[0]
    assert row["entity"] == "policy"
    assert row["kind"] == "settingsCatalog"
    assert row["id"] == "p-1"
    assert "explain assignment-drift --policy p-1" in env.next_actions


def test_show_policy_include_assignments_and_status(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_resolve(
        monkeypatch,
        {"p-1": Locator(type="policy", id="p-1", kind="settingsCatalog")},
    )
    _install_transport(
        monkeypatch,
        {
            "/deviceManagement/configurationPolicies/p-1": FakeResp(200, {"id": "p-1"}),
            "/deviceManagement/configurationPolicies/p-1/assignments": FakeResp(200, {"value": [{"id": "p-1_g-1"}]}),
            "/deviceManagement/reports/getConfigurationPolicyNonComplianceReport": FakeResp(
                200,
                {
                    "Schema": [{"Column": "IntuneDeviceId"}, {"Column": "PolicyStatus"}],
                    "Values": [["dev-1", 5]],
                },
            ),
        },
    )
    env = asyncio.run(_show_policy_async("p-1", profile="default", include_assignments=True, include_status=True))
    entities = [d["entity"] for d in env.data]
    assert entities == ["policy", "assignments", "status"]
    status_rows = next(d for d in env.data if d["entity"] == "status")["items"]
    assert status_rows == [{"IntuneDeviceId": "dev-1", "PolicyStatus": 5, "Status": "Error"}]


def test_show_policy_conditional_access_skips_assignment_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_resolve(monkeypatch, {"ca-1": Locator(type="policy", id="ca-1", kind="conditionalAccess")})
    calls = _install_transport(
        monkeypatch,
        {
            "/identity/conditionalAccess/policies/ca-1": FakeResp(200, {"id": "ca-1", "displayName": "Block Legacy"}),
        },
    )
    env = asyncio.run(_show_policy_async("ca-1", profile="default", include_assignments=True, include_status=False))
    assert env.ok is True
    # For CA, we don't hit a separate assignments endpoint
    assert all("assignments" not in c for c in calls)


def test_show_policy_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_resolve(monkeypatch, {})
    _install_transport(monkeypatch, {})
    env = asyncio.run(_show_policy_async("ghost-policy", profile="default", include_assignments=False, include_status=False))
    assert env.ok is False


# --- assignment -------------------------------------------------------------


def test_show_assignment_found(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_resolve(monkeypatch, {})  # assignment lookup doesn't resolve
    _install_transport(
        monkeypatch,
        {
            "/deviceManagement/configurationPolicies/p-1/assignments/p-1_g-1": FakeResp(
                200, {"id": "p-1_g-1", "target": {"groupId": "g-1"}}
            ),
        },
    )
    env = asyncio.run(_show_assignment_async("p-1_g-1", profile="default"))
    assert env.ok is True
    assert env.data[0]["entity"] == "assignment"
    assert env.data[0]["id"] == "p-1_g-1"


def test_show_assignment_falls_back_across_kinds(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_graph_request(method: str, path: str, **kw: Any) -> FakeResp:
        if path == "/deviceManagement/configurationPolicies/p-2/assignments/p-2_g-1":
            raise GraphTransportError("missing", status_code=404, body={"error": {"message": "missing"}})
        if path == "/deviceManagement/deviceConfigurations/p-2/assignments/p-2_g-1":
            return FakeResp(200, {"id": "p-2_g-1"})
        return FakeResp(404, {"error": {"message": "not found"}})

    monkeypatch.setattr(show_mod, "graph_request", fake_graph_request)
    env = asyncio.run(_show_assignment_async("p-2_g-1", profile="default"))
    assert env.ok is True
    assert env.data[0]["id"] == "p-2_g-1"


def test_show_assignment_malformed_id(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_transport(monkeypatch, {})
    env = asyncio.run(_show_assignment_async("just-a-guid", profile="default"))
    assert env.ok is False
    assert env.error.code.value == "bad_request"


def test_show_assignment_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_transport(monkeypatch, {})  # everything 404s
    env = asyncio.run(_show_assignment_async("p-9_g-9", profile="default"))
    assert env.ok is False
    assert env.error.code.value == "not_found"


# --- registration -----------------------------------------------------------


def test_register_attaches_to_parent() -> None:
    parent = typer.Typer()
    register(parent)
    runner = CliRunner()
    result = runner.invoke(parent, ["show", "--help"])
    assert result.exit_code == 0
    out = result.stdout
    for sub in ("device", "user", "group", "policy", "assignment"):
        assert sub in out


def test_import_register_symbol() -> None:
    from graphconnect.commands.show import register as reg

    assert callable(reg)
