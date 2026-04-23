"""Tests for the `explain` verb and its four subcommands."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from graphconnect.commands.explain import register as register_explain
from graphconnect.explain import (
    assignment_drift,
    enrollment_failure,
    noncompliance,
    policy_failure,
)
from graphconnect.types import Envelope


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class FakeGraph:
    """Captures (method, path) and returns canned responses."""

    def __init__(self, responses: dict[str, Any]):
        self.responses = responses
        self.calls: list[tuple[str, str]] = []

    async def get(self, path: str, **_: Any) -> Any:
        self.calls.append(("GET", path))
        for key, val in self.responses.items():
            if key in path:
                return val
        return {"value": []}

    async def post(self, path: str, body: dict, **_: Any) -> Any:
        self.calls.append(("POST", path))
        for key, val in self.responses.items():
            if key in path:
                return val
        return {}


def _run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# policy-failure: parity snapshot
# ---------------------------------------------------------------------------


CANNED_POLICY_ROWS = [
    {
        "DeviceId": "dev-1",
        "PolicyId": "pol-target",
        "SettingId": "s1",
        "SettingInstanceId": "si1",
        "SettingName": "BitLocker_EncryptionMethod",
        "SettingStatus": 6,  # Conflict
        "ErrorCode": -2016281211,
        "SettingValue": "AES256",
    },
    {
        "DeviceId": "dev-1",
        "PolicyId": "pol-target",
        "SettingInstanceId": "si2",
        "SettingName": "BitLocker_RecoveryPassword",
        "SettingStatus": 5,  # Error
        "ErrorCode": 65000,
    },
    {
        "DeviceId": "dev-1",
        "PolicyId": "pol-target",
        "SettingInstanceId": "si3",
        "SettingName": "BitLocker_Compliant",
        "SettingStatus": 2,  # Compliant -> filtered out by default
    },
    {
        # Overlapping policy on the same device touching setting #1
        "DeviceId": "dev-1",
        "PolicyId": "pol-other",
        "SettingInstanceId": "si1-other",
        "SettingName": "BitLocker_EncryptionMethod",
        "SettingStatus": 2,
    },
]


def _install_policy_fakes(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_list_lookup(*, profile: str) -> dict:
        return {
            "pol-target": {
                "id": "pol-target",
                "name": "BitLocker",
                "kind": "settings_catalog",
            },
            "pol-other": {
                "id": "pol-other",
                "name": "Overlap Profile",
                "kind": "config_profile",
            },
        }

    async def fake_resolve_device(*, device_id, device_name, profile):
        return {"id": "dev-1", "name": "PC-A", "userPrincipalName": "a@b"}

    async def fake_fetch(*, device_id, policy_id, profile):
        if policy_id is None:
            return list(CANNED_POLICY_ROWS)
        return [r for r in CANNED_POLICY_ROWS if r["PolicyId"] == policy_id]

    monkeypatch.setattr(policy_failure, "list_policy_lookup", fake_list_lookup)
    monkeypatch.setattr(policy_failure, "resolve_device", fake_resolve_device)
    monkeypatch.setattr(policy_failure, "fetch_policy_setting_rows", fake_fetch)


def test_policy_failure_parity_snapshot(monkeypatch):
    _install_policy_fakes(monkeypatch)

    env = _run(
        policy_failure.run(
            device_name="PC-A",
            policy_name="BitLocker",
            include_compliant=False,
            include_overlap_context=True,
        )
    )

    assert isinstance(env, Envelope)
    assert env.ok is True
    assert env.mode == "read"
    assert env.data is not None
    assert len(env.data) == 2  # compliant filtered out

    setting_names = [r["SettingName"] for r in env.data]
    assert setting_names == [
        "BitLocker_EncryptionMethod",
        "BitLocker_RecoveryPassword",
    ]

    enc = env.data[0]
    assert enc["DeviceName"] == "PC-A"
    assert enc["PolicyName"] == "BitLocker"
    assert enc["PolicyKind"] == "settings_catalog"
    assert enc["OtherPolicyIds"] == ["pol-other"]
    assert enc["OtherPolicies"] == ["Overlap Profile"]
    assert "Also set by: Overlap Profile" in enc["ConflictHint"]
    assert enc["ErrorHint"] == "Conflict: another assigned policy is setting this value."
    assert enc["SettingLabel"]  # humanized label was applied

    err = env.data[1]
    assert err["ErrorHint"] == "Device returned an unspecified Intune error."
    assert "OtherPolicyIds" not in err  # no overlap for this setting


def test_policy_failure_include_compliant(monkeypatch):
    _install_policy_fakes(monkeypatch)
    env = _run(
        policy_failure.run(
            device_name="PC-A", policy_name="BitLocker", include_compliant=True
        )
    )
    assert env.data is not None
    assert len(env.data) == 3
    # Compliant row sorts last (failures first).
    assert env.data[-1]["SettingName"] == "BitLocker_Compliant"


# ---------------------------------------------------------------------------
# noncompliance
# ---------------------------------------------------------------------------


def test_noncompliance_rows_have_required_fields(monkeypatch):
    async def fake_resolve_device(*, device_id, device_name, profile):
        return {"id": "dev-1", "name": "PC-A", "userPrincipalName": "a@b"}

    monkeypatch.setattr(noncompliance, "resolve_device", fake_resolve_device)

    responses = {
        "deviceCompliancePolicyStates": {
            "value": [
                {
                    "id": "compl-1",
                    "displayName": "Baseline",
                    "settingStates": [
                        {
                            "setting": "passwordRequired",
                            "settingName": "passwordRequired",
                            "state": "nonCompliant",
                            "errorCode": 0,
                            "expectedValue": "true",
                            "currentValue": "false",
                            "remediationMsg": "Enable a device password.",
                        },
                        {
                            "setting": "osMinVersion",
                            "settingName": "osMinVersion",
                            "state": "compliant",
                        },
                        {
                            "setting": "encryption",
                            "settingName": "encryption",
                            "state": "error",
                            "errorCode": 65000,
                            "errorDescription": "Agent timeout",
                        },
                    ],
                }
            ]
        }
    }
    fake = FakeGraph(responses)
    monkeypatch.setattr(noncompliance, "graph_get", fake.get)

    env = _run(noncompliance.run(device_name="PC-A"))
    assert env.ok
    assert env.data is not None and len(env.data) == 2  # nonCompliant + error
    for row in env.data:
        for key in ("failed_setting", "expected", "current", "remediation_hint"):
            assert key in row
    assert env.data[0]["remediation_hint"] == "Enable a device password."
    assert "Agent timeout" in env.data[1]["remediation_hint"]


# ---------------------------------------------------------------------------
# assignment-drift
# ---------------------------------------------------------------------------


def test_assignment_drift_delta_reasons(monkeypatch):
    async def fake_lookup(*, profile):
        return {
            "pol-1": {"id": "pol-1", "name": "Corp Policy", "kind": "settings_catalog"}
        }

    monkeypatch.setattr(assignment_drift, "list_policy_lookup", fake_lookup)

    responses = {
        "/configurationPolicies/pol-1/assignments": {
            "value": [
                {
                    "id": "a1",
                    "target": {
                        "@odata.type": "#microsoft.graph.groupAssignmentTarget",
                        "groupId": "grp-include",
                    },
                },
                {
                    "id": "a2",
                    "target": {
                        "@odata.type": "#microsoft.graph.exclusionGroupAssignmentTarget",
                        "groupId": "grp-exclude",
                    },
                },
            ]
        },
        "/groups/grp-include/transitiveMembers": {
            "value": [
                {"id": "m1", "deviceId": "dev-A"},
                {"id": "m2", "deviceId": "dev-B"},
            ]
        },
        "/groups/grp-exclude/transitiveMembers": {
            "value": [{"id": "m3", "deviceId": "dev-C"}]
        },
        "/configurationPolicies/pol-1/deviceStatuses": {
            "value": [
                {"deviceId": "dev-A"},  # applied and in include: OK
                {"deviceId": "dev-C"},  # excluded but applied -> excluded reason
                {"deviceId": "dev-D"},  # not in any target -> extra_target
                # dev-B in include but not applied -> unassigned
            ]
        },
    }
    fake = FakeGraph(responses)
    monkeypatch.setattr(assignment_drift, "graph_get", fake.get)

    env = _run(assignment_drift.run(policy_id="pol-1"))
    reasons = {(r["device_id"], r["reason"]) for r in env.data or []}
    assert ("dev-B", "unassigned") in reasons
    assert ("dev-D", "extra_target") in reasons
    assert ("dev-C", "excluded") in reasons
    assert ("dev-A", "unassigned") not in reasons
    assert all(
        r["reason"] in {"unassigned", "extra_target", "excluded"} for r in env.data
    )


# ---------------------------------------------------------------------------
# enrollment-failure
# ---------------------------------------------------------------------------


def test_enrollment_failure_classifies_modes(monkeypatch):
    responses = {
        "/auditLogs/directoryAudits": {
            "value": [
                {
                    "id": "e1",
                    "activityDateTime": "2026-04-01T00:00:00Z",
                    "activityDisplayName": "Enrollment attempt",
                    "result": "failure",
                    "resultReason": "User is not licensed for Intune.",
                    "initiatedBy": {
                        "user": {"userPrincipalName": "alice@contoso.com"}
                    },
                },
                {
                    "id": "e2",
                    "activityDateTime": "2026-04-02T00:00:00Z",
                    "activityDisplayName": "Enrollment attempt",
                    "result": "failure",
                    "resultReason": "Device cap exceeded for user.",
                    "initiatedBy": {
                        "user": {"userPrincipalName": "alice@contoso.com"}
                    },
                },
                {
                    "id": "e3",
                    "activityDateTime": "2026-04-03T00:00:00Z",
                    "activityDisplayName": "Enrollment attempt",
                    "result": "failure",
                    "resultReason": "Azure AD Join failed with hybrid credentials.",
                    "initiatedBy": {
                        "user": {"userPrincipalName": "alice@contoso.com"}
                    },
                },
                {
                    "id": "e4",
                    "result": "success",
                    "activityDisplayName": "Enrollment attempt",
                },
            ]
        },
        "/deviceManagement/autopilotEvents": {"value": []},
    }
    fake = FakeGraph(responses)
    monkeypatch.setattr(enrollment_failure, "graph_get", fake.get)

    env = _run(enrollment_failure.run(user="alice@contoso.com"))
    assert env.ok
    modes = {r["failure_mode"] for r in env.data or []}
    assert "no_license" in modes
    assert "device_cap_exceeded" in modes
    assert "azure_ad_join_failed" in modes
    assert len(modes) >= 3


# ---------------------------------------------------------------------------
# register() smoke check
# ---------------------------------------------------------------------------


def test_register_adds_explain_group():
    import typer

    app = typer.Typer()
    register_explain(app)
    # Typer stores registered sub-apps; we only need to confirm no exception and
    # that an "explain" group is present on the app.
    names = [
        getattr(g, "name", None) or getattr(g.typer_instance, "info", None)
        for g in getattr(app, "registered_groups", [])
    ]
    # Collapse to plain strings
    names = [
        n.name if hasattr(n, "name") else n for n in names if n is not None
    ]
    assert any(str(n).lower() == "explain" for n in names), names
