from __future__ import annotations

import pytest

from graphconnect.types import CatalogEntry, Envelope, ErrorCode, ErrorPayload, SafetyTier


def test_envelope_roundtrip_preserves_fields():
    env = Envelope(
        ok=True,
        trace_id="trace-123",
        mode="read",
        summary="List 3 users",
        data=[{"id": "a"}, {"id": "b"}, {"id": "c"}],
        warnings=["slow call"],
        next_actions=["graphconnect show user:a"],
    )
    dumped = env.model_dump()
    restored = Envelope.model_validate(dumped)
    assert restored.ok is True
    assert restored.trace_id == "trace-123"
    assert restored.mode == "read"
    assert restored.summary == "List 3 users"
    assert restored.data == [{"id": "a"}, {"id": "b"}, {"id": "c"}]
    assert restored.plan is None
    assert restored.warnings == ["slow call"]
    assert restored.next_actions == ["graphconnect show user:a"]
    assert restored.error is None


def test_ok_read_constructor_sets_mode_and_data():
    env = Envelope.ok_read("4 devices", [{"id": "1"}], trace_id="t1")
    assert env.ok is True
    assert env.mode == "read"
    assert env.data == [{"id": "1"}]
    assert env.plan is None
    assert env.warnings == []
    assert env.next_actions == []
    assert env.trace_id == "t1"


def test_ok_plan_constructor_carries_plan_payload():
    plan = {"token": "xyz", "steps": [{"op": "assignConfig"}]}
    env = Envelope.ok_plan("plan built", plan, trace_id="t2", next_actions=["--apply --token xyz"])
    assert env.mode == "plan"
    assert env.plan == plan
    assert env.data is None
    assert env.next_actions == ["--apply --token xyz"]


def test_ok_apply_defaults_to_apply_mode():
    env = Envelope.ok_apply("applied", trace_id="t3")
    assert env.mode == "apply"
    assert env.ok is True


def test_ok_apply_breakglass_flag_flips_mode():
    env = Envelope.ok_apply("emergency", trace_id="t4", breakglass=True)
    assert env.mode == "breakglass"


def test_err_constructor_sets_error_payload():
    payload = ErrorPayload(code=ErrorCode.NOT_FOUND, message="device not found")
    env = Envelope.err("not found", payload, trace_id="t5")
    assert env.ok is False
    assert env.error is not None
    assert env.error.code == ErrorCode.NOT_FOUND
    assert env.error.message == "device not found"
    assert env.mode == "read"


@pytest.mark.parametrize(
    "field,value",
    [
        ("national_cloud_overrides", {"usgov": "https://graph.microsoft.us"}),
        ("auth_profile_required", "app-only"),
        ("emergency_safe", True),
        ("workflow_pack", "explain_policy_failure"),
    ],
)
def test_catalog_entry_accepts_v2_extensions(field, value):
    entry = CatalogEntry(
        id="devices.list_managed",
        summary="list",
        domain="devices",
        safety_tier=SafetyTier.READ,
        endpoint="/deviceManagement/managedDevices",
        **{field: value},
    )
    assert getattr(entry, field) == value


def test_catalog_entry_defaults_for_v2_extensions_are_safe():
    entry = CatalogEntry(
        id="devices.list_managed",
        summary="list",
        domain="devices",
        safety_tier=SafetyTier.READ,
        endpoint="/deviceManagement/managedDevices",
    )
    assert entry.national_cloud_overrides is None
    assert entry.auth_profile_required == "any"
    assert entry.emergency_safe is False
    assert entry.workflow_pack is None
