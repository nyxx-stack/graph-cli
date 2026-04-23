"""Tests for graphconnect.selectors — mocked at the graph_request boundary."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

import pytest

from graphconnect.selectors import (
    AmbiguousMatch,
    Locator,
    NotFound,
    find,
    resolve,
)
from graphconnect.selectors import resolvers


@dataclass
class _StubResp:
    body: Any
    status_code: int = 200
    headers: dict = None  # type: ignore[assignment]
    request_id: str = "test-req"
    trace_id: str = "test-trace"
    attempts: int = 1
    throttle_wait_s: float = 0.0
    pages: int = 1

    def __post_init__(self) -> None:
        if self.headers is None:
            self.headers = {}


class _StubTransport:
    """Records calls and returns pre-seeded responses keyed by URL substring."""

    def __init__(self, rules: list[tuple[str, Any]]):
        self.rules = rules
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    async def __call__(self, method: str, path: str, **kw: Any):
        self.calls.append((method, path, kw))
        for needle, body in self.rules:
            if needle in path:
                if isinstance(body, Exception):
                    raise body
                return _StubResp(body=body)
        return _StubResp(body={"value": []})


@pytest.fixture
def patch_transport(monkeypatch):
    def _install(rules):
        stub = _StubTransport(rules)
        monkeypatch.setattr(resolvers, "graph_request", stub)
        return stub

    return _install


GUID_A = "11111111-2222-3333-4444-555555555555"
GUID_B = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def test_resolve_device_by_guid_short_circuits(patch_transport):
    stub = patch_transport([
        (f"/deviceManagement/managedDevices/{GUID_A}", {"id": GUID_A, "deviceName": "LAPTOP-01"}),
    ])
    loc = asyncio.run(resolve(GUID_A, type="device"))
    assert loc == Locator(type="device", id=GUID_A, display_name="LAPTOP-01")
    # Only one call — no $filter fallback issued.
    assert len(stub.calls) == 1
    assert "$filter" not in stub.calls[0][1]


def test_resolve_device_by_exact_name_one_match(patch_transport):
    patch_transport([
        (
            "/deviceManagement/managedDevices",
            {"value": [{"id": GUID_A, "deviceName": "LAPTOP-01"}]},
        ),
    ])
    loc = asyncio.run(resolve("LAPTOP-01", type="device"))
    assert loc.id == GUID_A
    assert loc.display_name == "LAPTOP-01"
    assert loc.type == "device"


def test_resolve_partial_name_ambiguous_returns_candidates(patch_transport):
    patch_transport([
        (
            "/deviceManagement/managedDevices",
            {
                "value": [
                    {"id": GUID_A, "deviceName": "LAPTOP-01"},
                    {"id": GUID_B, "deviceName": "LAPTOP-02"},
                ]
            },
        ),
    ])

    with pytest.raises(AmbiguousMatch) as excinfo:
        asyncio.run(resolve("LAPTOP", type="device"))
    assert len(excinfo.value.candidates) == 2

    candidates = asyncio.run(find("LAPTOP", type="device"))
    assert len(candidates) == 2
    assert {c.id for c in candidates} == {GUID_A, GUID_B}


def test_find_not_found_returns_empty_list(patch_transport):
    patch_transport([
        ("/deviceManagement/managedDevices", {"value": []}),
    ])
    out = asyncio.run(find("nothing-matches", type="device"))
    assert out == []


def test_resolve_not_found_raises(patch_transport):
    patch_transport([
        ("/users", {"value": []}),
    ])
    with pytest.raises(NotFound):
        asyncio.run(resolve("ghost", type="user"))


def test_resolve_user_by_upn_short_circuits(patch_transport):
    stub = patch_transport([
        ("/users/alice@example.com", {"id": GUID_A, "displayName": "Alice", "userPrincipalName": "alice@example.com"}),
    ])
    loc = asyncio.run(resolve("alice@example.com", type="user"))
    assert loc.upn == "alice@example.com"
    assert loc.id == GUID_A
    # Only the direct UPN lookup call; no $filter search issued.
    assert all("$filter" not in c[1] for c in stub.calls)


def test_find_group_by_guid(patch_transport):
    stub = patch_transport([
        (f"/groups/{GUID_A}", {"id": GUID_A, "displayName": "HR-Group"}),
    ])
    locs = asyncio.run(find(GUID_A, type="group"))
    assert len(locs) == 1
    assert locs[0].type == "group"
    assert locs[0].display_name == "HR-Group"
    assert len(stub.calls) == 1


def test_find_policy_tries_all_endpoints(patch_transport):
    patch_transport([
        ("/deviceManagement/configurationPolicies", {"value": [{"id": GUID_A, "name": "BitLocker"}]}),
        ("/deviceManagement/deviceConfigurations", {"value": []}),
        ("/deviceManagement/deviceCompliancePolicies", {"value": []}),
        ("/identity/conditionalAccess/policies", {"value": []}),
    ])
    locs = asyncio.run(find("BitLocker", type="policy"))
    assert len(locs) == 1
    assert locs[0].kind == "settingsCatalog"
    assert locs[0].display_name == "BitLocker"


def test_find_policy_ranks_across_kinds(patch_transport):
    patch_transport([
        ("/deviceManagement/configurationPolicies", {"value": []}),
        ("/deviceManagement/deviceConfigurations", {"value": [{"id": GUID_A, "displayName": "BitLocker-Legacy"}]}),
        ("/deviceManagement/deviceCompliancePolicies", {"value": []}),
        ("/identity/conditionalAccess/policies", {"value": [{"id": GUID_B, "displayName": "BitLocker-CA"}]}),
    ])
    locs = asyncio.run(find("BitLocker", type="policy"))
    kinds = {loc.kind for loc in locs}
    assert kinds == {"configurationProfile", "conditionalAccess"}


def test_type_filter_narrows_search(patch_transport):
    stub = patch_transport([
        ("/deviceManagement/managedDevices", {"value": [{"id": GUID_A, "deviceName": "DEV-01"}]}),
    ])
    locs = asyncio.run(find("DEV", type="device"))
    assert len(locs) == 1
    assert locs[0].type == "device"
    # No calls to /users, /groups, /configurationPolicies, etc.
    assert all("managedDevices" in c[1] for c in stub.calls)


def test_find_without_type_searches_all(patch_transport):
    patch_transport([
        ("/deviceManagement/managedDevices", {"value": [{"id": GUID_A, "deviceName": "match-dev"}]}),
        ("/users", {"value": [{"id": GUID_B, "displayName": "match-user", "userPrincipalName": "mu@x.com"}]}),
        ("/groups", {"value": []}),
        ("/deviceManagement/configurationPolicies", {"value": []}),
        ("/deviceManagement/deviceConfigurations", {"value": []}),
        ("/deviceManagement/deviceCompliancePolicies", {"value": []}),
        ("/identity/conditionalAccess/policies", {"value": []}),
    ])
    locs = asyncio.run(find("match"))
    types = {loc.type for loc in locs}
    assert "device" in types
    assert "user" in types


def test_guid_short_circuit_skips_list_endpoints(patch_transport):
    stub = patch_transport([
        (f"/deviceManagement/managedDevices/{GUID_A}", {"id": GUID_A, "deviceName": "DEV-01"}),
    ])
    asyncio.run(find(GUID_A, type="device"))
    for method, path, _ in stub.calls:
        assert "$filter" not in path, f"unexpected $filter call: {path}"
    assert len(stub.calls) == 1


def test_resolve_exact_match_beats_containing(patch_transport):
    patch_transport([
        (
            "/deviceManagement/managedDevices",
            {
                "value": [
                    {"id": GUID_A, "deviceName": "LAPTOP"},
                    {"id": GUID_B, "deviceName": "LAPTOP-02"},
                ]
            },
        ),
    ])
    loc = asyncio.run(resolve("LAPTOP", type="device"))
    assert loc.id == GUID_A
