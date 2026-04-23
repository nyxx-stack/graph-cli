from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from types import SimpleNamespace

import httpx
import pytest

from graphconnect.transport import (
    DeadlineExceeded,
    GraphTransportError,
    NationalCloud,
    apply_advanced_query,
    get_authority,
    get_endpoint_base,
    graph_request,
    needs_advanced_query,
    paginate,
    set_http_client,
    sleep_for_retry,
)
from graphconnect.transport.throttle import _parse_retry_after
import graphconnect.transport.client as client_mod


# ---------- test helpers ----------


@pytest.fixture(autouse=True)
def _fast_sleep(monkeypatch):
    """Skip real sleeps but record requested durations."""
    waits: list[float] = []

    class _DummyCredential:
        def get_token(self, *scopes: str):
            del scopes
            return SimpleNamespace(token="stub-token", expires_on=None)

    def fake_context(profile="default"):
        del profile
        return SimpleNamespace(
            credential=_DummyCredential(),
            scopes=["https://graph.microsoft.com/.default"],
        )

    async def fake_sleep(duration: float) -> None:
        waits.append(duration)

    monkeypatch.setattr("graphconnect.transport.client.asyncio.sleep", fake_sleep)
    monkeypatch.setattr(client_mod, "_resolve_auth_context", fake_context)
    yield waits
    set_http_client(None)


def _install_mock(handler):
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    set_http_client(client)
    return client


def _run(coro):
    return asyncio.run(coro)


# ---------- national cloud ----------


def test_national_cloud_commercial():
    assert get_endpoint_base("commercial") == "https://graph.microsoft.com"
    assert get_endpoint_base(NationalCloud.COMMERCIAL) == "https://graph.microsoft.com"


def test_national_cloud_usgov():
    assert get_endpoint_base("USGov") == "https://graph.microsoft.us"


def test_national_cloud_dod():
    assert get_endpoint_base("DoD") == "https://dod-graph.microsoft.us"


def test_national_cloud_china():
    assert get_endpoint_base("China") == "https://microsoftgraph.chinacloudapi.cn"


def test_national_cloud_authority():
    assert get_authority("commercial") == "https://login.microsoftonline.com"
    assert get_authority("China") == "https://login.chinacloudapi.cn"


def test_national_cloud_unknown():
    with pytest.raises(ValueError):
        get_endpoint_base("Neptune")


# ---------- consistency injection ----------


def test_needs_advanced_query_users_filter():
    assert needs_advanced_query("/users", {"$filter": "startswith(displayName,'A')"})


def test_needs_advanced_query_groups_orderby():
    assert needs_advanced_query("/v1.0/groups", {"$orderby": "displayName"})


def test_needs_advanced_query_directory_objects_search():
    assert needs_advanced_query("/directoryObjects", {"$search": '"hello"'})


def test_needs_advanced_query_non_directory():
    assert not needs_advanced_query(
        "/deviceManagement/managedDevices", {"$filter": "operatingSystem eq 'iOS'"}
    )


def test_needs_advanced_query_users_no_params():
    assert not needs_advanced_query("/users", {"$select": "id"})


def test_apply_advanced_query_sets_headers_and_count():
    headers, query = apply_advanced_query({}, {"$filter": "x"})
    assert headers["ConsistencyLevel"] == "eventual"
    assert query["$count"] == "true"
    assert query["$filter"] == "x"


def test_apply_advanced_query_preserves_existing_consistency():
    headers, query = apply_advanced_query({"consistencylevel": "eventual"}, {"$filter": "x"})
    # not duplicated
    assert sum(1 for k in headers if k.lower() == "consistencylevel") == 1


# ---------- retry-after parsing ----------


def test_parse_retry_after_seconds():
    assert _parse_retry_after("2") == 2.0
    assert _parse_retry_after("  0 ") == 0.0


def test_parse_retry_after_negative_clamped():
    assert _parse_retry_after("-5") == 0.0


def test_parse_retry_after_http_date():
    now = datetime(2026, 10, 21, 7, 28, 0, tzinfo=timezone.utc) - \
        __import__("datetime").timedelta(seconds=30)
    delta = _parse_retry_after("Wed, 21 Oct 2026 07:28:00 GMT", now=now)
    assert delta is not None
    assert 29.0 <= delta <= 31.0


def test_parse_retry_after_past_date_zero():
    now = datetime(2030, 1, 1, tzinfo=timezone.utc)
    delta = _parse_retry_after("Wed, 21 Oct 2026 07:28:00 GMT", now=now)
    assert delta == 0.0


def test_parse_retry_after_bogus():
    assert _parse_retry_after("not-a-date") is None


# ---------- sleep_for_retry ----------


def test_sleep_for_retry_honors_seconds_header():
    resp = httpx.Response(429, headers={"Retry-After": "2"})
    wait = _run(sleep_for_retry(resp, attempt=1))
    assert wait == 2.0


def test_sleep_for_retry_exhausted():
    resp = httpx.Response(429, headers={"Retry-After": "1"})
    wait = _run(sleep_for_retry(resp, attempt=5))
    assert wait is None


def test_sleep_for_retry_non_retryable_status():
    resp = httpx.Response(500)
    wait = _run(sleep_for_retry(resp, attempt=1))
    assert wait is None


def test_sleep_for_retry_exponential_backoff(monkeypatch):
    # strip jitter for determinism
    import graphconnect.transport.throttle as throttle_mod
    monkeypatch.setattr(throttle_mod.random, "uniform", lambda a, b: 0.0)
    resp = httpx.Response(429)  # no Retry-After
    wait1 = _run(sleep_for_retry(resp, attempt=1))
    wait2 = _run(sleep_for_retry(resp, attempt=2))
    wait3 = _run(sleep_for_retry(resp, attempt=3))
    assert wait1 == 1.0
    assert wait2 == 2.0
    assert wait3 == 4.0


# ---------- pagination standalone ----------


def test_paginate_follows_pages():
    pages = {
        "p2": {"value": [{"id": 2}], "@odata.nextLink": "p3"},
        "p3": {"value": [{"id": 3}]},
    }

    async def fetch(url: str) -> dict:
        return pages[url]

    first = {"value": [{"id": 1}], "@odata.nextLink": "p2"}
    result = _run(paginate(first, request_fn=fetch))
    assert [r["id"] for r in result] == [1, 2, 3]


def test_paginate_max_items_stops_early():
    pages = {
        "p2": {"value": [{"id": 2}, {"id": 3}], "@odata.nextLink": "p3"},
        "p3": {"value": [{"id": 4}]},
    }

    async def fetch(url: str) -> dict:
        return pages[url]

    first = {"value": [{"id": 1}], "@odata.nextLink": "p2"}
    result = _run(paginate(first, request_fn=fetch, max_items=2))
    assert [r["id"] for r in result] == [1, 2]


# ---------- graph_request: retries ----------


def test_429_with_retry_after_seconds_retries_and_succeeds(_fast_sleep):
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, headers={"Retry-After": "2"})
        return httpx.Response(200, json={"value": [{"id": "u1"}]})

    _install_mock(handler)
    resp = _run(graph_request("GET", "/users"))
    assert resp.status_code == 200
    assert resp.attempts == 2
    assert _fast_sleep == [2.0]
    assert resp.throttle_wait_s == 2.0


def test_503_retry_after_http_date_parsed(_fast_sleep, monkeypatch):
    # Pin "now" inside throttle to produce a deterministic wait (30s).
    import graphconnect.transport.throttle as throttle_mod

    real_parse = throttle_mod._parse_retry_after

    def patched_parse(value, *, now=None):
        pinned = datetime(2026, 10, 21, 7, 27, 30, tzinfo=timezone.utc)
        return real_parse(value, now=pinned)

    monkeypatch.setattr(throttle_mod, "_parse_retry_after", patched_parse)

    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(503, headers={"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"})
        return httpx.Response(200, json={"ok": True})

    _install_mock(handler)
    resp = _run(graph_request("GET", "/deviceManagement/managedDevices", deadline_s=120))
    assert resp.status_code == 200
    assert len(_fast_sleep) == 1
    assert 29.0 <= _fast_sleep[0] <= 31.0


def test_429_without_retry_after_uses_backoff(_fast_sleep, monkeypatch):
    import graphconnect.transport.throttle as throttle_mod
    monkeypatch.setattr(throttle_mod.random, "uniform", lambda a, b: 0.0)

    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] < 3:
            return httpx.Response(429)  # no Retry-After
        return httpx.Response(200, json={"ok": True})

    _install_mock(handler)
    resp = _run(graph_request("GET", "/deviceManagement/managedDevices"))
    assert resp.status_code == 200
    assert _fast_sleep == [1.0, 2.0]


def test_five_consecutive_429_gives_up(_fast_sleep):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"Retry-After": "1"})

    _install_mock(handler)
    with pytest.raises(GraphTransportError) as exc:
        _run(graph_request("GET", "/deviceManagement/managedDevices"))
    assert exc.value.status_code == 429
    # attempts 1..5 each tried; after 5th we don't sleep again -> 4 sleeps
    assert len(_fast_sleep) == 4


def test_deadline_exceeded_before_retry(_fast_sleep):
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(429, headers={"Retry-After": "10"})

    _install_mock(handler)
    with pytest.raises(DeadlineExceeded):
        _run(graph_request("GET", "/deviceManagement/managedDevices", deadline_s=2.0))
    # We made one attempt, saw Retry-After=10s, remaining deadline < 10 -> raise.
    assert calls["n"] == 1


# ---------- graph_request: consistency auto-inject ----------


def test_users_filter_injects_consistency_and_count(_fast_sleep):
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["headers"] = dict(request.headers)
        seen["url"] = str(request.url)
        return httpx.Response(200, json={"value": []})

    _install_mock(handler)
    _run(graph_request("GET", "/users?$filter=startswith(displayName,'A')"))
    assert seen["headers"].get("consistencylevel") == "eventual"
    # $ is %24 when URL-encoded
    assert "count=true" in seen["url"]


def test_managed_devices_filter_does_not_inject(_fast_sleep):
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["headers"] = dict(request.headers)
        seen["url"] = str(request.url)
        return httpx.Response(200, json={"value": []})

    _install_mock(handler)
    _run(graph_request("GET", "/deviceManagement/managedDevices?$filter=operatingSystem eq 'iOS'"))
    assert "consistencylevel" not in seen["headers"]
    assert "count=true" not in seen["url"]


def test_graph_request_uses_delegated_profile_scopes(_fast_sleep, monkeypatch):
    class FakeCredential:
        def __init__(self):
            self.last_scopes = None

        def get_token(self, *scopes: str):
            self.last_scopes = scopes
            return SimpleNamespace(token="delegated-token", expires_on=None)

    credential = FakeCredential()
    def fake_context(profile="default"):
        del profile
        return SimpleNamespace(
            credential=credential,
            scopes=["User.Read.All", "Group.Read.All"],
        )

    monkeypatch.setattr(client_mod, "_resolve_auth_context", fake_context)

    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["authorization"] = request.headers.get("Authorization")
        return httpx.Response(200, json={"value": []})

    _install_mock(handler)
    _run(graph_request("GET", "/users"))
    assert credential.last_scopes == ("User.Read.All", "Group.Read.All")
    assert seen["authorization"] == "Bearer delegated-token"


def test_graph_request_uses_powershell_context_when_no_credential(_fast_sleep, monkeypatch):
    def fake_context(profile="default"):
        del profile
        return SimpleNamespace(
            credential=None,
            scopes=["Device.Read.All"],
        )

    monkeypatch.setattr(client_mod, "_resolve_auth_context", fake_context)
    async def fake_powershell_request(method, url, **kwargs):
        del method, url, kwargs
        return client_mod.GraphResponse(
            status_code=200,
            headers={"request-id": "req-ps"},
            body={"value": [{"id": "u1"}]},
            request_id="req-ps",
            trace_id="trace-ps",
        )

    monkeypatch.setattr(client_mod, "_graph_request_via_powershell", fake_powershell_request)

    response = _run(graph_request("GET", "/users"))
    assert response.status_code == 200
    assert response.body == {"value": [{"id": "u1"}]}
    assert response.request_id == "req-ps"


# ---------- graph_request: pagination ----------


def test_pagination_follows_three_pages(_fast_sleep):
    base = "https://graph.microsoft.com/v1.0"

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url.endswith("/users"):
            return httpx.Response(
                200,
                json={
                    "value": [{"id": "u1"}],
                    "@odata.nextLink": f"{base}/users?page=2",
                },
            )
        if "page=2" in url:
            return httpx.Response(
                200,
                json={
                    "value": [{"id": "u2"}],
                    "@odata.nextLink": f"{base}/users?page=3",
                },
            )
        if "page=3" in url:
            return httpx.Response(200, json={"value": [{"id": "u3"}]})
        return httpx.Response(404)

    _install_mock(handler)
    resp = _run(graph_request("GET", "/users", paginate=True))
    assert [u["id"] for u in resp.body["value"]] == ["u1", "u2", "u3"]
    assert resp.pages == 3
    assert "@odata.nextLink" not in resp.body


def test_pagination_max_items_cap(_fast_sleep):
    base = "https://graph.microsoft.com/v1.0"

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url.endswith("/users") or "page=1" in url:
            return httpx.Response(
                200,
                json={
                    "value": [{"id": "u1"}, {"id": "u2"}],
                    "@odata.nextLink": f"{base}/users?page=2",
                },
            )
        if "page=2" in url:
            return httpx.Response(
                200,
                json={
                    "value": [{"id": "u3"}, {"id": "u4"}],
                    "@odata.nextLink": f"{base}/users?page=3",
                },
            )
        return httpx.Response(200, json={"value": [{"id": "u5"}]})

    _install_mock(handler)
    resp = _run(graph_request("GET", "/users", paginate=True, max_items=3))
    assert [u["id"] for u in resp.body["value"]] == ["u1", "u2", "u3"]
