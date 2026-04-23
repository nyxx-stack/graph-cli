"""`explain enrollment-failure` logic.

Pulls recent enrollment-related audit events for a user or device and
classifies the failure mode into one of a small fixed set of categories so
the operator can jump to the right remediation.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

from ..types import Envelope
from ._transport import _values, graph_get


_CLASSIFIERS: list[tuple[str, list[str]]] = [
    ("no_license", ["license", "not licensed", "insufficient license", "license required"]),
    ("mdm_authority_missing", ["mdm authority", "no mdm authority", "not configured"]),
    ("device_cap_exceeded", ["device cap", "limit", "quota", "maximum number of devices"]),
    ("azure_ad_join_failed", ["aadj", "azure ad join", "entra join", "hybrid join"]),
    ("autopilot_profile_missing", ["autopilot", "enrollment profile"]),
    ("wrong_enrollment_restriction", ["enrollment restriction", "platform blocked", "device type"]),
    ("authentication_failed", ["authentication", "invalid credentials", "mfa", "conditional access"]),
    ("timeout", ["timeout", "timed out"]),
    ("unknown", []),
]


def _classify(text: str) -> str:
    haystack = text.lower()
    for label, needles in _CLASSIFIERS:
        if label == "unknown":
            continue
        for needle in needles:
            if needle in haystack:
                return label
    return "unknown"


def _event_text(event: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in (
        "activityDisplayName",
        "displayName",
        "result",
        "resultReason",
        "category",
        "statusCode",
        "status",
        "errorCode",
        "details",
    ):
        val = event.get(key)
        if isinstance(val, str) and val:
            parts.append(val)
        elif isinstance(val, dict):
            parts.append(str(val))
    extra = event.get("additionalDetails") or []
    if isinstance(extra, list):
        for item in extra:
            if isinstance(item, dict):
                v = item.get("value")
                if isinstance(v, str):
                    parts.append(v)
    return " | ".join(parts)


async def _fetch_directory_audits(
    *, upn: str | None, device_id: str | None, profile: str
) -> list[dict[str, Any]]:
    path = "/auditLogs/directoryAudits"
    filters: list[str] = ["(category eq 'DeviceManagement' or activityDisplayName contains 'enrollment')"]
    if upn:
        filters.append(f"initiatedBy/user/userPrincipalName eq '{upn.replace(chr(39), chr(39) * 2)}'")
    # Graph doesn't support a clean targetResource filter by device id, so we
    # fetch and filter client-side when device_id was given.
    query = "?$top=50&$orderby=activityDateTime desc"
    body = await graph_get(path + query, profile=profile)
    events = _values(body)
    if device_id:
        events = [
            e
            for e in events
            if any(
                str((t or {}).get("id")) == device_id
                for t in (e.get("targetResources") or [])
            )
        ]
    return events


async def _fetch_registration_requests(
    *, upn: str | None, device_id: str | None, profile: str
) -> list[dict[str, Any]]:
    try:
        body = await graph_get(
            "/deviceManagement/autopilotEvents?$top=50&$orderby=eventDateTime desc",
            profile=profile,
            api_version="beta",
        )
    except Exception:
        return []
    events = _values(body)
    if upn:
        events = [e for e in events if str(e.get("userPrincipalName") or "").lower() == upn.lower()]
    if device_id:
        events = [
            e
            for e in events
            if str(e.get("deviceId") or e.get("managedDeviceId") or "") == device_id
        ]
    return events


async def run(
    *,
    user: str | None = None,
    device: str | None = None,
    profile: str = "default",
    trace_id: str | None = None,
) -> Envelope:
    trace_id = trace_id or uuid.uuid4().hex
    if not user and not device:
        raise ValueError("Provide --user or --device.")

    directory, registration = await asyncio.gather(
        _fetch_directory_audits(upn=user, device_id=device, profile=profile),
        _fetch_registration_requests(upn=user, device_id=device, profile=profile),
    )

    rows: list[dict[str, Any]] = []
    for event in directory:
        result = str(event.get("result") or "").lower()
        if result and result not in {"failure", "clientError", "error", "timeout"}:
            continue
        text = _event_text(event)
        rows.append(
            {
                "source": "directoryAudits",
                "timestamp": event.get("activityDateTime"),
                "activity": event.get("activityDisplayName"),
                "result": event.get("result"),
                "failure_mode": _classify(text),
                "upn": (event.get("initiatedBy") or {})
                .get("user", {})
                .get("userPrincipalName"),
                "correlation_id": event.get("correlationId"),
                "detail": text,
            }
        )
    for event in registration:
        status = str(
            event.get("enrollmentState") or event.get("status") or ""
        ).lower()
        if status in {"success", "enrolled"}:
            continue
        text = _event_text(event)
        rows.append(
            {
                "source": "autopilotEvents",
                "timestamp": event.get("eventDateTime"),
                "activity": event.get("deploymentState") or "autopilot",
                "result": event.get("enrollmentState") or event.get("status"),
                "failure_mode": _classify(text),
                "upn": event.get("userPrincipalName"),
                "device_id": event.get("deviceId") or event.get("managedDeviceId"),
                "detail": text,
            }
        )

    summary = (
        f"{len(rows)} enrollment failure event(s)"
        if rows
        else "No enrollment failure events found"
    )
    modes = sorted({r["failure_mode"] for r in rows if r.get("failure_mode")})
    next_actions = [f"Classified modes: {', '.join(modes)}"] if modes else []

    return Envelope(
        ok=True,
        trace_id=trace_id,
        mode="read",
        summary=summary,
        data=rows,
        next_actions=next_actions,
    )
