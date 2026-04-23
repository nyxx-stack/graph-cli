"""Microsoft Graph national cloud endpoint resolution.

Reference: https://learn.microsoft.com/graph/deployments
"""

from __future__ import annotations

from enum import Enum


class NationalCloud(str, Enum):
    COMMERCIAL = "commercial"
    USGOV = "USGov"
    USGOV_HIGH = "USGovHigh"
    DOD = "DoD"
    CHINA = "China"


_GRAPH_BASE: dict[str, str] = {
    NationalCloud.COMMERCIAL.value: "https://graph.microsoft.com",
    NationalCloud.USGOV.value: "https://graph.microsoft.us",
    NationalCloud.USGOV_HIGH.value: "https://graph.microsoft.us",
    NationalCloud.DOD.value: "https://dod-graph.microsoft.us",
    NationalCloud.CHINA.value: "https://microsoftgraph.chinacloudapi.cn",
}

_AUTHORITIES: dict[str, str] = {
    NationalCloud.COMMERCIAL.value: "https://login.microsoftonline.com",
    NationalCloud.USGOV.value: "https://login.microsoftonline.us",
    NationalCloud.USGOV_HIGH.value: "https://login.microsoftonline.us",
    NationalCloud.DOD.value: "https://login.microsoftonline.us",
    NationalCloud.CHINA.value: "https://login.chinacloudapi.cn",
}


def _normalize(cloud: NationalCloud | str) -> str:
    if isinstance(cloud, NationalCloud):
        return cloud.value
    for member in NationalCloud:
        if member.value.lower() == cloud.lower():
            return member.value
    raise ValueError(f"unknown national cloud: {cloud!r}")


def get_endpoint_base(cloud: NationalCloud | str) -> str:
    return _GRAPH_BASE[_normalize(cloud)]


def get_authority(cloud: NationalCloud | str) -> str:
    return _AUTHORITIES[_normalize(cloud)]
