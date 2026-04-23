"""Graph transport: retries, consistency, pagination, national clouds."""

from .client import (
    DeadlineExceeded,
    GraphResponse,
    GraphTransportError,
    graph_request,
    set_http_client,
)
from .consistency import apply_advanced_query, needs_advanced_query
from .national_cloud import NationalCloud, get_authority, get_endpoint_base
from .pagination import paginate
from .throttle import ThrottleState, sleep_for_retry

__all__ = [
    "DeadlineExceeded",
    "GraphResponse",
    "GraphTransportError",
    "NationalCloud",
    "ThrottleState",
    "apply_advanced_query",
    "get_authority",
    "get_endpoint_base",
    "graph_request",
    "needs_advanced_query",
    "paginate",
    "set_http_client",
    "sleep_for_retry",
]
