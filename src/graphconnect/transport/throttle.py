"""Throttle middleware: Retry-After and exponential backoff for 429/503."""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
from datetime import datetime, timezone

import httpx


MAX_ATTEMPTS = 5
BACKOFF_BASE_S = 1.0
BACKOFF_CAP_S = 30.0


@dataclass
class ThrottleState:
    attempts: int = 0
    total_wait_s: float = 0.0
    last_retry_after: float | None = None
    history: list[float] = field(default_factory=list)

    def record(self, wait_s: float) -> None:
        self.attempts += 1
        self.total_wait_s += wait_s
        self.last_retry_after = wait_s
        self.history.append(wait_s)


def _parse_retry_after(value: str, *, now: datetime | None = None) -> float | None:
    if value is None:
        return None
    stripped = value.strip()
    if not stripped:
        return None
    try:
        seconds = float(stripped)
        if seconds < 0:
            return 0.0
        return seconds
    except ValueError:
        pass
    try:
        dt = parsedate_to_datetime(stripped)
    except (TypeError, ValueError):
        return None
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    reference = now or datetime.now(timezone.utc)
    delta = (dt - reference).total_seconds()
    return max(0.0, delta)


def _backoff(attempt: int) -> float:
    exponent = max(0, attempt - 1)
    base = min(BACKOFF_CAP_S, BACKOFF_BASE_S * (2 ** exponent))
    jitter = random.uniform(0, base / 2)
    return min(BACKOFF_CAP_S, base + jitter)


async def sleep_for_retry(
    response: httpx.Response,
    attempt: int,
    *,
    max_attempts: int = MAX_ATTEMPTS,
    now: datetime | None = None,
) -> float | None:
    """Compute the wait (in seconds) before the next retry, or None to give up.

    attempt is 1-based: attempt=1 means we have already made one request.
    Returns None when we've exhausted retries or the response isn't retryable.
    """
    if response.status_code not in (429, 503):
        return None
    if attempt >= max_attempts:
        return None
    header = response.headers.get("Retry-After")
    wait_s: float | None = None
    if header is not None:
        wait_s = _parse_retry_after(header, now=now)
    if wait_s is None:
        wait_s = _backoff(attempt)
    return wait_s
