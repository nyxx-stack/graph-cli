"""Tier enforcement, confirmation tokens, and rate limiting."""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from graphconnect.types import ConfirmationToken, SafetyTier

TOKEN_DIR = Path.home() / ".graphconnect"
TOKEN_FILE = TOKEN_DIR / "pending_tokens.json"

# Token TTLs by safety tier
TOKEN_TTL = {
    SafetyTier.WRITE: timedelta(seconds=120),
    SafetyTier.DESTRUCTIVE: timedelta(seconds=60),
}

# Rate limits: max calls per minute
RATE_LIMITS = {
    SafetyTier.READ: 60,
    SafetyTier.WRITE: 10,
    SafetyTier.DESTRUCTIVE: 2,
}

# In-memory rate tracking (per-process)
_rate_windows: dict[str, list[float]] = defaultdict(list)


def compute_request_hash(operation_id: str, parameters: dict, body: dict | None) -> str:
    """Deterministic hash of an operation request for token binding."""
    payload = json.dumps(
        {"op": operation_id, "params": parameters, "body": body},
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def generate_token(
    operation_id: str,
    safety_tier: SafetyTier,
    parameters: dict,
    body: dict | None = None,
) -> ConfirmationToken:
    """Generate a confirmation token for a write/destructive preview."""
    now = datetime.now(timezone.utc)
    ttl = TOKEN_TTL.get(safety_tier, TOKEN_TTL[SafetyTier.WRITE])
    prefix = "dst" if safety_tier == SafetyTier.DESTRUCTIVE else "wrt"
    token_value = f"{prefix}_{secrets.token_hex(8)}"

    token = ConfirmationToken(
        token=token_value,
        operation_id=operation_id,
        request_hash=compute_request_hash(operation_id, parameters, body),
        created_at=now,
        expires_at=now + ttl,
        used=False,
    )

    _save_token(token)
    return token


def validate_token(
    confirm_token: str,
    operation_id: str,
    parameters: dict,
    body: dict | None = None,
) -> ConfirmationToken:
    """Validate a confirmation token. Raises on failure."""
    tokens = _load_tokens()
    now = datetime.now(timezone.utc)

    tokens = {k: v for k, v in tokens.items() if v.expires_at > now}

    if confirm_token not in tokens:
        raise ValueError(
            "Invalid or expired confirmation token. "
            "Run the command without --execute first to get a new token."
        )

    token = tokens[confirm_token]

    if token.used:
        raise ValueError("Token has already been used. Run the preview again for a new token.")

    if token.expires_at <= now:
        raise ValueError(
            f"Token expired at {token.expires_at.isoformat()}. "
            "Run the preview again for a new token."
        )

    expected_hash = compute_request_hash(operation_id, parameters, body)
    if token.request_hash != expected_hash:
        raise ValueError(
            "Token does not match the current request parameters. "
            "The operation or parameters have changed since the preview. "
            "Run the preview again."
        )

    if token.operation_id != operation_id:
        raise ValueError(
            f"Token was issued for '{token.operation_id}', not '{operation_id}'. "
            "Run the preview for the correct operation."
        )

    token.used = True
    tokens[confirm_token] = token
    _save_all_tokens(tokens)

    return token


def check_rate_limit(safety_tier: SafetyTier) -> float | None:
    """Check rate limit. Returns retry_after_seconds if limited, None if OK."""
    limit = RATE_LIMITS.get(safety_tier, 60)
    tier_key = safety_tier.value
    now = time.monotonic()

    # Clean old entries (older than 60 seconds)
    _rate_windows[tier_key] = [t for t in _rate_windows[tier_key] if now - t < 60]

    if len(_rate_windows[tier_key]) >= limit:
        oldest = _rate_windows[tier_key][0]
        return 60 - (now - oldest)

    _rate_windows[tier_key].append(now)
    return None


def _load_tokens() -> dict[str, ConfirmationToken]:
    """Load pending tokens from file."""
    try:
        with open(TOKEN_FILE, encoding="utf-8") as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}
    try:
        return {k: ConfirmationToken(**v) for k, v in data.items()}
    except (TypeError, ValueError):
        return {}


def _save_token(token: ConfirmationToken) -> None:
    """Append a token to the file."""
    tokens = _load_tokens()
    tokens[token.token] = token
    _save_all_tokens(tokens)


def _save_all_tokens(tokens: dict[str, ConfirmationToken]) -> None:
    """Write all tokens to file."""
    TOKEN_DIR.mkdir(parents=True, exist_ok=True)
    with open(TOKEN_FILE, "w", encoding="utf-8") as f:
        json.dump(
            {k: json.loads(v.model_dump_json()) for k, v in tokens.items()},
            f,
            indent=2,
        )

