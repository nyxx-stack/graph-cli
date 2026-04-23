"""Pydantic models for catalog entries, results, and configuration."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


class SafetyTier(str, Enum):
    READ = "read"
    WRITE = "write"
    DESTRUCTIVE = "destructive"


class ApiVersion(str, Enum):
    V1 = "v1.0"
    BETA = "beta"


class AuthMethod(str, Enum):
    DEVICE_CODE = "device_code"
    GRAPH_POWERSHELL = "graph_powershell"


class ErrorCode(str, Enum):
    """Semantic error codes mapped to POSIX-style exit codes (see output.exit_for_code)."""

    USAGE_ERROR = "usage_error"
    NOT_FOUND = "not_found"
    PERMISSION_DENIED = "permission_denied"
    CONFLICT = "conflict"
    THROTTLED = "throttled"
    AUTH_REQUIRED = "auth_required"
    BAD_REQUEST = "bad_request"
    TOKEN_INVALID = "token_invalid"
    TOKEN_EXPIRED = "token_expired"
    WRONG_TIER = "wrong_tier"
    UPSTREAM_ERROR = "upstream_error"
    UNKNOWN = "unknown"


class ErrorPayload(BaseModel):
    """Structured error emitted on stderr in JSON mode or rendered in TTY mode."""

    code: ErrorCode
    message: str
    hint: str | None = None
    retryable: bool = False
    http_status: int | None = None
    graph_error_code: str | None = None
    correlation_id: str | None = None


class CliError(Exception):
    """Exception carrying a structured ErrorPayload for CLI surfaces to render."""

    def __init__(self, payload: ErrorPayload) -> None:
        self.payload = payload
        super().__init__(payload.message)


class CatalogParameter(BaseModel):
    name: str
    type: str = "string"
    required: bool = False
    description: str = ""
    default: Any = None
    enum: list[str] | None = None
    maps_to_filter: str | None = None
    multi: bool = False  # Comma-separated input → OData list (e.g. id in ('a','b'))
    # enum value → OData filter clause. Use for params where each value translates
    # to a different filter expression (e.g. status_filter=failure →
    # status/errorCode ne 0, status_filter=success → status/errorCode eq 0).
    # Takes precedence over maps_to_filter when the incoming value matches a key.
    value_map: dict[str, str] | None = None


class CatalogProjection(BaseModel):
    """Flatten/enrich a nested response field into a top-level column.

    The `path` is dotted (e.g. `target.groupId` or `settingInstance.settingDefinitionId`).
    `enum_map` optionally maps codes to a readable label at `name`; the raw value at
    `path` is untouched, so numeric sorts still work when `name != path`.
    """

    name: str
    path: str
    enum_map: dict[str, str] | None = None


class CatalogExample(BaseModel):
    description: str
    parameters: dict[str, Any] | None = None
    filter: str | None = None
    order_by: str | None = None


class CatalogEntry(BaseModel):
    id: str
    summary: str
    description: str = ""
    domain: str
    safety_tier: SafetyTier
    method: str = "GET"
    endpoint: str
    api_version: ApiVersion = ApiVersion.V1
    graph_permissions: list[str] = Field(default_factory=list)
    parameters: list[CatalogParameter] = Field(default_factory=list)
    default_select: list[str] | None = None
    default_filter: str | None = None
    default_orderby: str | None = None
    default_expand: str | None = None
    computed_filter: str | None = None
    body_template: dict[str, Any] | None = None
    preview_lookup_endpoint: str | None = None
    preview_lookup_select: list[str] | None = None
    execute_fingerprint_fields: list[str] = Field(default_factory=list)
    expected_success_status: int | None = None
    tags: list[str] = Field(default_factory=list)
    cmmc_controls: list[str] = Field(default_factory=list)
    examples: list[CatalogExample] = Field(default_factory=list)
    singleton: bool = False
    supports_top: bool = True
    advanced_query: bool = False
    aliases: list[str] = Field(default_factory=list)
    response_schema: str | None = None  # Key into catalog/_schemas.yaml
    rate_limit_class: str | None = None  # Free-form tag: light|standard|heavy|throttle_sensitive
    projections: list[CatalogProjection] = Field(default_factory=list)
    drop_paths: list[str] = Field(default_factory=list)
    download_export: bool = False  # POST /reports/exportJobs: poll + download result payload
    # Drop rows whose tuple of these field values matches a previously-seen row
    # (keeps first occurrence). Use on endpoints where Graph returns the same
    # logical row once per user on multi-user devices. Callers can override with
    # --no-dedupe on `read`.
    dedupe_by: list[str] = Field(default_factory=list)
    # v2 extensions (optional; defaults keep existing catalog YAML valid).
    national_cloud_overrides: dict[str, str] | None = None
    auth_profile_required: Literal["delegated", "app-only", "any"] = "any"
    emergency_safe: bool = False
    workflow_pack: str | None = None

    @property
    def search_text(self) -> str:
        """Combined text for fuzzy search indexing (names + descriptions + params)."""
        parts = [self.id, self.summary, self.description]
        parts.extend(self.aliases)
        parts.extend(self.tags)
        parts.extend(self.cmmc_controls)
        for p in self.parameters:
            parts.append(p.name)
            parts.append(p.description)
        return " ".join(parts).lower()

    def annotations(self) -> dict[str, bool]:
        """MCP-style tool annotations."""
        is_read = self.safety_tier == SafetyTier.READ
        return {
            "readOnlyHint": is_read,
            "destructiveHint": self.safety_tier == SafetyTier.DESTRUCTIVE,
            "idempotentHint": is_read or self.method.upper() in ("PUT", "DELETE"),
            "openWorldHint": True,
        }


class OperationResult(BaseModel):
    operation_id: str
    item_count: int = 0
    total_count: int | None = None
    has_more: bool = False
    data: list[dict[str, Any]] = Field(default_factory=list)
    execution_time_ms: int = 0
    graph_url: str = ""
    request_id: str = ""
    correlation_id: str = ""


class WritePreview(BaseModel):
    operation_id: str
    safety_tier: SafetyTier
    method: str
    url: str
    body: dict[str, Any] | None = None
    description: str
    affected_resources: list[str] = Field(default_factory=list)
    reversible: bool = True
    reverse_operation: str | None = None
    confirm_token: str
    expires_at: datetime
    warnings: list[str] = Field(default_factory=list)
    correlation_id: str = ""
    idempotency_key: str = ""


class ConfirmationToken(BaseModel):
    token: str
    operation_id: str
    request_hash: str
    created_at: datetime
    expires_at: datetime
    used: bool = False
    correlation_id: str = ""
    idempotency_key: str = ""
    resource_fingerprint: str | None = None


class AuditEntry(BaseModel):
    timestamp: datetime
    operation_id: str
    safety_tier: SafetyTier
    user_principal: str | None = None
    method: str
    graph_url: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    status: str = "success"
    http_status: int | None = None
    item_count: int | None = None
    execution_time_ms: int = 0
    confirm_token: str | None = None
    preview_shown: bool | None = None
    confirmed_at: datetime | None = None
    error: str | None = None
    request_id: str | None = None
    correlation_id: str | None = None
    idempotency_key: str | None = None
    response_bytes: int | None = None
    error_code: str | None = None


class AuthConfig(BaseModel):
    tenant_id: str
    client_id: str


class AuthStatus(BaseModel):
    authenticated: bool = False
    auth_method: AuthMethod | None = None
    user_principal: str | None = None
    display_name: str | None = None
    token_expires: datetime | None = None
    scopes: list[str] = Field(default_factory=list)


class Envelope(BaseModel):
    """Uniform v2 response shape emitted by every verb."""

    ok: bool
    trace_id: str
    mode: Literal["read", "plan", "apply", "breakglass"]
    summary: str
    data: list[dict[str, Any]] | None = None
    plan: dict[str, Any] | None = None
    warnings: list[str] = Field(default_factory=list)
    next_actions: list[str] = Field(default_factory=list)
    error: ErrorPayload | None = None

    @classmethod
    def ok_read(
        cls,
        summary: str,
        data: list[dict[str, Any]],
        *,
        trace_id: str,
        warnings: list[str] | None = None,
        next_actions: list[str] | None = None,
    ) -> "Envelope":
        return cls(
            ok=True,
            trace_id=trace_id,
            mode="read",
            summary=summary,
            data=data,
            warnings=warnings or [],
            next_actions=next_actions or [],
        )

    @classmethod
    def ok_plan(
        cls,
        summary: str,
        plan: dict[str, Any],
        *,
        trace_id: str,
        warnings: list[str] | None = None,
        next_actions: list[str] | None = None,
    ) -> "Envelope":
        return cls(
            ok=True,
            trace_id=trace_id,
            mode="plan",
            summary=summary,
            plan=plan,
            warnings=warnings or [],
            next_actions=next_actions or [],
        )

    @classmethod
    def ok_apply(
        cls,
        summary: str,
        *,
        trace_id: str,
        data: list[dict[str, Any]] | None = None,
        plan: dict[str, Any] | None = None,
        warnings: list[str] | None = None,
        next_actions: list[str] | None = None,
        breakglass: bool = False,
    ) -> "Envelope":
        return cls(
            ok=True,
            trace_id=trace_id,
            mode="breakglass" if breakglass else "apply",
            summary=summary,
            data=data,
            plan=plan,
            warnings=warnings or [],
            next_actions=next_actions or [],
        )

    @classmethod
    def err(
        cls,
        summary: str,
        error: ErrorPayload,
        *,
        trace_id: str,
        mode: Literal["read", "plan", "apply", "breakglass"] = "read",
        warnings: list[str] | None = None,
        next_actions: list[str] | None = None,
    ) -> "Envelope":
        return cls(
            ok=False,
            trace_id=trace_id,
            mode=mode,
            summary=summary,
            warnings=warnings or [],
            next_actions=next_actions or [],
            error=error,
        )
