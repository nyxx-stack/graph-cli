"""Pydantic models for catalog entries, results, and configuration."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

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
    AZURE_CLI = "azure_cli"
    AZURE_POWERSHELL = "azure_powershell"


class CatalogParameter(BaseModel):
    name: str
    type: str = "string"
    required: bool = False
    description: str = ""
    default: Any = None
    enum: list[str] | None = None
    maps_to_filter: str | None = None


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
    computed_filter: str | None = None
    body_template: dict[str, Any] | None = None
    tags: list[str] = Field(default_factory=list)
    cmmc_controls: list[str] = Field(default_factory=list)
    examples: list[CatalogExample] = Field(default_factory=list)
    beta: bool = False
    singleton: bool = False
    supports_top: bool = True
    advanced_query: bool = False

    @property
    def search_text(self) -> str:
        """Combined text for fuzzy search indexing."""
        parts = [self.id, self.summary, self.description]
        parts.extend(self.tags)
        parts.extend(self.cmmc_controls)
        return " ".join(parts).lower()


class OperationResult(BaseModel):
    operation_id: str
    item_count: int = 0
    has_more: bool = False
    data: list[dict[str, Any]] = Field(default_factory=list)
    execution_time_ms: int = 0
    graph_url: str = ""


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


class ConfirmationToken(BaseModel):
    token: str
    operation_id: str
    request_hash: str
    created_at: datetime
    expires_at: datetime
    used: bool = False


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
