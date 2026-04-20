"""Pydantic v2 response models for all API endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


# ─── Assets ──────────────────────────────────────────────────────────────────

class AssetListItem(BaseModel):
    """Single row returned by GET /api/assets."""

    id: str
    mac: Optional[str] = None
    ip: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    confidence_score: Optional[float] = None
    deviceType: Optional[str] = None
    os: Optional[str] = None
    osVersion: Optional[str] = None
    cpe: Optional[str] = None
    confidence: Optional[float] = None
    inference_method: Optional[str] = None
    protocols: Optional[list[str]] = None
    ports: Optional[list[int]] = None
    connection_count: Optional[int] = None
    status: str = "offline"


class AssetDetail(BaseModel):
    """Full asset record returned by GET /api/assets/{id}."""

    model_config = {"extra": "allow"}

    id: Optional[str] = None
    mac_address: Optional[str] = None
    vendor: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    confidence_score: Optional[float] = None
    asset_status: Optional[str] = None
    ips: Optional[list[dict[str, Any]]] = None
    hostnames: Optional[list[dict[str, Any]]] = None
    behaviors: Optional[list[dict[str, Any]]] = None
    fingerprints: Optional[list[dict[str, Any]]] = None
    inference: Optional[dict[str, Any]] = None
    inference_evidence: Optional[list[dict[str, Any]]] = None


# ─── Stats ───────────────────────────────────────────────────────────────────

class StatsResponse(BaseModel):
    """Dashboard KPI aggregate returned by GET /api/stats."""

    assets: dict[str, Any]
    connections: dict[str, Any]
    dns: dict[str, Any]
    tls: dict[str, Any]
    http: dict[str, Any]
    topProtocols: list[dict[str, Any]]
    topAssets: list[dict[str, Any]]
    trafficByHour: list[dict[str, Any]]


# ─── Inference ───────────────────────────────────────────────────────────────

class InferenceSummaryItem(BaseModel):
    """One row of GET /api/inference/summary."""

    device_type: Optional[str] = None
    count: int
    avg_confidence: Optional[float] = None


# ─── Network ─────────────────────────────────────────────────────────────────

class ConnectionRow(BaseModel):
    """Single connection row."""

    id: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    service: Optional[str] = None
    duration: Optional[float] = None
    bytes_sent: Optional[int] = None
    bytes_received: Optional[int] = None
    timestamp: Optional[datetime] = None
    src_vendor: Optional[str] = None
    dst_vendor: Optional[str] = None


class BehaviorRow(BaseModel):
    """Aggregated behavior row."""

    protocol: Optional[str] = None
    port: Optional[int] = None
    service: Optional[str] = None
    total_frequency: Optional[int] = None
    asset_count: Optional[int] = None


# ─── Logs ────────────────────────────────────────────────────────────────────

class DnsRow(BaseModel):
    """DNS query row."""

    id: str
    query: Optional[str] = None
    answer: Optional[str] = None
    query_type: Optional[str] = None
    timestamp: Optional[datetime] = None
    src_ip: Optional[str] = None


class TlsRow(BaseModel):
    """TLS session row."""

    id: str
    server_name: Optional[str] = None
    version: Optional[str] = None
    ja3: Optional[str] = None
    ja3s: Optional[str] = None
    certificate_issuer: Optional[str] = None
    next_protocol: Optional[str] = None
    validation_status: Optional[str] = None
    sni_matches_cert: Optional[bool] = None
    ssl_history: Optional[str] = None
    timestamp: Optional[datetime] = None
    src_ip: Optional[str] = None


class HttpRow(BaseModel):
    """HTTP session row."""

    id: str
    host: Optional[str] = None
    uri: Optional[str] = None
    method: Optional[str] = None
    status_code: Optional[int] = None
    user_agent: Optional[str] = None
    timestamp: Optional[datetime] = None
    src_ip: Optional[str] = None


# ─── Asset CRUD ──────────────────────────────────────────────────────────────

class AssetCreate(BaseModel):
    """Request body for POST /api/assets."""

    mac_address: str
    ip_address: Optional[str] = None
    vendor: Optional[str] = None
    hostname: Optional[str] = None


class AssetUpdate(BaseModel):
    """Request body for PUT /api/assets/{id}."""

    mac_address: Optional[str] = None
    ip_address: Optional[str] = None
    vendor: Optional[str] = None
    hostname: Optional[str] = None


# ─── Scan ────────────────────────────────────────────────────────────────────

class ScanStartRequest(BaseModel):
    """Optional request body for POST /api/scan/start and /api/scan/restart."""

    mode: Optional[str] = Field(
        default=None,
        pattern="^(file|live)$",
        description="'file' reads static logs once; 'live' continuously polls the log directory",
    )
    log_dir: Optional[str] = Field(
        default=None,
        description="Override the default ZEEK_LOG_DIR config value",
    )
    interface: Optional[str] = Field(
        default=None,
        description="Informational — which interface Zeek is capturing on (e.g. 'eth0')",
    )


# ─── Alerts ──────────────────────────────────────────────────────────────────

class AlertItem(BaseModel):
    """Single alert returned by GET /api/alerts."""

    id: str
    alert_type: str
    severity: str
    message: str
    source_ip: Optional[str] = None
    asset_id: Optional[str] = None
    status: str = "new"
    metadata: Optional[dict] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class AlertUpdateRequest(BaseModel):
    """Request body for PATCH /api/alerts/{id}."""

    status: str  # 'new', 'false_positive'
    note: Optional[str] = None


# ─── Vulnerabilities ─────────────────────────────────────────────────────────

class VulnerabilityItem(BaseModel):
    """Single vulnerability returned by GET /api/vulnerabilities."""

    id: str
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    severity: Optional[str] = None
    description: Optional[str] = None
    affected_assets: int = 0


# ─── NVD Integration ─────────────────────────────────────────────────────────

class NvdConfigRequest(BaseModel):
    """Request body for POST /api/integrations/nvd."""

    api_key: str


# ─── Health Check ────────────────────────────────────────────────────────────

class HealthResponse(BaseModel):
    """Response for GET /api/health."""

    database: str  # 'connected' | 'disconnected'
    ingestion: str  # 'idle' | 'running'
    last_log_timestamp: Optional[datetime] = None
    total_assets: int = 0


# ─── Auth ─────────────────────────────────────────────────────────────────────

class TokenResponse(BaseModel):
    """Returned by POST /api/auth/login."""

    access_token: str
    token_type: str = "bearer"


class UserInfo(BaseModel):
    """Returned by GET /api/auth/me and POST /api/auth/users."""

    username: str
    role: str


class UserCreateRequest(BaseModel):
    """Request body for POST /api/auth/users (admin only)."""

    username: str = Field(min_length=2, max_length=64, pattern=r"^[A-Za-z0-9_\-]+$")
    password: str = Field(min_length=10, description="Plaintext; hashed before storage")
    role: str = Field(default="analyst", pattern="^(admin|analyst)$")
