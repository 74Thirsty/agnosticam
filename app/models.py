from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class CameraStatus(str, Enum):
    ONLINE = "online"
    OFFLINE = "offline"
    MAINTENANCE = "maintenance"


class UserRole(str, Enum):
    ADMIN = "admin"
    VIEWER = "viewer"


@dataclass(slots=True)
class Camera:
    id: int
    name: str
    ip_address: str
    stream_url: str
    location: str
    manufacturer: str
    model_name: str
    status: CameraStatus
    tags: tuple[str, ...]
    is_active: bool
    last_health_check_at: datetime | None
    health_message: str | None
    created_at: datetime
    updated_at: datetime


@dataclass(slots=True)
class User:
    id: int
    email: str
    role: UserRole
    is_active: bool
    created_at: datetime


@dataclass(slots=True)
class CameraLayout:
    id: int
    name: str
    grid: str
    camera_ids: tuple[int, ...]
    created_by: int
    created_at: datetime
    updated_at: datetime


@dataclass(slots=True)
class FleetSummary:
    total_cameras: int
    online: int
    offline: int
    maintenance: int
    active: int
    unique_locations: int
    unique_manufacturers: int


@dataclass(slots=True)
class ShodanHost:
    ip_address: str
    port: int
    transport: str
    org: str | None
    isp: str | None
    os: str | None
    hostnames: tuple[str, ...]
    domains: tuple[str, ...]
    product: str | None
    title: str | None
    location: str | None
    timestamp: datetime | None


@dataclass(slots=True)
class ShodanScanResult:
    query: str
    total: int
    hosts: tuple[ShodanHost, ...]
    created_at: str
    
    
@dataclass(slots=True)
class ShodanScanSummary:
    total_results: int
    unique_ips: int
    unique_orgs: int
    unique_products: int
    top_ports: tuple[int, ...]
    top_orgs: tuple[str, ...]
    top_products: tuple[str, ...]
    
    
@dataclass(slots=True)
class ShodanScanHistoryEntry:
    id: int
    source: str
    query: str
    created_by: int
    created_at: datetime


@dataclass(slots=True)
class ShodanScanHistorySummary:
    total_scans: int
    unique_sources: int
    unique_queries: int
    scans_by_source: dict[str, int]
    scans_by_query: dict[str, int]


@dataclass(slots=True)
class ScanRun:
    id: int
    source: str
    query: str
    created_by: int
    imported_count: int
    notes: str | None
    created_at: datetime
