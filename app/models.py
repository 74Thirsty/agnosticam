from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class UserRole(str, Enum):
    ADMIN = "admin"
    VIEWER = "viewer"


class CameraStatus(str, Enum):
    ONLINE = "online"
    OFFLINE = "offline"
    MAINTENANCE = "maintenance"


@dataclass(frozen=True)
class User:
    id: int
    email: str
    role: UserRole
    is_active: bool
    created_at: datetime


@dataclass(frozen=True)
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


@dataclass(frozen=True)
class CameraLayout:
    id: int
    name: str
    grid: str
    camera_ids: tuple[int, ...]
    created_by: int
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True)
class FleetSummary:
    total_cameras: int
    online: int
    offline: int
    maintenance: int
    active: int
    unique_locations: int
    unique_manufacturers: int


@dataclass(frozen=True)
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

@dataclass(frozen=True)
class ShodanScanResult:
    query: str
    total: int
    page: int
    hosts: tuple[ShodanHost, ...]
    fetched_at: datetime
