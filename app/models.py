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


@dataclass
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


@dataclass
class User:
    id: int
    email: str
    role: UserRole
    is_active: bool
    created_at: datetime


@dataclass
class CameraLayout:
    id: int
    name: str
    grid: str
    camera_ids: tuple[int, ...]
    created_by: int
    created_at: datetime
    updated_at: datetime


@dataclass
class FleetSummary:
    total_cameras: int
    online: int
    offline: int
    maintenance: int
    active: int
    unique_locations: int
    unique_manufacturers: int