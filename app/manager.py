from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import asdict
import secrets
import socket
import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

from app.models import Camera, CameraLayout, CameraStatus, FleetSummary, User, UserRole


class ValidationError(ValueError):
    """Raised when input violates constraints."""


class CameraNotFoundError(LookupError):
    """Raised when a camera cannot be found."""


class CameraConflictError(ValueError):
    """Raised when unique camera constraints are violated."""


class AuthError(PermissionError):
    """Raised for invalid authentication actions."""


class FleetManager:
    def __init__(self, db_path: str | Path = "agnosticam.db") -> None:
        self.db_path = str(db_path)
        self._initialize_db()

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _initialize_db(self) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL,
                    is_active INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cameras (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    ip_address TEXT NOT NULL,
                    stream_url TEXT NOT NULL,
                    location TEXT NOT NULL,
                    manufacturer TEXT NOT NULL,
                    model_name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    tags TEXT NOT NULL DEFAULT '',
                    is_active INTEGER NOT NULL DEFAULT 1,
                    last_health_check_at TEXT,
                    health_message TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS layouts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    grid TEXT NOT NULL,
                    camera_ids TEXT NOT NULL,
                    created_by INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(created_by) REFERENCES users(id)
                )
                """
            )
            if not conn.execute("SELECT id FROM users LIMIT 1").fetchone():
                now = self._now().isoformat()
                conn.execute(
                    "INSERT INTO users (email, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                    ("admin@agnosticam.local", self._hash_password("admin123"), UserRole.ADMIN.value, now),
                )

    @staticmethod
    def _now() -> datetime:
        return datetime.now(UTC).replace(microsecond=0)

    @staticmethod
    def _validate_string(field: str, value: str, *, min_len: int = 2, max_len: int = 120) -> str:
        v = value.strip()
        if not (min_len <= len(v) <= max_len):
            raise ValidationError(f"{field} must be between {min_len} and {max_len} chars")
        return v

    @staticmethod
    def _validate_ip(ip_address: str) -> str:
        parts = ip_address.strip().split(".")
        if len(parts) != 4:
            raise ValidationError("ip_address must be an IPv4 address")
        try:
            values = [int(p) for p in parts]
        except ValueError as exc:
            raise ValidationError("ip_address must contain numeric octets") from exc
        if any(v < 0 or v > 255 for v in values):
            raise ValidationError("ip_address octets must be 0-255")
        return ".".join(str(v) for v in values)

    @staticmethod
    def _normalize_tags(tags: list[str] | tuple[str, ...] | None) -> tuple[str, ...]:
        if tags is None:
            return ()
        normalized = tuple(sorted({t.strip().lower() for t in tags if t.strip()}))
        if len(normalized) > 20:
            raise ValidationError("A camera may have up to 20 tags")
        return normalized

    @staticmethod
    def _validate_status(status: str | CameraStatus) -> CameraStatus:
        try:
            return status if isinstance(status, CameraStatus) else CameraStatus(status.lower())
        except Exception as exc:
            raise ValidationError("status must be online, offline, or maintenance") from exc

    @staticmethod
    def _hash_password(password: str) -> str:
        salt = secrets.token_hex(16)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120_000)
        return f"{salt}${digest.hex()}"

    @staticmethod
    def _verify_password(password: str, encoded: str) -> bool:
        salt, digest = encoded.split("$", 1)
        candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120_000).hex()
        return hmac.compare_digest(candidate, digest)

    @staticmethod
    def _camera_from_row(row: sqlite3.Row) -> Camera:
        return Camera(
            id=row["id"],
            name=row["name"],
            ip_address=row["ip_address"],
            stream_url=row["stream_url"],
            location=row["location"],
            manufacturer=row["manufacturer"],
            model_name=row["model_name"],
            status=CameraStatus(row["status"]),
            tags=tuple(t for t in row["tags"].split(",") if t),
            is_active=bool(row["is_active"]),
            last_health_check_at=datetime.fromisoformat(row["last_health_check_at"]) if row["last_health_check_at"] else None,
            health_message=row["health_message"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )

    @staticmethod
    def _user_from_row(row: sqlite3.Row) -> User:
        return User(
            id=row["id"],
            email=row["email"],
            role=UserRole(row["role"]),
            is_active=bool(row["is_active"]),
            created_at=datetime.fromisoformat(row["created_at"]),
        )

    @staticmethod
    def _layout_from_row(row: sqlite3.Row) -> CameraLayout:
        return CameraLayout(
            id=row["id"],
            name=row["name"],
            grid=row["grid"],
            camera_ids=tuple(json.loads(row["camera_ids"])),
            created_by=row["created_by"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )

    def create_user(self, *, email: str, password: str, role: str | UserRole = UserRole.VIEWER) -> User:
        email = self._validate_string("email", email, min_len=6, max_len=120).lower()
        password = self._validate_string("password", password, min_len=8, max_len=128)
        role = role if isinstance(role, UserRole) else UserRole(role)
        now = self._now().isoformat()
        with self._conn() as conn:
            try:
                cur = conn.execute(
                    "INSERT INTO users (email, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                    (email, self._hash_password(password), role.value, now),
                )
            except sqlite3.IntegrityError as exc:
                raise ValidationError("email already exists") from exc
            row = conn.execute("SELECT * FROM users WHERE id = ?", (cur.lastrowid,)).fetchone()
            return self._user_from_row(row)

    def authenticate_user(self, *, email: str, password: str) -> User:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM users WHERE email = ?", (email.lower(),)).fetchone()
        if not row or not row["is_active"]:
            raise AuthError("invalid credentials")
        if not self._verify_password(password, row["password_hash"]):
            raise AuthError("invalid credentials")
        return self._user_from_row(row)

    def get_user(self, user_id: int) -> User:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not row:
            raise AuthError("user not found")
        return self._user_from_row(row)

    def list_users(self) -> list[User]:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
        return [self._user_from_row(r) for r in rows]

    def add_camera(
        self,
        *,
        name: str,
        ip_address: str,
        stream_url: str,
        location: str,
        manufacturer: str,
        model_name: str,
        status: str | CameraStatus = CameraStatus.OFFLINE,
        tags: list[str] | None = None,
        is_active: bool = True,
    ) -> Camera:
        name = self._validate_string("name", name, min_len=3, max_len=80)
        ip_address = self._validate_ip(ip_address)
        stream_url = self._validate_string("stream_url", stream_url, min_len=8, max_len=250)
        location = self._validate_string("location", location)
        manufacturer = self._validate_string("manufacturer", manufacturer)
        model_name = self._validate_string("model_name", model_name)
        status = self._validate_status(status)
        tags = self._normalize_tags(tags)

        now = self._now().isoformat()
        with self._conn() as conn:
            try:
                cur = conn.execute(
                    """
                    INSERT INTO cameras (name, ip_address, stream_url, location, manufacturer, model_name, status, tags, is_active, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (name, ip_address, stream_url, location, manufacturer, model_name, status.value, ",".join(tags), int(is_active), now, now),
                )
            except sqlite3.IntegrityError as exc:
                raise CameraConflictError("camera name already exists") from exc
            row = conn.execute("SELECT * FROM cameras WHERE id = ?", (cur.lastrowid,)).fetchone()
            return self._camera_from_row(row)

    def get_camera(self, camera_id: int) -> Camera:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM cameras WHERE id = ?", (camera_id,)).fetchone()
        if not row:
            raise CameraNotFoundError(f"camera {camera_id} not found")
        return self._camera_from_row(row)

    def list_cameras(
        self,
        *,
        query: str | None = None,
        location: str | None = None,
        tags: list[str] | None = None,
        status: str | CameraStatus | None = None,
        active: bool | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[Camera], int]:
        if page < 1 or page_size < 1:
            raise ValidationError("page and page_size must be positive")

        where, params = [], []
        if query:
            q = f"%{query.strip().lower()}%"
            where.append("(lower(name) LIKE ? OR lower(location) LIKE ? OR lower(manufacturer) LIKE ? OR lower(model_name) LIKE ?)")
            params.extend([q, q, q, q])
        if location:
            where.append("lower(location) = ?")
            params.append(location.strip().lower())
        if status:
            where.append("status = ?")
            params.append(self._validate_status(status).value)
        if active is not None:
            where.append("is_active = ?")
            params.append(int(active))
        for tag in self._normalize_tags(tags):
            where.append("lower(tags) LIKE ?")
            params.append(f"%{tag}%")

        where_sql = f"WHERE {' AND '.join(where)}" if where else ""
        offset = (page - 1) * page_size
        with self._conn() as conn:
            total = conn.execute(f"SELECT COUNT(*) FROM cameras {where_sql}", params).fetchone()[0]
            rows = conn.execute(
                f"SELECT * FROM cameras {where_sql} ORDER BY created_at DESC LIMIT ? OFFSET ?",
                [*params, page_size, offset],
            ).fetchall()
        return [self._camera_from_row(r) for r in rows], total

    def update_camera(self, camera_id: int, **changes) -> Camera:
        current = self.get_camera(camera_id)
        allowed = {"name", "ip_address", "stream_url", "location", "manufacturer", "model_name", "status", "tags", "is_active"}
        unexpected = set(changes) - allowed
        if unexpected:
            raise ValidationError(f"unsupported fields: {', '.join(sorted(unexpected))}")

        payload = {
            "name": current.name,
            "ip_address": current.ip_address,
            "stream_url": current.stream_url,
            "location": current.location,
            "manufacturer": current.manufacturer,
            "model_name": current.model_name,
            "status": current.status,
            "tags": list(current.tags),
            "is_active": current.is_active,
        }
        payload.update(changes)

        payload["name"] = self._validate_string("name", payload["name"], min_len=3, max_len=80)
        payload["ip_address"] = self._validate_ip(payload["ip_address"])
        payload["stream_url"] = self._validate_string("stream_url", payload["stream_url"], min_len=8, max_len=250)
        payload["location"] = self._validate_string("location", payload["location"])
        payload["manufacturer"] = self._validate_string("manufacturer", payload["manufacturer"])
        payload["model_name"] = self._validate_string("model_name", payload["model_name"])
        payload["status"] = self._validate_status(payload["status"]).value
        payload["tags"] = ",".join(self._normalize_tags(payload["tags"]))

        with self._conn() as conn:
            try:
                conn.execute(
                    """
                    UPDATE cameras
                    SET name = ?, ip_address = ?, stream_url = ?, location = ?, manufacturer = ?, model_name = ?,
                        status = ?, tags = ?, is_active = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        payload["name"], payload["ip_address"], payload["stream_url"], payload["location"],
                        payload["manufacturer"], payload["model_name"], payload["status"], payload["tags"],
                        int(payload["is_active"]), self._now().isoformat(), camera_id,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise CameraConflictError("camera name already exists") from exc
        return self.get_camera(camera_id)

    def delete_camera(self, camera_id: int) -> None:
        self.get_camera(camera_id)
        with self._conn() as conn:
            conn.execute("DELETE FROM cameras WHERE id = ?", (camera_id,))

    def check_camera_health(self, camera_id: int, *, timeout_s: float = 1.5) -> Camera:
        camera = self.get_camera(camera_id)
        parsed = urlparse(camera.stream_url)
        host = parsed.hostname or camera.ip_address
        port = parsed.port or (554 if parsed.scheme == "rtsp" else 80)

        ok = False
        message = "offline"
        try:
            with socket.create_connection((host, port), timeout=timeout_s):
                ok = True
                message = f"reachable on {host}:{port}"
        except OSError as exc:
            message = str(exc)

        new_status = CameraStatus.ONLINE.value if ok else CameraStatus.OFFLINE.value
        now = self._now().isoformat()
        with self._conn() as conn:
            conn.execute(
                "UPDATE cameras SET status = ?, health_message = ?, last_health_check_at = ?, updated_at = ? WHERE id = ?",
                (new_status, message[:240], now, now, camera_id),
            )
        return self.get_camera(camera_id)

    def check_all_cameras_health(self) -> list[Camera]:
        cameras, _ = self.list_cameras(page_size=10_000)
        return [self.check_camera_health(camera.id) for camera in cameras if camera.is_active]

    def summary(self) -> FleetSummary:
        with self._conn() as conn:
            total = conn.execute("SELECT COUNT(*) FROM cameras").fetchone()[0]
            online = conn.execute("SELECT COUNT(*) FROM cameras WHERE status = ?", (CameraStatus.ONLINE.value,)).fetchone()[0]
            offline = conn.execute("SELECT COUNT(*) FROM cameras WHERE status = ?", (CameraStatus.OFFLINE.value,)).fetchone()[0]
            maintenance = conn.execute("SELECT COUNT(*) FROM cameras WHERE status = ?", (CameraStatus.MAINTENANCE.value,)).fetchone()[0]
            active = conn.execute("SELECT COUNT(*) FROM cameras WHERE is_active = 1").fetchone()[0]
            unique_locations = conn.execute("SELECT COUNT(DISTINCT location) FROM cameras").fetchone()[0]
            unique_manufacturers = conn.execute("SELECT COUNT(DISTINCT manufacturer) FROM cameras").fetchone()[0]
        return FleetSummary(total, online, offline, maintenance, active, unique_locations, unique_manufacturers)

    def save_layout(self, *, name: str, grid: str, camera_ids: list[int], created_by: int) -> CameraLayout:
        name = self._validate_string("name", name, min_len=2, max_len=80)
        grid = self._validate_string("grid", grid, min_len=3, max_len=10)
        for cid in camera_ids:
            self.get_camera(cid)
        self.get_user(created_by)

        now = self._now().isoformat()
        with self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO layouts (name, grid, camera_ids, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                (name, grid, json.dumps(camera_ids), created_by, now, now),
            )
            row = conn.execute("SELECT * FROM layouts WHERE id = ?", (cur.lastrowid,)).fetchone()
            return self._layout_from_row(row)

    def list_layouts(self) -> list[CameraLayout]:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM layouts ORDER BY updated_at DESC").fetchall()
        return [self._layout_from_row(r) for r in rows]

    def export_json(self, path: str | Path) -> Path:
        cameras, _ = self.list_cameras(page_size=10_000)
        users = self.list_users()
        layouts = self.list_layouts()
        payload = {
            "cameras": [asdict(camera) for camera in cameras],
            "users": [asdict(user) for user in users],
            "layouts": [asdict(layout) for layout in layouts],
            "summary": asdict(self.summary()),
        }
        output = Path(path)
        output.write_text(json.dumps(payload, default=str, indent=2))
        return output
