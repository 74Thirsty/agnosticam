from pathlib import Path

import pytest

from app.manager import AuthError, CameraConflictError, CameraNotFoundError, FleetManager, ValidationError
from app.models import CameraStatus, UserRole
from typing import Any, cast


@pytest.fixture()
def manager(tmp_path: Path) -> FleetManager:
    return FleetManager(tmp_path / "test.db")


def test_seed_admin_can_login(manager: FleetManager) -> None:
    admin = manager.authenticate_user(email="admin@agnosticam.local", password="admin123")
    assert admin.role == UserRole.ADMIN


def test_user_creation_and_login(manager: FleetManager) -> None:
    user = manager.create_user(email="viewer@example.com", password="password123", role="viewer")
    assert user.email == "viewer@example.com"

    logged = manager.authenticate_user(email="viewer@example.com", password="password123")
    assert logged.role == UserRole.VIEWER


def test_camera_crud_and_filters(manager: FleetManager) -> None:
    camera = manager.add_camera(
        name="Front Gate",
        ip_address="192.168.1.10",
        stream_url="rtsp://192.168.1.10:554/stream1",
        location="HQ",
        manufacturer="Axis",
        model_name="P3265",
        status="offline",
        tags=["security", "outdoor"],
    )
    assert camera.status == CameraStatus.OFFLINE

    fetched = manager.get_camera(camera.id)
    assert fetched.name == "Front Gate"

    updated = manager.update_camera(camera.id, status="maintenance", is_active=False)
    assert updated.status == CameraStatus.MAINTENANCE
    assert updated.is_active is False

    items, total = manager.list_cameras(location="HQ", tags=["security"])
    assert total == 1
    assert items[0].id == camera.id

    manager.delete_camera(camera.id)
    with pytest.raises(CameraNotFoundError):
        manager.get_camera(camera.id)


def test_duplicate_name_validation(manager: FleetManager) -> None:
    manager.add_camera(
        name="Lobby",
        ip_address="10.0.0.1",
        stream_url="rtsp://10.0.0.1/live",
        location="HQ",
        manufacturer="Hanwha",
        model_name="A1",
    )
    with pytest.raises(CameraConflictError):
        manager.add_camera(
            name="Lobby",
            ip_address="10.0.0.2",
            stream_url="rtsp://10.0.0.2/live",
            location="HQ",
            manufacturer="Hanwha",
            model_name="A2",
        )


def test_layout_summary_and_export(manager: FleetManager, tmp_path: Path) -> None:
    user = manager.create_user(email="ops@example.com", password="password123", role="admin")
    c1 = manager.add_camera(
        name="Cam1",
        ip_address="172.16.1.10",
        stream_url="rtsp://172.16.1.10/live",
        location="Warehouse",
        manufacturer="Axis",
        model_name="M1",
        status="online",
    )
    c2 = manager.add_camera(
        name="Cam2",
        ip_address="172.16.1.11",
        stream_url="rtsp://172.16.1.11/live",
        location="Warehouse",
        manufacturer="Axis",
        model_name="M2",
        status="offline",
    )

    layout = manager.save_layout(name="Warehouse", grid="2x2", camera_ids=[c1.id, c2.id], created_by=user.id)
    assert layout.camera_ids == (c1.id, c2.id)

    summary = manager.summary()
    assert summary.total_cameras == 2
    assert summary.active == 2
    assert summary.online == 1

    export = manager.export_json(tmp_path / "fleet.json")
    assert export.exists()
    text = export.read_text()
    assert "Warehouse" in text and "Cam1" in text


def test_validation_and_auth_errors(manager: FleetManager) -> None:

    with pytest.raises(ValidationError):
        manager.add_camera(
            name="x",
            ip_address="bad",
            stream_url="rtsp://stream",
            location="HQ",
            manufacturer="Axis",
            model_name="A1",
        )

    with pytest.raises(AuthError):
        manager.authenticate_user(email="admin@agnosticam.local", password="wrongpass")


def test_allows_public_and_non_rtsp_stream_urls(manager: FleetManager) -> None:
    camera = manager.add_camera(
        name="RemoteCam",
        ip_address="8.8.8.8",
        stream_url="ftp://8.8.8.8/feed",
        location="Internet",
        manufacturer="Axis",
        model_name="R1",
    )

    assert camera.ip_address == "8.8.8.8"
    assert camera.stream_url == "ftp://8.8.8.8/feed"


def test_shodan_search_and_import(manager: FleetManager, monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeResponse:
        def __init__(self, payload: str) -> None:
            self.payload = payload.encode("utf-8")

        def read(self) -> bytes:
            return self.payload

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:
            return None

    payload: dict[str, Any] = {
        "total": 1,
        "matches": [
            {
                "ip_str": "8.8.8.8",
                "port": 554,
                "transport": "rtsp",
                "org": "Google",
                "product": "CamX",
                "location": {"city": "Mountain View", "country_name": "United States"},
            }
        ],
    }

    def fake_urlopen(_url: str, timeout: int = 10):
        return FakeResponse(__import__("json").dumps(payload))

    monkeypatch.setenv("AGNOSTICAM_SHODAN_API_KEY", "test-key")
    monkeypatch.setattr("app.manager.urllib_request.urlopen", fake_urlopen)

    result = manager.shodan_search(query="product:webcam")
    assert result.total == 1
    assert result.hosts[0].ip_address == "8.8.8.8"

    created = manager.import_shodan_hosts([payload["matches"][0]])  # type: ignore[index]
    assert len(created) == 1
    assert created[0].ip_address == "8.8.8.8"

    scans = manager.list_shodan_scans(limit=5)
    assert scans
    assert scans[0].query == "product:webcam"
