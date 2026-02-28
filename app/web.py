from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from dataclasses import asdict
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from app.manager import AuthError, CameraConflictError, CameraNotFoundError, FleetManager, ValidationError
from app.models import UserRole


class APIServer(BaseHTTPRequestHandler):
    manager = FleetManager(os.getenv("AGNOSTICAM_DB", "agnosticam.db"))
    secret = os.getenv("AGNOSTICAM_SECRET", "agnosticam-dev-secret").encode("utf-8")

    def _json(self, status: int, payload: dict) -> None:
        blob = json.dumps(payload, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(blob)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(blob)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        data = self.rfile.read(length) if length else b"{}"
        return json.loads(data.decode("utf-8"))

    @classmethod
    def _create_token(cls, *, user_id: int, role: str, ttl_s: int = 8 * 3600) -> str:
        exp = int(time.time()) + ttl_s
        body = f"{user_id}:{role}:{exp}".encode("utf-8")
        sig = hmac.new(cls.secret, body, hashlib.sha256).digest()
        return base64.urlsafe_b64encode(body + b"." + sig).decode("utf-8")

    @classmethod
    def _parse_token(cls, token: str) -> tuple[int, str]:
        raw = base64.urlsafe_b64decode(token.encode("utf-8"))
        body, sig = raw.rsplit(b".", 1)
        expected = hmac.new(cls.secret, body, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, expected):
            raise AuthError("invalid token")
        user_id_raw, role, exp_raw = body.decode("utf-8").split(":", 2)
        if int(exp_raw) < int(time.time()):
            raise AuthError("token expired")
        return int(user_id_raw), role

    def _auth_user(self, *, require_admin: bool = False) -> tuple[int, str]:
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            raise AuthError("missing bearer token")
        user_id, role = self._parse_token(auth.removeprefix("Bearer ").strip())
        if require_admin and role != UserRole.ADMIN.value:
            raise AuthError("admin access required")
        return user_id, role

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/" or parsed.path == "/dashboard":
            return self._serve_file("index.html", content_type="text/html")
        if parsed.path.startswith("/static/"):
            rel = parsed.path.removeprefix("/static/")
            content_type = "text/plain"
            if rel.endswith(".js"):
                content_type = "application/javascript"
            elif rel.endswith(".css"):
                content_type = "text/css"
            return self._serve_file(rel, content_type=content_type)

        try:
            if parsed.path == "/api/health":
                return self._json(200, {"status": "ok"})
            if parsed.path == "/api/cameras":
                self._auth_user()
                qs = parse_qs(parsed.query)
                items, total = self.manager.list_cameras(
                    query=qs.get("query", [None])[0],
                    location=qs.get("location", [None])[0],
                    status=qs.get("status", [None])[0],
                    tags=qs.get("tags", []),
                    active=None if "active" not in qs else qs.get("active", ["true"])[0].lower() == "true",
                )
                return self._json(200, {"items": [asdict(i) for i in items], "total": total})
            if parsed.path.startswith("/api/cameras/"):
                self._auth_user()
                camera_id = int(parsed.path.split("/")[-1])
                return self._json(200, asdict(self.manager.get_camera(camera_id)))
            if parsed.path == "/api/users":
                self._auth_user(require_admin=True)
                return self._json(200, {"items": [asdict(u) for u in self.manager.list_users()]})
            if parsed.path == "/api/layouts":
                self._auth_user()
                return self._json(200, {"items": [asdict(l) for l in self.manager.list_layouts()]})
            if parsed.path == "/api/summary":
                self._auth_user()
                return self._json(200, asdict(self.manager.summary()))
            if parsed.path == "/api/shodan/scans":
                self._auth_user(require_admin=True)
                qs = parse_qs(parsed.query)
                limit = int(qs.get("limit", ["20"])[0])
                scans = self.manager.list_shodan_scans(limit=limit)
                return self._json(200, {"items": [asdict(i) for i in scans]})
        except (AuthError, ValidationError, CameraNotFoundError) as exc:
            return self._json(401 if isinstance(exc, AuthError) else 400, {"error": str(exc)})

        return self._json(404, {"error": "not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        body = self._read_json()
        try:
            if parsed.path == "/api/auth/login":
                user = self.manager.authenticate_user(email=body.get("email", ""), password=body.get("password", ""))
                token = self._create_token(user_id=user.id, role=user.role.value)
                return self._json(200, {"token": token, "user": asdict(user)})
            if parsed.path == "/api/users":
                self._auth_user(require_admin=True)
                user = self.manager.create_user(email=body["email"], password=body["password"], role=body.get("role", "viewer"))
                return self._json(201, asdict(user))
            if parsed.path == "/api/cameras":
                self._auth_user(require_admin=True)
                camera = self.manager.add_camera(
                    name=body["name"],
                    ip_address=body["ip_address"],
                    stream_url=body["stream_url"],
                    location=body["location"],
                    manufacturer=body["manufacturer"],
                    model_name=body["model_name"],
                    tags=body.get("tags", []),
                    status=body.get("status", "offline"),
                    is_active=body.get("is_active", True),
                )
                return self._json(201, asdict(camera))
            if parsed.path.endswith("/health-check") and parsed.path.startswith("/api/cameras/"):
                self._auth_user(require_admin=True)
                camera_id = int(parsed.path.split("/")[-2])
                return self._json(200, asdict(self.manager.check_camera_health(camera_id)))
            if parsed.path == "/api/layouts":
                user_id, _ = self._auth_user()
                layout = self.manager.save_layout(
                    name=body["name"],
                    grid=body.get("grid", "2x2"),
                    camera_ids=body.get("camera_ids", []),
                    created_by=user_id,
                )
                return self._json(201, asdict(layout))
            if parsed.path == "/api/shodan/search":
                self._auth_user(require_admin=True)
                result = self.manager.shodan_search(query=body.get("query", ""), page=int(body.get("page", 1)))
                return self._json(200, asdict(result))
            if parsed.path == "/api/shodan/import":
                self._auth_user(require_admin=True)
                created = self.manager.import_shodan_hosts(body.get("hosts", []), default_location=body.get("default_location", "Internet"))
                return self._json(201, {"count": len(created), "items": [asdict(c) for c in created]})
        except AuthError as exc:
            return self._json(401, {"error": str(exc)})
        except (ValidationError, CameraNotFoundError, CameraConflictError, KeyError) as exc:
            return self._json(400, {"error": str(exc)})

        return self._json(404, {"error": "not found"})

    def do_PUT(self):
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/cameras/"):
            try:
                self._auth_user(require_admin=True)
                camera_id = int(parsed.path.split("/")[-1])
                camera = self.manager.update_camera(camera_id, **self._read_json())
                return self._json(200, asdict(camera))
            except AuthError as exc:
                return self._json(401, {"error": str(exc)})
            except (ValidationError, CameraConflictError, CameraNotFoundError) as exc:
                return self._json(400, {"error": str(exc)})
        return self._json(404, {"error": "not found"})

    def do_DELETE(self):
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/cameras/"):
            try:
                self._auth_user(require_admin=True)
                camera_id = int(parsed.path.split("/")[-1])
                self.manager.delete_camera(camera_id)
                return self._json(HTTPStatus.NO_CONTENT, {})
            except AuthError as exc:
                return self._json(401, {"error": str(exc)})
            except CameraNotFoundError as exc:
                return self._json(404, {"error": str(exc)})
        return self._json(404, {"error": "not found"})

    def _serve_file(self, filename: str, *, content_type: str) -> None:
        static_root = Path(__file__).with_name("static")
        target = static_root / filename
        if not target.exists() or not target.is_file():
            return self._json(404, {"error": "asset not found"})
        payload = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def run_server(host: str = "0.0.0.0", port: int = 8000) -> None:
    with ThreadingHTTPServer((host, port), APIServer) as server:
        print(f"AgnostiCam dashboard running on http://{host}:{port}")
        server.serve_forever()


if __name__ == "__main__":
    run_server()
