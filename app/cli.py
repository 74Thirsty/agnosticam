from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from app.manager import AuthError, CameraConflictError, CameraNotFoundError, FleetManager, ValidationError


def main() -> int:
    parser = argparse.ArgumentParser(description="AgnostiCam CLI")
    parser.add_argument("--db", default="agnosticam.db")
    sub = parser.add_subparsers(dest="command", required=True)

    add_user = sub.add_parser("add-user", help="Create a user")
    add_user.add_argument("email")
    add_user.add_argument("password")
    add_user.add_argument("--role", default="viewer", choices=["admin", "viewer"])

    login = sub.add_parser("login", help="Validate credentials")
    login.add_argument("email")
    login.add_argument("password")

    add = sub.add_parser("add-camera", help="Register camera")
    add.add_argument("name")
    add.add_argument("ip_address")
    add.add_argument("stream_url")
    add.add_argument("location")
    add.add_argument("manufacturer")
    add.add_argument("model_name")
    add.add_argument("--status", default="offline")
    add.add_argument("--tags", nargs="*", default=[])

    ls = sub.add_parser("list-cameras", help="List cameras")
    ls.add_argument("--query")
    ls.add_argument("--location")
    ls.add_argument("--status")
    ls.add_argument("--tags", nargs="*")
    ls.add_argument("--active", choices=["true", "false"])

    health = sub.add_parser("check-health", help="Run camera health check")
    health.add_argument("camera_id", type=int)

    sub.add_parser("summary", help="Fleet summary")

    layout = sub.add_parser("save-layout", help="Save camera layout")
    layout.add_argument("name")
    layout.add_argument("grid")
    layout.add_argument("created_by", type=int)
    layout.add_argument("camera_ids", nargs="+", type=int)

    export = sub.add_parser("export", help="Export all data")
    export.add_argument("output")

    shodan_search = sub.add_parser("shodan-search", help="Search Shodan hosts")
    shodan_search.add_argument("query")
    shodan_search.add_argument("--page", type=int, default=1)

    shodan_import = sub.add_parser("shodan-import", help="Import last Shodan scan into cameras")
    shodan_import.add_argument("--limit", type=int, default=1)
    shodan_import.add_argument("--default-location", default="Internet")

    args = parser.parse_args()
    shodan_key = getattr(args, "api_key", None) or __import__("os").getenv("AGNOSTICAM_SHODAN_API_KEY", "")
    shodan_client = ShodanClient(shodan_key) if shodan_key else None
    mgr = FleetManager(args.db, shodan_client=shodan_client)

    try:
        if args.command == "add-user":
            print(json.dumps(asdict(mgr.create_user(email=args.email, password=args.password, role=args.role)), default=str, indent=2))
        elif args.command == "login":
            print(json.dumps(asdict(mgr.authenticate_user(email=args.email, password=args.password)), default=str, indent=2))
        elif args.command == "add-camera":
            print(
                json.dumps(
                    asdict(
                        mgr.add_camera(
                            name=args.name,
                            ip_address=args.ip_address,
                            stream_url=args.stream_url,
                            location=args.location,
                            manufacturer=args.manufacturer,
                            model_name=args.model_name,
                            status=args.status,
                            tags=args.tags,
                        )
                    ),
                    default=str,
                    indent=2,
                )
            )
        elif args.command == "list-cameras":
            active = None if args.active is None else args.active == "true"
            items, total = mgr.list_cameras(
                query=args.query,
                location=args.location,
                status=args.status,
                tags=args.tags,
                active=active,
            )
            print(json.dumps({"total": total, "items": [asdict(i) for i in items]}, default=str, indent=2))
        elif args.command == "check-health":
            print(json.dumps(asdict(mgr.check_camera_health(args.camera_id)), default=str, indent=2))
        elif args.command == "summary":
            print(json.dumps(asdict(mgr.summary()), default=str, indent=2))
        elif args.command == "save-layout":
            print(
                json.dumps(
                    asdict(
                        mgr.save_layout(name=args.name, grid=args.grid, camera_ids=args.camera_ids, created_by=args.created_by)
                    ),
                    default=str,
                    indent=2,
                )
            )
        elif args.command == "export":
            print(f"Exported to {mgr.export_json(Path(args.output))}")
        elif args.command == "shodan-search":
            print(json.dumps(asdict(mgr.shodan_search(query=args.query, page=args.page)), default=str, indent=2))
        elif args.command == "shodan-import":
            scans = mgr.list_shodan_scans(limit=args.limit)
            hosts = []
            for scan in scans:
                hosts.extend([asdict(host) for host in scan.hosts])
            created = mgr.import_shodan_hosts(hosts, default_location=args.default_location)
            print(json.dumps({"count": len(created), "items": [asdict(c) for c in created]}, default=str, indent=2))

    except (ValidationError, CameraConflictError, CameraNotFoundError, AuthError) as exc:
        print(f"Error: {exc}")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
