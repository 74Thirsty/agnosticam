# AgnostiCam

AgnostiCam is a **self-hosted camera operations dashboard** for IP cameras you explicitly configure yourself.

> ✅ Designed for authorized, manually managed camera fleets.
> ⚠️ Optional Shodan integration is available when you set an API key for authorized discovery workflows.

## Features

- Secure login with role-based access (`admin`, `viewer`)
- Camera registry with rich metadata:
  - name, IP address, stream URL, location, manufacturer/model
  - tags and active/inactive state
- Fleet filters and search (query, location, tags, status)
- Camera health checks (socket reachability to stream host/port)
- Multi-view dashboard tiles
- Saved camera layouts (`2x2`, `3x3`)
- Fleet analytics summary
- CLI + JSON export for integrations/backups
- Optional Shodan search + one-click host import into camera registry (GUI + API + CLI)

## Default credentials

On first startup, AgnostiCam creates:

- **Email:** `admin@agnosticam.local`
- **Password:** `admin123`

Change/add users immediately in real deployments.

## Run web dashboard

```bash
python -m app.web
```

Open `http://127.0.0.1:8000/dashboard`.

## CLI examples

```bash
python -m app.cli add-user ops@example.com password123 --role admin
python -m app.cli add-camera "Front Gate" 192.168.1.10 rtsp://192.168.1.10:554/stream1 HQ Axis P3265 --tags security outdoor
python -m app.cli list-cameras --location HQ --tags security
python -m app.cli check-health 1
python -m app.cli save-layout "HQ Overview" 2x2 1 1
python -m app.cli export fleet-export.json
```

## Testing

```bash
pytest
```


## Shodan integration

Set `AGNOSTICAM_SHODAN_API_KEY` before running the web app or CLI to enable Shodan search/import.

```bash
export AGNOSTICAM_SHODAN_API_KEY=your_key
python -m app.cli shodan-search "product:webcam"
```
