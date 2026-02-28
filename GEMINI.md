# AgnostiCam - Project Context

Agnosticam is a self-hosted camera operations dashboard designed for manually managed camera fleets. It provides a web dashboard and a CLI for managing IP cameras, users, and layouts.

## Project Overview

- **Purpose:** Secure, manually managed camera fleet management.
- **Main Technologies:**
    - **Language:** Python 3.10+
    - **Database:** SQLite
    - **Web Server:** Standard library `http.server.ThreadingHTTPServer` (no external web framework like Flask or FastAPI used).
    - **Authentication:** Custom HMAC-based token system and PBKDF2 password hashing.
    - **Testing:** `pytest`
- **Architecture:**
    - `app/manager.py`: Core business logic (`FleetManager`) handling database operations, authentication, and health checks.
    - `app/models.py`: Data structures (dataclasses) and Enums.
    - `app/web.py`: REST API and static file server.
    - `app/cli.py`: Command-line interface.
    - `app/static/`: Frontend assets (HTML/CSS).

## Building and Running

### Development Setup

```bash
# Install dependencies
pip install -e ".[dev]"
```

### Running the Web Dashboard

```bash
python -m app.web
```
The dashboard will be available at `http://127.0.0.1:8000/dashboard`.

### Using the CLI

```bash
python -m app.cli --help
```

### Running Tests

```bash
pytest
```

## Development Conventions

- **Type Hinting:** Extensive use of Python type hints and `from __future__ import annotations`.
- **Code Style:** Clean, modular Python using standard library where possible.
- **Database:** SQLite is used for persistence. The schema is initialized automatically in `FleetManager._initialize_db()`.
- **Environment Variables:**
    - `AGNOSTICAM_DB`: Path to the SQLite database file (default: `agnosticam.db`).
    - `AGNOSTICAM_SECRET`: Secret key for JWT-like token generation (default: `agnosticam-dev-secret`).

## Key Files

- `app/manager.py`: The heart of the application logic.
- `app/models.py`: Domain models and enums.
- `app/web.py`: API endpoints and server logic.
- `app/cli.py`: CLI entry point.
- `tests/test_manager.py`: Comprehensive tests for the `FleetManager`.
