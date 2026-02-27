# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Full-stack IoT pipeline that collects binary/JSON sensor data from ESP32 devices (G-CU firmware v4.1.1+) via MQTT, parses and stores it as CSV, and serves a real-time web dashboard with 3D visualization.

## Commands

### Local Development (devmin — primary workflow)

```bash
# First-time setup
wsl --update                    # Windows only
pip install paho-mqtt

# Start all containers (broker + sink + web stack)
docker compose -f devmin/docker-compose.yml up -d --build

# Daily: start prebuilt containers first, THEN the collector (order matters)
docker compose -f devmin/docker-compose.yml up -d
python devmin/data_receive_local.py

# Check logs
docker compose -f devmin/docker-compose.yml logs -f sink
```

Access: dashboard at `http://localhost:5000`, config console at `http://localhost:5002`.

### Production Deployment (TLS)

```bash
docker-compose -f docker-compose.secure.yml up -d --build
docker-compose -f docker-compose.secure.yml logs -f
```

Access: `https://localhost` (self-signed cert), config console at `http://localhost:5002`.

> **Important:** Root-level `docker-compose.yml` and `docker-compose.localdev.yml` are for debugging only — do not use for normal dev/production.

### Running Individual Python Services

```bash
python -m venv .venv && source .venv/Scripts/activate   # Windows
pip install -r backend/requirements.txt -r web/requirements.txt

BROKER_HOST=localhost python web/app.py        # Web UI
BROKER_HOST=localhost python server/bridge.py  # MQTT-to-SSE bridge
BROKER_HOST=localhost python backend/sink.py   # Data persistence worker
```

## Architecture

### Data Flow

```
ESP32 (G-CU firmware)
  ↓ MQTT: etx/v1/raw/<DN>
Mosquitto Broker (port 1883 internal / 8883 TLS)
  ↓
backend/sink.py          — Subscribes, parses payloads, writes CSVs, indexes DB
server/bridge.py         — Subscribes to etx/v1/parsed/#, caches, streams via SSE
  ↓
web/app.py (Flask)       — Auth gateway, proxies SSE, serves dashboard & file downloads
web/config_backend.py    — Separate MQTT thread for device discovery/config commands
```

### Key Services & Ports

| Service | File | Port |
|---------|------|------|
| Web UI | `web/app.py` | 443 (prod) / 5000 (dev) |
| Config Console | `web/config_backend.py` | 5002 |
| MQTT Bridge | `server/bridge.py` | 5001 |
| Mosquitto | `broker/config/` | 1883 (internal), 8883 (TLS) |
| PostgreSQL | (external or embedded) | 5432 |

### Data Persistence

- CSVs: `mqtt_store/<DN>/<YYYYMMDD>/<exp_time>.csv` (under `devmin/data/` locally or `backend/mqtt_store/` in production)
- Metadata: PostgreSQL tables — `app_user`, `user_group`, `device_info`, `data_files`
- DB indexed on sink startup + every 24h full-disk scan

### Authentication

- Users: Flask signed cookie session (30-min expiry), validated against PostgreSQL `app_user`
- Device access: filtered by `device_info` MAC → `user_group` mapping; `admin` bypasses all filters
- License: per-device E256-signed keys; `license/priv.pem` must be present (copy from NAS)

## Coding Conventions

- **Language:** Python 3.11 (PEP 8), JavaScript/Three.js frontend
- **Comments/output:** Primarily Chinese (Simplified) or English — do not convert existing Chinese text to English
- **Encoding:** UTF-8 throughout
- **Async pattern:** Gevent-based (not asyncio) — `web/app.py` and `server/bridge.py` use `gevent.monkey.patch_all()`

## Configuration

- `config.ini` / `config.secure.ini` — base MQTT, queue, parser, GCU settings
- Environment variables override config at runtime (see `docker-compose.secure.yml` for full list)
- Key env vars: `BROKER_HOST`, `DB_HOST/PORT/NAME/USER/PASS`, `FLASK_SECRET_KEY`, `BRIDGE_API_BASE_URL`

## Common Pitfalls

- **Windows shell scripts:** `devmin/scripts/*.sh` must use **LF** line endings, not CRLF — containers silently fail to start otherwise
- **Startup order:** Always start Docker containers before `data_receive_local.py`; reverse order fails because MQTT isn't ready
- **Device registration:** JSCMS device form is broken — use `force_register_devices.py` to register devices directly to DB
- **503 on config console:** `config_service` failed to connect to broker — check `BROKER_HOST` env var
- **Certificate errors:** Verify `certs/` contains `ca.crt`, `server.crt`, `server.key`
