# NETWATCH — Local Network Telemetry Documentation

## Overview
Phase 2 implements passive local network telemetry collection directly on the host machine running NetWatch.

## Data Source
- **Library**: Python `psutil.net_connections(kind='all')`
- **Method**: Passive observation of existing local socket connections (IPv4/IPv6, TCP/UDP).
- **Security Guarantee**: Zero network probes, zero packet injection, zero scanning, zero remote traffic generation.

## Telemetry Flow
```
LOCAL MACHINE (psutil.net_connections)
        ↓
LocalNetworkCollector (backend/app/collectors/local_network.py)
        ↓
Deduplication Window (60-second stable fingerprint check)
        ↓
SQLAlchemy ORM -> SQLite Database (network_events)
        ↓
FastAPI Endpoints (GET /api/events, GET /api/statistics)
        ↓
React Dashboard UI (apiService.ts)
```

## Deduplication Strategy
To prevent excessive database growth from high-frequency identical socket observations, the collector generates a 6-element tuple fingerprint:
`(source_ip, source_port, dest_ip, dest_port, protocol, connection_state)`

If an identical fingerprint exists in the database within a rolling 60-second window, duplicate insertion is bypassed while count metrics remain tracked.

## Environment Configuration
| Variable Name | Default | Description |
|---|---|---|
| `NETWATCH_COLLECTION_INTERVAL` | `10` | Collection loop interval in seconds (Min: 5s). |
| `DATABASE_URL` | `sqlite:///./netwatch.db` | Connection string for SQLite database. |

## Privacy & Safety
- **Local Persistence Only**: Telemetry records are stored in the local SQLite database (`netwatch.db`) and never transmitted externally.
- **Process Inspection Safety**: Process names are resolved safely using non-blocking exception handling (`psutil.NoSuchProcess`, `psutil.AccessDenied`, `psutil.ZombieProcess`).
