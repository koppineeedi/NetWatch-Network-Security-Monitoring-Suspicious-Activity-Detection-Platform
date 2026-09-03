# NETWATCH — System Architecture & Component Design

## Overview
NetWatch is a defensive Network Security Monitoring (NSM) and SOC Analyst Platform. It ingests authorized local system network telemetry, normalizes events, applies authoritative detection rules, creates security alerts, and supports incident case management.

## Component Architecture

```
+-------------------------------------------------------------+
|                      React 18 Frontend                      |
| (Vite + TypeScript + Tailwind CSS + Recharts + Lucide Icons)|
+-------------------------------------------------------------+
                              |
                     REST API / WebSockets
                              |
+-------------------------------------------------------------+
|                    FastAPI Python Backend                   |
|  - Collectors (local_network, local_system, file_collector) |
|  - Parsers & Normalizers (syslog, json, csv)               |
|  - Authoritative Detection Engine                           |
|  - Alert & Case Management Services                         |
+-------------------------------------------------------------+
                              |
                       SQLAlchemy ORM
                              |
+-------------------------------------------------------------+
|                 Database (SQLite / PostgreSQL)              |
|  Tables: network_events, alerts, detections,                |
|  investigations, analyst_notes, detection_rules, assets     |
+-------------------------------------------------------------+
```

## Data Lifecycle & Source Attribution
Every security event processed by NetWatch is attributed with a explicit `source` tag:
- `LOCAL_NETWORK`: Direct system socket connection telemetry (`psutil`).
- `LOCAL_SYSTEM`: Local OS system telemetry.
- `WINDOWS_EVENT`: Windows Security Log Events.
- `LOG_FILE`: Uploaded raw log files (.log, .json, .csv).
- `SURICATA`: Suricata EVE JSON telemetry.
- `ZEEK`: Zeek connection log telemetry.
- `TEST`: Clearly labeled synthetic lab test data.

## Defensive Security & Privacy Safeguards
- 100% Defensive: No automated attacks, scanning, or exploits.
- Monitored scope restricted strictly to authorized local machine sockets & explicitly provided log files.
