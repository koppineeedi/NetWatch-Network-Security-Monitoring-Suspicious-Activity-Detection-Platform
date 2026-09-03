# NETWATCH — Real Telemetry Pipeline & Normalization Specification

## Telemetry Principles
1. **Real Data First**: NetWatch never invents security events or evidence.
2. **Explicit Attribution**: Every event carries a mandatory `source` tag.
3. **Controlled Ingestion**: Telemetry collectors default to `STOPPED` state until explicitly started by an authorized analyst via `POST /api/collector/start`.

## Normalized Event Schema
| Field | Type | Description |
|---|---|---|
| `id` | Integer | Primary Key |
| `timestamp` | DateTime | Ingestion / event timestamp (UTC) |
| `source` | String | Data origin tag (`LOCAL_NETWORK`, `LOG_FILE`, etc.) |
| `collector` | String | Collector module name |
| `event_type` | String | Event classification (`NETWORK_CONNECTION`, etc.) |
| `source_ip` | String | Source IP address |
| `source_port` | Integer | Source port |
| `dest_ip` | String | Destination IP address |
| `dest_port` | Integer | Destination port |
| `protocol` | String | Protocol name (TCP, UDP, HTTPS, DNS, ICMP) |
| `connection_state` | String | TCP connection state (ESTABLISHED, LISTEN, TIME_WAIT) |
| `status` | String | Anomaly status (`NORMAL`, `SUSPICIOUS`, `FLAGGED`) |
| `risk_score` | Float | Calculated risk rating (0.0 to 100.0) |
| `process_name` | String | Associated local OS process name (when available) |
| `username` | String | OS user identity |
| `bytes_sent` | Integer | Outbound bytes transferred |
| `bytes_received` | Integer | Inbound bytes received |
