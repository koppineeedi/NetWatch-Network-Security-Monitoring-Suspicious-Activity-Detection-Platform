# NetWatch Remote Syslog Ingestion

## Overview
NetWatch provides a non-blocking background Syslog collector supporting UDP syslog telemetry.

## Configuration
Set environment variables:
```bash
NETWATCH_SYSLOG_ENABLED=true
NETWATCH_SYSLOG_HOST=0.0.0.0
NETWATCH_SYSLOG_UDP_PORT=514
NETWATCH_SYSLOG_TCP_PORT=514
```
Default setting: `NETWATCH_SYSLOG_ENABLED=false`. NetWatch remains fully operational when Syslog ingestion is disabled.

## Parser Architecture
- **RFC Priority Header Parsing**: Extracts Facility (0–23) and Severity (0–7) from Syslog RFC headers (e.g., `<34>`).
- **Structured Extraction**: Extracts RFC timestamps, source IP, hostname, syslog severity, facility, and raw syslog message payload.
- **Bounded Queue**: Bounded packet processing queue (max 10,000 packets) prevents memory starvation under heavy traffic.
- **Non-Blocking Architecture**: Runs as an isolated daemon listener thread, dispatching parsed events into the NetWatch detection engine without blocking main API operations.
- **Fault Tolerance**: Malformed packets are logged silently and discarded without crashing the process loop.
