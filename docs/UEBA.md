# NetWatch User and Entity Behavior Analytics (UEBA)

## Overview

NetWatch UEBA extends traditional rule-based detection with statistical behavioral baselines, explainable anomaly scoring, entity risk aggregation, and campaign clustering.

All analytics operate strictly on actual telemetry observed by NetWatch (psutil local network, remote UDP Syslog, and cloud connectors). NetWatch never generates fake production telemetry or synthetic anomalies.

## Key Principles

- **Real Data Only**: If an entity has fewer than `NETWATCH_UEBA_MIN_EVENTS` (default: 20), UEBA reports `INSUFFICIENT_DATA` rather than inventing a baseline.
- **Explainable Analytics**: Every detected anomaly provides explicit mathematical evidence (mean, median, 95th percentile, z-score, deviation percentage).
- **Non-blocking Operations**: Analytics processing runs in background threads and non-blocking jobs without hindering real-time telemetry collection.
- **Role-Based Access Control**: VIEWER roles have read-only visibility, ANALYST roles can trigger on-demand analytics recalculation, and ADMIN roles can modify thresholds and settings.

## Entity Abstraction

NetWatch supports five primary entity types:
- `IP`: Source and destination IP addresses.
- `HOST`: Hostnames observed in network logs and telemetry.
- `USER`: Authenticated user identities (created only when explicit log evidence exists).
- `PROCESS`: Operating system processes initiating network connections.
- `DOMAIN`: Fully qualified domain names resolved via DNS.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `NETWATCH_UEBA_ENABLED` | `true` | Enables/disables UEBA analytics subsystem |
| `NETWATCH_UEBA_BASELINE_HOURS` | `168` | Baseline observation window (7 days) |
| `NETWATCH_UEBA_MIN_EVENTS` | `20` | Minimum events required before computing baseline |
| `NETWATCH_UEBA_REFRESH_MINUTES` | `60` | Periodic baseline update interval |
| `NETWATCH_RISK_DECAY_HOURS` | `24` | Half-life window for entity risk score decay |
| `NETWATCH_ANOMALY_LOW` | `30` | Threshold for LOW severity anomalies |
| `NETWATCH_ANOMALY_MEDIUM` | `60` | Threshold for MEDIUM severity anomalies |
| `NETWATCH_ANOMALY_HIGH` | `80` | Threshold for HIGH severity anomalies |
| `NETWATCH_ANOMALY_CRITICAL` | `90` | Threshold for CRITICAL severity anomalies |
| `NETWATCH_ANALYTICS_RETENTION_DAYS` | `90` | Retention period for historical analytics records |
