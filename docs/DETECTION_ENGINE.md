# NETWATCH — Backend Detection Engine Documentation

## Overview
Phase 4 implements the authoritative, evidence-backed backend detection engine for NetWatch. It dynamically evaluates normalized network events (`LOCAL_NETWORK`, `LOG_FILE`, `TEST_LOG`) against configurable behavioral detection rules stored in the database.

## Architecture
```
REAL TELEMETRY
      ↓
NORMALIZED NETWORK EVENT (NetworkEvent model)
      ↓
BACKEND DETECTION ENGINE (backend/app/detection/engine.py)
      ↓
RULE EVALUATION (backend/app/detection/rules.py)
      ↓
DEDUPLICATION (10-minute rolling fingerprint window)
      ↓
DETECTION & ALERT PERSISTENCE (SQLite DB)
      ↓
FASTAPI REST APIs (GET /api/detections, GET /api/rules)
      ↓
REACT SOC DASHBOARD & RULES MANAGEMENT UI
```

## Modular Components
1. **`engine.py`**: Orchestrates event evaluation, batch evaluation, default rule seeding, and deduplication.
2. **`rules.py`**: Defines behavioral rule logic (`R-SCAN-01`, `R-CONN-01`, `R-FAIL-01`, `R-PORT-01`, `R-DNS-01`).
3. **`correlator.py`**: Performs temporal and spatial connection grouping over bounded time windows.
4. **`risk.py`**: Calculates evidence-backed risk scores (0–100) and confidence ratings (0.0–1.0).

## Configured Behavioral Rules
| Rule Code | Rule Name | Severity | Default Threshold | Description |
|---|---|---|---|---|
| `R-SCAN-01` | Possible Port Scan | HIGH | 8 unique ports in 30s | Triggers when source IP contacts >=8 unique destination ports. |
| `R-CONN-01` | Excessive Connection Attempts | MEDIUM | 20 connections in 60s | Triggers when connection volume exceeds threshold. |
| `R-FAIL-01` | Repeated Failed Connections | HIGH | 5 failures in 60s | Evaluates explicit connection failure states (CLOSED, REFUSED, REJECTED). Returns "Insufficient evidence" if state missing. |
| `R-PORT-01` | Unusual Destination Port | MEDIUM | 1 hit in 60s | Detects connections targeting non-standard high ports (e.g. 4444, 6667, 31337). |
| `R-DNS-01` | Unusual DNS Activity | MEDIUM | 15 DNS queries in 60s | Evaluates DNS protocol telemetry. Returns no detection if DNS fields absent. |

## Evidence & Risk Model
- **Confidence Rating**: Represents evidence strength (e.g. 0.85 = high confidence that rule parameters were satisfied).
- **Risk Score**: Deterministic float (0.0 – 100.0) derived from severity base, event frequency, unique port span, and failure indicators.
- **Evidence JSON**: Contains `source_ip`, `unique_destination_ports`, `time_window_seconds`, `event_count`, `source_event_ids`, and structured `risk_factors`.

## Deduplication Strategy
To avoid creating thousands of identical alerts for continuous stream events, the engine checks for existing `Detection` records matching `(rule_code, source_ip)` created within a rolling 10-minute window.
