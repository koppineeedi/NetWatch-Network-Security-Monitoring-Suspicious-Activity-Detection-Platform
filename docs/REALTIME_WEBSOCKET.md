# NetWatch — Phase 7: Real-Time SOC Monitoring & WebSocket Event Streaming

## 1. Overview
Phase 7 implements an authenticated, real-time WebSocket event streaming pipeline connecting NetWatch's real telemetry collectors (`LocalNetworkCollector`), log file parser, and backend detection engine directly to the React frontend SOC dashboard.

---

## 2. Architecture & Data Flow

```
REAL LOCAL NETWORK TELEMETRY
        ↓
LocalNetworkCollector (psutil)
        ↓
Normalized NetworkEvent
        ↓
Database Persistence (SQLite)
        ↓
Detection Engine Evaluation
        ↓
Detection / Alert Creation
        ↓
Real-Time Event Publisher (publisher.py)
        ↓
Authenticated WebSocket Connection Manager (ws_manager)
        ↓
React SOC Dashboard / Events / Alerts (websocketService.ts)
```

### Log Ingestion Real-Time Stream
```
LOG FILE UPLOAD (.log, .txt, .json, .csv)
        ↓
Log Parser
        ↓
Normalized NetworkEvent
        ↓
Database Persistence (SQLite)
        ↓
Detection Engine Evaluation
        ↓
WebSocket Event Publisher
        ↓
React SOC Dashboard Live Updates
```

---

## 3. WebSocket Endpoint Specification

* **Endpoint**: `GET /ws/events` (or `/api/ws/events`)
* **Protocol**: `ws://` / `wss://`
* **Authentication**: JWT token passed in query parameter `?token=<jwt_token>` or `Authorization: Bearer <token>` header.

### Security Rejections
1. **Missing Token**: Immediately rejected with `WS 1008 Policy Violation` ("Authentication token required").
2. **Invalid Token**: Immediately rejected with `WS 1008 Policy Violation` ("Invalid or expired token").
3. **Disabled / Inactive User**: Connection closed immediately.

---

## 4. Standardized JSON Message Schemas

### 1. Connected Acknowledgement
```json
{
  "type": "connected",
  "message": "Connected to NetWatch Real-Time SOC Stream",
  "user": "admin",
  "role": "ADMIN"
}
```

### 2. Network Event Stream (`network_event`)
```json
{
  "type": "network_event",
  "timestamp": "2026-09-03T18:00:00Z",
  "data": {
    "id": 123,
    "timestamp": "2026-09-03T18:00:00Z",
    "source": "LOCAL_NETWORK",
    "collector": "LOCAL_NETWORK",
    "source_ip": "127.0.0.1",
    "source_port": 54321,
    "dest_ip": "10.0.0.1",
    "dest_port": 443,
    "protocol": "TCP",
    "connection_state": "ESTABLISHED",
    "status": "NORMAL",
    "risk_score": 0.0,
    "process_name": "chrome.exe",
    "hostname": "SOC-WORKSTATION"
  }
}
```

### 3. Detection Stream (`detection`)
```json
{
  "type": "detection",
  "timestamp": "2026-09-03T18:00:05Z",
  "data": {
    "id": 45,
    "timestamp": "2026-09-03T18:00:05Z",
    "rule_code": "R-001",
    "rule_name": "Port Scan Activity",
    "source_ip": "192.168.1.100",
    "target_ip": "10.0.0.1",
    "mitre_tactic": "RECONNAISSANCE",
    "mitre_technique": "T1046",
    "action_taken": "ALERTED",
    "details": "Observed 8+ unique ports accessed from single IP within window",
    "risk_score": 75.0
  }
}
```

### 4. Alert Stream (`alert`)
```json
{
  "type": "alert",
  "timestamp": "2026-09-03T18:00:05Z",
  "data": {
    "id": 12,
    "timestamp": "2026-09-03T18:00:05Z",
    "detection_id": 45,
    "detection_type": "Port Scan Activity",
    "severity": "HIGH",
    "confidence": 0.9,
    "risk_score": 75.0,
    "source_ip": "192.168.1.100",
    "dest_ip": "10.0.0.1",
    "dest_port": 443,
    "protocol": "TCP",
    "description": "Port Scan Activity triggered for 192.168.1.100",
    "explanation": "Multiple sequential port connection attempts detected",
    "status": "NEW",
    "assigned_analyst": "Unassigned",
    "rule_id": "R-001"
  }
}
```

### 5. Telemetry Status Stream (`telemetry_status`)
```json
{
  "type": "telemetry_status",
  "timestamp": "2026-09-03T18:00:10Z",
  "data": {
    "running": true,
    "collector": "LOCAL_NETWORK",
    "interval": 10,
    "last_collection_time": "2026-09-03T18:00:10Z",
    "events_collected": 150,
    "events_stored": 120,
    "errors": 0
  }
}
```

### 6. Protocol Heartbeat (Ping / Pong)
* Client sends: `{"type": "ping"}`
* Server responds: `{"type": "pong"}`

---

## 5. Frontend Client Lifecycle & Integration
* `frontend/src/services/websocketService.ts` implements automatic exponential backoff reconnection (2s, 4s, 8s up to 30s max).
* Disconnects and stops reconnect loops when user logs out.
* Status badge (`● LIVE STREAM`, `● RECONNECTING`, `● STREAM OFFLINE`) rendered in top `Navbar.tsx`.
* Bounded client-side buffers (latest 50-200 events) prevent browser memory leaks while keeping database REST APIs authoritative.

---

## 6. Automated Testing Verification
Run `python tests/test_websocket.py` to verify:
- Authentication & rejection of missing/invalid tokens.
- Heartbeat ping/pong.
- Real-time event, detection, alert, and status broadcasting.
- Isolation across multiple connected clients.
- Telemetry collector independence from client availability.
