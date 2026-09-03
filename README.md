# NetWatch — Defensive Network Security Monitoring & SOC Platform

NetWatch is an authoritative, evidence-backed Network Security Monitoring (NSM) and SOC Analyst Platform built with **FastAPI (Python)**, **SQLAlchemy**, **React (TypeScript)**, **Vite**, and **Tailwind CSS**.

---

## Key Features & Completed Architecture

1. **Real Local Telemetry Collection**: Passive local system socket observation via `psutil` without synthetic probes or simulated traffic.
2. **Log File Ingestion**: Authorized parser supporting `.log`, `.txt`, `.json`, and `.csv` files.
3. **Backend Detection Engine**: Rule evaluation, correlation windows, risk scoring, MITRE ATT&CK mapping, and deduplication.
4. **Defensive SOC Workflow**: Alert triage, investigation case management, analyst notes, event timeline, verdicts, and audit logging.
5. **Authentication & RBAC**: JWT authentication, Argon2id/bcrypt password security, and granular roles (`ADMIN`, `ANALYST`, `VIEWER`).
6. **Real-Time SOC Event Streaming**: Authenticated WebSocket pipeline broadcasting telemetry, detections, and alerts live to connected frontend SOC clients.

---

## Quick Start (Development)

### 1. Environment Configuration
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

### 2. Admin Bootstrap Script
Bootstrap initial administrator account:
```bash
python -m app.scripts.create_admin
```

### 3. Backend API & WebSocket Server
```bash
cd backend
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```
* **REST API & Swagger**: `http://127.0.0.1:8000/docs`
* **WebSocket Stream**: `ws://127.0.0.1:8000/ws/events?token=<jwt_token>`

### 4. Frontend Application
```bash
cd frontend
npm install
npm run dev
```
* **SOC Interface**: `http://127.0.0.1:5173/`

---

## Automated Test Suites

```bash
# Run all automated test suites
python tests/test_websocket.py
python tests/test_auth.py
python tests/test_soc_workflow.py
python tests/test_detection_engine.py

# Python backend compilation check
python -m compileall backend/app

# Frontend production bundle build
cd frontend && npx vite build
```

---

## Environment Variables Reference

| Variable | Description | Default |
| :--- | :--- | :--- |
| `DATABASE_URL` | SQLite / PostgreSQL connection URI | `sqlite:///./netwatch.db` |
| `NETWATCH_SECRET_KEY` | JWT signing secret key | *(Required in prod)* |
| `NETWATCH_ADMIN_USER` | Bootstrap Admin Username | `admin` |
| `NETWATCH_ADMIN_PASSWORD` | Bootstrap Admin Password | `Admin123!` |
| `NETWATCH_CORS_ORIGINS` | Allowed CORS origins list | `http://localhost:5173,http://127.0.0.1:5173` |
