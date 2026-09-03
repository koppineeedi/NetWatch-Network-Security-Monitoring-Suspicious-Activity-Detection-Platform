# NETWATCH — Development & Engineering Manual

## Quick Start Development Commands

### Backend API Server (FastAPI)
```bash
cd backend
pip install -r requirements.txt
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

### Frontend UI Server (Vite + React)
```bash
cd frontend
npm install
npm run dev
```

## System Architecture Phases
- Phase 1: Clean Foundation & SQLite DB initialization (Zero fake operational security data).
- Phase 2: Real Local Network Telemetry Ingestion via `psutil`.
- Phase 3: Real Log File Ingestion (.log, .json, .csv).
- Phase 4: Authoritative Detection Engine.
- Phase 5: Security Alerts & Incident Investigations Workflow.
