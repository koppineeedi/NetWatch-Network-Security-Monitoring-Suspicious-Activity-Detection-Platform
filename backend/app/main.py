import os
import uvicorn
from datetime import datetime
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.database.connection import engine, Base
from app.collectors.local_network import local_collector_instance
from app.collectors.syslog_collector import syslog_collector_instance

from app.api.health import router as health_router
from app.api.auth import router as auth_router
from app.api.users import router as users_router
from app.api.telemetry import router as telemetry_router
from app.api.events import router as events_router
from app.api.alerts import router as alerts_router
from app.api.detections import router as detections_router
from app.api.investigations import router as investigations_router
from app.api.rules import router as rules_router
from app.api.assets import router as assets_router
from app.api.logs import router as logs_router
from app.api.statistics import router as stats_router
from app.api.audit import router as audit_router
from app.api.ws import router as ws_router

from app.api.connectors import router as connectors_router
from app.api.threat_intel import router as threat_intel_router, ip_router
from app.api.iocs import router as iocs_router

# Initialize database schema
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="NetWatch - Defensive SIEM & SOC Platform API",
    description="Backend REST API & Telemetry Engine for Network Security Monitoring & Threat Intelligence",
    version="1.1.0"
)

# Configurable CORS middleware for production deployment
cors_origins_raw = os.getenv("NETWATCH_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000,http://localhost:3001,http://127.0.0.1:3000,http://127.0.0.1:3001")
cors_origins = [origin.strip() for origin in cors_origins_raw.split(",") if origin.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_origin_regex=r"http://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(health_router)
app.include_router(auth_router)
app.include_router(users_router)
app.include_router(telemetry_router)
app.include_router(events_router)
app.include_router(alerts_router)
app.include_router(detections_router)
app.include_router(investigations_router)
app.include_router(rules_router)
app.include_router(assets_router)
app.include_router(logs_router)
app.include_router(stats_router)
app.include_router(audit_router)
app.include_router(ip_router)
app.include_router(ws_router)

# Enterprise Cycle 1 Routers
app.include_router(connectors_router)
app.include_router(threat_intel_router)
app.include_router(iocs_router)

# Enterprise Cycle 2 Routers (UEBA & Behavioral Analytics)
from app.api.ueba import router as ueba_router
from app.api.entities import router as entities_router
from app.api.anomalies import router as anomalies_router
from app.api.campaigns import router as campaigns_router

app.include_router(ueba_router)
app.include_router(entities_router)
app.include_router(anomalies_router)
app.include_router(campaigns_router)

# Enterprise Cycle 3 Routers (Sigma Engine & Sandbox)
from app.api.sigma import router as sigma_router
app.include_router(sigma_router)

# Enterprise Cycle 4 Routers (SOAR Subsystem)
from app.api.soar import router as soar_router
app.include_router(soar_router)

# Defensive SOC Upgrades (Hunting, MITRE ATT&CK, Replay, Evidence)
from app.api.hunting import router as hunting_router
from app.api.mitre import router as mitre_router
from app.api.replay import router as replay_router
from app.api.evidence import router as evidence_router

app.include_router(hunting_router)
app.include_router(mitre_router)
app.include_router(replay_router)
app.include_router(evidence_router)

@app.on_event("startup")
def startup_event():
    """Automatically start local network telemetry collector and syslog receiver on backend launch."""
    local_collector_instance.start()
    syslog_collector_instance.start()

@app.on_event("shutdown")
def shutdown_event():
    """Ensure collectors stop cleanly when backend shuts down."""
    local_collector_instance.stop()
    syslog_collector_instance.stop()

@app.get("/")
def root():
    return {
        "status": "ONLINE",
        "system": "NetWatch Defensive SIEM/SOC Engine",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.1.0"
    }

if __name__ == "__main__":
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
