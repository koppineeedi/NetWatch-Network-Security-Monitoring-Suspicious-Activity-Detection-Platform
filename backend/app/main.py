import os
import uvicorn
from datetime import datetime
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.database.connection import engine, Base
from app.collectors.local_network import local_collector_instance

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
from app.api.ip import router as ip_router
from app.api.ws import router as ws_router

# Initialize database schema
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="NetWatch - Defensive SOC Platform API",
    description="Backend REST API & Telemetry Engine for Network Security Monitoring",
    version="1.0.0"
)

# Configurable CORS middleware for production deployment
cors_origins_raw = os.getenv("NETWATCH_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000")
cors_origins = [origin.strip() for origin in cors_origins_raw.split(",") if origin.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins if cors_origins else ["*"],
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

@app.on_event("startup")
def startup_event():
    """Automatically start the real local network telemetry collector on backend launch."""
    local_collector_instance.start()

@app.on_event("shutdown")
def shutdown_event():
    """Ensure collector stops cleanly when backend shuts down."""
    local_collector_instance.stop()

@app.get("/")
def root():
    return {
        "status": "ONLINE",
        "system": "NetWatch Defensive SOC Engine",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0"
    }

if __name__ == "__main__":
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
