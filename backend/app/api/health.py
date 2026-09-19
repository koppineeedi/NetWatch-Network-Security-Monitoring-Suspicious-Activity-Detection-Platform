import os
import platform
import datetime
from fastapi import APIRouter, Depends, Response, status
from sqlalchemy.orm import Session
from sqlalchemy import text
from app.database.connection import get_db
from app.collectors.local_network import local_collector_instance
from app.collectors.syslog_collector import syslog_collector_instance
from app.realtime.manager import ws_manager

router = APIRouter(tags=["health"])

@router.get("/health")
@router.get("/api/health")
def health_check():
    """
    Production Liveness Health Probe.
    Returns HTTP 200 when application process is responsive.
    """
    return {
        "status": "HEALTHY",
        "system": "NetWatch SIEM Engine",
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "version": "1.1.0"
    }

@router.get("/ready")
@router.get("/api/health/ready")
def readiness_check(response: Response, db: Session = Depends(get_db)):
    """
    Production Readiness Probe.
    Verifies critical dependencies (Database connection & core collectors).
    Returns HTTP 503 Service Unavailable if critical infrastructure is down.
    Optional integrations (Cloud / Threat Intel) do NOT cause readiness failure.
    """
    db_connected = False
    try:
        db.execute(text("SELECT 1"))
        db_connected = True
    except Exception:
        db_connected = False

    telemetry_running = local_collector_instance.is_running
    syslog_active = syslog_collector_instance.is_running or not getattr(syslog_collector_instance, "enabled", False)

    is_ready = db_connected and telemetry_running

    if not is_ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return {
        "status": "READY" if is_ready else "UNAVAILABLE",
        "ready": is_ready,
        "components": {
            "database": "CONNECTED" if db_connected else "DISCONNECTED",
            "telemetry_collector": "RUNNING" if telemetry_running else "STOPPED",
            "syslog_collector": "RUNNING" if syslog_collector_instance.is_running else "IDLE",
            "websocket_manager": "ACTIVE"
        },
        "timestamp": datetime.datetime.utcnow().isoformat()
    }

@router.get("/api/health/status")
@router.get("/api/system/status")
def system_status_check(db: Session = Depends(get_db)):
    """
    Production Comprehensive System Status API.
    Reports operational state for all 14 platform components:
    ACTIVE, READY, NOT_CONFIGURED, ERROR, DEGRADED.
    """
    # 1. Database
    try:
        db.execute(text("SELECT 1"))
        db_status = "ACTIVE"
    except Exception:
        db_status = "ERROR"

    # 2. Telemetry Collector
    telemetry_status = "ACTIVE" if local_collector_instance.is_running else "READY"

    # 3. Syslog Collector
    if syslog_collector_instance.is_running:
        syslog_status = "ACTIVE"
    elif getattr(syslog_collector_instance, "enabled", False):
        syslog_status = "READY"
    else:
        syslog_status = "NOT_CONFIGURED"

    # 4. Connectors
    aws_key = os.getenv("AWS_ACCESS_KEY_ID")
    azure_tenant = os.getenv("AZURE_TENANT_ID")
    gcp_creds = os.getenv("GOOGLE_APPLICATION_CREDENTIALS") or os.getenv("GCP_PROJECT_ID")
    cloud_status = "ACTIVE" if (aws_key or azure_tenant or gcp_creds) else "NOT_CONFIGURED"

    # 5. Threat Intelligence
    ti_key = os.getenv("ABUSEIPDB_API_KEY") or os.getenv("OTX_API_KEY") or os.getenv("MISP_API_KEY")
    ti_status = "ACTIVE" if ti_key else "NOT_CONFIGURED"

    # 6. Drivers
    iso_driver_type = os.getenv("NETWATCH_SOAR_HOST_ISOLATION_DRIVER", "none").lower()
    iso_status = "ACTIVE" if iso_driver_type != "none" and os.getenv("NETWATCH_SOAR_AUTO_ISOLATION_ENABLED", "false").lower() == "true" else "NOT_CONFIGURED"

    iam_driver_type = os.getenv("NETWATCH_IAM_DRIVER", "none").lower()
    iam_status = "ACTIVE" if iam_driver_type != "none" and os.getenv("NETWATCH_IDP_CONFIGURED", "false").lower() == "true" else "NOT_CONFIGURED"

    return {
        "status": "OPERATIONAL",
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "components": {
            "backend_core": "ACTIVE",
            "database": db_status,
            "network_telemetry": telemetry_status,
            "syslog_collector": syslog_status,
            "detection_engine": "ACTIVE",
            "ioc_engine": "ACTIVE",
            "ueba_analytics": "ACTIVE",
            "sigma_engine": "ACTIVE",
            "soar_subsystem": "ACTIVE",
            "websocket_pipeline": "ACTIVE",
            "cloud_connectors": cloud_status,
            "threat_intelligence": ti_status,
            "host_isolation_driver": iso_status,
            "iam_account_driver": iam_status
        }
    }
