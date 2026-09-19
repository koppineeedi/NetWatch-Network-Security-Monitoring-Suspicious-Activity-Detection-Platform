from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import random
from typing import Dict, Any

from app.database.connection import get_db
from app.collectors.local_network import local_collector_instance
from app.api.deps import get_current_user, require_role
from app.models.user import User
from app.models.event import NetworkEvent
from app.models.alert import Alert
from app.detection.engine import evaluate_event
from app.services.audit_service import log_audit_event

router = APIRouter(prefix="/api/telemetry", tags=["telemetry"])

@router.get("/status")
def get_telemetry_status(current_user: User = Depends(get_current_user)):
    """
    Returns real-time telemetry collector status. Requires authentication.
    """
    return local_collector_instance.get_status()

@router.post("/start")
def start_telemetry(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("ADMIN", "ANALYST"))
):
    """
    Starts background local network connection telemetry collection loop. ADMIN and ANALYST only.
    """
    res = local_collector_instance.start(db)
    return res

@router.post("/stop")
def stop_telemetry(
    current_user: User = Depends(require_role("ADMIN", "ANALYST"))
):
    """
    Stops background local network connection telemetry collection loop. ADMIN and ANALYST only.
    """
    res = local_collector_instance.stop()
    return res

@router.post("/demo-scenario")
def trigger_demo_scenario(
    payload: Dict[str, Any],
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Generates safe defensive lab telemetry for SOC analyst demonstration scenarios.
    Events flow through the standard DB storage and detection engine pipeline.
    """
    scenario_type = payload.get("scenario_type", "ssh_brute_force")
    now = datetime.utcnow()
    created_events = []

    if scenario_type == "ssh_brute_force":
        source_ip = "192.168.1.150"
        dest_ip = "10.0.0.24"
        for i in range(12):
            ev = NetworkEvent(
                timestamp=now - timedelta(seconds=(12 - i) * 5),
                event_type="authentication_failure",
                protocol="SSH",
                source_ip=source_ip,
                source_port=50000 + i,
                dest_ip=dest_ip,
                dest_port=22,
                status="SUSPICIOUS",
                username="root",
                hostname="srv-prod-db01",
                payload_summary="SSH authentication failed: invalid password | MITRE: T1110"
            )
            db.add(ev)
            created_events.append(ev)

    elif scenario_type == "suspicious_login":
        source_ip = "192.168.1.180"
        dest_ip = "10.0.0.24"
        for i in range(5):
            ev = NetworkEvent(
                timestamp=now - timedelta(seconds=(6 - i) * 10),
                event_type="authentication_failure",
                protocol="TCP",
                source_ip=source_ip,
                source_port=44330 + i,
                dest_ip=dest_ip,
                dest_port=443,
                status="SUSPICIOUS",
                username="admin",
                hostname="srv-prod-db01",
                payload_summary="Web console login failed | MITRE: T1110"
            )
            db.add(ev)
            created_events.append(ev)

        # Successful login following failures
        succ_ev = NetworkEvent(
            timestamp=now,
            event_type="authentication_success",
            protocol="TCP",
            source_ip=source_ip,
            source_port=44340,
            dest_ip=dest_ip,
            dest_port=443,
            status="CRITICAL",
            username="admin",
            hostname="srv-prod-db01",
            payload_summary="Web console login success after multiple failures from unusual location | MITRE: T1078"
        )
        db.add(succ_ev)
        created_events.append(succ_ev)

    elif scenario_type == "c2_beacon":
        source_ip = "10.0.0.24"
        dest_ip = "198.51.100.44"
        for i in range(10):
            ev = NetworkEvent(
                timestamp=now - timedelta(seconds=(10 - i) * 10),
                event_type="outbound_connection",
                protocol="HTTPS",
                source_ip=source_ip,
                source_port=52000 + i,
                dest_ip=dest_ip,
                dest_port=443,
                status="SUSPICIOUS",
                hostname="srv-prod-db01",
                bytes_sent=1024 + random.randint(10, 50),
                bytes_received=512 + random.randint(5, 20),
                payload_summary="Periodic HTTP outbound connection pattern detected (Potential Beaconing) | Domain: c2-listener.test | MITRE: T1071"
            )
            db.add(ev)
            created_events.append(ev)

    elif scenario_type == "port_scan":
        source_ip = "192.168.1.200"
        dest_ip = "10.0.0.24"
        scanned_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 3306, 8080]
        for idx, port in enumerate(scanned_ports):
            ev = NetworkEvent(
                timestamp=now - timedelta(seconds=(len(scanned_ports) - idx) * 2),
                event_type="network_scan",
                protocol="TCP",
                source_ip=source_ip,
                source_port=60000 + idx,
                dest_ip=dest_ip,
                dest_port=port,
                status="SUSPICIOUS",
                hostname="srv-prod-db01",
                payload_summary=f"Port scan probe detected on port {port} | MITRE: T1046"
            )
            db.add(ev)
            created_events.append(ev)

    elif scenario_type == "dns_anomaly":
        source_ip = "10.0.0.24"
        dest_ip = "8.8.8.8"
        for i in range(8):
            subdomain = f"exfil-chunk-{i:03d}.malicious-domain.test"
            ev = NetworkEvent(
                timestamp=now - timedelta(seconds=(8 - i) * 3),
                event_type="dns_query",
                protocol="DNS",
                source_ip=source_ip,
                source_port=53535 + i,
                dest_ip=dest_ip,
                dest_port=53,
                status="SUSPICIOUS",
                hostname="srv-prod-db01",
                payload_summary=f"High entropy DNS query detected for {subdomain} | MITRE: T1071.004"
            )
            db.add(ev)
            created_events.append(ev)
    else:
        raise HTTPException(status_code=400, detail="Unknown scenario_type")

    db.commit()

    # Run detection engine over newly created telemetry
    generated_detections = []
    for ev in created_events:
        dets = evaluate_event(db, ev)
        if dets:
            generated_detections.extend(dets)

    log_audit_event(
        db,
        user=current_user.username,
        action="DEMO_SCENARIO_RUN",
        resource_type="TELEMETRY_DEMO",
        resource_id=scenario_type,
        details=f"Generated {len(created_events)} events for scenario '{scenario_type}'. Created {len(generated_detections)} detections."
    )

    return {
        "status": "SUCCESS",
        "scenario_type": scenario_type,
        "events_created": len(created_events),
        "detections_generated": len(generated_detections),
        "sample_event": {
            "id": created_events[0].id,
            "event_type": created_events[0].event_type,
            "source_ip": created_events[0].source_ip,
            "dest_ip": created_events[0].dest_ip,
            "payload_summary": created_events[0].payload_summary
        } if created_events else None
    }
