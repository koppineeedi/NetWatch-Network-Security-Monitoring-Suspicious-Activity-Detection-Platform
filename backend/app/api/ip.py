from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.database.connection import get_db
from app.models.event import NetworkEvent
from app.models.alert import Alert
from app.models.detection import Detection
from app.api.deps import get_current_user
from app.models.user import User

router = APIRouter(prefix="/api/ip", tags=["ip"])

@router.get("/{ip_address}")
def analyze_ip(
    ip_address: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns authoritative telemetry summary for a specific IP address based on real database records.
    Requires authentication. No fake reputation scores.
    """
    events = db.query(NetworkEvent).filter(
        (NetworkEvent.source_ip == ip_address) | (NetworkEvent.dest_ip == ip_address)
    ).order_by(NetworkEvent.timestamp.desc()).all()

    if not events:
        return {
            "ip": ip_address,
            "total_events": 0,
            "total_alerts": 0,
            "total_detections": 0,
            "first_seen": None,
            "last_seen": None,
            "observed_ports": [],
            "observed_protocols": [],
            "alerts": [],
            "events": []
        }

    first_seen = min(e.timestamp for e in events if e.timestamp)
    last_seen = max(e.timestamp for e in events if e.timestamp)

    ports = list(set(e.dest_port for e in events if e.dest_port is not None))
    protocols = list(set(e.protocol for e in events if e.protocol is not None))

    alerts = db.query(Alert).filter(Alert.source_ip == ip_address).all()
    detections = db.query(Detection).filter(Detection.source_ip == ip_address).all()

    return {
        "ip": ip_address,
        "total_events": len(events),
        "total_alerts": len(alerts),
        "total_detections": len(detections),
        "first_seen": first_seen.isoformat() if first_seen else None,
        "last_seen": last_seen.isoformat() if last_seen else None,
        "observed_ports": ports,
        "observed_protocols": protocols,
        "alerts": [
            {
                "id": a.id,
                "title": a.detection_type,
                "severity": a.severity,
                "status": a.status,
                "timestamp": a.timestamp.isoformat() if a.timestamp else None
            }
            for a in alerts
        ],
        "events": [
            {
                "id": e.id,
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                "source": e.source,
                "source_ip": e.source_ip,
                "dest_ip": e.dest_ip,
                "dest_port": e.dest_port,
                "protocol": e.protocol,
                "connection_state": e.connection_state,
                "process_name": e.process_name
            }
            for e in events[:20]
        ]
    }
