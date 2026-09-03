from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Optional
from app.database.connection import get_db
from app.services.alert_service import AlertService
from app.api.deps import get_current_user, require_role
from app.models.user import User

router = APIRouter(prefix="/api/alerts", tags=["alerts"])

class AlertUpdateRequest(BaseModel):
    status: Optional[str] = None
    assigned_analyst: Optional[str] = None
    resolution: Optional[str] = None
    resolution_reason: Optional[str] = None

@router.get("")
def get_alerts(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    source_ip: Optional[str] = None,
    rule_code: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns filterable, paginated alerts list from SQLite database. Requires authentication.
    """
    alerts = AlertService.get_alerts(
        db=db,
        status=status,
        severity=severity,
        source_ip=source_ip,
        rule_code=rule_code,
        limit=limit,
        offset=offset
    )
    return [
        {
            "id": a.id,
            "timestamp": a.timestamp.isoformat() if a.timestamp else None,
            "updated_at": a.updated_at.isoformat() if a.updated_at else None,
            "detection_id": a.detection_id,
            "detection_type": a.detection_type,
            "severity": a.severity,
            "confidence": a.confidence,
            "risk_score": a.risk_score,
            "source_ip": a.source_ip,
            "dest_ip": a.dest_ip,
            "dest_port": a.dest_port,
            "protocol": a.protocol,
            "description": a.description,
            "explanation": a.explanation,
            "status": a.status,
            "assigned_analyst": a.assigned_analyst,
            "rule_id": a.rule_id,
            "resolution": a.resolution,
            "resolution_reason": a.resolution_reason
        }
        for a in alerts
    ]

@router.get("/{alert_id}")
def get_alert_by_id(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns single alert details with detection explanation. Requires authentication.
    """
    alert = AlertService.get_alert_by_id(db, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {
        "id": alert.id,
        "timestamp": alert.timestamp.isoformat() if alert.timestamp else None,
        "updated_at": alert.updated_at.isoformat() if alert.updated_at else None,
        "detection_id": alert.detection_id,
        "detection_type": alert.detection_type,
        "severity": alert.severity,
        "confidence": alert.confidence,
        "risk_score": alert.risk_score,
        "source_ip": alert.source_ip,
        "dest_ip": alert.dest_ip,
        "dest_port": alert.dest_port,
        "protocol": alert.protocol,
        "description": alert.description,
        "explanation": alert.explanation,
        "status": alert.status,
        "assigned_analyst": alert.assigned_analyst,
        "rule_id": alert.rule_id,
        "resolution": alert.resolution,
        "resolution_reason": alert.resolution_reason
    }

@router.patch("/{alert_id}")
def update_alert(
    alert_id: int,
    data: AlertUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("ADMIN", "ANALYST"))
):
    """
    Performs controlled alert status transition, analyst assignment, or resolution. ADMIN and ANALYST only.
    """
    return AlertService.update_alert(
        db=db,
        alert_id=alert_id,
        user=current_user.username,
        status=data.status,
        assigned_analyst=data.assigned_analyst or current_user.username,
        resolution=data.resolution,
        resolution_reason=data.resolution_reason
    )

@router.get("/{alert_id}/events")
def get_alert_evidence_events(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns actual NetworkEvent records associated with an alert's evidence. Requires authentication.
    """
    events = AlertService.get_alert_evidence_events(db, alert_id)
    return [
        {
            "id": e.id,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            "source": e.source,
            "collector": e.collector,
            "source_ip": e.source_ip,
            "source_port": e.source_port,
            "dest_ip": e.dest_ip,
            "dest_port": e.dest_port,
            "protocol": e.protocol,
            "connection_state": e.connection_state,
            "status": e.status,
            "process_name": e.process_name,
            "hostname": e.hostname,
            "bytes_sent": e.bytes_sent,
            "bytes_received": e.bytes_received,
            "payload_summary": e.payload_summary
        }
        for e in events
    ]
