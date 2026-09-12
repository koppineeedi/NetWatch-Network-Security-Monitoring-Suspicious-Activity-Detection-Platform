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


@router.get("/{alert_id}/threat-intel")
def get_alert_threat_intel(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns Threat Intelligence enrichment data for an alert if an IOC match or IP reputation exists.
    Returns matched=false if no threat intelligence match.
    """
    alert = AlertService.get_alert_by_id(db, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    from app.models.threat_intel import IOCMatch, IOC, IPReputationCache, IPGeolocationCache

    # 1. Direct match check on alert_id
    matches = db.query(IOCMatch).filter(IOCMatch.alert_id == alert_id).all()

    # 2. IP match check on dest_ip or source_ip if no direct match
    if not matches:
        target_ips = [ip for ip in [alert.dest_ip, alert.source_ip] if ip]
        if target_ips:
            matches = db.query(IOCMatch).filter(IOCMatch.ioc_value.in_(target_ips)).all()
            if not matches:
                # Direct lookup in IOC table
                iocs = db.query(IOC).filter(IOC.normalized_value.in_([ip.strip().lower() for ip in target_ips])).all()
                if iocs:
                    ioc = iocs[0]
                    # Geo & Rep info
                    geo = db.query(IPGeolocationCache).filter(IPGeolocationCache.ip_address.in_(target_ips)).first()
                    rep = db.query(IPReputationCache).filter(IPReputationCache.ip_address.in_(target_ips)).first()

                    return {
                        "matched": True,
                        "match": {
                            "ioc_value": ioc.ioc_value,
                            "ioc_type": ioc.ioc_type,
                            "provider": ioc.source,
                            "confidence": ioc.confidence,
                            "severity": ioc.severity,
                            "country": geo.country if geo else (rep.country if rep else None),
                            "asn": geo.asn if geo else (rep.asn if rep else None),
                            "organization": geo.organization if geo else (rep.organization if rep else None),
                            "first_seen": ioc.first_seen.isoformat() if ioc.first_seen else None,
                            "last_seen": ioc.last_seen.isoformat() if ioc.last_seen else None,
                            "tags": ioc.tags
                        }
                    }

    if matches:
        m = matches[0]
        ioc = db.query(IOC).filter(IOC.id == m.ioc_id).first()
        geo = db.query(IPGeolocationCache).filter(IPGeolocationCache.ip_address == m.ioc_value).first()
        rep = db.query(IPReputationCache).filter(IPReputationCache.ip_address == m.ioc_value).first()

        return {
            "matched": True,
            "match": {
                "ioc_value": m.ioc_value,
                "ioc_type": m.ioc_type,
                "provider": m.provider,
                "confidence": m.confidence,
                "severity": m.severity,
                "country": geo.country if geo else (rep.country if rep else None),
                "asn": geo.asn if geo else (rep.asn if rep else None),
                "organization": geo.organization if geo else (rep.organization if rep else None),
                "first_seen": ioc.first_seen.isoformat() if (ioc and ioc.first_seen) else m.timestamp.isoformat(),
                "last_seen": ioc.last_seen.isoformat() if (ioc and ioc.last_seen) else m.timestamp.isoformat(),
                "tags": m.tags or (ioc.tags if ioc else None)
            }
        }

    return {
        "matched": False,
        "message": "No threat intelligence match"
    }

