from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_, desc
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
import json

from app.database.connection import get_db
from app.models.event import NetworkEvent
from app.models.alert import Alert
from app.models.investigation import Investigation
from app.models.soc_models import ThreatHuntReport
from app.models.user import User
from app.api.auth import get_current_user
from app.services.audit_service import log_audit_event

router = APIRouter(prefix="/api/hunting", tags=["Threat Hunting"])

@router.get("/query")
def execute_threat_hunt_query(
    source_ip: Optional[str] = None,
    destination_ip: Optional[str] = None,
    username: Optional[str] = None,
    hostname: Optional[str] = None,
    domain: Optional[str] = None,
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    time_range: Optional[str] = "24h",
    mitre_technique: Optional[str] = None,
    ioc_value: Optional[str] = None,
    protocol: Optional[str] = None,
    dest_port: Optional[int] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Structured Threat Hunting query over real stored network telemetry.
    Supports pivoting across IP, user, host, domain, MITRE technique, and IOC values.
    """
    query = db.query(NetworkEvent)

    # Time filter
    now = datetime.utcnow()
    if time_range == "1h":
        start_time = now - timedelta(hours=1)
        query = query.filter(NetworkEvent.timestamp >= start_time)
    elif time_range == "24h":
        start_time = now - timedelta(hours=24)
        query = query.filter(NetworkEvent.timestamp >= start_time)
    elif time_range == "7d":
        start_time = now - timedelta(days=7)
        query = query.filter(NetworkEvent.timestamp >= start_time)

    # Filter clauses
    filters = []
    if source_ip:
        filters.append(NetworkEvent.source_ip.ilike(f"%{source_ip.strip()}%"))
    if destination_ip:
        filters.append(NetworkEvent.dest_ip.ilike(f"%{destination_ip.strip()}%"))
    if username:
        filters.append(NetworkEvent.username.ilike(f"%{username.strip()}%"))
    if hostname:
        filters.append(NetworkEvent.hostname.ilike(f"%{hostname.strip()}%"))
    if domain:
        filters.append(NetworkEvent.payload_summary.ilike(f"%{domain.strip()}%"))
    if event_type:
        filters.append(NetworkEvent.event_type.ilike(f"%{event_type.strip()}%"))
    if severity:
        filters.append(NetworkEvent.status.ilike(f"%{severity.strip()}%"))
    if protocol:
        filters.append(NetworkEvent.protocol.ilike(f"%{protocol.strip()}%"))
    if dest_port is not None:
        filters.append(NetworkEvent.dest_port == dest_port)
    if mitre_technique:
        filters.append(NetworkEvent.payload_summary.ilike(f"%{mitre_technique.strip()}%"))
    if ioc_value:
        filters.append(or_(
            NetworkEvent.source_ip == ioc_value,
            NetworkEvent.dest_ip == ioc_value,
            NetworkEvent.payload_summary.ilike(f"%{ioc_value}%")
        ))

    if filters:
        query = query.filter(and_(*filters))

    total_count = query.count()
    events = query.order_by(desc(NetworkEvent.timestamp)).offset((page - 1) * page_size).limit(page_size).all()

    # Discover related alerts and investigations
    related_alerts = []
    related_incidents = []
    matched_ips = set()
    for ev in events:
        if ev.source_ip: matched_ips.add(ev.source_ip)
        if ev.dest_ip: matched_ips.add(ev.dest_ip)

    if matched_ips:
        alerts = db.query(Alert).filter(or_(
            Alert.source_ip.in_(matched_ips),
            Alert.dest_ip.in_(matched_ips)
        )).limit(10).all()
        related_alerts = [{"id": a.id, "title": a.description or a.detection_type, "severity": a.severity, "status": a.status, "source_ip": a.source_ip} for a in alerts]

        incidents = db.query(Investigation).filter(or_(
            Investigation.source_ip.in_(matched_ips),
            Investigation.dest_ip.in_(matched_ips)
        )).limit(10).all()
        related_incidents = [{"id": i.id, "case_number": i.case_number, "title": i.title, "severity": i.severity, "status": i.status} for i in incidents]

    # Audit log entry
    log_audit_event(
        db,
        user=current_user.username,
        action="HUNT_EXECUTE",
        resource_type="THREAT_HUNT",
        resource_id=f"query-{now.strftime('%Y%m%d%H%M%S')}",
        details=f"Threat hunt executed. Filters: {filters}. Matches: {total_count}"
    )

    return {
        "total": total_count,
        "page": page,
        "page_size": page_size,
        "events": events,
        "related_alerts": related_alerts,
        "related_incidents": related_incidents,
        "pivot_summary": {
            "unique_source_ips": len(set(e.source_ip for e in events if e.source_ip)),
            "unique_dest_ips": len(set(e.dest_ip for e in events if e.dest_ip)),
            "unique_users": len(set(e.username for e in events if e.username)),
            "unique_hosts": len(set(e.hostname for e in events if e.hostname))
        }
    }

def _format_hunt_report(r: ThreatHuntReport) -> Dict[str, Any]:
    return {
        "id": r.id,
        "hunt_id": r.hunt_id,
        "title": r.title,
        "hypothesis": r.hypothesis,
        "scope": r.scope,
        "query_params": r.query_params,
        "findings": r.findings,
        "affected_entities": r.affected_entities,
        "iocs": r.iocs,
        "mitre_techniques": r.mitre_techniques,
        "conclusion": r.conclusion,
        "recommended_action": r.recommended_action,
        "status": r.status,
        "analyst": r.analyst,
        "created_at": r.created_at.isoformat() if r.created_at else None,
        "updated_at": r.updated_at.isoformat() if r.updated_at else None
    }

@router.get("/reports")
def list_threat_hunt_reports(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    reports = db.query(ThreatHuntReport).order_by(desc(ThreatHuntReport.created_at)).all()
    return [_format_hunt_report(r) for r in reports]

@router.post("/reports")
def create_threat_hunt_report(
    payload: Dict[str, Any],
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    hunt_count = db.query(ThreatHuntReport).count() + 1
    hunt_id = f"TH-{datetime.utcnow().strftime('%Y')}-{hunt_count:03d}"

    report = ThreatHuntReport(
        hunt_id=hunt_id,
        title=payload.get("title", f"Threat Hunt Report {hunt_id}"),
        hypothesis=payload.get("hypothesis", ""),
        scope=payload.get("scope", "24h"),
        query_params=json.dumps(payload.get("query_params", {})),
        findings=payload.get("findings", ""),
        affected_entities=payload.get("affected_entities", ""),
        iocs=payload.get("iocs", ""),
        mitre_techniques=payload.get("mitre_techniques", ""),
        conclusion=payload.get("conclusion", ""),
        recommended_action=payload.get("recommended_action", ""),
        status=payload.get("status", "COMPLETED"),
        analyst=current_user.username
    )
    db.add(report)
    db.commit()
    db.refresh(report)

    log_audit_event(
        db,
        user=current_user.username,
        action="HUNT_REPORT_CREATED",
        resource_type="THREAT_HUNT_REPORT",
        resource_id=report.hunt_id,
        details=f"Created hunt report {report.hunt_id}: {report.title}"
    )

    return _format_hunt_report(report)
