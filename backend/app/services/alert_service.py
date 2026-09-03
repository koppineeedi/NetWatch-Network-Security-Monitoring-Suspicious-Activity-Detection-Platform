from sqlalchemy.orm import Session
from datetime import datetime
from typing import Optional, List, Dict, Any
from fastapi import HTTPException
from app.models.alert import Alert
from app.models.detection import Detection
from app.models.event import NetworkEvent
from app.services.audit_service import AuditService
import json

VALID_ALERT_TRANSITIONS = {
    "NEW": ["INVESTIGATING"],
    "INVESTIGATING": ["TRUE_POSITIVE", "FALSE_POSITIVE"],
    "TRUE_POSITIVE": ["RESOLVED"],
    "FALSE_POSITIVE": ["RESOLVED"],
    "RESOLVED": ["CLOSED"],
    "CLOSED": []
}

class AlertService:
    @staticmethod
    def get_alerts(
        db: Session,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        source_ip: Optional[str] = None,
        rule_code: Optional[str] = None,
        limit: int = 50,
        offset: int = 0
    ) -> List[Alert]:
        query = db.query(Alert)
        if status and status != "ALL":
            query = query.filter(Alert.status == status)
        if severity and severity != "ALL":
            query = query.filter(Alert.severity == severity)
        if source_ip:
            query = query.filter(Alert.source_ip == source_ip)
        if rule_code:
            query = query.filter(Alert.rule_id == rule_code)

        return query.order_by(Alert.timestamp.desc()).offset(offset).limit(limit).all()

    @staticmethod
    def get_alert_by_id(db: Session, alert_id: int) -> Optional[Alert]:
        return db.query(Alert).filter(Alert.id == alert_id).first()

    @staticmethod
    def update_alert(
        db: Session,
        alert_id: int,
        user: str,
        status: Optional[str] = None,
        assigned_analyst: Optional[str] = None,
        resolution: Optional[str] = None,
        resolution_reason: Optional[str] = None
    ) -> Alert:
        alert = db.query(Alert).filter(Alert.id == alert_id).first()
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")

        # Validate Status Transition
        if status and status != alert.status:
            allowed = VALID_ALERT_TRANSITIONS.get(alert.status, [])
            if status not in allowed:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid alert status transition from '{alert.status}' to '{status}'. Allowed next states: {allowed}"
                )
            old_status = alert.status
            alert.status = status
            AuditService.log(
                db=db,
                user=user,
                action="ALERT_STATUS_CHANGED",
                resource_type="ALERT",
                resource_id=alert.id,
                details=f"Transitioned from {old_status} to {status}"
            )

        if assigned_analyst:
            alert.assigned_analyst = assigned_analyst
            AuditService.log(
                db=db,
                user=user,
                action="ALERT_ASSIGNED",
                resource_type="ALERT",
                resource_id=alert.id,
                details=f"Assigned to {assigned_analyst}"
            )

        if resolution:
            alert.resolution = resolution
        if resolution_reason:
            alert.resolution_reason = resolution_reason

        alert.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(alert)
        return alert

    @staticmethod
    def get_alert_evidence_events(db: Session, alert_id: int) -> List[NetworkEvent]:
        alert = db.query(Alert).filter(Alert.id == alert_id).first()
        if not alert or not alert.detection_id:
            return []

        detection = db.query(Detection).filter(Detection.id == alert.detection_id).first()
        if not detection or not detection.evidence:
            # Fallback to source IP matching if direct evidence JSON missing
            return db.query(NetworkEvent).filter(NetworkEvent.source_ip == alert.source_ip).limit(50).all()

        try:
            ev_data = json.loads(detection.evidence)
            event_ids = ev_data.get("source_event_ids", [])
            if event_ids:
                return db.query(NetworkEvent).filter(NetworkEvent.id.in_(event_ids)).all()
        except Exception:
            pass

        return db.query(NetworkEvent).filter(NetworkEvent.source_ip == alert.source_ip).limit(50).all()
