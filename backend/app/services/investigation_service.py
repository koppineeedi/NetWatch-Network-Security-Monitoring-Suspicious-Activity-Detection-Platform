import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any
from sqlalchemy.orm import Session
from fastapi import HTTPException

from app.models.investigation import Investigation, AnalystNote
from app.models.alert import Alert
from app.models.event import NetworkEvent
from app.models.detection import Detection
from app.services.audit_service import AuditService
from app.services.alert_service import AlertService

VALID_INVESTIGATION_TRANSITIONS = {
    "OPEN": ["IN_PROGRESS", "RESOLVED", "CLOSED"],
    "IN_PROGRESS": ["CONTAINED", "RESOLVED", "CLOSED"],
    "CONTAINED": ["RESOLVED", "CLOSED"],
    "RESOLVED": ["CLOSED"],
    "CLOSED": []
}

class InvestigationService:
    @staticmethod
    def get_investigations(db: Session, limit: int = 50, offset: int = 0) -> List[Investigation]:
        return db.query(Investigation).order_by(Investigation.created_at.desc()).offset(offset).limit(limit).all()

    @staticmethod
    def get_investigation_by_id(db: Session, inv_id: int) -> Optional[Investigation]:
        return db.query(Investigation).filter(Investigation.id == inv_id).first()

    @staticmethod
    def create_investigation_from_alert(db: Session, alert_id: int, user: str) -> Investigation:
        alert = db.query(Alert).filter(Alert.id == alert_id).first()
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")

        case_num = f"INC-2026-{str(uuid.uuid4())[:6].upper()}"

        inv = Investigation(
            alert_id=alert.id,
            case_number=case_num,
            title=f"Incident Investigation: {alert.detection_type}",
            summary=alert.explanation or alert.description,
            source_ip=alert.source_ip or "UNKNOWN",
            dest_ip=alert.dest_ip or "UNKNOWN",
            severity=alert.severity,
            status="OPEN",
            assigned_analyst=user or "SOC Analyst",
            created_at=datetime.utcnow()
        )
        db.add(inv)

        # Update Alert status to INVESTIGATING
        if alert.status == "NEW":
            alert.status = "INVESTIGATING"
            alert.assigned_analyst = user or "SOC Analyst"
            alert.updated_at = datetime.utcnow()

        db.commit()
        db.refresh(inv)

        AuditService.log(
            db=db,
            user=user,
            action="INVESTIGATION_CREATED",
            resource_type="INVESTIGATION",
            resource_id=inv.id,
            details=f"Created Case {inv.case_number} for Alert ID {alert.id}"
        )

        return inv

    @staticmethod
    def add_note(db: Session, inv_id: int, author: str, note_text: str) -> AnalystNote:
        inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
        if not inv:
            raise HTTPException(status_code=404, detail="Investigation not found")

        note = AnalystNote(
            investigation_id=inv.id,
            timestamp=datetime.utcnow(),
            author=author or "SOC Analyst",
            note_text=note_text
        )
        db.add(note)
        inv.updated_at = datetime.utcnow()

        db.commit()
        db.refresh(note)

        AuditService.log(
            db=db,
            user=author,
            action="NOTE_CREATED",
            resource_type="NOTE",
            resource_id=note.id,
            details=f"Added note to Case {inv.case_number}"
        )

        return note

    @staticmethod
    def update_investigation(
        db: Session,
        inv_id: int,
        user: str,
        status: Optional[str] = None,
        verdict: Optional[str] = None,
        verdict_reason: Optional[str] = None
    ) -> Investigation:
        inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
        if not inv:
            raise HTTPException(status_code=404, detail="Investigation not found")

        # Validate Status Transition
        if status and status != inv.status:
            allowed = VALID_INVESTIGATION_TRANSITIONS.get(inv.status, [])
            if status not in allowed:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid investigation status transition from '{inv.status}' to '{status}'. Allowed next states: {allowed}"
                )
            old_status = inv.status
            inv.status = status
            if status == "CLOSED":
                inv.closed_at = datetime.utcnow()

            AuditService.log(
                db=db,
                user=user,
                action="INVESTIGATION_STATUS_CHANGED",
                resource_type="INVESTIGATION",
                resource_id=inv.id,
                details=f"Status changed from {old_status} to {status}"
            )

        if verdict:
            inv.verdict = verdict
            inv.verdict_reason = verdict_reason
            AuditService.log(
                db=db,
                user=user,
                action="VERDICT_CHANGED",
                resource_type="INVESTIGATION",
                resource_id=inv.id,
                details=f"Verdict set to {verdict}: {verdict_reason}"
            )

            # Sync with underlying Alert if present
            if inv.alert_id:
                alert = db.query(Alert).filter(Alert.id == inv.alert_id).first()
                if alert:
                    if verdict in ["TRUE_POSITIVE", "FALSE_POSITIVE"]:
                        alert.status = verdict
                    if status in ["RESOLVED", "CLOSED"]:
                        alert.status = "RESOLVED" if status == "RESOLVED" else "CLOSED"
                        alert.resolution = verdict
                        alert.resolution_reason = verdict_reason
                    alert.updated_at = datetime.utcnow()

        inv.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(inv)
        return inv

    @staticmethod
    def get_timeline(db: Session, inv_id: int) -> List[Dict[str, Any]]:
        inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
        if not inv:
            raise HTTPException(status_code=404, detail="Investigation not found")

        timeline = []

        # 1. Investigation created
        timeline.append({
            "timestamp": inv.created_at.isoformat(),
            "event_type": "INVESTIGATION_STARTED",
            "actor": inv.assigned_analyst,
            "title": f"Investigation Case {inv.case_number} Created",
            "details": inv.summary
        })

        # 2. Associated Alert & Detection timeline
        if inv.alert_id:
            alert = db.query(Alert).filter(Alert.id == inv.alert_id).first()
            if alert:
                timeline.append({
                    "timestamp": alert.timestamp.isoformat(),
                    "event_type": "ALERT_TRIGGERED",
                    "actor": "NetWatch Detection Engine",
                    "title": f"Alert Generated: {alert.detection_type}",
                    "details": alert.explanation or alert.description
                })

                # Fetch associated evidence events
                events = AlertService.get_alert_evidence_events(db, alert.id)
                for evt in events[:5]:
                    timeline.append({
                        "timestamp": evt.timestamp.isoformat() if evt.timestamp else alert.timestamp.isoformat(),
                        "event_type": "NETWORK_TELEMETRY_OBSERVED",
                        "actor": evt.source or "LOCAL_NETWORK",
                        "title": f"Observed Connection: {evt.source_ip} -> {evt.dest_ip}:{evt.dest_port}",
                        "details": f"Protocol: {evt.protocol} | State: {evt.connection_state} | Process: {evt.process_name or 'N/A'}"
                    })

        # 3. Analyst Notes timeline
        for note in inv.notes:
            timeline.append({
                "timestamp": note.timestamp.isoformat(),
                "event_type": "ANALYST_NOTE_ADDED",
                "actor": note.author,
                "title": f"Analyst Note by {note.author}",
                "details": note.note_text
            })

        # 4. Verdict & Resolution timeline
        if inv.verdict:
            timeline.append({
                "timestamp": inv.updated_at.isoformat(),
                "event_type": "VERDICT_RECORDED",
                "actor": inv.assigned_analyst,
                "title": f"Verdict Recorded: {inv.verdict}",
                "details": inv.verdict_reason or "No details provided"
            })

        # Sort timeline chronologically
        timeline.sort(key=lambda x: x["timestamp"])
        return timeline
