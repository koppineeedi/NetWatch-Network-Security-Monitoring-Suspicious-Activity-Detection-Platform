from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import Dict, Any, List
from datetime import datetime

from app.database.connection import get_db
from app.models.soc_models import IncidentEvidence
from app.models.investigation import Investigation
from app.models.user import User
from app.api.auth import get_current_user
from app.services.audit_service import log_audit_event

router = APIRouter(prefix="/api/investigations", tags=["Incident Evidence"])

@router.get("/{investigation_id}/evidence")
def list_investigation_evidence(
    investigation_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    return db.query(IncidentEvidence).filter(IncidentEvidence.investigation_id == investigation_id).all()

@router.post("/{investigation_id}/evidence")
def attach_evidence_to_investigation(
    investigation_id: int,
    payload: Dict[str, Any],
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    evidence = IncidentEvidence(
        investigation_id=investigation_id,
        evidence_type=payload.get("evidence_type", "EVENT"),
        source=payload.get("source", "SOC Analyst"),
        reference_id=str(payload.get("reference_id", "")),
        summary=payload.get("summary", "Analyst evidence attachment"),
        analyst_note=payload.get("analyst_note", ""),
        created_by=current_user.username
    )
    db.add(evidence)
    db.commit()
    db.refresh(evidence)

    log_audit_event(
        db,
        user=current_user.username,
        action="EVIDENCE_ATTACHED",
        resource_type="INCIDENT_EVIDENCE",
        resource_id=str(evidence.id),
        details=f"Attached {evidence.evidence_type} evidence to Investigation #{investigation_id}"
    )

    return evidence

@router.delete("/{investigation_id}/evidence/{evidence_id}")
def detach_evidence_from_investigation(
    investigation_id: int,
    evidence_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    evidence = db.query(IncidentEvidence).filter(
        IncidentEvidence.id == evidence_id,
        IncidentEvidence.investigation_id == investigation_id
    ).first()
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence item not found")

    db.delete(evidence)
    db.commit()

    log_audit_event(
        db,
        user=current_user.username,
        action="EVIDENCE_REMOVED",
        resource_type="INCIDENT_EVIDENCE",
        resource_id=str(evidence_id),
        details=f"Removed evidence #{evidence_id} from Investigation #{investigation_id}"
    )

    return {"status": "SUCCESS", "message": f"Evidence #{evidence_id} removed"}
