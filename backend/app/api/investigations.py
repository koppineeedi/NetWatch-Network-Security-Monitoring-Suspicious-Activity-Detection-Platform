from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Optional
from app.database.connection import get_db
from app.services.investigation_service import InvestigationService
from app.api.deps import get_current_user, require_role
from app.models.user import User

router = APIRouter(prefix="/api/investigations", tags=["investigations"])

class InvestigationCreateRequest(BaseModel):
    alert_id: int

class InvestigationUpdateRequest(BaseModel):
    status: Optional[str] = None
    verdict: Optional[str] = None
    verdict_reason: Optional[str] = None

class AnalystNoteRequest(BaseModel):
    note_text: str

@router.get("")
def get_investigations(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns list of active and resolved SOC investigations. Requires authentication.
    """
    invs = InvestigationService.get_investigations(db, limit, offset)
    return [
        {
            "id": i.id,
            "alert_id": i.alert_id,
            "case_number": i.case_number,
            "title": i.title,
            "summary": i.summary,
            "source_ip": i.source_ip,
            "dest_ip": i.dest_ip,
            "severity": i.severity,
            "status": i.status,
            "assigned_analyst": i.assigned_analyst,
            "verdict": i.verdict,
            "verdict_reason": i.verdict_reason,
            "created_at": i.created_at.isoformat() if i.created_at else None,
            "updated_at": i.updated_at.isoformat() if i.updated_at else None,
            "closed_at": i.closed_at.isoformat() if i.closed_at else None,
            "notes": [
                {
                    "id": n.id,
                    "timestamp": n.timestamp.isoformat() if n.timestamp else None,
                    "author": n.author,
                    "note_text": n.note_text
                }
                for n in i.notes
            ]
        }
        for i in invs
    ]

@router.get("/{investigation_id}")
def get_investigation_by_id(
    investigation_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns single investigation case details including notes. Requires authentication.
    """
    i = InvestigationService.get_investigation_by_id(db, investigation_id)
    if not i:
        raise HTTPException(status_code=404, detail="Investigation not found")

    return {
        "id": i.id,
        "alert_id": i.alert_id,
        "case_number": i.case_number,
        "title": i.title,
        "summary": i.summary,
        "source_ip": i.source_ip,
        "dest_ip": i.dest_ip,
        "severity": i.severity,
        "status": i.status,
        "assigned_analyst": i.assigned_analyst,
        "verdict": i.verdict,
        "verdict_reason": i.verdict_reason,
        "created_at": i.created_at.isoformat() if i.created_at else None,
        "updated_at": i.updated_at.isoformat() if i.updated_at else None,
        "closed_at": i.closed_at.isoformat() if i.closed_at else None,
        "notes": [
            {
                "id": n.id,
                "timestamp": n.timestamp.isoformat() if n.timestamp else None,
                "author": n.author,
                "note_text": n.note_text
            }
            for n in i.notes
        ]
    }

@router.post("")
def create_investigation(
    req: InvestigationCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("ADMIN", "ANALYST"))
):
    """
    Opens a new SOC incident investigation from a database alert. ADMIN and ANALYST only.
    """
    return InvestigationService.create_investigation_from_alert(
        db=db,
        alert_id=req.alert_id,
        user=current_user.username
    )

@router.patch("/{investigation_id}")
def update_investigation(
    investigation_id: int,
    req: InvestigationUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("ADMIN", "ANALYST"))
):
    """
    Performs controlled investigation status update, verdict assignment, and resolution. ADMIN and ANALYST only.
    """
    return InvestigationService.update_investigation(
        db=db,
        inv_id=investigation_id,
        user=current_user.username,
        status=req.status,
        verdict=req.verdict,
        verdict_reason=req.verdict_reason
    )

@router.post("/{investigation_id}/notes")
def add_analyst_note(
    investigation_id: int,
    req: AnalystNoteRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("ADMIN", "ANALYST"))
):
    """
    Persists an analyst note to an open investigation case. ADMIN and ANALYST only.
    """
    note = InvestigationService.add_note(
        db=db,
        inv_id=investigation_id,
        author=current_user.username,
        note_text=req.note_text
    )
    return {
        "id": note.id,
        "timestamp": note.timestamp.isoformat(),
        "author": note.author,
        "note_text": note.note_text
    }

@router.get("/{investigation_id}/notes")
def get_investigation_notes(
    investigation_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns all analyst notes for an investigation. Requires authentication.
    """
    i = InvestigationService.get_investigation_by_id(db, investigation_id)
    if not i:
        raise HTTPException(status_code=404, detail="Investigation not found")

    return [
        {
            "id": n.id,
            "timestamp": n.timestamp.isoformat(),
            "author": n.author,
            "note_text": n.note_text
        }
        for n in i.notes
    ]

@router.get("/{investigation_id}/timeline")
def get_investigation_timeline(
    investigation_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns real chronological timeline of events, alerts, notes, and verdicts. Requires authentication.
    """
    return InvestigationService.get_timeline(db, investigation_id)
