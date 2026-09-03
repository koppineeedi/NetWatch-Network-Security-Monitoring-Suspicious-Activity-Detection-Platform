from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from app.database.connection import get_db
from app.models.detection import Detection
from app.detection.engine import evaluate_batch
from app.api.deps import get_current_user, require_role
from app.models.user import User

router = APIRouter(prefix="/api/detections", tags=["detections"])

@router.get("")
def get_detections(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns list of authoritative detection records evaluated by backend detection engine.
    """
    dets = db.query(Detection).order_by(Detection.timestamp.desc()).offset(offset).limit(limit).all()
    return [
        {
            "id": d.id,
            "timestamp": d.timestamp.isoformat() if d.timestamp else None,
            "rule_code": d.rule_code,
            "rule_name": d.rule_name,
            "source_ip": d.source_ip,
            "target_ip": d.target_ip,
            "mitre_tactic": d.mitre_tactic,
            "mitre_technique": d.mitre_technique,
            "action_taken": d.action_taken,
            "details": d.details,
            "evidence": d.evidence,
            "risk_score": d.risk_score
        }
        for d in dets
    ]

@router.get("/{detection_id}")
def get_detection_by_id(
    detection_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns single detection record detail with evidence string.
    """
    d = db.query(Detection).filter(Detection.id == detection_id).first()
    if not d:
        raise HTTPException(status_code=404, detail="Detection record not found")
    return {
        "id": d.id,
        "timestamp": d.timestamp.isoformat() if d.timestamp else None,
        "rule_code": d.rule_code,
        "rule_name": d.rule_name,
        "source_ip": d.source_ip,
        "target_ip": d.target_ip,
        "mitre_tactic": d.mitre_tactic,
        "mitre_technique": d.mitre_technique,
        "action_taken": d.action_taken,
        "details": d.details,
        "evidence": d.evidence,
        "risk_score": d.risk_score
    }

@router.post("/evaluate")
def trigger_detection_evaluation(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("ADMIN", "ANALYST"))
):
    """
    Triggers manual evaluation sweep of unprocessed events against active rules. ADMIN and ANALYST only.
    """
    res = evaluate_batch(db)
    return {
        "status": "SUCCESS",
        "evaluated_by": current_user.username,
        "events_evaluated": res.get("events_evaluated", 0),
        "detections_created": res.get("detections_created", 0)
    }
