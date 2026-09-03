from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from typing import List
from app.database.connection import get_db
from app.models.audit import AuditLog
from app.api.deps import get_current_user
from app.models.user import User

router = APIRouter(prefix="/api/audit", tags=["audit"])

@router.get("")
def get_audit_logs(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns audit log history of analyst state transitions, assignments, notes, and logins. Requires authentication.
    """
    logs = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).offset(offset).limit(limit).all()
    return [
        {
            "id": l.id,
            "timestamp": l.timestamp.isoformat() if l.timestamp else None,
            "user": l.user,
            "action": l.action,
            "resource_type": l.resource_type,
            "resource_id": l.resource_id,
            "result": l.result,
            "details": l.details
        }
        for l in logs
    ]
