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
    user_filter: str = Query(None, alias="user"),
    action_filter: str = Query(None, alias="action"),
    resource_type_filter: str = Query(None, alias="resource_type"),
    search: str = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns audit log history of analyst state transitions, assignments, notes, and logins. Requires authentication.
    """
    query = db.query(AuditLog)

    if user_filter:
        query = query.filter(AuditLog.user.ilike(f"%{user_filter}%"))
    if action_filter:
        query = query.filter(AuditLog.action.ilike(f"%{action_filter}%"))
    if resource_type_filter:
        query = query.filter(AuditLog.resource_type.ilike(f"%{resource_type_filter}%"))
    if search:
        query = query.filter(
            (AuditLog.user.ilike(f"%{search}%")) |
            (AuditLog.action.ilike(f"%{search}%")) |
            (AuditLog.resource_type.ilike(f"%{search}%")) |
            (AuditLog.details.ilike(f"%{search}%"))
        )

    total = query.count()
    logs = query.order_by(AuditLog.timestamp.desc()).offset(offset).limit(limit).all()
    
    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "logs": [
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
    }
