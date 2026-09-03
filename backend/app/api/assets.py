from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database.connection import get_db
from app.models.asset import Asset
from app.api.deps import get_current_user
from app.models.user import User

router = APIRouter(prefix="/api/assets", tags=["assets"])

@router.get("")
def get_assets(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns list of discovered host assets. Requires authentication.
    """
    assets = db.query(Asset).all()
    return [
        {
            "id": a.id,
            "ip_address": a.ip_address,
            "hostname": a.hostname,
            "os": a.os,
            "role": a.role,
            "criticality": a.criticality,
            "last_seen": a.last_seen.isoformat() if a.last_seen else None
        }
        for a in assets
    ]
