from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database.connection import get_db
from app.collectors.local_network import local_collector_instance
from app.api.deps import get_current_user, require_role
from app.models.user import User

router = APIRouter(prefix="/api/telemetry", tags=["telemetry"])

@router.get("/status")
def get_telemetry_status(current_user: User = Depends(get_current_user)):
    """
    Returns real-time telemetry collector status. Requires authentication.
    """
    return local_collector_instance.get_status()

@router.post("/start")
def start_telemetry(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("ADMIN", "ANALYST"))
):
    """
    Starts background local network connection telemetry collection loop. ADMIN and ANALYST only.
    """
    res = local_collector_instance.start(db)
    return res

@router.post("/stop")
def stop_telemetry(
    current_user: User = Depends(require_role("ADMIN", "ANALYST"))
):
    """
    Stops background local network connection telemetry collection loop. ADMIN and ANALYST only.
    """
    res = local_collector_instance.stop()
    return res
