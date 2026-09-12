"""
NetWatch Enterprise Enhancement Cycle 2 - UEBA & Analytics API Router
Provides operational status, statistical overview, and manual trigger control.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import Dict, Any

from app.database.connection import get_db
from app.api.deps import get_current_user, require_role
from app.models.user import User
from app.analytics.manager import AnalyticsManager
from app.analytics.schemas import UEBAStatusResponse, AnalyticsStatsResponse

router = APIRouter(prefix="/api/ueba", tags=["UEBA & Analytics"])

@router.get("/status", response_model=UEBAStatusResponse)
def get_ueba_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Returns operational status and baseline counts for the UEBA engine."""
    return AnalyticsManager.get_status(db)

@router.get("/stats", response_model=AnalyticsStatsResponse)
def get_analytics_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Returns aggregated summary metrics for UEBA & Behavioral Analytics dashboard."""
    return AnalyticsManager.get_stats(db)

@router.post("/trigger-cycle")
def trigger_analytics_cycle(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("ADMIN", "ANALYST"))
):
    """Manually triggers an immediate analytics cycle across all entities."""
    res = AnalyticsManager.run_cycle(db)
    return {
        "message": "Analytics and UEBA cycle completed successfully",
        "result": res
    }
