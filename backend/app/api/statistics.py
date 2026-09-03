from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database.connection import get_db
from app.services.statistics_service import StatisticsService
from app.api.deps import get_current_user
from app.models.user import User

router = APIRouter(prefix="/api/statistics", tags=["statistics"])

@router.get("")
def get_statistics(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns real dashboard statistics computed directly from SQLite database records. Requires authentication.
    """
    return StatisticsService.get_statistics(db)
