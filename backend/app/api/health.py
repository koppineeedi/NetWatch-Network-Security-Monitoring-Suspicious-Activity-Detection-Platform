from fastapi import APIRouter
from datetime import datetime

router = APIRouter(prefix="/api/health", tags=["health"])

@router.get("")
def health_check():
    return {
        "status": "HEALTHY",
        "database": "CONNECTED",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0"
    }
