from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class AlertBase(BaseModel):
    detection_id: Optional[int] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    severity: str = "HIGH"
    status: str = "NEW"
    title: str
    description: str
    risk_score: float = 0.0

class AlertResponse(AlertBase):
    id: int

    class Config:
        from_attributes = True
