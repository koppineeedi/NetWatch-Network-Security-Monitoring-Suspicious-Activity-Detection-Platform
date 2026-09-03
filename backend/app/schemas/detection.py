from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class DetectionResponse(BaseModel):
    id: int
    timestamp: datetime
    rule_code: str
    rule_name: str
    source_ip: Optional[str] = None
    target_ip: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    action_taken: str = "ALERTED"
    details: Optional[str] = None
    evidence: Optional[str] = None
    risk_score: float = 0.0

    class Config:
        from_attributes = True
