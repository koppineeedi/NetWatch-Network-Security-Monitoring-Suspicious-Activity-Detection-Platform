from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

class AnalystNoteResponse(BaseModel):
    id: int
    timestamp: datetime
    author: str
    note_text: str

    class Config:
        from_attributes = True

class InvestigationResponse(BaseModel):
    id: int
    alert_id: Optional[int] = None
    case_number: str
    title: str
    summary: str
    source_ip: str
    dest_ip: str
    severity: str
    status: str
    assigned_analyst: str
    created_at: datetime
    updated_at: datetime
    notes: List[AnalystNoteResponse] = []

    class Config:
        from_attributes = True
