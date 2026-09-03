from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

class TelemetryStatusResponse(BaseModel):
    running: bool
    interval: int = 10
    last_collection_time: Optional[datetime] = None
    events_collected: int = 0
    errors: List[str] = []
