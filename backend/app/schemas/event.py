from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class EventBase(BaseModel):
    timestamp: Optional[datetime] = None
    source: str = "LOCAL_NETWORK"
    collector: str = "LOCAL_SYSTEM_COLLECTOR"
    event_type: str = "NETWORK_CONNECTION"
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    protocol: Optional[str] = None
    connection_state: Optional[str] = None
    status: str = "NORMAL"
    risk_score: float = 0.0
    hostname: Optional[str] = None
    process_name: Optional[str] = None
    username: Optional[str] = None
    bytes_sent: int = 0
    bytes_received: int = 0
    packets: int = 1
    bytes: int = 0
    asset_id: Optional[int] = None
    source_host: Optional[str] = None
    dest_host: Optional[str] = None
    payload_summary: Optional[str] = None

class EventCreate(EventBase):
    pass

class EventResponse(EventBase):
    id: int

    class Config:
        from_attributes = True
