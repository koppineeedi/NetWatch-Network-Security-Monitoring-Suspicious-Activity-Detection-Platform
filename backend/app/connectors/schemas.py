from pydantic import BaseModel
from typing import Optional, Dict, Any
from datetime import datetime

class ConnectorCreate(BaseModel):
    connector_id: str
    name: str
    connector_type: str  # SYSLOG, AWS_CLOUDTRAIL, AZURE_ACTIVITY, GCP_AUDIT
    config: Optional[Dict[str, Any]] = None

class ConnectorUpdate(BaseModel):
    name: Optional[str] = None
    config: Optional[Dict[str, Any]] = None

class ConnectorResponse(BaseModel):
    id: int
    connector_id: str
    name: str
    connector_type: str
    status: str  # DISABLED, CONFIGURED, CONNECTED, ERROR, NOT_CONFIGURED
    config: Optional[Dict[str, Any]] = None  # Redacted parameters only
    last_seen: Optional[datetime] = None
    last_error: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class ConnectorTestResult(BaseModel):
    connector_id: str
    status: str
    message: str
    details: Optional[Dict[str, Any]] = None
