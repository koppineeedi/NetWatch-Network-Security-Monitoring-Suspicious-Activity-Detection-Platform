from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime

class IOCCreate(BaseModel):
    ioc_value: str
    ioc_type: str  # IP, DOMAIN, URL, HASH_MD5, HASH_SHA1, HASH_SHA256, EMAIL
    source: str = "MANUAL_UPLOAD"
    confidence: int = 50
    severity: str = "MEDIUM"
    expiration: Optional[datetime] = None
    tags: Optional[str] = None
    raw_metadata: Optional[str] = None

class IOCResponse(BaseModel):
    id: int
    ioc_value: str
    normalized_value: str
    ioc_type: str
    source: str
    confidence: int
    severity: str
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    expiration: Optional[datetime] = None
    tags: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class IOCMatchResponse(BaseModel):
    id: int
    event_id: Optional[int] = None
    alert_id: Optional[int] = None
    ioc_id: int
    ioc_value: str
    ioc_type: str
    matched_field: str
    provider: str
    confidence: int
    severity: str
    tags: Optional[str] = None
    timestamp: datetime

    class Config:
        from_attributes = True

class IPReputationResponse(BaseModel):
    ip_address: str
    reputation_score: float
    abuse_confidence: int
    country: Optional[str] = None
    asn: Optional[str] = None
    organization: Optional[str] = None
    isp: Optional[str] = None
    categories: Optional[str] = None
    provider: str
    status: str  # SUCCESS, ERROR, NOT_CONFIGURED
    last_error: Optional[str] = None
    lookup_timestamp: datetime

class IPGeolocationResponse(BaseModel):
    ip_address: str
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    asn: Optional[str] = None
    organization: Optional[str] = None
    provider: str
    status: str

class ProviderStatusResponse(BaseModel):
    provider_name: str
    display_name: str
    status: str  # CONNECTED, NOT_CONFIGURED, DISABLED, ERROR
    enabled: bool
    ioc_count: int
    last_sync: Optional[datetime] = None
    last_error: Optional[str] = None
