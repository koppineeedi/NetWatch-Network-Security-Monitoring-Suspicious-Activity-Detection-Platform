import datetime
from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text, ForeignKey, Index
from app.database.connection import Base

class IOC(Base):
    __tablename__ = "iocs"

    id = Column(Integer, primary_key=True, index=True)
    ioc_value = Column(String, nullable=False)
    normalized_value = Column(String, index=True, nullable=False)
    ioc_type = Column(String, index=True, nullable=False)  # IP, DOMAIN, URL, HASH_MD5, HASH_SHA1, HASH_SHA256, EMAIL
    source = Column(String, index=True, nullable=False)  # AbuseIPDB, AlienVault_OTX, MISP, MANUAL_UPLOAD, FEED
    confidence = Column(Integer, default=50)  # 0 to 100
    severity = Column(String, default="MEDIUM")  # CRITICAL, HIGH, MEDIUM, LOW
    first_seen = Column(DateTime, default=datetime.datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.datetime.utcnow)
    expiration = Column(DateTime, index=True, nullable=True)
    tags = Column(String, nullable=True)  # Comma-separated tags
    raw_metadata = Column(Text, nullable=True)  # JSON string metadata
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    __table_args__ = (
        Index("idx_ioc_norm_type", "normalized_value", "ioc_type"),
    )

class IOCMatch(Base):
    __tablename__ = "ioc_matches"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(Integer, ForeignKey("network_events.id"), nullable=True, index=True)
    alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=True, index=True)
    ioc_id = Column(Integer, ForeignKey("iocs.id"), nullable=False, index=True)
    ioc_value = Column(String, nullable=False)
    ioc_type = Column(String, nullable=False)
    matched_field = Column(String, nullable=False)  # source_ip, dest_ip, domain, etc.
    provider = Column(String, nullable=False)
    confidence = Column(Integer, default=50)
    severity = Column(String, default="MEDIUM")
    tags = Column(String, nullable=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)

class IPReputationCache(Base):
    __tablename__ = "ip_reputation_cache"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, unique=True, index=True, nullable=False)
    reputation_score = Column(Float, default=0.0)
    abuse_confidence = Column(Integer, default=0)
    country = Column(String, nullable=True)
    asn = Column(String, nullable=True)
    organization = Column(String, nullable=True)
    isp = Column(String, nullable=True)
    categories = Column(String, nullable=True)
    provider = Column(String, nullable=False)
    status = Column(String, default="SUCCESS")  # SUCCESS, ERROR, NOT_CONFIGURED
    last_error = Column(Text, nullable=True)
    lookup_timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)

class IPGeolocationCache(Base):
    __tablename__ = "ip_geolocation_cache"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, unique=True, index=True, nullable=False)
    country = Column(String, nullable=True)
    country_code = Column(String, nullable=True)
    region = Column(String, nullable=True)
    city = Column(String, nullable=True)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    asn = Column(String, nullable=True)
    organization = Column(String, nullable=True)
    provider = Column(String, nullable=False)
    status = Column(String, default="SUCCESS")
    lookup_timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)

class ThreatIntelProvider(Base):
    __tablename__ = "threat_intel_providers"

    id = Column(Integer, primary_key=True, index=True)
    provider_name = Column(String, unique=True, index=True, nullable=False)
    display_name = Column(String, nullable=False)
    status = Column(String, default="NOT_CONFIGURED")  # CONNECTED, NOT_CONFIGURED, DISABLED, ERROR
    enabled = Column(Boolean, default=False)
    last_sync = Column(DateTime, nullable=True)
    last_error = Column(Text, nullable=True)
    ioc_count = Column(Integer, default=0)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
