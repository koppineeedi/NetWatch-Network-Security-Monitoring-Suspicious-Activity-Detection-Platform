from sqlalchemy import Column, Integer, String, DateTime, Float, Text
from datetime import datetime
from app.database.connection import Base

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    detection_id = Column(Integer, nullable=True, index=True)
    detection_type = Column(String, index=True)
    severity = Column(String, index=True)  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    confidence = Column(Float, default=0.85)
    risk_score = Column(Float, default=0.0)
    source_ip = Column(String, index=True, nullable=True)
    dest_ip = Column(String, index=True, nullable=True)
    dest_port = Column(Integer, nullable=True)
    protocol = Column(String, nullable=True)
    description = Column(String)
    explanation = Column(Text)
    status = Column(String, default="NEW", index=True)  # NEW, INVESTIGATING, TRUE_POSITIVE, FALSE_POSITIVE, RESOLVED, CLOSED
    assigned_analyst = Column(String, default="Unassigned")
    rule_id = Column(String, nullable=True)
    resolution = Column(String, nullable=True)
    resolution_reason = Column(Text, nullable=True)
