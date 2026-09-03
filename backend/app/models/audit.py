from sqlalchemy import Column, Integer, String, DateTime, Text
from datetime import datetime
from app.database.connection import Base

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    user = Column(String)
    action = Column(String)  # e.g., ALERT_CREATED, ALERT_STATUS_CHANGED, INVESTIGATION_CREATED, NOTE_CREATED
    resource_type = Column(String)  # ALERT, INVESTIGATION, NOTE
    resource_id = Column(String)
    result = Column(String, default="SUCCESS")
    details = Column(Text, nullable=True)
