import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, JSON
from app.database.connection import Base

class Connector(Base):
    __tablename__ = "connectors"

    id = Column(Integer, primary_key=True, index=True)
    connector_id = Column(String, unique=True, index=True, nullable=False)
    name = Column(String, nullable=False)
    connector_type = Column(String, nullable=False)  # SYSLOG, AWS_CLOUDTRAIL, AZURE_ACTIVITY, GCP_AUDIT
    status = Column(String, default="DISABLED", nullable=False)  # DISABLED, CONFIGURED, CONNECTED, ERROR
    config_json = Column(Text, nullable=True)  # Redacted/encrypted configuration string
    last_seen = Column(DateTime, nullable=True)
    last_error = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
