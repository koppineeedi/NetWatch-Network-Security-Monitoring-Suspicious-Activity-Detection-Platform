from sqlalchemy import Column, Integer, String, DateTime, Float, Text
from datetime import datetime
from app.database.connection import Base

class NetworkEvent(Base):
    __tablename__ = "network_events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    source = Column(String, default="LOCAL_NETWORK", index=True)  # LOCAL_NETWORK, LOCAL_SYSTEM, WINDOWS_EVENT, LOG_FILE, SURICATA, ZEEK, TEST
    collector = Column(String, default="LOCAL_SYSTEM_COLLECTOR")
    event_type = Column(String, default="NETWORK_CONNECTION", index=True)
    source_ip = Column(String, index=True, nullable=True)
    source_port = Column(Integer, nullable=True)
    dest_ip = Column(String, index=True, nullable=True)
    dest_port = Column(Integer, index=True, nullable=True)
    protocol = Column(String, index=True, nullable=True)
    connection_state = Column(String, nullable=True)
    status = Column(String, default="NORMAL", index=True)
    risk_score = Column(Float, default=0.0)
    hostname = Column(String, nullable=True)
    process_name = Column(String, nullable=True)
    username = Column(String, nullable=True)
    bytes_sent = Column(Integer, default=0)
    bytes_received = Column(Integer, default=0)
    packets = Column(Integer, default=1)
    bytes = Column(Integer, default=0)
    asset_id = Column(Integer, nullable=True)
    source_host = Column(String, nullable=True)
    dest_host = Column(String, nullable=True)
    payload_summary = Column(Text, nullable=True)
