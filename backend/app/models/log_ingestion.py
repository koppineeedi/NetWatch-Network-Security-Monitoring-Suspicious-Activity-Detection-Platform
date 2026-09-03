from sqlalchemy import Column, Integer, String, DateTime
from datetime import datetime
from app.database.connection import Base

class LogIngestion(Base):
    __tablename__ = "log_ingestions"

    id = Column(Integer, primary_key=True, index=True)
    ingestion_id = Column(String, unique=True, index=True)
    filename = Column(String)
    file_type = Column(String)
    file_size_bytes = Column(Integer)
    source = Column(String, default="LOG_FILE")
    timestamp = Column(DateTime, default=datetime.utcnow)
    status = Column(String, default="SUCCESS")  # SUCCESS, PARTIAL_SUCCESS, FAILED
    records_received = Column(Integer, default=0)
    records_stored = Column(Integer, default=0)
    records_rejected = Column(Integer, default=0)
    records_duplicate = Column(Integer, default=0)
