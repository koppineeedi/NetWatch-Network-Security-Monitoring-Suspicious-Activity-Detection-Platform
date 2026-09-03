from sqlalchemy import Column, Integer, String, DateTime, Text, Float
from datetime import datetime
from app.database.connection import Base

class Detection(Base):
    __tablename__ = "detections"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    rule_code = Column(String, index=True)
    rule_name = Column(String)
    source_ip = Column(String, nullable=True)
    target_ip = Column(String, nullable=True)
    mitre_tactic = Column(String, nullable=True)
    mitre_technique = Column(String, nullable=True)
    action_taken = Column(String, default="ALERTED")
    details = Column(Text, nullable=True)
    evidence = Column(Text, nullable=True)
    risk_score = Column(Float, default=0.0)
