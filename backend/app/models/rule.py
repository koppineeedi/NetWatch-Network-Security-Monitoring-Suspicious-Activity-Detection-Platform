from sqlalchemy import Column, Integer, String, Boolean, Float, Text
from app.database.connection import Base

class DetectionRule(Base):
    __tablename__ = "detection_rules"

    id = Column(Integer, primary_key=True, index=True)
    rule_code = Column(String, unique=True, index=True)  # e.g., R-SCAN-01
    name = Column(String)
    category = Column(String)  # RECONNAISSANCE, BRUTE_FORCE, EXFILTRATION, ANOMALY, COMMAND_AND_CONTROL
    condition_desc = Column(Text)
    severity = Column(String, default="HIGH")  # CRITICAL, HIGH, MEDIUM, LOW
    threshold = Column(Integer, default=10)
    time_window = Column(Integer, default=60)  # seconds
    enabled = Column(Boolean, default=True)
