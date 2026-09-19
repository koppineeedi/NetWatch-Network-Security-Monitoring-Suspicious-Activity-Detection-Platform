from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey
from datetime import datetime
from app.database.connection import Base

class IncidentEvidence(Base):
    __tablename__ = "incident_evidence"

    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id"), index=True, nullable=False)
    evidence_type = Column(String, index=True)  # EVENT, ALERT, IOC, NETWORK_FLOW, LOG_ENTRY, NOTE
    source = Column(String)  # System or Analyst
    reference_id = Column(String, nullable=True)  # ID of linked event/alert/ioc
    summary = Column(Text)
    analyst_note = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    created_by = Column(String, default="SOC Analyst")

class ThreatHuntReport(Base):
    __tablename__ = "threat_hunt_reports"

    id = Column(Integer, primary_key=True, index=True)
    hunt_id = Column(String, unique=True, index=True)  # e.g. TH-2026-001
    title = Column(String)
    hypothesis = Column(Text)
    scope = Column(String, default="24h")
    query_params = Column(Text, nullable=True)  # JSON string of query/filters
    findings = Column(Text)
    affected_entities = Column(Text, nullable=True)
    iocs = Column(Text, nullable=True)
    mitre_techniques = Column(Text, nullable=True)
    conclusion = Column(Text)
    recommended_action = Column(Text, nullable=True)
    status = Column(String, default="COMPLETED", index=True)  # DRAFT, IN_PROGRESS, COMPLETED
    analyst = Column(String, default="SOC Analyst")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
