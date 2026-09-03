from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from app.database.connection import Base

class Investigation(Base):
    __tablename__ = "investigations"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(Integer, nullable=True, index=True)
    case_number = Column(String, unique=True, index=True)  # e.g., INC-2026-001
    title = Column(String)
    summary = Column(Text)
    source_ip = Column(String)
    dest_ip = Column(String)
    severity = Column(String, default="HIGH")
    status = Column(String, default="OPEN", index=True)  # OPEN, IN_PROGRESS, CONTAINED, RESOLVED, CLOSED
    assigned_analyst = Column(String, default="SOC Analyst")
    verdict = Column(String, nullable=True)  # TRUE_POSITIVE, FALSE_POSITIVE, BENIGN, INCONCLUSIVE
    verdict_reason = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    closed_at = Column(DateTime, nullable=True)

    notes = relationship("AnalystNote", back_populates="investigation", cascade="all, delete-orphan")

class AnalystNote(Base):
    __tablename__ = "analyst_notes"

    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id"))
    timestamp = Column(DateTime, default=datetime.utcnow)
    author = Column(String)
    note_text = Column(Text)

    investigation = relationship("Investigation", back_populates="notes")
