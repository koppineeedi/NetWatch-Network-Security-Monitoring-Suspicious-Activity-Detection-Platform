import datetime
from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text, ForeignKey, Index
from sqlalchemy.orm import relationship
from app.database.connection import Base

class BehaviorBaseline(Base):
    __tablename__ = "behavior_baselines"

    id = Column(Integer, primary_key=True, index=True)
    entity_type = Column(String, index=True, nullable=False)  # IP, HOST, USER, PROCESS
    entity_id = Column(String, index=True, nullable=False)
    feature_name = Column(String, index=True, nullable=False)
    mean_value = Column(Float, default=0.0)
    standard_deviation = Column(Float, default=0.0)
    median_value = Column(Float, default=0.0)
    percentile_95 = Column(Float, default=0.0)
    minimum_value = Column(Float, default=0.0)
    maximum_value = Column(Float, default=0.0)
    sample_count = Column(Integer, default=0)
    baseline_window_start = Column(DateTime, nullable=True)
    baseline_window_end = Column(DateTime, nullable=True)
    last_updated = Column(DateTime, default=datetime.datetime.utcnow)
    status = Column(String, default="ACTIVE", index=True)  # ACTIVE, INSUFFICIENT_DATA, STALE

    __table_args__ = (
        Index("idx_baseline_entity_feature", "entity_type", "entity_id", "feature_name"),
    )

class Entity(Base):
    __tablename__ = "entities"

    id = Column(Integer, primary_key=True, index=True)
    entity_id = Column(String, unique=True, index=True, nullable=False)
    entity_type = Column(String, index=True, nullable=False)  # IP, HOST, USER, PROCESS, DOMAIN
    first_seen = Column(DateTime, default=datetime.datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.datetime.utcnow)
    event_count = Column(Integer, default=0)
    current_risk_score = Column(Float, default=0.0, index=True)  # 0.0 to 100.0
    baseline_status = Column(String, default="INSUFFICIENT_DATA", index=True)
    anomaly_count = Column(Integer, default=0)
    high_risk_count = Column(Integer, default=0)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

class EntityRiskHistory(Base):
    __tablename__ = "entity_risk_history"

    id = Column(Integer, primary_key=True, index=True)
    entity_type = Column(String, index=True, nullable=False)
    entity_id = Column(String, index=True, nullable=False)
    previous_score = Column(Float, default=0.0)
    new_score = Column(Float, default=0.0)
    contributing_factor = Column(String, nullable=True)
    evidence_id = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, index=True)

class Anomaly(Base):
    __tablename__ = "anomalies"

    id = Column(Integer, primary_key=True, index=True)
    entity_type = Column(String, index=True, nullable=False)
    entity_id = Column(String, index=True, nullable=False)
    feature = Column(String, index=True, nullable=False)
    observed_value = Column(Float, nullable=False)
    baseline_value = Column(Float, nullable=False)
    deviation = Column(Float, nullable=False)
    anomaly_score = Column(Float, nullable=False, index=True)  # 0 to 100
    confidence = Column(Float, default=0.85)  # 0 to 1
    severity = Column(String, index=True, nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    explanation = Column(Text, nullable=False)
    evidence = Column(Text, nullable=True)  # JSON metadata
    mitre_technique = Column(String, nullable=True)  # e.g., T1046
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)

class Campaign(Base):
    __tablename__ = "campaigns"

    id = Column(Integer, primary_key=True, index=True)
    campaign_id = Column(String, unique=True, index=True, nullable=False)  # e.g., CMP-2026-0001
    name = Column(String, nullable=False)
    status = Column(String, default="ACTIVE", index=True)  # ACTIVE, MONITORING, RESOLVED, CLOSED
    risk_score = Column(Float, default=0.0, index=True)
    confidence = Column(Float, default=0.85)
    first_seen = Column(DateTime, default=datetime.datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.datetime.utcnow)
    event_count = Column(Integer, default=0)
    entity_count = Column(Integer, default=0)
    technique_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

class CampaignEvent(Base):
    __tablename__ = "campaign_events"

    id = Column(Integer, primary_key=True, index=True)
    campaign_id = Column(String, ForeignKey("campaigns.campaign_id"), index=True, nullable=False)
    event_id = Column(Integer, nullable=True)
    alert_id = Column(Integer, nullable=True)
    anomaly_id = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
