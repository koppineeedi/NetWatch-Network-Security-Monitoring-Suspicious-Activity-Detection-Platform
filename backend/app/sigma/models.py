from sqlalchemy import Column, Integer, String, DateTime, Float, Text, Boolean, JSON, ForeignKey
from datetime import datetime
from app.database.connection import Base

class SigmaRule(Base):
    __tablename__ = "sigma_rules"

    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(String, unique=True, index=True, nullable=False)
    title = Column(String, index=True, nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String, default="DRAFT", index=True)  # DRAFT, VALIDATED, ENABLED, DISABLED, ERROR
    level = Column(String, default="medium", index=True)   # informational, low, medium, high, critical
    author = Column(String, nullable=True)
    date = Column(String, nullable=True)
    modified = Column(String, nullable=True)
    logsource = Column(JSON, nullable=True)
    detection = Column(JSON, nullable=True)
    tags = Column(JSON, nullable=True)
    references = Column(JSON, nullable=True)
    falsepositives = Column(JSON, nullable=True)
    raw_yaml = Column(Text, nullable=False)
    normalized_rule = Column(JSON, nullable=True)
    enabled = Column(Boolean, default=False, index=True)
    version = Column(Integer, default=1)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = Column(String, default="system")
    updated_by = Column(String, default="system")

class SigmaRuleVersion(Base):
    __tablename__ = "sigma_rule_versions"

    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(String, index=True, nullable=False)
    version = Column(Integer, nullable=False)
    raw_yaml = Column(Text, nullable=False)
    normalized_rule = Column(JSON, nullable=True)
    author = Column(String, nullable=True)
    change_summary = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

class SigmaRuleExecution(Base):
    __tablename__ = "sigma_rule_executions"

    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(String, index=True, nullable=False)
    execution_type = Column(String, default="LIVE", index=True)  # LIVE, SANDBOX
    execution_time_ms = Column(Float, default=0.0)
    events_evaluated = Column(Integer, default=0)
    matches_found = Column(Integer, default=0)
    status = Column(String, default="SUCCESS", index=True)      # SUCCESS, ERROR, INSUFFICIENT_DATA
    error_message = Column(Text, nullable=True)
    executed_at = Column(DateTime, default=datetime.utcnow, index=True)

class SigmaRuleMatch(Base):
    __tablename__ = "sigma_rule_matches"

    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(String, index=True, nullable=False)
    event_id = Column(Integer, index=True, nullable=False)
    matched_fields = Column(JSON, nullable=False)
    evidence = Column(JSON, nullable=True)
    explanation = Column(Text, nullable=True)
    severity = Column(String, default="MEDIUM", index=True)
    mitre_techniques = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

class SigmaFieldMapping(Base):
    __tablename__ = "sigma_rule_field_mappings"

    id = Column(Integer, primary_key=True, index=True)
    sigma_field = Column(String, unique=True, index=True, nullable=False)
    netwatch_field = Column(String, nullable=True)
    supported = Column(Boolean, default=True, index=True)
    description = Column(Text, nullable=True)
