from sqlalchemy import Column, Integer, String, DateTime, Float, Text, Boolean, JSON, ForeignKey
from datetime import datetime
from app.database.connection import Base

class SoarPlaybook(Base):
    __tablename__ = "soar_playbooks"

    id = Column(Integer, primary_key=True, index=True)
    playbook_id = Column(String, unique=True, index=True, nullable=False)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    enabled = Column(Boolean, default=True, index=True)
    version = Column(Integer, default=1)
    trigger_type = Column(String, nullable=False)  # ALERT_CREATED, SIGMA_MATCH, IOC_MATCH, UEBA_ANOMALY, ENTITY_RISK_THRESHOLD, MANUAL
    trigger_config = Column(JSON, nullable=True)
    approval_policy = Column(String, default="ANALYST_APPROVAL")  # AUTOMATIC, ANALYST_APPROVAL, ADMIN_APPROVAL, MANUAL_ONLY
    steps = Column(JSON, nullable=False)  # List of ordered step dicts
    created_by = Column(String, default="system")
    updated_by = Column(String, default="system")
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class SoarPlaybookVersion(Base):
    __tablename__ = "soar_playbook_versions"

    id = Column(Integer, primary_key=True, index=True)
    playbook_id = Column(String, index=True, nullable=False)
    version = Column(Integer, nullable=False)
    name = Column(String, nullable=False)
    steps = Column(JSON, nullable=False)
    approval_policy = Column(String, default="ANALYST_APPROVAL")
    created_by = Column(String, default="system")
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

class SoarPlaybookExecution(Base):
    __tablename__ = "soar_playbook_executions"

    id = Column(Integer, primary_key=True, index=True)
    execution_id = Column(String, unique=True, index=True, nullable=False)
    playbook_id = Column(String, index=True, nullable=False)
    trigger_event = Column(String, nullable=False)
    alert_id = Column(Integer, nullable=True, index=True)
    status = Column(String, default="RUNNING", index=True)  # RUNNING, SUCCESS, FAILED, CANCELLED
    step_results = Column(JSON, nullable=True)
    started_at = Column(DateTime, default=datetime.utcnow, index=True)
    completed_at = Column(DateTime, nullable=True, index=True)

class SoarAction(Base):
    __tablename__ = "soar_actions"

    id = Column(Integer, primary_key=True, index=True)
    action_id = Column(String, unique=True, index=True, nullable=False)
    action_type = Column(String, index=True, nullable=False)  # BLOCK_IP, UNBLOCK_IP, ISOLATE_HOST, RESTORE_HOST, KILL_PROCESS, DISABLE_ACCOUNT, ENABLE_ACCOUNT, ADD_FIREWALL_RULE, REMOVE_FIREWALL_RULE, NOTIFY_ANALYST
    status = Column(String, default="PENDING_APPROVAL", index=True)  # PENDING_APPROVAL, APPROVED, RUNNING, SUCCESS, FAILED, DENIED, CANCELLED, DRY_RUN, NOT_CONFIGURED
    alert_id = Column(Integer, nullable=True, index=True)
    case_id = Column(String, nullable=True, index=True)
    playbook_id = Column(String, nullable=True, index=True)
    requested_by = Column(String, default="system")
    approved_by = Column(String, nullable=True)
    target = Column(String, nullable=False, index=True)
    parameters = Column(JSON, nullable=True)
    result = Column(JSON, nullable=True)
    error = Column(Text, nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True, index=True)
    rollback_available = Column(Boolean, default=False)
    rollback_status = Column(String, default="NONE")  # NONE, PENDING, EXECUTED, FAILED, NOT_AVAILABLE
    idempotency_key = Column(String, index=True, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

class SoarApproval(Base):
    __tablename__ = "soar_approvals"

    id = Column(Integer, primary_key=True, index=True)
    approval_id = Column(String, unique=True, index=True, nullable=False)
    action_id = Column(String, index=True, nullable=False)
    required_role = Column(String, default="ANALYST")  # ANALYST, ADMIN
    status = Column(String, default="PENDING", index=True)  # PENDING, APPROVED, DENIED, EXPIRED, CANCELLED
    requested_by = Column(String, default="system")
    decided_by = Column(String, nullable=True)
    decision_reason = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    expires_at = Column(DateTime, nullable=True)

class SoarIntegration(Base):
    __tablename__ = "soar_integrations"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    type = Column(String, nullable=False)  # LOCAL_FIREWALL, HOST_ISOLATION, PROCESS_CONTROL, IDENTITY_PROVIDER, NOTIFICATION
    status = Column(String, default="NOT_CONFIGURED", index=True)  # CONFIGURED, CONNECTED, NOT_CONFIGURED, ERROR
    config = Column(JSON, nullable=True)
    last_checked = Column(DateTime, default=datetime.utcnow)

class SoarActionResult(Base):
    __tablename__ = "soar_action_results"

    id = Column(Integer, primary_key=True, index=True)
    action_id = Column(String, index=True, nullable=False)
    step_index = Column(Integer, default=0)
    status = Column(String, nullable=False)
    output = Column(JSON, nullable=True)
    executed_at = Column(DateTime, default=datetime.utcnow)
