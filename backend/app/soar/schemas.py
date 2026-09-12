from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from datetime import datetime

class PlaybookStepSchema(BaseModel):
    step_id: str
    action: str  # BLOCK_IP, UNBLOCK_IP, ISOLATE_HOST, RESTORE_HOST, KILL_PROCESS, DISABLE_ACCOUNT, ENABLE_ACCOUNT, ADD_FIREWALL_RULE, REMOVE_FIREWALL_RULE, NOTIFY_ANALYST
    target: Optional[str] = None
    parameters: Dict[str, Any] = Field(default_factory=dict)
    conditions: Dict[str, Any] = Field(default_factory=dict)
    timeout: int = 30
    retry_count: int = 0
    continue_on_failure: bool = False

class PlaybookCreate(BaseModel):
    name: str
    description: Optional[str] = None
    trigger_type: str = "ALERT_CREATED"  # ALERT_CREATED, ALERT_UPDATED, SIGMA_MATCH, IOC_MATCH, UEBA_ANOMALY, ENTITY_RISK_THRESHOLD, MANUAL
    trigger_config: Dict[str, Any] = Field(default_factory=dict)
    approval_policy: str = "ANALYST_APPROVAL"  # AUTOMATIC, ANALYST_APPROVAL, ADMIN_APPROVAL, MANUAL_ONLY
    steps: List[PlaybookStepSchema]

class PlaybookUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    enabled: Optional[bool] = None
    approval_policy: Optional[str] = None
    steps: Optional[List[PlaybookStepSchema]] = None

class PlaybookResponse(BaseModel):
    id: int
    playbook_id: str
    name: str
    description: Optional[str] = None
    enabled: bool
    version: int
    trigger_type: str
    trigger_config: Optional[Dict[str, Any]] = None
    approval_policy: str
    steps: List[Dict[str, Any]]
    created_by: str
    updated_by: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class ActionRequest(BaseModel):
    action_type: str
    target: str
    alert_id: Optional[int] = None
    case_id: Optional[str] = None
    playbook_id: Optional[str] = None
    parameters: Dict[str, Any] = Field(default_factory=dict)
    dry_run: bool = False

class ActionResponse(BaseModel):
    id: int
    action_id: str
    action_type: str
    status: str
    alert_id: Optional[int] = None
    case_id: Optional[str] = None
    playbook_id: Optional[str] = None
    requested_by: str
    approved_by: Optional[str] = None
    target: str
    parameters: Optional[Dict[str, Any]] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    rollback_available: bool
    rollback_status: str
    idempotency_key: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True

class ApprovalDecisionRequest(BaseModel):
    decision: str  # APPROVED, DENIED, CANCELLED
    reason: Optional[str] = None

class ApprovalResponse(BaseModel):
    id: int
    approval_id: str
    action_id: str
    required_role: str
    status: str
    requested_by: str
    decided_by: Optional[str] = None
    decision_reason: Optional[str] = None
    created_at: datetime
    expires_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class IntegrationResponse(BaseModel):
    id: int
    name: str
    type: str
    status: str
    config: Optional[Dict[str, Any]] = None
    last_checked: datetime

    class Config:
        from_attributes = True

class SoarStatisticsResponse(BaseModel):
    total_playbooks: int
    enabled_playbooks: int
    total_actions: int
    pending_approvals: int
    successful_actions: int
    failed_actions: int
    dry_run_actions: int
    not_configured_actions: int
    integrations_status: Dict[str, str]
