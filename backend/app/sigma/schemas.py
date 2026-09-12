from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

class SigmaRuleCreate(BaseModel):
    raw_yaml: str

class SigmaRuleUpdate(BaseModel):
    raw_yaml: Optional[str] = None
    enabled: Optional[bool] = None

class ValidationResult(BaseModel):
    valid: bool
    status: str  # VALID, INVALID, UNSUPPORTED, DUPLICATE
    errors: List[str] = []
    warnings: List[str] = []
    unsupported_features: List[str] = []
    rule_id: Optional[str] = None
    title: Optional[str] = None

class FieldMappingResponse(BaseModel):
    sigma_field: str
    netwatch_field: Optional[str] = None
    supported: bool
    description: Optional[str] = None

class SandboxRequest(BaseModel):
    raw_yaml: Optional[str] = None
    rule_id: Optional[str] = None
    hours: int = Field(default=24, ge=1, le=168)
    log_source: Optional[str] = None

class MatchExplanation(BaseModel):
    reason: str
    matched_fields: List[Dict[str, Any]] = []
    condition: str

class SandboxResult(BaseModel):
    status: str  # SUCCESS, INSUFFICIENT_DATA, ERROR
    rule_id: Optional[str] = None
    rule_title: Optional[str] = None
    valid: bool = True
    mapped_fields_count: int = 0
    unsupported_fields: List[str] = []
    historical_matches_count: int = 0
    execution_time_ms: float = 0.0
    matches: List[Dict[str, Any]] = []
    warnings: List[str] = []

class SigmaRuleResponse(BaseModel):
    id: int
    rule_id: str
    title: str
    description: Optional[str] = None
    status: str
    level: str
    author: Optional[str] = None
    date: Optional[str] = None
    modified: Optional[str] = None
    logsource: Optional[Dict[str, Any]] = None
    tags: Optional[List[str]] = None
    references: Optional[List[str]] = None
    falsepositives: Optional[List[str]] = None
    enabled: bool
    version: int
    raw_yaml: str
    created_at: Any
    updated_at: Any

    class Config:
        from_attributes = True

class ExecutionStatisticsResponse(BaseModel):
    total_rules: int
    enabled_rules: int
    valid_rules: int
    invalid_rules: int
    total_executions: int
    total_matches: int
    average_execution_ms: float
