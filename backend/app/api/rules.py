from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Optional
from app.database.connection import get_db
from app.models.rule import DetectionRule
from app.api.deps import get_current_user, require_role
from app.models.user import User

router = APIRouter(prefix="/api/rules", tags=["rules"])

class RuleCreateRequest(BaseModel):
    rule_code: str
    name: str
    description: str
    severity: str
    enabled: bool = True
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    condition_logic: Optional[str] = None

class RuleUpdateRequest(BaseModel):
    enabled: Optional[bool] = None
    severity: Optional[str] = None
    description: Optional[str] = None

@router.get("")
def get_rules(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns list of active detection rules. Requires authentication.
    """
    rules = db.query(DetectionRule).all()
    return [
        {
            "id": r.id,
            "rule_code": r.rule_code,
            "name": r.name,
            "description": r.description,
            "severity": r.severity,
            "enabled": r.enabled,
            "mitre_tactic": r.mitre_tactic,
            "mitre_technique": r.mitre_technique,
            "condition_logic": r.condition_logic,
            "created_at": r.created_at.isoformat() if r.created_at else None
        }
        for r in rules
    ]

@router.post("")
def create_rule(
    req: RuleCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("ADMIN"))
):
    """
    Creates a new detection rule. ADMIN only.
    """
    existing = db.query(DetectionRule).filter(DetectionRule.rule_code == req.rule_code).first()
    if existing:
        raise HTTPException(status_code=400, detail="Rule code already exists")

    rule = DetectionRule(
        rule_code=req.rule_code,
        name=req.name,
        description=req.description,
        severity=req.severity,
        enabled=req.enabled,
        mitre_tactic=req.mitre_tactic,
        mitre_technique=req.mitre_technique,
        condition_logic=req.condition_logic
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return {
        "id": rule.id,
        "rule_code": rule.rule_code,
        "name": rule.name,
        "description": rule.description,
        "severity": rule.severity,
        "enabled": rule.enabled
    }

@router.patch("/{rule_id}")
def update_rule(
    rule_id: int,
    req: RuleUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("ADMIN"))
):
    """
    Updates rule status, severity, or description. ADMIN only.
    """
    rule = db.query(DetectionRule).filter(DetectionRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    if req.enabled is not None:
        rule.enabled = req.enabled
    if req.severity:
        rule.severity = req.severity
    if req.description:
        rule.description = req.description

    db.commit()
    db.refresh(rule)
    return {
        "id": rule.id,
        "rule_code": rule.rule_code,
        "name": rule.name,
        "description": rule.description,
        "severity": rule.severity,
        "enabled": rule.enabled
    }
