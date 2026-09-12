from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any

from app.database.connection import get_db
from app.api.deps import get_current_user
from app.models.user import User
from app.sigma.models import SigmaRule, SigmaRuleVersion
from app.sigma.schemas import (
    SigmaRuleCreate, SigmaRuleUpdate, SigmaRuleResponse,
    ValidationResult, SandboxRequest, SandboxResult,
    ExecutionStatisticsResponse, FieldMappingResponse
)
from app.sigma.parser import parse_sigma_yaml
from app.sigma.validator import validate_sigma_rule
from app.sigma.mapper import SigmaFieldMapper
from app.sigma.manager import SigmaManager
from app.sigma.sandbox import run_sigma_sandbox
from app.sigma.statistics import get_sigma_statistics
from app.sigma.versioning import get_rule_versions
from app.realtime.publisher import (
    publish_sigma_rule_update, publish_sigma_rule_enabled,
    publish_sigma_rule_disabled, publish_sigma_sandbox_completed
)

router = APIRouter(prefix="/api/sigma", tags=["Sigma Engine"])

def check_rbac(current_user: User, allowed_roles: List[str]):
    if current_user.role not in allowed_roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role '{current_user.role}' is not authorized to perform this operation."
        )

@router.get("/rules", response_model=List[SigmaRuleResponse])
def get_sigma_rules(
    skip: int = 0,
    limit: int = 100,
    enabled: Optional[bool] = None,
    level: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns list of stored Sigma rules with filtering options. Accessible by VIEWER, ANALYST, and ADMIN.
    """
    query = db.query(SigmaRule)
    if enabled is not None:
        query = query.filter(SigmaRule.enabled == enabled)
    if level:
        query = query.filter(SigmaRule.level == level.lower())
    if status:
        query = query.filter(SigmaRule.status == status.upper())
    if search:
        query = query.filter(
            (SigmaRule.title.ilike(f"%{search}%")) |
            (SigmaRule.rule_id.ilike(f"%{search}%")) |
            (SigmaRule.description.ilike(f"%{search}%"))
        )

    return query.order_by(SigmaRule.created_at.desc()).offset(skip).limit(limit).all()

@router.post("/rules/import", status_code=status.HTTP_201_CREATED)
def import_sigma_rules(
    payload: SigmaRuleCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Imports single or multi-doc Sigma YAML rules into NetWatch. Requires ANALYST or ADMIN role.
    """
    check_rbac(current_user, ["ANALYST", "ADMIN"])
    try:
        res = SigmaManager.import_rule(db, payload.raw_yaml, user_id=current_user.username)
        return res
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/rules/{rule_id}", response_model=SigmaRuleResponse)
def get_sigma_rule_by_id(
    rule_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns single Sigma rule details by rule_id.
    """
    rule = db.query(SigmaRule).filter(SigmaRule.rule_id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=44, detail=f"Rule '{rule_id}' not found.")
    return rule

@router.put("/rules/{rule_id}", response_model=SigmaRuleResponse)
def update_sigma_rule(
    rule_id: str,
    payload: SigmaRuleUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Updates an existing Sigma rule. Requires ANALYST or ADMIN role.
    """
    check_rbac(current_user, ["ANALYST", "ADMIN"])
    rule = db.query(SigmaRule).filter(SigmaRule.rule_id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail=f"Rule '{rule_id}' not found.")

    if payload.raw_yaml:
        res = SigmaManager.import_rule(db, payload.raw_yaml, user_id=current_user.username)
        rule = db.query(SigmaRule).filter(SigmaRule.rule_id == rule_id).first()

    if payload.enabled is not None:
        rule = SigmaManager.toggle_rule(db, rule_id, payload.enabled, user_id=current_user.username)

    publish_sigma_rule_update(rule)
    return rule

@router.delete("/rules/{rule_id}")
def delete_sigma_rule(
    rule_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Deletes a Sigma rule. Requires ADMIN role.
    """
    check_rbac(current_user, ["ADMIN"])
    rule = db.query(SigmaRule).filter(SigmaRule.rule_id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail=f"Rule '{rule_id}' not found.")

    db.delete(rule)
    db.commit()
    return {"message": f"Rule '{rule_id}' deleted successfully."}

@router.post("/rules/{rule_id}/enable")
def enable_sigma_rule(
    rule_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Enables a validated Sigma rule for live production evaluation. Requires ANALYST or ADMIN role.
    """
    check_rbac(current_user, ["ANALYST", "ADMIN"])
    try:
        rule = SigmaManager.toggle_rule(db, rule_id, True, user_id=current_user.username)
        publish_sigma_rule_enabled(rule)
        return {"status": "SUCCESS", "message": f"Rule '{rule_id}' enabled.", "rule": rule}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/rules/{rule_id}/disable")
def disable_sigma_rule(
    rule_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Disables an active Sigma rule. Requires ANALYST or ADMIN role.
    """
    check_rbac(current_user, ["ANALYST", "ADMIN"])
    try:
        rule = SigmaManager.toggle_rule(db, rule_id, False, user_id=current_user.username)
        publish_sigma_rule_disabled(rule)
        return {"status": "SUCCESS", "message": f"Rule '{rule_id}' disabled.", "rule": rule}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/rules/{rule_id}/versions")
def get_rule_version_history(
    rule_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Retrieves version history for a Sigma rule.
    """
    versions = get_rule_versions(db, rule_id)
    return [
        {
            "id": v.id,
            "rule_id": v.rule_id,
            "version": v.version,
            "author": v.author,
            "change_summary": v.change_summary,
            "created_at": v.created_at
        } for v in versions
    ]

@router.post("/validate", response_model=ValidationResult)
def validate_yaml(
    payload: SigmaRuleCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Validates raw Sigma YAML without saving it to database.
    """
    try:
        parsed_list = parse_sigma_yaml(payload.raw_yaml)
        res = validate_sigma_rule(parsed_list[0], db=db)
        return res
    except Exception as e:
        return ValidationResult(
            valid=False,
            status="INVALID",
            errors=[str(e)],
            warnings=[],
            unsupported_features=[]
        )

@router.post("/sandbox/test", response_model=SandboxResult)
def test_in_sandbox(
    payload: SandboxRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Executes a Sigma rule in Detection Sandbox mode against REAL historical telemetry events.
    Does NOT activate rules or generate fake production alerts. Accessible by ANALYST and ADMIN.
    """
    check_rbac(current_user, ["ANALYST", "ADMIN"])
    res = run_sigma_sandbox(
        db,
        raw_yaml=payload.raw_yaml,
        rule_id=payload.rule_id,
        hours=payload.hours,
        log_source=payload.log_source
    )
    publish_sigma_sandbox_completed(res)
    return res

@router.get("/statistics", response_model=ExecutionStatisticsResponse)
def get_statistics(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns aggregated execution statistics for all Sigma rules.
    """
    return get_sigma_statistics(db)

@router.get("/mappings", response_model=List[FieldMappingResponse])
def get_field_mappings(
    current_user: User = Depends(get_current_user)
):
    """
    Returns list of supported field mappings between Sigma and NetWatch.
    """
    return SigmaFieldMapper.get_all_mappings()
