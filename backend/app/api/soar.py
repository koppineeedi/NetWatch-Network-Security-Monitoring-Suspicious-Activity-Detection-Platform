from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any

from app.database.connection import get_db
from app.api.deps import get_current_user
from app.models.user import User
from app.soar.models import SoarPlaybook, SoarPlaybookVersion, SoarAction, SoarApproval
from app.soar.schemas import (
    PlaybookCreate, PlaybookUpdate, PlaybookResponse,
    ActionRequest, ActionResponse, ApprovalDecisionRequest,
    ApprovalResponse, IntegrationResponse, SoarStatisticsResponse
)
from app.soar.manager import SoarManager
from app.soar.playbooks import PlaybookRunner
from app.soar.executor import ActionExecutor
from app.soar.approvals import ApprovalManager
from app.soar.rollback import RollbackEngine
from app.realtime.publisher import publish_soar_event

router = APIRouter(prefix="/api/soar", tags=["SOAR Engine"])

def check_rbac(current_user: User, allowed_roles: List[str]):
    if current_user.role not in allowed_roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role '{current_user.role}' is not authorized to perform this operation."
        )

@router.get("/playbooks", response_model=List[PlaybookResponse])
def get_playbooks(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns list of all stored SOAR playbooks. Accessible by VIEWER, ANALYST, and ADMIN.
    """
    SoarManager.seed_default_playbooks(db)
    return db.query(SoarPlaybook).order_by(SoarPlaybook.created_at.desc()).all()

@router.post("/playbooks", response_model=PlaybookResponse, status_code=status.HTTP_201_CREATED)
def create_playbook(
    payload: PlaybookCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Creates a new playbook. Requires ANALYST or ADMIN role.
    """
    check_rbac(current_user, ["ANALYST", "ADMIN"])
    pb_dict = payload.dict()
    # Convert step Pydantic objects to dicts
    pb_dict["steps"] = [s.dict() if hasattr(s, "dict") else s for s in payload.steps]
    pb = SoarManager.create_playbook(db, pb_dict, user_id=current_user.username)
    return pb

@router.get("/playbooks/{playbook_id}", response_model=PlaybookResponse)
def get_playbook_by_id(
    playbook_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns details of a single playbook by playbook_id.
    """
    pb = db.query(SoarPlaybook).filter(SoarPlaybook.playbook_id == playbook_id).first()
    if not pb:
        raise HTTPException(status_code=404, detail=f"Playbook '{playbook_id}' not found.")
    return pb

@router.put("/playbooks/{playbook_id}", response_model=PlaybookResponse)
def update_playbook(
    playbook_id: str,
    payload: PlaybookUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Updates a playbook and creates a new immutable version. Requires ANALYST or ADMIN role.
    """
    check_rbac(current_user, ["ANALYST", "ADMIN"])
    up_dict = payload.dict(exclude_unset=True)
    if "steps" in up_dict and up_dict["steps"] is not None:
        up_dict["steps"] = [s.dict() if hasattr(s, "dict") else s for s in payload.steps]
    try:
        pb = SoarManager.update_playbook(db, playbook_id, up_dict, user_id=current_user.username)
        return pb
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@router.delete("/playbooks/{playbook_id}")
def delete_playbook(
    playbook_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Deletes a playbook. Requires ADMIN role.
    """
    check_rbac(current_user, ["ADMIN"])
    pb = db.query(SoarPlaybook).filter(SoarPlaybook.playbook_id == playbook_id).first()
    if not pb:
        raise HTTPException(status_code=404, detail=f"Playbook '{playbook_id}' not found.")
    db.delete(pb)
    db.commit()
    return {"message": f"Playbook '{playbook_id}' deleted successfully."}

@router.post("/playbooks/{playbook_id}/enable")
def enable_playbook(
    playbook_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Enables a playbook. Requires ANALYST or ADMIN role.
    """
    check_rbac(current_user, ["ANALYST", "ADMIN"])
    pb = db.query(SoarPlaybook).filter(SoarPlaybook.playbook_id == playbook_id).first()
    if not pb:
        raise HTTPException(status_code=404, detail=f"Playbook '{playbook_id}' not found.")
    pb.enabled = True
    db.commit()
    return {"status": "SUCCESS", "message": f"Playbook '{playbook_id}' enabled."}

@router.post("/playbooks/{playbook_id}/disable")
def disable_playbook(
    playbook_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Disables a playbook. Requires ANALYST or ADMIN role.
    """
    check_rbac(current_user, ["ANALYST", "ADMIN"])
    pb = db.query(SoarPlaybook).filter(SoarPlaybook.playbook_id == playbook_id).first()
    if not pb:
        raise HTTPException(status_code=404, detail=f"Playbook '{playbook_id}' not found.")
    pb.enabled = False
    db.commit()
    return {"status": "SUCCESS", "message": f"Playbook '{playbook_id}' disabled."}

@router.post("/playbooks/{playbook_id}/dry-run")
def dry_run_playbook(
    playbook_id: str,
    context: Dict[str, Any],
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Runs a playbook in DRY-RUN mode without mutating real production state. Requires ANALYST or ADMIN role.
    """
    check_rbac(current_user, ["ANALYST", "ADMIN"])
    pb = db.query(SoarPlaybook).filter(SoarPlaybook.playbook_id == playbook_id).first()
    if not pb:
        raise HTTPException(status_code=404, detail=f"Playbook '{playbook_id}' not found.")

    res = PlaybookRunner.execute_playbook(db, pb, context, user_id=current_user.username, dry_run=True)
    return res

@router.post("/playbooks/{playbook_id}/execute")
def execute_playbook(
    playbook_id: str,
    context: Dict[str, Any],
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Manually triggers execution of a playbook. Requires ANALYST or ADMIN role.
    """
    check_rbac(current_user, ["ANALYST", "ADMIN"])
    pb = db.query(SoarPlaybook).filter(SoarPlaybook.playbook_id == playbook_id).first()
    if not pb:
        raise HTTPException(status_code=404, detail=f"Playbook '{playbook_id}' not found.")

    res = PlaybookRunner.execute_playbook(db, pb, context, user_id=current_user.username, dry_run=False)
    return res

@router.get("/playbooks/{playbook_id}/versions")
def get_playbook_versions(
    playbook_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Retrieves version history for a playbook.
    """
    versions = db.query(SoarPlaybookVersion).filter(
        SoarPlaybookVersion.playbook_id == playbook_id
    ).order_by(SoarPlaybookVersion.version.desc()).all()
    return versions

@router.get("/actions", response_model=List[ActionResponse])
def get_actions(
    skip: int = 0,
    limit: int = 100,
    status: Optional[str] = None,
    action_type: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns list of executed and pending SOAR actions. Accessible by VIEWER, ANALYST, and ADMIN.
    """
    query = db.query(SoarAction)
    if status:
        query = query.filter(SoarAction.status == status.upper())
    if action_type:
        query = query.filter(SoarAction.action_type == action_type.upper())
    return query.order_by(SoarAction.created_at.desc()).offset(skip).limit(limit).all()

@router.get("/actions/{action_id}", response_model=ActionResponse)
def get_action_by_id(
    action_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns details of a single action.
    """
    action = db.query(SoarAction).filter(SoarAction.action_id == action_id).first()
    if not action:
        raise HTTPException(status_code=404, detail=f"Action '{action_id}' not found.")
    return action

@router.post("/actions", response_model=ActionResponse, status_code=status.HTTP_201_CREATED)
def request_action(
    payload: ActionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Requests a single response action. Requires ANALYST or ADMIN role.
    """
    check_rbac(current_user, ["ANALYST", "ADMIN"])

    # Determine required approval policy
    policy = ApprovalManager.get_required_approval_policy(payload.action_type)

    if policy in ["ANALYST_APPROVAL", "ADMIN_APPROVAL", "MANUAL_ONLY"] and not payload.dry_run:
        # Create action record in PENDING_APPROVAL status
        action = ActionExecutor.execute_action(
            db=db,
            action_type=payload.action_type,
            target=payload.target,
            alert_id=payload.alert_id,
            case_id=payload.case_id,
            playbook_id=payload.playbook_id,
            parameters=payload.parameters,
            requested_by=current_user.username,
            dry_run=False
        )
        if action.status == "RUNNING" or action.status == "PENDING_APPROVAL":
            ApprovalManager.create_approval_request(db, action, policy, requested_by=current_user.username)
        return action
    else:
        # Execute directly (or dry run)
        action = ActionExecutor.execute_action(
            db=db,
            action_type=payload.action_type,
            target=payload.target,
            alert_id=payload.alert_id,
            case_id=payload.case_id,
            playbook_id=payload.playbook_id,
            parameters=payload.parameters,
            requested_by=current_user.username,
            dry_run=payload.dry_run
        )
        return action

@router.get("/approvals", response_model=List[ApprovalResponse])
def get_approvals(
    status: Optional[str] = "PENDING",
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns list of approval requests. Accessible by VIEWER, ANALYST, and ADMIN.
    """
    query = db.query(SoarApproval)
    if status:
        query = query.filter(SoarApproval.status == status.upper())
    return query.order_by(SoarApproval.created_at.desc()).all()

@router.post("/approvals/{approval_id}/decide")
def decide_approval(
    approval_id: str,
    payload: ApprovalDecisionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Approves or denies a pending response approval request. Requires ANALYST or ADMIN role.
    If approved, automatically triggers execution of the associated action.
    """
    check_rbac(current_user, ["ANALYST", "ADMIN"])
    try:
        approval, action = ApprovalManager.decide_approval(
            db=db,
            approval_id=approval_id,
            decision=payload.decision,
            user_role=current_user.role,
            user_id=current_user.username,
            reason=payload.reason
        )

        if payload.decision.upper() == "APPROVED" and action:
            # Execute action now that it is approved
            action_exec = ActionExecutor.execute_action(
                db=db,
                action_type=action.action_type,
                target=action.target,
                alert_id=action.alert_id,
                case_id=action.case_id,
                playbook_id=action.playbook_id,
                parameters=action.parameters or {},
                requested_by=action.requested_by,
                approved_by=current_user.username,
                dry_run=False
            )
            return {"status": "SUCCESS", "approval": approval, "action": action_exec}

        return {"status": "SUCCESS", "approval": approval, "action": action}
    except (ValueError, PermissionError) as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/actions/{action_id}/rollback")
def rollback_action(
    action_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Triggers inverse/rollback operation for a previously executed action. Requires ANALYST or ADMIN role.
    """
    check_rbac(current_user, ["ANALYST", "ADMIN"])
    try:
        action, result = RollbackEngine.execute_rollback(db, action_id, user_id=current_user.username)
        return {"status": "SUCCESS", "action": action, "rollback_result": result}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/integrations")
def get_integrations(
    current_user: User = Depends(get_current_user)
):
    """
    Returns status of real system integrations (Local Firewall, Host Isolation, Process Control, Identity, Notification).
    """
    return SoarManager.get_integrations_status()

@router.get("/integrations/host-isolation/status")
def get_host_isolation_status(
    current_user: User = Depends(get_current_user)
):
    """
    Returns detailed configuration and status of the Host Isolation driver.
    """
    from app.soar.integrations import HostIsolationIntegration
    return HostIsolationIntegration.get_status()

@router.get("/integrations/iam/status")
def get_iam_status(
    current_user: User = Depends(get_current_user)
):
    """
    Returns detailed configuration and status of the IAM Identity Provider driver.
    """
    from app.soar.integrations import IdentityProviderIntegration
    return IdentityProviderIntegration.get_status()

@router.get("/statistics", response_model=SoarStatisticsResponse)
def get_statistics(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns aggregated metrics for SOAR dashboard.
    """
    return SoarManager.get_soar_statistics(db)

