import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Tuple
from sqlalchemy.orm import Session

from app.soar.models import SoarAction, SoarApproval
from app.realtime.publisher import publish_soar_event

DESTRUCTIVE_ACTIONS = {
    "BLOCK_IP": "ANALYST_APPROVAL",
    "UNBLOCK_IP": "ANALYST_APPROVAL",
    "ADD_FIREWALL_RULE": "ANALYST_APPROVAL",
    "REMOVE_FIREWALL_RULE": "ANALYST_APPROVAL",
    "ISOLATE_HOST": "ADMIN_APPROVAL",
    "RESTORE_HOST": "ADMIN_APPROVAL",
    "KILL_PROCESS": "ADMIN_APPROVAL",
    "DISABLE_ACCOUNT": "ADMIN_APPROVAL",
    "ENABLE_ACCOUNT": "ADMIN_APPROVAL",
    "NOTIFY_ANALYST": "AUTOMATIC"
}

class ApprovalManager:
    @staticmethod
    def get_required_approval_policy(action_type: str, playbook_policy: Optional[str] = None) -> str:
        """
        Determines effective approval policy combining action default and playbook setting.
        Safeguard: Destructive actions default to approval requirement unless explicitly overridden by admin policy.
        """
        if playbook_policy and playbook_policy != "AUTOMATIC":
            return playbook_policy

        default_policy = DESTRUCTIVE_ACTIONS.get(action_type.upper(), "ANALYST_APPROVAL")
        return default_policy

    @staticmethod
    def create_approval_request(
        db: Session,
        action: SoarAction,
        policy: str,
        requested_by: str = "system",
        timeout_minutes: int = 30
    ) -> SoarApproval:
        """
        Creates persistent approval request record for an action requiring authorization.
        """
        approval_id = f"APP-{uuid.uuid4().hex[:8].upper()}"
        required_role = "ADMIN" if policy == "ADMIN_APPROVAL" else "ANALYST"
        expires_at = datetime.utcnow() + timedelta(minutes=timeout_minutes)

        approval = SoarApproval(
            approval_id=approval_id,
            action_id=action.action_id,
            required_role=required_role,
            status="PENDING",
            requested_by=requested_by,
            created_at=datetime.utcnow(),
            expires_at=expires_at
        )
        db.add(approval)

        action.status = "PENDING_APPROVAL"
        db.commit()
        db.refresh(approval)
        db.refresh(action)

        publish_soar_event("ACTION_APPROVAL_REQUIRED", {
            "action_id": action.action_id,
            "approval_id": approval.approval_id,
            "action_type": action.action_type,
            "target": action.target,
            "required_role": required_role,
            "expires_at": expires_at.isoformat()
        })

        return approval

    @staticmethod
    def decide_approval(
        db: Session,
        approval_id: str,
        decision: str,
        user_role: str,
        user_id: str,
        reason: Optional[str] = None
    ) -> Tuple[SoarApproval, SoarAction]:
        """
        Processes approval/denial decision with strict RBAC enforcement.
        """
        approval = db.query(SoarApproval).filter(SoarApproval.approval_id == approval_id).first()
        if not approval:
            raise ValueError(f"Approval request '{approval_id}' not found.")

        if approval.status != "PENDING":
            raise ValueError(f"Approval request '{approval_id}' is already {approval.status}.")

        # Check expiration
        if approval.expires_at and datetime.utcnow() > approval.expires_at:
            approval.status = "EXPIRED"
            db.commit()
            raise ValueError(f"Approval request '{approval_id}' has expired.")

        # Check role permission
        if approval.required_role == "ADMIN" and user_role != "ADMIN":
            raise PermissionError(f"Decision requires ADMIN role. Current user role is '{user_role}'.")

        if user_role not in ["ANALYST", "ADMIN"]:
            raise PermissionError("Only ANALYST or ADMIN role can decide approval requests.")

        decision_upper = decision.upper()
        if decision_upper not in ["APPROVED", "DENIED", "CANCELLED"]:
            raise ValueError(f"Invalid decision '{decision}'. Must be APPROVED, DENIED, or CANCELLED.")

        approval.status = decision_upper
        approval.decided_by = user_id
        approval.decision_reason = reason

        action = db.query(SoarAction).filter(SoarAction.action_id == approval.action_id).first()
        if action:
            if decision_upper == "APPROVED":
                action.status = "APPROVED"
                action.approved_by = user_id
                publish_soar_event("ACTION_APPROVED", {
                    "action_id": action.action_id,
                    "approval_id": approval.approval_id,
                    "decided_by": user_id
                })
            else:
                action.status = decision_upper
                action.completed_at = datetime.utcnow()
                publish_soar_event(f"ACTION_{decision_upper}", {
                    "action_id": action.action_id,
                    "approval_id": approval.approval_id,
                    "decided_by": user_id,
                    "reason": reason
                })

        db.commit()
        db.refresh(approval)
        if action:
            db.refresh(action)

        return approval, action
