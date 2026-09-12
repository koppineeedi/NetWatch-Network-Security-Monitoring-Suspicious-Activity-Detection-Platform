from typing import Dict, Any, Tuple
from sqlalchemy.orm import Session
from datetime import datetime

from app.soar.models import SoarAction
from app.soar.actions import execute_action_handler
from app.realtime.publisher import publish_soar_event
from app.soar.audit import log_soar_audit

ROLLBACK_MAP = {
    "BLOCK_IP": "UNBLOCK_IP",
    "ADD_FIREWALL_RULE": "REMOVE_FIREWALL_RULE",
    "ISOLATE_HOST": "RESTORE_HOST",
    "DISABLE_ACCOUNT": "ENABLE_ACCOUNT"
}

class RollbackEngine:
    @staticmethod
    def execute_rollback(db: Session, action_id: str, user_id: str = "system") -> Tuple[SoarAction, Dict[str, Any]]:
        """
        Executes inverse/rollback action for a previously executed successful action.
        """
        action = db.query(SoarAction).filter(SoarAction.action_id == action_id).first()
        if not action:
            raise ValueError(f"Action '{action_id}' not found.")

        if action.status != "SUCCESS":
            raise ValueError(f"Cannot rollback action '{action_id}' with status '{action.status}'. Must be SUCCESS.")

        inverse_action_type = ROLLBACK_MAP.get(action.action_type)
        if not inverse_action_type:
            action.rollback_status = "NOT_AVAILABLE"
            db.commit()
            raise ValueError(f"Rollback not available for action type '{action.action_type}'.")

        publish_soar_event("ACTION_ROLLBACK_STARTED", {
            "action_id": action.action_id,
            "action_type": action.action_type,
            "rollback_type": inverse_action_type,
            "target": action.target
        })

        rb_status, rb_result = execute_action_handler(inverse_action_type, action.target, action.parameters or {})

        action.rollback_status = rb_status
        db.commit()
        db.refresh(action)

        event_name = "ACTION_ROLLBACK_COMPLETED" if rb_status == "SUCCESS" else "ACTION_ROLLBACK_FAILED"
        publish_soar_event(event_name, {
            "action_id": action.action_id,
            "status": rb_status,
            "result": rb_result
        })

        log_soar_audit(
            db=db,
            user=user_id,
            action=f"SOAR_ACTION_ROLLBACK_{rb_status}",
            resource_id=action_id,
            details=f"Rollback {inverse_action_type} for target '{action.target}': {rb_status}"
        )

        return action, rb_result
