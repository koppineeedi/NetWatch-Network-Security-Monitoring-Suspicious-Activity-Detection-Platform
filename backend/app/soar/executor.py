import os
import uuid
import time
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Tuple
from sqlalchemy.orm import Session

from app.soar.models import SoarAction, SoarActionResult
from app.soar.actions import execute_action_handler
from app.soar.rollback import ROLLBACK_MAP
from app.realtime.publisher import publish_soar_event
from app.soar.audit import log_soar_audit

# Simple in-memory rate limiting sliding window tracker
_action_execution_timestamps = []

class ActionExecutor:
    @staticmethod
    def _check_rate_limit() -> bool:
        """
        Enforces MAX_ACTIONS_PER_MINUTE rate limiting.
        """
        max_per_min = int(os.getenv("NETWATCH_SOAR_MAX_ACTIONS_PER_MINUTE", "20"))
        now = time.time()
        global _action_execution_timestamps
        _action_execution_timestamps = [t for t in _action_execution_timestamps if now - t < 60]

        if len(_action_execution_timestamps) >= max_per_min:
            return False

        _action_execution_timestamps.append(now)
        return True

    @staticmethod
    def execute_action(
        db: Session,
        action_type: str,
        target: str,
        alert_id: Optional[int] = None,
        case_id: Optional[str] = None,
        playbook_id: Optional[str] = None,
        parameters: Dict[str, Any] = None,
        requested_by: str = "system",
        approved_by: Optional[str] = None,
        dry_run: bool = False
    ) -> SoarAction:
        """
        Executes a single SOAR action with idempotency, rate-limiting, dry-run, and audit tracking.
        """
        if parameters is None:
            parameters = {}

        action_id = f"ACT-{uuid.uuid4().hex[:8].upper()}"
        idempotency_key = f"{action_type.upper()}:{target}:{alert_id or ''}"

        # 1. Idempotency Check: Prevent duplicate active actions
        existing_action = db.query(SoarAction).filter(
            SoarAction.idempotency_key == idempotency_key,
            SoarAction.status.in_(["RUNNING", "SUCCESS", "PENDING_APPROVAL"])
        ).first()

        if existing_action and action_type.upper() not in ["NOTIFY_ANALYST"]:
            # Duplicate action detected
            duplicate = SoarAction(
                action_id=action_id,
                action_type=action_type.upper(),
                status="CANCELLED",
                alert_id=alert_id,
                case_id=case_id,
                playbook_id=playbook_id,
                requested_by=requested_by,
                target=target,
                parameters=parameters,
                result={"message": f"Duplicate action cancelled by idempotency key '{idempotency_key}'."},
                error="DUPLICATE_ACTION",
                rollback_available=False,
                idempotency_key=idempotency_key,
                created_at=datetime.utcnow(),
                completed_at=datetime.utcnow()
            )
            db.add(duplicate)
            db.commit()
            db.refresh(duplicate)
            return duplicate

        # Determine Dry Run mode
        global_dry_run = os.getenv("NETWATCH_SOAR_DRY_RUN", "false").lower() == "true"
        is_dry_run = dry_run or global_dry_run

        rollback_avail = action_type.upper() in ROLLBACK_MAP

        # 2. Dry-Run Execution Path
        if is_dry_run:
            action = SoarAction(
                action_id=action_id,
                action_type=action_type.upper(),
                status="DRY_RUN",
                alert_id=alert_id,
                case_id=case_id,
                playbook_id=playbook_id,
                requested_by=requested_by,
                approved_by=approved_by,
                target=target,
                parameters=parameters,
                result={"dry_run": True, "intended_action": action_type.upper(), "target": target},
                started_at=datetime.utcnow(),
                completed_at=datetime.utcnow(),
                rollback_available=rollback_avail,
                rollback_status="NONE",
                idempotency_key=idempotency_key,
                created_at=datetime.utcnow()
            )
            db.add(action)
            db.commit()
            db.refresh(action)

            publish_soar_event("ACTION_COMPLETED", {
                "action_id": action.action_id,
                "action_type": action.action_type,
                "target": target,
                "status": "DRY_RUN"
            })
            log_soar_audit(db, requested_by, "SOAR_ACTION_DRY_RUN", action_id, details=parameters)
            return action

        # 3. Rate Limit Check
        if not ActionExecutor._check_rate_limit():
            action = SoarAction(
                action_id=action_id,
                action_type=action_type.upper(),
                status="FAILED",
                alert_id=alert_id,
                case_id=case_id,
                playbook_id=playbook_id,
                requested_by=requested_by,
                target=target,
                parameters=parameters,
                error="Rate limit exceeded. Too many actions executed per minute.",
                rollback_available=False,
                idempotency_key=idempotency_key,
                created_at=datetime.utcnow(),
                completed_at=datetime.utcnow()
            )
            db.add(action)
            db.commit()
            db.refresh(action)

            publish_soar_event("ACTION_FAILED", {
                "action_id": action.action_id,
                "action_type": action.action_type,
                "error": action.error
            })
            return action

        # 4. Real Action Execution
        action = SoarAction(
            action_id=action_id,
            action_type=action_type.upper(),
            status="RUNNING",
            alert_id=alert_id,
            case_id=case_id,
            playbook_id=playbook_id,
            requested_by=requested_by,
            approved_by=approved_by,
            target=target,
            parameters=parameters,
            started_at=datetime.utcnow(),
            rollback_available=rollback_avail,
            idempotency_key=idempotency_key,
            created_at=datetime.utcnow()
        )
        db.add(action)
        db.commit()
        db.refresh(action)

        publish_soar_event("ACTION_STARTED", {
            "action_id": action.action_id,
            "action_type": action.action_type,
            "target": target
        })

        # Execute integration handler
        status_code, result_dict = execute_action_handler(action_type, target, parameters)

        action.status = status_code
        action.result = result_dict
        action.completed_at = datetime.utcnow()

        if status_code != "SUCCESS":
            action.error = result_dict.get("error", f"Action failed with status {status_code}")

        # Store action result step entry
        res_record = SoarActionResult(
            action_id=action_id,
            step_index=0,
            status=status_code,
            output=result_dict,
            executed_at=datetime.utcnow()
        )
        db.add(res_record)
        db.commit()
        db.refresh(action)

        event_type = "ACTION_COMPLETED" if status_code == "SUCCESS" else ("ACTION_FAILED" if status_code == "FAILED" else "ACTION_NOT_CONFIGURED")
        publish_soar_event(event_type, {
            "action_id": action.action_id,
            "action_type": action.action_type,
            "target": target,
            "status": status_code,
            "result": result_dict
        })

        log_soar_audit(
            db=db,
            user=requested_by,
            action=f"SOAR_ACTION_EXECUTE_{status_code}",
            resource_id=action_id,
            details={"action_type": action_type, "target": target, "result": result_dict}
        )

        return action
