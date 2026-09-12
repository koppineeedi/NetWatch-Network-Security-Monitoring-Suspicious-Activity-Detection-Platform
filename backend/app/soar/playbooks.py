import os
import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from app.soar.models import SoarPlaybook, SoarPlaybookExecution, SoarAction
from app.soar.conditions import ConditionEvaluator
from app.soar.approvals import ApprovalManager
from app.soar.executor import ActionExecutor
from app.realtime.publisher import publish_soar_event
from app.soar.audit import log_soar_audit

class PlaybookRunner:
    @staticmethod
    def execute_playbook(
        db: Session,
        playbook: SoarPlaybook,
        context: Dict[str, Any],
        user_id: str = "system",
        alert_id: Optional[int] = None,
        dry_run: bool = False
    ) -> Dict[str, Any]:
        """
        Executes a playbook sequentially over ordered steps with condition evaluation,
        approval handling, and loop protection.
        """
        max_depth = int(os.getenv("NETWATCH_SOAR_MAX_PLAYBOOK_DEPTH", "20"))
        steps = playbook.steps or []

        if len(steps) > max_depth:
            return {
                "status": "FAILED",
                "error": f"Playbook steps ({len(steps)}) exceed max depth limit ({max_depth}).",
                "playbook_id": playbook.playbook_id
            }

        execution_id = f"EX-{uuid.uuid4().hex[:8].upper()}"
        execution = SoarPlaybookExecution(
            execution_id=execution_id,
            playbook_id=playbook.playbook_id,
            trigger_event=playbook.trigger_type,
            alert_id=alert_id,
            status="RUNNING",
            step_results=[],
            started_at=datetime.utcnow()
        )
        db.add(execution)
        db.commit()

        publish_soar_event("PLAYBOOK_STARTED", {
            "execution_id": execution_id,
            "playbook_id": playbook.playbook_id,
            "name": playbook.name
        })

        step_results = []
        overall_status = "SUCCESS"

        for idx, step_dict in enumerate(steps):
            step_id = step_dict.get("step_id", f"step_{idx+1}")
            action_type = step_dict.get("action")
            conditions = step_dict.get("conditions")
            continue_on_failure = step_dict.get("continue_on_failure", False)
            target = step_dict.get("target") or context.get("source_ip") or context.get("target") or "LOCAL_HOST"
            parameters = step_dict.get("parameters", {})

            # 1. Evaluate step condition
            if conditions and not ConditionEvaluator.evaluate_all(conditions, context):
                step_results.append({
                    "step_id": step_id,
                    "action": action_type,
                    "status": "SKIPPED",
                    "reason": "Condition evaluation evaluated to False."
                })
                continue

            # 2. Determine approval policy
            req_policy = ApprovalManager.get_required_approval_policy(action_type, playbook.approval_policy)

            # 3. Create Action record
            if req_policy in ["ANALYST_APPROVAL", "ADMIN_APPROVAL", "MANUAL_ONLY"] and not dry_run:
                # Action requires approval
                action = ActionExecutor.execute_action(
                    db=db,
                    action_type=action_type,
                    target=target,
                    alert_id=alert_id,
                    playbook_id=playbook.playbook_id,
                    parameters=parameters,
                    requested_by=user_id,
                    dry_run=False
                )
                if action.status == "RUNNING" or action.status == "PENDING_APPROVAL":
                    approval = ApprovalManager.create_approval_request(db, action, req_policy, requested_by=user_id)
                    step_results.append({
                        "step_id": step_id,
                        "action": action_type,
                        "status": "PENDING_APPROVAL",
                        "action_id": action.action_id,
                        "approval_id": approval.approval_id
                    })
                    overall_status = "PENDING_APPROVAL"
                    break
            else:
                # Execute action directly (or dry-run)
                action = ActionExecutor.execute_action(
                    db=db,
                    action_type=action_type,
                    target=target,
                    alert_id=alert_id,
                    playbook_id=playbook.playbook_id,
                    parameters=parameters,
                    requested_by=user_id,
                    dry_run=dry_run
                )
                step_results.append({
                    "step_id": step_id,
                    "action": action_type,
                    "status": action.status,
                    "action_id": action.action_id,
                    "result": action.result,
                    "error": action.error
                })

                if action.status in ["FAILED", "NOT_CONFIGURED"] and not continue_on_failure and not dry_run:
                    overall_status = "FAILED"
                    break

        execution.status = overall_status
        execution.step_results = step_results
        execution.completed_at = datetime.utcnow()
        db.commit()

        event_name = f"PLAYBOOK_{overall_status}"
        publish_soar_event(event_name, {
            "execution_id": execution_id,
            "playbook_id": playbook.playbook_id,
            "status": overall_status,
            "step_results": step_results
        })

        log_soar_audit(
            db=db,
            user=user_id,
            action=f"SOAR_PLAYBOOK_{overall_status}",
            resource_id=playbook.playbook_id,
            details={"execution_id": execution_id, "status": overall_status, "step_count": len(step_results)}
        )

        return {
            "execution_id": execution_id,
            "playbook_id": playbook.playbook_id,
            "status": overall_status,
            "step_results": step_results
        }
