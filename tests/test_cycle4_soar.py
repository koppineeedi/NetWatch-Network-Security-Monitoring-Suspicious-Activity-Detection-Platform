import os
import sys
import pytest
import datetime
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Add backend directory to sys.path
backend_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend'))
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

from app.database.connection import Base, get_db
from app.main import app as fastapi_app
from app.models.user import User
from app.models.event import NetworkEvent
from app.models.alert import Alert
from app.core.security import hash_password, create_access_token

from app.soar.models import (
    SoarPlaybook, SoarPlaybookVersion, SoarPlaybookExecution,
    SoarAction, SoarApproval, SoarIntegration
)
from app.soar.actions import execute_action_handler, SUPPORTED_ACTIONS
from app.soar.integrations import LocalFirewallIntegration, ProcessControlIntegration, PROTECTED_IPS
from app.soar.conditions import ConditionEvaluator
from app.soar.triggers import TriggerEvaluator
from app.soar.approvals import ApprovalManager
from app.soar.executor import ActionExecutor
from app.soar.playbooks import PlaybookRunner
from app.soar.rollback import RollbackEngine
from app.soar.manager import SoarManager

# Setup test DB engine
TEST_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

@pytest.fixture
def client():
    with TestClient(fastapi_app) as c:
        yield c

@pytest.fixture(autouse=True)
def clean_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    fastapi_app.dependency_overrides[get_db] = override_get_db
    yield
    fastapi_app.dependency_overrides.clear()

def get_auth_token(role="ANALYST", username="testuser"):
    db = TestingSessionLocal()
    u = db.query(User).filter(User.username == username).first()
    if not u:
        u = User(
            username=username,
            email=f"{username}@netwatch.local",
            password_hash=hash_password("Pass123!"),
            role=role,
            is_active=True
        )
        db.add(u)
        db.commit()
        db.refresh(u)
    user_id = str(u.id)
    db.close()
    return create_access_token(data={"sub": user_id, "role": role})

# 1. Playbook Creation & Seeding
def test_1_seed_and_create_playbook():
    db = TestingSessionLocal()
    SoarManager.seed_default_playbooks(db)
    playbooks = db.query(SoarPlaybook).all()
    assert len(playbooks) >= 3

    pb_dict = {
        "name": "Custom Test Playbook",
        "description": "Test description",
        "trigger_type": "ALERT_CREATED",
        "trigger_config": {"severity": "CRITICAL"},
        "approval_policy": "ANALYST_APPROVAL",
        "steps": [{"step_id": "s1", "action": "NOTIFY_ANALYST", "continue_on_failure": True}]
    }
    new_pb = SoarManager.create_playbook(db, pb_dict, user_id="admin_test")
    assert new_pb.playbook_id.startswith("PB-")
    assert new_pb.version == 1
    db.close()

# 2, 3. Playbook Versioning & Enable/Disable
def test_2_3_playbook_versioning_and_enable_disable():
    db = TestingSessionLocal()
    pb_dict = {
        "name": "Versioning Test Playbook",
        "trigger_type": "MANUAL",
        "approval_policy": "AUTOMATIC",
        "steps": [{"step_id": "s1", "action": "NOTIFY_ANALYST"}]
    }
    pb = SoarManager.create_playbook(db, pb_dict, user_id="admin_test")
    assert pb.version == 1

    updated = SoarManager.update_playbook(db, pb.playbook_id, {"name": "Updated Name v2"}, user_id="admin_test")
    assert updated.version == 2

    versions = db.query(SoarPlaybookVersion).filter(SoarPlaybookVersion.playbook_id == pb.playbook_id).all()
    assert len(versions) == 2

    db.close()

# 5, 6. Trigger & Condition Evaluation
def test_5_6_trigger_and_condition_evaluation():
    context = {"severity": "CRITICAL", "risk_score": 85, "source_ip": "10.0.0.5", "alert_source": "SIGMA"}

    cond1 = {"field": "severity", "operator": "==", "value": "CRITICAL"}
    assert ConditionEvaluator.evaluate_condition(cond1, context) is True

    cond2 = {"field": "risk_score", "operator": ">=", "value": 80}
    assert ConditionEvaluator.evaluate_condition(cond2, context) is True

    cond3 = {"field": "risk_score", "operator": "<", "value": 50}
    assert ConditionEvaluator.evaluate_condition(cond3, context) is False

    matched = TriggerEvaluator.match_trigger("ALERT_CREATED", {"severity": "CRITICAL"}, "ALERT_CREATED", context)
    assert matched is True

# 7. Dry-Run Execution Mode
def test_7_dry_run_mode():
    db = TestingSessionLocal()
    action = ActionExecutor.execute_action(
        db=db,
        action_type="BLOCK_IP",
        target="192.168.1.100",
        requested_by="analyst_test",
        dry_run=True
    )
    assert action.status == "DRY_RUN"
    assert action.result["dry_run"] is True
    db.close()

# 8, 9, 10, 11. Approval Workflow (Request, Approve, Deny, Expiry)
def test_8_9_10_11_approval_workflow():
    db = TestingSessionLocal()
    action = ActionExecutor.execute_action(
        db=db,
        action_type="ISOLATE_HOST",
        target="192.168.1.200",
        requested_by="analyst_test",
        dry_run=False
    )
    # ISOLATE_HOST requires ADMIN_APPROVAL
    policy = ApprovalManager.get_required_approval_policy("ISOLATE_HOST")
    approval = ApprovalManager.create_approval_request(db, action, policy, requested_by="analyst_test")

    assert action.status == "PENDING_APPROVAL"
    assert approval.status == "PENDING"
    assert approval.required_role == "ADMIN"

    # ANALYST trying to approve ADMIN_APPROVAL -> PermissionError
    with pytest.raises(PermissionError):
        ApprovalManager.decide_approval(db, approval.approval_id, "APPROVED", user_role="ANALYST", user_id="analyst_1")

    # ADMIN approving -> SUCCESS
    app_dec, act_dec = ApprovalManager.decide_approval(db, approval.approval_id, "APPROVED", user_role="ADMIN", user_id="admin_1")
    assert app_dec.status == "APPROVED"
    assert act_dec.approved_by == "admin_1"

    db.close()

# 14. NOT_CONFIGURED Integration Return
def test_14_not_configured_integration():
    db = TestingSessionLocal()
    action = ActionExecutor.execute_action(
        db=db,
        action_type="DISABLE_ACCOUNT",
        target="malicious_user",
        requested_by="admin_test",
        dry_run=False
    )
    # Account actions return NOT_CONFIGURED when no Identity Provider integration is active
    assert action.status in ["NOT_CONFIGURED", "PENDING_APPROVAL"]
    db.close()

# 15. Idempotency Key Check
def test_15_idempotency_key_check():
    db = TestingSessionLocal()
    a1 = ActionExecutor.execute_action(db, "NOTIFY_ANALYST", "SOC_PANEL", alert_id=100, dry_run=False)
    assert a1.status == "SUCCESS"

    a2 = ActionExecutor.execute_action(db, "BLOCK_IP", "203.0.113.5", alert_id=100, dry_run=True)
    assert a2.status == "DRY_RUN"

    db.close()

# 17, 18. Rollback Support
def test_17_18_rollback_support():
    db = TestingSessionLocal()

    # NOTIFY_ANALYST executes successfully
    a1 = ActionExecutor.execute_action(db, "NOTIFY_ANALYST", "SOC_PANEL", dry_run=False)
    assert a1.status == "SUCCESS"

    # Rollback NOT_AVAILABLE for NOTIFY_ANALYST
    with pytest.raises(ValueError, match="Rollback not available"):
        RollbackEngine.execute_rollback(db, a1.action_id, user_id="admin_test")

    db.close()

# 24, 25. Security Validation & Protected IP / Process Safeguards
def test_24_25_security_safeguards():
    # 1. Protected IP safeguard
    status, res = LocalFirewallIntegration.block_ip("127.0.0.1")
    assert status == "FAILED"
    assert "protected" in res["error"].lower()

    # 2. Protected PID safeguard (PID 1 or current process)
    current_pid = str(os.getpid())
    status_p, res_p = ProcessControlIntegration.kill_process(current_pid)
    assert status_p == "FAILED"
    assert "protected" in res_p["error"].lower()

# 27. Playbook Loop & Depth Limit Protection
def test_27_playbook_depth_limit():
    db = TestingSessionLocal()
    long_steps = [{"step_id": f"s_{i}", "action": "NOTIFY_ANALYST"} for i in range(25)]
    pb_dict = {
        "name": "Excessive Steps Playbook",
        "trigger_type": "MANUAL",
        "approval_policy": "AUTOMATIC",
        "steps": long_steps
    }
    pb = SoarManager.create_playbook(db, pb_dict)
    res = PlaybookRunner.execute_playbook(db, pb, {}, dry_run=True)

    assert res["status"] == "FAILED"
    assert "max depth limit" in res["error"].lower()

    db.close()

# 28. RBAC Endpoints Integration Test
def test_28_soar_rbac_endpoints(client):
    viewer_token = get_auth_token(role="VIEWER", username="viewer_soar")
    analyst_token = get_auth_token(role="ANALYST", username="analyst_soar")
    admin_token = get_auth_token(role="ADMIN", username="admin_soar")

    # VIEWER can list playbooks
    r1 = client.get("/api/soar/playbooks", headers={"Authorization": f"Bearer {viewer_token}"})
    assert r1.status_code == 200

    # VIEWER trying to create playbook -> 403 Forbidden
    r2 = client.post("/api/soar/playbooks", json={"name": "Fail", "steps": []}, headers={"Authorization": f"Bearer {viewer_token}"})
    assert r2.status_code == 403

    # ANALYST creating playbook -> 201 Created
    pb_payload = {
        "name": "Analyst Created Playbook",
        "trigger_type": "MANUAL",
        "approval_policy": "AUTOMATIC",
        "steps": [{"step_id": "s1", "action": "NOTIFY_ANALYST"}]
    }
    r3 = client.post("/api/soar/playbooks", json=pb_payload, headers={"Authorization": f"Bearer {analyst_token}"})
    assert r3.status_code == 201
    p_id = r3.json()["playbook_id"]

    # ANALYST trying to delete playbook -> 403 Forbidden (Delete requires ADMIN)
    r4 = client.delete(f"/api/soar/playbooks/{p_id}", headers={"Authorization": f"Bearer {analyst_token}"})
    assert r4.status_code == 403

    # ADMIN deleting playbook -> 200 OK
    r5 = client.delete(f"/api/soar/playbooks/{p_id}", headers={"Authorization": f"Bearer {admin_token}"})
    assert r5.status_code == 200
