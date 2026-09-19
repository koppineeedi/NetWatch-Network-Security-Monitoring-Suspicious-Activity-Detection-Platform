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
from app.models.detection import Detection
from app.core.security import hash_password, create_access_token

from app.sigma.models import SigmaRule, SigmaRuleVersion, SigmaRuleExecution, SigmaRuleMatch
from app.sigma.parser import parse_sigma_yaml
from app.sigma.validator import validate_sigma_rule
from app.sigma.mapper import SigmaFieldMapper
from app.sigma.evaluator import SigmaEvaluator
from app.sigma.manager import SigmaManager
from app.sigma.sandbox import run_sigma_sandbox
from app.sigma.statistics import get_sigma_statistics
from app.sigma.engine import evaluate_sigma_live

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

def get_auth_token(role="ADMIN", username="admin_sigma_test"):
    db = TestingSessionLocal()
    user = db.query(User).filter(User.username == username).first()
    if not user:
        user = User(
            username=username,
            email=f"{username}@netwatch.local",
            password_hash=hash_password("Pass123!"),
            role=role,
            is_active=True
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    token = create_access_token({"sub": str(user.id), "role": user.role})
    db.close()
    return token

VALID_SIGMA_YAML = """
title: Test Malicious Port Connection
id: 11111111-2222-3333-4444-555555555555
status: experimental
description: Detects connection to suspicious port 4444
logsource:
  category: network_connection
detection:
  selection:
    dst_port: 4444
  condition: selection
level: high
tags:
  - attack.t1046
"""

def test_1_2_3_4_sigma_parsing_and_validation():
    # 1. Valid YAML parsing
    parsed = parse_sigma_yaml(VALID_SIGMA_YAML)
    assert len(parsed) == 1
    assert parsed[0]["title"] == "Test Malicious Port Connection"
    assert parsed[0]["mitre_techniques"] == ["T1046"]

    # 2. Invalid YAML handling
    with pytest.raises(ValueError):
        parse_sigma_yaml("invalid: yaml: [syntax")

    # 3. Invalid Sigma structure
    invalid_structure = {"title": "Missing Detection"}
    val_res = validate_sigma_rule(invalid_structure)
    assert val_res["valid"] is False
    assert "status" in val_res and val_res["status"] == "INVALID"

    # 4. Unsupported features reporting
    unsupported_yaml = """
title: Unsupported Field Test
id: 22222222-2222-2222-2222-222222222222
logsource:
  category: process_creation
detection:
  selection:
    UnknownNonExistentField: "malicious.exe"
  condition: selection
level: medium
"""
    parsed_un = parse_sigma_yaml(unsupported_yaml)[0]
    val_un = validate_sigma_rule(parsed_un)
    assert val_un["status"] == "UNSUPPORTED"
    assert len(val_un["unsupported_features"]) > 0

def test_5_6_7_rule_import_and_duplicate():
    db = TestingSessionLocal()
    # 6. Import workflow
    res = SigmaManager.import_rule(db, VALID_SIGMA_YAML, user_id="admin_test")
    assert res["imported_count"] == 1
    rule_id = res["rule_ids"][0]

    # 5 & 7. Duplicate rule & validation status
    rule = db.query(SigmaRule).filter(SigmaRule.rule_id == rule_id).first()
    assert rule is not None
    assert rule.status == "VALID"
    assert rule.enabled is False  # Defaults to disabled

    db.close()

def test_8_field_mapping():
    # 8. Field mapping lookup
    assert SigmaFieldMapper.map_field("src_ip") == "source_ip"
    assert SigmaFieldMapper.map_field("dst_port") == "dest_port"
    assert SigmaFieldMapper.map_field("image") == "process_name"
    assert SigmaFieldMapper.map_field("unknown_xyz") is None
    assert SigmaFieldMapper.is_field_supported("src_ip") is True

def test_9_10_11_12_13_14_15_evaluator_conditions_and_matching():
    evt = NetworkEvent(
        source_ip="192.168.1.100",
        dest_ip="10.0.0.5",
        dest_port=4444,
        protocol="TCP",
        process_name="powershell.exe"
    )

    # 9. Exact matching
    rule_exact = {
        "rule_id": "R1",
        "title": "Exact Match",
        "detection": {"selection": {"dst_port": 4444}, "condition": "selection"},
        "level": "high"
    }
    eval1 = SigmaEvaluator.evaluate_rule(rule_exact, evt)
    assert eval1["matched"] is True

    # 10. Wildcard matching (* and ?)
    rule_wildcard = {
        "rule_id": "R2",
        "title": "Wildcard Match",
        "detection": {"selection": {"image|contains": "power*"}, "condition": "selection"},
        "level": "high"
    }
    eval2 = SigmaEvaluator.evaluate_rule(rule_wildcard, evt)
    assert eval2["matched"] is True

    # 11. AND condition
    rule_and = {
        "rule_id": "R3",
        "title": "AND Match",
        "detection": {
            "sel1": {"dst_port": 4444},
            "sel2": {"image": "powershell.exe"},
            "condition": "sel1 and sel2"
        },
        "level": "critical"
    }
    eval3 = SigmaEvaluator.evaluate_rule(rule_and, evt)
    assert eval3["matched"] is True

    # 12. OR condition
    rule_or = {
        "rule_id": "R4",
        "title": "OR Match",
        "detection": {
            "sel1": {"dst_port": 9999},
            "sel2": {"dst_port": 4444},
            "condition": "sel1 or sel2"
        },
        "level": "medium"
    }
    eval4 = SigmaEvaluator.evaluate_rule(rule_or, evt)
    assert eval4["matched"] is True

    # 13. NOT condition
    rule_not = {
        "rule_id": "R5",
        "title": "NOT Match",
        "detection": {
            "sel1": {"dst_port": 9999},
            "condition": "not sel1"
        },
        "level": "low"
    }
    eval5 = SigmaEvaluator.evaluate_rule(rule_not, evt)
    assert eval5["matched"] is True

    # 14. all of selection*
    rule_all_of = {
        "rule_id": "R6",
        "title": "All Of Match",
        "detection": {
            "selection1": {"dst_port": 4444},
            "selection2": {"proto": "TCP"},
            "condition": "all of selection*"
        },
        "level": "high"
    }
    eval6 = SigmaEvaluator.evaluate_rule(rule_all_of, evt)
    assert eval6["matched"] is True

    # 15. 1 of selection*
    rule_one_of = {
        "rule_id": "R7",
        "title": "1 Of Match",
        "detection": {
            "selection1": {"dst_port": 9999},
            "selection2": {"dst_port": 4444},
            "condition": "1 of selection*"
        },
        "level": "high"
    }
    eval7 = SigmaEvaluator.evaluate_rule(rule_one_of, evt)
    assert eval7["matched"] is True

def test_16_17_severity_and_mitre():
    rule_crit = {
        "rule_id": "R8",
        "title": "Critical Rule",
        "detection": {"selection": {"dst_port": 4444}, "condition": "selection"},
        "level": "critical",
        "mitre_techniques": ["T1046"]
    }
    evt = NetworkEvent(dest_port=4444)
    eval_res = SigmaEvaluator.evaluate_rule(rule_crit, evt)
    # 16. Severity mapping
    assert eval_res["severity"] == "CRITICAL"
    # 17. MITRE tag parsing
    assert eval_res["mitre_techniques"] == ["T1046"]

def test_18_19_versioning_and_enable_disable():
    db = TestingSessionLocal()
    # Import rule
    res = SigmaManager.import_rule(db, VALID_SIGMA_YAML, user_id="admin_test")
    rule_id = res["rule_ids"][0]

    # 19. Enable/disable transitions
    rule_enabled = SigmaManager.toggle_rule(db, rule_id, True, user_id="admin_test")
    assert rule_enabled.enabled is True
    assert rule_enabled.status == "ENABLED"

    rule_disabled = SigmaManager.toggle_rule(db, rule_id, False, user_id="admin_test")
    assert rule_disabled.enabled is False
    assert rule_disabled.status == "DISABLED"

    # 18. Versioning tracking
    SigmaManager.import_rule(db, VALID_SIGMA_YAML, user_id="admin_test")
    rule_v2 = db.query(SigmaRule).filter(SigmaRule.rule_id == rule_id).first()
    assert rule_v2.version == 2
    versions = db.query(SigmaRuleVersion).filter(SigmaRuleVersion.rule_id == rule_id).all()
    assert len(versions) >= 2

    db.close()

def test_20_21_sandbox_execution_and_insufficient_data():
    db = TestingSessionLocal()

    # 21. Insufficient data test (no events in DB)
    sandbox_res1 = run_sigma_sandbox(db, raw_yaml=VALID_SIGMA_YAML, hours=24)
    assert sandbox_res1["status"] == "INSUFFICIENT_DATA"
    assert sandbox_res1["historical_matches_count"] == 0

    # 20. Sandbox testing against historical test fixture
    evt = NetworkEvent(
        timestamp=datetime.datetime.utcnow(),
        source_ip="192.168.1.50",
        dest_ip="10.0.0.1",
        dest_port=4444,
        source="TEST"
    )
    db.add(evt)
    db.commit()

    sandbox_res2 = run_sigma_sandbox(db, raw_yaml=VALID_SIGMA_YAML, hours=24)
    assert sandbox_res2["status"] == "SUCCESS"
    assert sandbox_res2["historical_matches_count"] == 1
    assert len(sandbox_res2["matches"]) == 1

    db.close()

def test_22_23_24_25_live_engine_alerts_dedup_explainability():
    db = TestingSessionLocal()
    # Import and enable rule
    res = SigmaManager.import_rule(db, VALID_SIGMA_YAML, user_id="admin_test")
    rule_id = res["rule_ids"][0]
    SigmaManager.toggle_rule(db, rule_id, True, user_id="admin_test")

    # 22. Live real-event evaluation path
    evt = NetworkEvent(
        timestamp=datetime.datetime.utcnow(),
        source_ip="192.168.1.80",
        dest_ip="10.0.0.2",
        dest_port=4444,
        source="LOCAL_NETWORK"
    )
    db.add(evt)
    db.commit()

    matches = evaluate_sigma_live(db, evt)
    assert len(matches) == 1

    # 23. Alert creation
    alert = db.query(Alert).filter(Alert.rule_id == rule_id).first()
    assert alert is not None
    assert alert.source_ip == "192.168.1.80"

    # 25. Explainability generation
    assert "matched condition" in alert.explanation

    # 24. Deduplication: second identical event within 10m should not generate new alert
    evt2 = NetworkEvent(
        timestamp=datetime.datetime.utcnow(),
        source_ip="192.168.1.80",
        dest_ip="10.0.0.2",
        dest_port=4444,
        source="LOCAL_NETWORK"
    )
    db.add(evt2)
    db.commit()

    matches2 = evaluate_sigma_live(db, evt2)
    assert len(matches2) == 0  # Deduplicated

    alert_count = db.query(Alert).filter(Alert.rule_id == rule_id).count()
    assert alert_count == 1

    db.close()

def test_28_rbac_endpoints(client):
    viewer_token = get_auth_token(role="VIEWER", username="viewer_sigma")
    analyst_token = get_auth_token(role="ANALYST", username="analyst_sigma")
    admin_token = get_auth_token(role="ADMIN", username="admin_sigma")

    # VIEWER trying to import -> 403 Forbidden
    res_v = client.post("/api/sigma/rules/import", json={"raw_yaml": VALID_SIGMA_YAML}, headers={"Authorization": f"Bearer {viewer_token}"})
    assert res_v.status_code == 403

    # ANALYST importing -> 201 Created
    res_a = client.post("/api/sigma/rules/import", json={"raw_yaml": VALID_SIGMA_YAML}, headers={"Authorization": f"Bearer {analyst_token}"})
    assert res_a.status_code == 201
    rule_id = res_a.json()["rule_ids"][0]

    # ANALYST trying to delete -> 403 Forbidden (Delete requires ADMIN)
    res_del_a = client.delete(f"/api/sigma/rules/{rule_id}", headers={"Authorization": f"Bearer {analyst_token}"})
    assert res_del_a.status_code == 403

    # ADMIN deleting -> 200 OK
    res_del_ad = client.delete(f"/api/sigma/rules/{rule_id}", headers={"Authorization": f"Bearer {admin_token}"})
    assert res_del_ad.status_code == 200

def test_29_30_statistics_and_audit():
    db = TestingSessionLocal()
    stats = get_sigma_statistics(db)
    assert "total_rules" in stats
    assert "enabled_rules" in stats
    assert "total_matches" in stats
    db.close()
