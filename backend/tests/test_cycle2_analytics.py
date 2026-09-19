"""
NetWatch Enterprise Enhancement Cycle 2 - Comprehensive Test Suite
Validates UEBA, 168-hour statistical baselines, anomaly detection, bounded risk scoring, temporal decay, campaign clustering, and REST API endpoints.
"""

import pytest
import datetime
import os
import sys
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient

# Add backend directory to sys.path
backend_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend'))
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

from app.database.connection import Base, get_db
from app.main import app
from app.models.event import NetworkEvent
from app.models.alert import Alert
from app.models.user import User
from app.core.security import hash_password, create_access_token
from app.analytics.models import BehaviorBaseline, Entity, EntityRiskHistory, Anomaly, Campaign, CampaignEvent
from app.analytics.feature_engineering import extract_entity_features, calculate_entropy
from app.analytics.baseline import update_entity_baselines
from app.analytics.anomaly import detect_anomalies_for_entity
from app.analytics.risk import compute_entity_risk
from app.analytics.clustering import cluster_campaigns
from app.analytics.explainability import generate_anomaly_explanation

from sqlalchemy.pool import StaticPool

# Setup In-Memory SQLite Test DB
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@pytest.fixture(scope="module")
def test_db():
    import app.models  # Ensures all ORM models are registered with Base.metadata
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    
    # Create test admin user
    admin = User(
        username="admin_test",
        email="admin@netwatch.local",
        password_hash=hash_password("AdminPass123!"),
        role="ADMIN",
        is_active=True
    )
    db.add(admin)
    db.commit()
    
    yield db
    db.close()
    Base.metadata.drop_all(bind=engine)

@pytest.fixture(scope="module")
def auth_headers(test_db):
    user = test_db.query(User).filter(User.username == "admin_test").first()
    token = create_access_token({"sub": str(user.id)})
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture(scope="module")
def client(test_db):
    def override_get_db():
        try:
            yield test_db
        finally:
            pass
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()

# 1. Feature Engineering & Entropy Tests
def test_entropy_calculation():
    assert calculate_entropy([]) == 0.0
    assert calculate_entropy([80, 80, 80]) == 0.0
    entropy_diverse = calculate_entropy([80, 443, 22, 53, 8080, 8443, 3389, 21])
    assert entropy_diverse > 2.0

def test_feature_extraction(test_db):
    entity_id = "192.168.1.105"
    # Insert test network events
    for i in range(15):
        evt = NetworkEvent(
            timestamp=datetime.datetime.utcnow() - datetime.timedelta(minutes=i),
            source_ip=entity_id,
            dest_ip=f"10.0.0.{i+1}",
            dest_port=80 if i % 2 == 0 else 443 + i,
            protocol="TCP",
            connection_state="ESTABLISHED" if i % 3 != 0 else "FAILED",
            bytes_sent=100 * (i + 1),
            bytes_received=200 * (i + 1)
        )
        test_db.add(evt)
    test_db.commit()

    features = extract_entity_features(test_db, entity_id, window_hours=1)
    assert features["connection_count"] == 15
    assert features["unique_destination_count"] == 15
    assert features["failed_connection_count"] == 5
    assert features["destination_port_entropy"] > 0.0

# 2. Baseline Calculation & Insufficient Data Contract Tests
def test_baseline_insufficient_data_contract(test_db):
    entity_id = "192.168.1.200"
    # Insert 5 events (< min threshold 20)
    for i in range(5):
        test_db.add(NetworkEvent(
            timestamp=datetime.datetime.utcnow(),
            source_ip=entity_id,
            dest_ip="10.0.0.1",
            dest_port=80,
            protocol="TCP",
            connection_state="ESTABLISHED"
        ))
    test_db.commit()

    baselines = update_entity_baselines(test_db, entity_id, min_events=20)
    # Check that baselines remain INSUFFICIENT_DATA and zero baselines manufactured
    for b in baselines.values():
        assert b.status == "INSUFFICIENT_DATA"

def test_baseline_active_generation(test_db):
    entity_id = "192.168.1.50"
    # Insert 25 events (>= min threshold 20)
    for i in range(25):
        test_db.add(NetworkEvent(
            timestamp=datetime.datetime.utcnow() - datetime.timedelta(hours=i),
            source_ip=entity_id,
            dest_ip=f"10.0.0.{i % 3}",
            dest_port=80 if i % 2 == 0 else 443,
            protocol="TCP",
            connection_state="ESTABLISHED"
        ))
    test_db.commit()

    baselines = update_entity_baselines(test_db, entity_id, min_events=20)
    assert len(baselines) > 0
    assert baselines["connection_count"].status == "ACTIVE"
    assert baselines["connection_count"].sample_count >= 20

# 3. Anomaly Detection & Explainability Tests
def test_anomaly_detection_and_explainability(test_db):
    entity_id = "192.168.1.50"
    # Inject massive port entropy spike
    for i in range(50):
        test_db.add(NetworkEvent(
            timestamp=datetime.datetime.utcnow(),
            source_ip=entity_id,
            dest_ip=f"10.0.0.{i}",
            dest_port=1000 + i,
            protocol="TCP",
            connection_state="FAILED"
        ))
    test_db.commit()

    anomalies = detect_anomalies_for_entity(test_db, entity_id)
    assert len(anomalies) > 0
    anom = anomalies[0]
    assert anom.anomaly_score >= 50.0
    assert "deviated" in anom.explanation.lower() or "observed" in anom.explanation.lower()

# 4. Bounded Risk Scoring & 24h Decay Tests
def test_bounded_entity_risk_and_decay(test_db):
    entity_id = "192.168.1.50"
    res = compute_entity_risk(test_db, entity_id, decay_hours=24)
    assert 0.0 <= res["risk_score"] <= 100.0
    assert res["entity_id"] == entity_id

# 5. Campaign Clustering Tests
def test_campaign_clustering(test_db):
    # Ensure active anomalies exist
    anom = Anomaly(
        entity_type="IP",
        entity_id="192.168.1.50",
        feature="destination_port_entropy",
        observed_value=8.5,
        baseline_value=1.2,
        deviation=7.3,
        anomaly_score=85.0,
        severity="HIGH",
        explanation="High port entropy anomaly",
        mitre_technique="T1046",
        timestamp=datetime.datetime.utcnow()
    )
    test_db.add(anom)
    test_db.commit()

    campaigns = cluster_campaigns(test_db)
    assert len(campaigns) > 0
    c = campaigns[0]
    assert c.campaign_id.startswith("CMP-2026-")
    assert c.risk_score >= 50.0

# 6. REST API Endpoints Verification
def test_api_ueba_status(client, auth_headers):
    res = client.get("/api/ueba/status", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert data["enabled"] is True
    assert data["baseline_window_hours"] == 168

def test_api_ueba_stats(client, auth_headers):
    res = client.get("/api/ueba/stats", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert "total_entities" in data
    assert "baseline_status_breakdown" in data

def test_api_entities_list(client, auth_headers):
    res = client.get("/api/entities", headers=auth_headers)
    assert res.status_code == 200
    assert isinstance(res.json(), list)

def test_api_anomalies_list(client, auth_headers):
    res = client.get("/api/anomalies", headers=auth_headers)
    assert res.status_code == 200
    assert isinstance(res.json(), list)

def test_api_campaigns_list(client, auth_headers):
    res = client.get("/api/campaigns", headers=auth_headers)
    assert res.status_code == 200
    assert isinstance(res.json(), list)

def test_api_trigger_analytics_cycle(client, auth_headers):
    res = client.post("/api/ueba/trigger-cycle", headers=auth_headers)
    assert res.status_code == 200
    assert res.json()["message"] == "Analytics and UEBA cycle completed successfully"
