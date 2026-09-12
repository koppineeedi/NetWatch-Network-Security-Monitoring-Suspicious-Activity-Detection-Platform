import os
import sys
import pytest
import datetime
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Add backend directory to sys.path
backend_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend'))
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

from app.database.connection import Base, get_db
from app.main import app as fastapi_app
from app.collectors.syslog_collector import parse_syslog_message, SyslogCollector
from app.threat_intelligence.services.ioc_matcher import normalize_ioc_value, validate_ioc
from app.models.threat_intel import IOC, IOCMatch, IPReputationCache, IPGeolocationCache, ThreatIntelProvider
from app.models.connector import Connector
from app.models.user import User
from app.core.security import hash_password, create_access_token
import app.models as _app_models

from sqlalchemy.pool import StaticPool

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

def get_auth_token(role="ADMIN", username="admin_test"):
    db = TestingSessionLocal()
    user = db.query(User).filter(User.username == username).first()
    if not user:
        user = User(
            username=username,
            email=f"{username}@netwatch.local",
            password_hash=hash_password("TestPass123!"),
            role=role,
            is_active=True
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    token = create_access_token(data={"sub": str(user.id), "role": role})
    db.close()
    return token

# =====================================================================
# 1. SYSLOG PARSER & COLLECTOR TESTS
# =====================================================================

def test_syslog_parser_valid():
    msg = "<34>Oct 11 22:14:15 myhost myapp: User admin logged in from 192.168.1.50"
    parsed = parse_syslog_message(msg, source_ip="192.168.1.50")
    assert parsed["facility"] == 4  # 34 // 8 = 4 (auth)
    assert parsed["severity"] == 2  # 34 % 8 = 2 (crit)
    assert parsed["hostname"] == "myhost"
    assert parsed["source_ip"] == "192.168.1.50"
    assert "User admin logged in" in parsed["message"]

def test_syslog_parser_malformed():
    # Should not crash on malformed string
    msg = "Malformed syslog message without priority header"
    parsed = parse_syslog_message(msg, source_ip="10.0.0.1")
    assert parsed["facility"] == 1  # user
    assert parsed["severity"] == 6  # info
    assert parsed["hostname"] == "10.0.0.1"
    assert parsed["message"] == msg

def test_syslog_collector_lifecycle():
    collector = SyslogCollector()
    collector.host = "127.0.0.1"
    collector.udp_port = 10514
    collector.enabled = True
    assert collector.is_running is False
    collector.start()
    assert collector.is_running is True
    collector.stop()
    assert collector.is_running is False

# =====================================================================
# 2. CONNECTOR ARCHITECTURE & SECRET REDACTION & RBAC TESTS
# =====================================================================

def test_connector_crud_and_rbac(client):
    token_admin = get_auth_token("ADMIN", "admin1")
    token_viewer = get_auth_token("VIEWER", "viewer1")

    headers_admin = {"Authorization": f"Bearer {token_admin}"}
    headers_viewer = {"Authorization": f"Bearer {token_viewer}"}

    # 1. Get connectors (should list default cloud/syslog connectors)
    res = client.get("/api/connectors", headers=headers_admin)
    assert res.status_code == 200
    data = res.json()
    assert len(data) >= 4

    # Secret redaction check: Ensure no API keys or secrets are exposed
    for conn in data:
        if conn.get("config"):
            for k, v in conn["config"].items():
                if "secret" in k.lower() or "key" in k.lower():
                    assert v.startswith("*")

    # 2. Non-ADMIN cannot create connector
    res = client.post("/api/connectors", json={
        "connector_id": "test-conn",
        "name": "Test Connector",
        "connector_type": "AWS_CLOUDTRAIL",
        "config": {"aws_access_key_id": "AKIA123", "aws_secret_access_key": "Secret123"}
    }, headers=headers_viewer)
    assert res.status_code == 403

    # 3. ADMIN creates connector
    res = client.post("/api/connectors", json={
        "connector_id": "test-conn",
        "name": "Test Connector",
        "connector_type": "AWS_CLOUDTRAIL",
        "config": {"aws_access_key_id": "AKIA123", "aws_secret_access_key": "Secret123"}
    }, headers=headers_admin)
    assert res.status_code == 200
    created = res.json()
    assert created["connector_id"] == "test-conn"
    assert created["config"]["aws_secret_access_key"].startswith("*")

    # 4. Test connector (without valid cloud credentials -> returns NOT_CONFIGURED)
    res = client.post("/api/connectors/aws_cloudtrail/test", headers=headers_admin)
    assert res.status_code == 200
    test_res = res.json()
    assert test_res["status"] == "NOT_CONFIGURED"

# =====================================================================
# 3. THREAT INTELLIGENCE IOC MODEL, NORMALIZATION & IMPORT TESTS
# =====================================================================

def test_ioc_normalization_and_validation():
    # IP normalization
    norm_ip = normalize_ioc_value(" 192.168.1.1 ", "IP")
    valid_ip, ioc_type = validate_ioc("192.168.1.1")
    assert norm_ip == "192.168.1.1"
    assert valid_ip is True
    assert ioc_type == "IP"

    # Domain lowercase normalization
    norm_dom = normalize_ioc_value("http://MALICIOUS-DOMAIN.COM/path", "DOMAIN")
    valid_dom, ioc_type_dom = validate_ioc("malicious-domain.com")
    assert norm_dom == "malicious-domain.com"
    assert valid_dom is True
    assert ioc_type_dom == "DOMAIN"

    # Hash lowercase normalization
    norm_hash = normalize_ioc_value(" 44D88612FEAB86424B5117DA448FFA5E ", "HASH_MD5")
    valid_hash, ioc_type_hash = validate_ioc("44D88612FEAB86424B5117DA448FFA5E")
    assert norm_hash == "44d88612feab86424b5117da448ffa5e"
    assert valid_hash is True
    assert ioc_type_hash == "HASH_MD5"

    # Validation
    valid, t = validate_ioc("1.1.1.1")
    assert valid is True
    assert t == "IP"

    valid, _ = validate_ioc("invalid_ioc_string_xyz")
    assert valid is False

def test_ioc_api_crud_and_import(client):
    token = get_auth_token("ADMIN", "admin_ioc")
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Create IOC manually
    res = client.post("/api/iocs", json={
        "ioc_value": "185.220.101.5",
        "ioc_type": "IP",
        "source": "AbuseIPDB",
        "confidence": 95,
        "severity": "HIGH",
        "tags": "tor,exit_node"
    }, headers=headers)
    assert res.status_code == 200
    ioc_data = res.json()
    assert ioc_data["normalized_value"] == "185.220.101.5"

    # 2. Get IOCs list
    res = client.get("/api/iocs", headers=headers)
    assert res.status_code == 200
    assert len(res.json()) >= 1

    # 3. Match endpoint check
    res = client.get("/api/iocs/match/185.220.101.5", headers=headers)
    assert res.status_code == 200
    match_res = res.json()
    assert match_res["matched"] is True
    assert match_res["match"]["confidence"] == 95

    # 4. Feed File Import
    csv_content = "ioc_value,ioc_type,confidence,severity\n198.51.100.1,IP,80,HIGH\nbad-site.org,DOMAIN,90,CRITICAL"
    res = client.post(
        "/api/iocs/import",
        files={"file": ("feed.csv", csv_content.encode("utf-8"), "text/csv")},
        data={"provider": "CUSTOM_FEED"},
        headers=headers
    )
    assert res.status_code == 200
    import_res = res.json()
    assert import_res["records_received"] == 3
    assert import_res["records_accepted"] == 2
    assert import_res["records_rejected"] == 0

# =====================================================================
# 4. IP REPUTATION & GEOLOCATION CACHING TESTS
# =====================================================================

def test_ip_reputation_and_geo(client):
    token = get_auth_token("ANALYST", "analyst_rep")
    headers = {"Authorization": f"Bearer {token}"}

    # Reputation endpoint (missing API keys -> returns NOT_CONFIGURED safely)
    res = client.get("/api/ip/8.8.8.8/reputation", headers=headers)
    assert res.status_code == 200
    rep_data = res.json()
    assert rep_data["ip_address"] == "8.8.8.8"
    assert rep_data["status"] == "NOT_CONFIGURED"

    # Geolocation endpoint (missing provider -> returns NOT_CONFIGURED safely)
    res = client.get("/api/ip/8.8.8.8/geolocation", headers=headers)
    assert res.status_code == 200
    geo_data = res.json()
    assert geo_data["ip_address"] == "8.8.8.8"
    assert geo_data["status"] == "NOT_CONFIGURED"

# =====================================================================
# 5. THREAT INTEL STATUS & PROVIDERS TEST
# =====================================================================

def test_threat_intel_status(client):
    token = get_auth_token("ANALYST", "analyst_ti")
    headers = {"Authorization": f"Bearer {token}"}

    res = client.get("/api/threat-intelligence/status", headers=headers)
    assert res.status_code == 200
    status = res.json()
    assert "total_iocs" in status
    assert "providers" in status

    res = client.get("/api/threat-intelligence/providers", headers=headers)
    assert res.status_code == 200
    providers = res.json()
    assert len(providers) >= 3
