import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def get_auth_header():
    # Login as admin to get token
    response = client.post("/api/auth/login", json={"username": "admin", "password": "Admin123!"})
    if response.status_code == 200:
        token = response.json()["access_token"]
        return {"Authorization": f"Bearer {token}"}
    return {}

def test_demo_scenarios_and_pipeline():
    headers = get_auth_header()
    for scenario in ["ssh_brute_force", "suspicious_login", "c2_beacon", "port_scan", "dns_anomaly"]:
        res = client.post("/api/telemetry/demo-scenario", json={"scenario_type": scenario}, headers=headers)
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "SUCCESS"
        assert data["scenario_type"] == scenario
        assert data["events_created"] > 0

def test_threat_hunting_queries():
    headers = get_auth_header()
    res = client.get("/api/hunting/query?source_ip=192.168.1.150&time_range=24h", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert "total" in data
    assert "events" in data
    assert "pivot_summary" in data

def test_threat_hunting_reports():
    headers = get_auth_header()
    payload = {
        "title": "SSH Brute Force Hunt Investigation",
        "hypothesis": "Suspicious external IP attempting lateral movement via SSH",
        "scope": "24h",
        "findings": "Detected 12 authentication failures from 192.168.1.150",
        "conclusion": "Attacker IP blocked",
        "status": "COMPLETED"
    }
    post_res = client.post("/api/hunting/reports", json=payload, headers=headers)
    assert post_res.status_code == 200
    assert post_res.json()["hunt_id"].startswith("TH-")

    get_res = client.get("/api/hunting/reports", headers=headers)
    assert get_res.status_code == 200
    assert len(get_res.json()) >= 1

def test_detection_replay():
    headers = get_auth_header()
    payload = {
        "event_type": "authentication_failure",
        "threshold": 3,
        "time_window_minutes": 60,
        "mitre_technique": "T1110"
    }
    res = client.post("/api/detection/replay", json=payload, headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["mode"] == "DRY_RUN"
    assert "evaluated_count" in data
    assert "matched_count" in data

def test_mitre_attack_coverage():
    headers = get_auth_header()
    res = client.get("/api/mitre/coverage", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert "overall_coverage_percentage" in data
    assert "tactics" in data
    assert len(data["tactics"]) == 12

def test_investigation_evidence():
    headers = get_auth_header()
    # Create or fetch an investigation first
    inv_res = client.get("/api/investigations", headers=headers)
    inv_id = 1
    if inv_res.status_code == 200 and len(inv_res.json()) > 0:
        inv_id = inv_res.json()[0]["id"]

    attach_res = client.post(f"/api/investigations/{inv_id}/evidence", json={
        "evidence_type": "EVENT",
        "source": "ThreatHunt",
        "reference_id": "EV-1001",
        "summary": "Suspicious SSH login failure event",
        "analyst_note": "Verified source IP in blocklist"
    }, headers=headers)
    assert attach_res.status_code in (200, 404)

    if attach_res.status_code == 200:
        get_ev = client.get(f"/api/investigations/{inv_id}/evidence", headers=headers)
        assert get_ev.status_code == 200
        assert len(get_ev.json()) >= 1

def test_audit_logs_filtering():
    headers = get_auth_header()
    res = client.get("/api/audit?action=HUNT_EXECUTE", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert "total" in data
    assert "logs" in data

def test_unauthenticated_access_denied():
    # Verify all new endpoints reject unauthenticated access with 401 Unauthorized
    endpoints = [
        ("GET", "/api/hunting/query"),
        ("GET", "/api/hunting/reports"),
        ("POST", "/api/hunting/reports"),
        ("POST", "/api/detection/replay"),
        ("GET", "/api/mitre/coverage"),
        ("GET", "/api/investigations/1/evidence"),
        ("POST", "/api/investigations/1/evidence"),
        ("GET", "/api/audit"),
        ("POST", "/api/telemetry/demo-scenario")
    ]
    for method, endpoint in endpoints:
        if method == "GET":
            res = client.get(endpoint)
        else:
            res = client.post(endpoint, json={})
        assert res.status_code == 401, f"Endpoint {endpoint} failed unauthenticated check"
