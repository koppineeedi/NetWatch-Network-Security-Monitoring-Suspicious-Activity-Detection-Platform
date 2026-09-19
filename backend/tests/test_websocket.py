import sys
import os
import uuid
import datetime
from fastapi.testclient import TestClient

# Add backend directory to sys.path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend"))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.database.connection import SessionLocal, Base, engine
from app.models.user import User
from app.models.event import NetworkEvent
from app.models.alert import Alert
from app.models.detection import Detection
from app.core.security import hash_password, create_access_token
from app.realtime.manager import ws_manager
from app.realtime.publisher import publish_network_event, publish_detection, publish_alert, publish_telemetry_status
from app.main import app

def run_websocket_tests():
    print("============================================================")
    print("STARTING PHASE 7 WEBSOCKET & REAL-TIME STREAM UNIT TEST SUITE")
    print("============================================================")

    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    client = TestClient(app)

    run_id = str(uuid.uuid4())[:6]

    # 1. Create Test User
    test_user = User(
        username=f"ws_user_{run_id}",
        email=f"ws_user_{run_id}@test.local",
        password_hash=hash_password("WsPass123!"),
        role="ADMIN",
        is_active=True
    )
    db.add(test_user)
    db.commit()

    token = create_access_token(data={"sub": str(test_user.id), "username": test_user.username, "role": "ADMIN"})
    invalid_token = "invalid.jwt.token.string"

    # 1. Unauthenticated connection rejection (No Token)
    try:
        with client.websocket_connect("/ws/events") as ws:
            test_1 = False
    except Exception:
        test_1 = True
    print(f"TEST 1 (Unauthenticated Request Rejected): {'PASS' if test_1 else 'FAIL'}")

    # 2. Invalid Token connection rejection
    try:
        with client.websocket_connect(f"/ws/events?token={invalid_token}") as ws:
            test_2 = False
    except Exception:
        test_2 = True
    print(f"TEST 2 (Invalid Token Rejected): {'PASS' if test_2 else 'FAIL'}")

    # 3. Valid Token Connection & Welcome Ack
    test_3 = False
    try:
        with client.websocket_connect(f"/ws/events?token={token}") as ws:
            data = ws.receive_json()
            if data and data.get("type") == "connected" and data.get("user") == test_user.username:
                test_3 = True
    except Exception as e:
        print(f"WS Connect Exception: {e}")
        test_3 = False
    print(f"TEST 3 (Authenticated WebSocket Connection): {'PASS' if test_3 else 'FAIL'}")

    # 4. Heartbeat Ping / Pong
    test_4 = False
    try:
        with client.websocket_connect(f"/ws/events?token={token}") as ws:
            ws.receive_json()  # ack
            ws.send_json({"type": "ping"})
            resp = ws.receive_json()
            if resp and resp.get("type") == "pong":
                test_4 = True
    except Exception:
        test_4 = False
    print(f"TEST 4 (Heartbeat Ping/Pong): {'PASS' if test_4 else 'FAIL'}")

    # 5. Network Event Real-Time Broadcast
    test_5 = False
    try:
        with client.websocket_connect(f"/ws/events?token={token}") as ws:
            ws.receive_json()  # ack
            dummy_evt = NetworkEvent(
                id=99991,
                timestamp=datetime.datetime.utcnow(),
                source="TEST_LOG",
                collector="TEST",
                event_type="TEST_EVENT",
                source_ip="192.168.1.100",
                source_port=54321,
                dest_ip="10.0.0.1",
                dest_port=443,
                protocol="TCP",
                connection_state="ESTABLISHED",
                status="NORMAL",
                risk_score=0.0
            )
            publish_network_event(dummy_evt)
            payload = ws.receive_json()
            if payload and payload.get("type") == "network_event" and payload["data"]["id"] == 99991:
                test_5 = True
    except Exception as e:
        print(f"Broadcast error: {e}")
        test_5 = False
    print(f"TEST 5 (Network Event Real-Time Broadcast): {'PASS' if test_5 else 'FAIL'}")

    # 6. Detection Real-Time Broadcast
    test_6 = False
    try:
        with client.websocket_connect(f"/ws/events?token={token}") as ws:
            ws.receive_json()  # ack
            dummy_det = Detection(
                id=88881,
                timestamp=datetime.datetime.utcnow(),
                rule_code="R-TEST",
                rule_name="Test Rule",
                source_ip="192.168.1.100",
                target_ip="10.0.0.1",
                mitre_tactic="TEST",
                mitre_technique="TEST-001",
                action_taken="ALERTED",
                details="Test detection",
                evidence="{}",
                risk_score=75.0
            )
            publish_detection(dummy_det)
            payload = ws.receive_json()
            if payload and payload.get("type") == "detection" and payload["data"]["id"] == 88881:
                test_6 = True
    except Exception:
        test_6 = False
    print(f"TEST 6 (Detection Real-Time Broadcast): {'PASS' if test_6 else 'FAIL'}")

    # 7. Alert Real-Time Broadcast
    test_7 = False
    try:
        with client.websocket_connect(f"/ws/events?token={token}") as ws:
            ws.receive_json()  # ack
            dummy_alert = Alert(
                id=77771,
                timestamp=datetime.datetime.utcnow(),
                detection_id=88881,
                detection_type="Test Alert",
                severity="HIGH",
                confidence=0.9,
                risk_score=80.0,
                source_ip="192.168.1.100",
                dest_ip="10.0.0.1",
                dest_port=443,
                protocol="TCP",
                description="Test alert payload",
                explanation="Test explanation",
                status="NEW",
                assigned_analyst="Unassigned",
                rule_id="R-TEST"
            )
            publish_alert(dummy_alert)
            payload = ws.receive_json()
            if payload and payload.get("type") == "alert" and payload["data"]["id"] == 77771:
                test_7 = True
    except Exception:
        test_7 = False
    print(f"TEST 7 (Alert Real-Time Broadcast): {'PASS' if test_7 else 'FAIL'}")

    # 8. Telemetry Status Real-Time Broadcast
    test_8 = False
    try:
        with client.websocket_connect(f"/ws/events?token={token}") as ws:
            ws.receive_json()  # ack
            dummy_status = {"running": True, "collector": "LOCAL_NETWORK", "events_stored": 42}
            publish_telemetry_status(dummy_status)
            payload = ws.receive_json()
            if payload and payload.get("type") == "telemetry_status" and payload["data"]["events_stored"] == 42:
                test_8 = True
    except Exception:
        test_8 = False
    print(f"TEST 8 (Telemetry Status Broadcast): {'PASS' if test_8 else 'FAIL'}")

    # 9. Multiple Concurrent Clients & Cleanup
    test_9 = False
    try:
        with client.websocket_connect(f"/ws/events?token={token}") as ws1:
            ws1.receive_json()
            with client.websocket_connect(f"/ws/events?token={token}") as ws2:
                ws2.receive_json()
                dummy_status = {"running": True, "collector": "LOCAL_NETWORK", "events_stored": 99}
                publish_telemetry_status(dummy_status)
                p1 = ws1.receive_json()
                p2 = ws2.receive_json()
                if p1.get("data", {}).get("events_stored") == 99 and p2.get("data", {}).get("events_stored") == 99:
                    test_9 = True
    except Exception:
        test_9 = False
    print(f"TEST 9 (Multiple Clients & Broadcast Isolation): {'PASS' if test_9 else 'FAIL'}")

    # 10. Robustness: Publisher safely handles no active connections without crashing
    test_10 = True
    try:
        publish_telemetry_status({"running": False})
        publish_network_event(dummy_evt)
    except Exception as e:
        print(f"Publish error without clients: {e}")
        test_10 = False
    print(f"TEST 10 (Publisher Robustness With Zero Clients): {'PASS' if test_10 else 'FAIL'}")

    db.close()
    print("============================================================")

if __name__ == "__main__":
    run_websocket_tests()
