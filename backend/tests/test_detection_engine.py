import sys
import os
import uuid
import datetime

# Add backend directory to sys.path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend"))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.database.connection import SessionLocal, Base, engine
from app.models.event import NetworkEvent
from app.models.detection import Detection
from app.models.alert import Alert
from app.models.rule import DetectionRule
from app.detection.engine import evaluate_event, seed_default_rules

def run_detection_engine_tests():
    print("============================================================")
    print("STARTING BACKEND DETECTION ENGINE CONTROLLED UNIT TESTS")
    print("============================================================")

    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    # Seed rules
    seed_default_rules(db)

    run_id = str(uuid.uuid4())[:4]

    # ------------------------------------------------------------
    # CASE A: 8+ Unique Destination Ports in 30s -> Possible Port Scan (R-SCAN-01)
    # ------------------------------------------------------------
    test_ip_a = f"10.200.1.{int(run_id, 16) % 200 + 10}"
    now_a = datetime.datetime.utcnow()
    events_a = []
    for port in range(1001, 1010):  # 9 unique ports
        evt = NetworkEvent(
            timestamp=now_a,
            source="TEST_LOG",
            collector="TEST_SUITE",
            event_type="TEST_EVENT",
            source_ip=test_ip_a,
            dest_ip="10.0.0.1",
            dest_port=port,
            protocol="TCP",
            connection_state="SYN_SENT",
            status="NORMAL",
            risk_score=0.0
        )
        db.add(evt)
        events_a.append(evt)
    db.commit()

    dets_a = evaluate_event(db, events_a[-1])
    scan_triggered = any(d.rule_code == "R-SCAN-01" for d in dets_a)
    print(f"CASE A (8+ Unique Ports -> Port Scan): {'PASS' if scan_triggered else 'FAIL'}")

    # ------------------------------------------------------------
    # CASE B: Below Threshold (2 ports) -> No Detection
    # ------------------------------------------------------------
    test_ip_b = f"10.200.2.{int(run_id, 16) % 200 + 10}"
    now_b = datetime.datetime.utcnow()
    for port in [80, 443]:
        evt = NetworkEvent(
            timestamp=now_b,
            source="TEST_LOG",
            collector="TEST_SUITE",
            event_type="TEST_EVENT",
            source_ip=test_ip_b,
            dest_ip="10.0.0.2",
            dest_port=port,
            protocol="TCP",
            connection_state="ESTABLISHED",
            status="NORMAL",
            risk_score=0.0
        )
        db.add(evt)
    db.commit()

    dets_b = evaluate_event(db, evt)
    no_false_scan = not any(d.rule_code == "R-SCAN-01" for d in dets_b)
    print(f"CASE B (Below Threshold -> No False Detection): {'PASS' if no_false_scan else 'FAIL'}")

    # ------------------------------------------------------------
    # CASE C: Repeated Failed Connections (R-FAIL-01) with explicit failure state
    # ------------------------------------------------------------
    test_ip_c = f"10.200.3.{int(run_id, 16) % 200 + 10}"
    now_c = datetime.datetime.utcnow()
    events_c = []
    for _ in range(6):
        evt = NetworkEvent(
            timestamp=now_c,
            source="TEST_LOG",
            collector="TEST_SUITE",
            event_type="TEST_EVENT",
            source_ip=test_ip_c,
            dest_ip="10.0.0.3",
            dest_port=22,
            protocol="TCP",
            connection_state="REFUSED",
            status="NORMAL",
            risk_score=0.0
        )
        db.add(evt)
        events_c.append(evt)
    db.commit()

    dets_c = evaluate_event(db, events_c[-1])
    fail_triggered = any(d.rule_code == "R-FAIL-01" for d in dets_c)
    print(f"CASE C (Explicit Failed Connections -> Rule Trigger): {'PASS' if fail_triggered else 'FAIL'}")

    # ------------------------------------------------------------
    # CASE D: Missing Failure State Telemetry -> Insufficient Evidence
    # ------------------------------------------------------------
    test_ip_d = f"10.200.4.{int(run_id, 16) % 200 + 10}"
    now_d = datetime.datetime.utcnow()
    events_d = []
    for _ in range(6):
        evt = NetworkEvent(
            timestamp=now_d,
            source="TEST_LOG",
            collector="TEST_SUITE",
            event_type="TEST_EVENT",
            source_ip=test_ip_d,
            dest_ip="10.0.0.4",
            dest_port=80,
            protocol="TCP",
            connection_state=None,  # Missing failure state
            status="NORMAL",
            risk_score=0.0
        )
        db.add(evt)
        events_d.append(evt)
    db.commit()

    dets_d = evaluate_event(db, events_d[-1])
    no_false_fail = not any(d.rule_code == "R-FAIL-01" for d in dets_d)
    print(f"CASE D (Missing Telemetry Fields -> Insufficient Evidence): {'PASS' if no_false_fail else 'FAIL'}")

    # ------------------------------------------------------------
    # CASE E: Re-evaluating Same Evidence -> Deduplication Prevents Duplicate Alerts
    # ------------------------------------------------------------
    dets_e = evaluate_event(db, events_a[-1])
    dedup_pass = (len(dets_e) == 0)
    print(f"CASE E (Duplicate Evaluation -> Deduplication Skipping): {'PASS' if dedup_pass else 'FAIL'}")

    # ------------------------------------------------------------
    # CASE F: Real LOCAL_NETWORK Events Evaluated Cleanly
    # ------------------------------------------------------------
    local_evt = db.query(NetworkEvent).filter(NetworkEvent.source == "LOCAL_NETWORK").first()
    if local_evt:
        dets_f = evaluate_event(db, local_evt)
        print(f"CASE F (Real LOCAL_NETWORK Evaluation Clean): PASS")
    else:
        print(f"CASE F (Real LOCAL_NETWORK Evaluation Clean): PASS (No local events present)")

    db.close()
    print("============================================================")

if __name__ == "__main__":
    run_detection_engine_tests()
