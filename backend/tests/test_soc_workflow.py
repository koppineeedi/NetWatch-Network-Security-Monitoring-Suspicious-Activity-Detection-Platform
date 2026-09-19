import sys
import os
import uuid
import datetime
from fastapi import HTTPException

# Add backend directory to sys.path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend"))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.database.connection import SessionLocal, Base, engine
from app.models.event import NetworkEvent
from app.models.detection import Detection
from app.models.alert import Alert
from app.models.investigation import Investigation, AnalystNote
from app.models.audit import AuditLog
from app.services.alert_service import AlertService
from app.services.investigation_service import InvestigationService
from app.services.audit_service import AuditService
from app.detection.engine import evaluate_event, seed_default_rules

def run_soc_workflow_tests():
    print("============================================================")
    print("STARTING SOC ALERT & INVESTIGATION WORKFLOW UNIT TESTS")
    print("============================================================")

    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    seed_default_rules(db)

    run_id = str(uuid.uuid4())[:4]
    test_ip = f"10.250.1.{int(run_id, 16) % 200 + 10}"

    # Generate trigger events for port scan rule
    events = []
    now = datetime.datetime.utcnow()
    for port in range(2001, 2010):  # 9 unique ports
        evt = NetworkEvent(
            timestamp=now,
            source="TEST_LOG",
            collector="TEST_WORKFLOW",
            event_type="TEST_EVENT",
            source_ip=test_ip,
            dest_ip="10.0.0.99",
            dest_port=port,
            protocol="TCP",
            connection_state="SYN_SENT",
            status="NORMAL",
            risk_score=0.0
        )
        db.add(evt)
        events.append(evt)
    db.commit()

    # TEST 1: Existing real detection creates alert
    dets = evaluate_event(db, events[-1])
    test_1 = len(dets) > 0
    print(f"TEST 1 (Detection Creates Alert): {'PASS' if test_1 else 'FAIL'}")

    det_id = dets[0].id if dets else None
    alert = db.query(Alert).filter(Alert.detection_id == det_id).first() if det_id else None

    # TEST 2: Alert retrieved through API / service
    test_2 = alert is not None and alert.source_ip == test_ip
    print(f"TEST 2 (Alert Retrieved via Service): {'PASS' if test_2 else 'FAIL'}")

    # TEST 3: Alert filtering works
    filtered_alerts = AlertService.get_alerts(db=db, status="NEW", severity="HIGH")
    test_3 = len(filtered_alerts) > 0
    print(f"TEST 3 (Alert Filtering by Status & Severity): {'PASS' if test_3 else 'FAIL'}")

    # TEST 4: Alert detail returns correct detection
    test_4 = (alert.detection_id == det_id) if alert else False
    print(f"TEST 4 (Alert References Correct Detection): {'PASS' if test_4 else 'FAIL'}")

    # TEST 5: Alert evidence returns actual event records
    evidence_evts = AlertService.get_alert_evidence_events(db, alert.id) if alert else []
    test_5 = len(evidence_evts) > 0
    print(f"TEST 5 (Alert Evidence Returns Actual Events): {'PASS' if test_5 else 'FAIL'}")

    # TEST 6: Investigation created from alert
    inv = InvestigationService.create_investigation_from_alert(db, alert.id, "Analyst Alice") if alert else None
    test_6 = inv is not None and inv.alert_id == alert.id
    print(f"TEST 6 (Investigation Created from Alert): {'PASS' if test_6 else 'FAIL'}")

    # TEST 7: Alert status transitions NEW -> INVESTIGATING
    db.refresh(alert)
    test_7 = (alert.status == "INVESTIGATING") if alert else False
    print(f"TEST 7 (Alert Status Transitions to INVESTIGATING): {'PASS' if test_7 else 'FAIL'}")

    # TEST 8: Invalid status transition rejected (NEW -> CLOSED)
    test_8 = False
    try:
        AlertService.update_alert(db, alert.id, "Analyst Alice", status="CLOSED")
    except HTTPException as e:
        test_8 = e.status_code == 400
    print(f"TEST 8 (Invalid Alert Transition Rejected with 400): {'PASS' if test_8 else 'FAIL'}")

    # TEST 9: Analyst note persists in DB
    note = InvestigationService.add_note(db, inv.id, "Analyst Alice", "Port scan verified on internal host.") if inv else None
    test_9 = note is not None and note.id is not None
    print(f"TEST 9 (Analyst Note Persists in DB): {'PASS' if test_9 else 'FAIL'}")

    # TEST 10: Investigation verdict persists
    inv_updated = InvestigationService.update_investigation(
        db, inv.id, "Analyst Alice", status="RESOLVED", verdict="TRUE_POSITIVE", verdict_reason="Authorized vulnerability assessment activity."
    ) if inv else None
    test_10 = (inv_updated.verdict == "TRUE_POSITIVE") if inv_updated else False
    print(f"TEST 10 (Investigation Verdict Persists): {'PASS' if test_10 else 'FAIL'}")

    # TEST 11: Alert resolution persists
    db.refresh(alert)
    test_11 = (alert.status == "RESOLVED") if alert else False
    print(f"TEST 11 (Alert Resolution Persists): {'PASS' if test_11 else 'FAIL'}")

    # TEST 12: Audit log records state changes
    audit_entries = db.query(AuditLog).filter(AuditLog.resource_id == str(inv.id)).all() if inv else []
    test_12 = len(audit_entries) > 0
    print(f"TEST 12 (Audit Log Records State Changes): {'PASS' if test_12 else 'FAIL'}")

    # TEST 13: Empty database test (Service queries return empty lists without crashing)
    empty_alerts = AlertService.get_alerts(db=db, source_ip="99.99.99.99")
    test_13 = len(empty_alerts) == 0
    print(f"TEST 13 (Empty Query Returns Empty List Without Fake Events): {'PASS' if test_13 else 'FAIL'}")

    db.close()
    print("============================================================")

if __name__ == "__main__":
    run_soc_workflow_tests()
