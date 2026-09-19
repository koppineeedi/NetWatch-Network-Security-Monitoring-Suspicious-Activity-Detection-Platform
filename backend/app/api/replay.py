from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import desc
from typing import Dict, Any, Optional
import time
from datetime import datetime, timedelta

from app.database.connection import get_db
from app.models.event import NetworkEvent
from app.models.rule import DetectionRule
from app.models.user import User
from app.api.auth import get_current_user
from app.services.audit_service import log_audit_event

router = APIRouter(prefix="/api/detection", tags=["Detection Replay"])

@router.post("/replay")
def replay_detection_rule(
    payload: Dict[str, Any],
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Safely dry-run/replay a detection rule against stored historical telemetry without triggering active response or mutations.
    Returns evaluated count, matches count, sample matches, MITRE technique, and execution timing.
    """
    start_time = time.time()
    
    rule_id = payload.get("rule_id")
    event_type = payload.get("event_type")
    category = payload.get("category", "SUSPICIOUS")
    threshold = int(payload.get("threshold", 5))
    time_window_minutes = int(payload.get("time_window_minutes", 60))
    mitre_technique = payload.get("mitre_technique", "T1046")

    # Fetch events in time window
    now = datetime.utcnow()
    window_start = now - timedelta(minutes=time_window_minutes)

    query = db.query(NetworkEvent).filter(NetworkEvent.timestamp >= window_start)
    if event_type:
        query = query.filter(NetworkEvent.event_type.ilike(f"%{event_type}%"))

    evaluated_events = query.all()
    evaluated_count = len(evaluated_events)

    # Evaluate matches based on threshold/grouping
    matches = []
    source_counts: Dict[str, List[NetworkEvent]] = {}

    for ev in evaluated_events:
        key = ev.source_ip or ev.username or ev.hostname or "unknown"
        source_counts.setdefault(key, []).append(ev)

    matched_count = 0
    sample_matches = []

    for key, ev_list in source_counts.items():
        if len(ev_list) >= threshold:
            matched_count += len(ev_list)
            for e in ev_list[:5]:  # limit samples
                sample_matches.append({
                    "id": e.id,
                    "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                    "event_type": e.event_type,
                    "source_ip": e.source_ip,
                    "dest_ip": e.dest_ip,
                    "severity": e.status or "SUSPICIOUS",
                    "details": f"Threshold met for entity '{key}' ({len(ev_list)} events >= {threshold} threshold)"
                })

    execution_duration_ms = round((time.time() - start_time) * 1000, 2)

    # Audit log entry
    log_audit_event(
        db,
        user=current_user.username,
        action="RULE_TEST",
        resource_type="DETECTION_RULE",
        resource_id=str(rule_id or "custom-replay"),
        details=f"Detection replay executed. Evaluated: {evaluated_count}, Matched: {matched_count} events in {execution_duration_ms}ms"
    )

    return {
        "status": "SUCCESS",
        "mode": "DRY_RUN",
        "rule_evaluated": {
            "rule_id": rule_id,
            "category": category,
            "threshold": threshold,
            "time_window_minutes": time_window_minutes,
            "mitre_technique": mitre_technique
        },
        "evaluated_count": evaluated_count,
        "matched_count": matched_count,
        "execution_duration_ms": execution_duration_ms,
        "sample_matches": sample_matches[:10],
        "false_positive_considerations": [
            "Verify whether source IP belongs to authorized network monitoring or security scanner",
            "Check if event spike correlates with scheduled backup or automated administrative task",
            "Review user role and standard baseline operating hours before escalating"
        ]
    }
