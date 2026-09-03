import json
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session

from app.models.event import NetworkEvent
from app.models.alert import Alert
from app.models.detection import Detection
from app.models.rule import DetectionRule
from app.models.asset import Asset
from app.detection.rules import DEFAULT_RULES, RuleEvaluator
from app.detection.correlator import EventCorrelator
from app.detection.risk import RiskCalculator
from app.realtime.publisher import publish_detection, publish_alert

def seed_default_rules(db: Session):
    """
    Seeds default configurable detection rules if detection_rules table is empty.
    """
    existing_count = db.query(DetectionRule).count()
    if existing_count == 0:
        for r_dict in DEFAULT_RULES:
            rule = DetectionRule(
                rule_code=r_dict["rule_code"],
                name=r_dict["name"],
                category=r_dict["category"],
                condition_desc=r_dict["condition_desc"],
                severity=r_dict["severity"],
                threshold=r_dict["threshold"],
                time_window=r_dict["time_window"],
                enabled=r_dict["enabled"]
            )
            db.add(rule)
        db.commit()

def evaluate_event(db: Session, event: NetworkEvent) -> List[Detection]:
    """
    Evaluates an ingested NetworkEvent against all enabled detection rules in DB.
    Generates evidence-backed Detections and Alerts with deduplication logic.
    Publishes new Detections & Alerts in real time to connected WebSocket clients.
    """
    if not event or not event.source_ip:
        return []

    # Ensure rules are seeded
    seed_default_rules(db)

    enabled_rules = db.query(DetectionRule).filter(DetectionRule.enabled == True).all()
    created_detections = []

    for rule in enabled_rules:
        # Correlate events for source IP within rule's time window
        ref_time = event.timestamp if event.timestamp else datetime.utcnow()
        correlated_events = EventCorrelator.get_source_events_in_window(
            db=db,
            source_ip=event.source_ip,
            time_window_seconds=rule.time_window,
            ref_timestamp=ref_time
        )

        res = RuleEvaluator.evaluate_rule(
            rule_code=rule.rule_code,
            threshold=rule.threshold,
            window=rule.time_window,
            events=correlated_events
        )

        if res.get("triggered"):
            # Deduplication: Check if an identical Detection was created in last 10 minutes
            dedup_window = ref_time - timedelta(minutes=10)
            existing_det = db.query(Detection).filter(
                Detection.rule_code == rule.rule_code,
                Detection.source_ip == event.source_ip,
                Detection.timestamp >= dedup_window
            ).first()

            if existing_det:
                continue  # Skip creating duplicate detection/alert

            # Calculate Evidence-Based Risk Score & Confidence Rating
            risk_score, confidence, risk_factors = RiskCalculator.calculate_risk(
                event_count=res["event_count"],
                unique_ports=len(res["unique_ports"]),
                severity=res["severity"],
                correlation_factor=1.1 if len(correlated_events) > 10 else 1.0,
                has_failed_states=res.get("has_failed_states", False)
            )

            # Format Evidence JSON
            evidence_json = RiskCalculator.format_evidence(
                source_ip=event.source_ip,
                target_ip=event.dest_ip or "MULTIPLE",
                unique_ports=res["unique_ports"],
                time_window_seconds=rule.time_window,
                event_count=res["event_count"],
                event_ids=res["event_ids"],
                risk_factors=risk_factors
            )

            # Save Detection
            detection = Detection(
                timestamp=datetime.utcnow(),
                rule_code=rule.rule_code,
                rule_name=rule.name,
                source_ip=event.source_ip,
                target_ip=event.dest_ip,
                mitre_tactic=res.get("mitre_tactic", "ANOMALY"),
                mitre_technique=res.get("mitre_technique", "UNKNOWN"),
                action_taken="ALERTED",
                details=res["explanation"],
                evidence=evidence_json,
                risk_score=risk_score
            )
            db.add(detection)
            db.commit()
            db.refresh(detection)
            created_detections.append(detection)

            # Save Alert referencing Detection
            alert = Alert(
                timestamp=datetime.utcnow(),
                detection_id=detection.id,
                detection_type=rule.name,
                severity=res["severity"],
                confidence=confidence,
                risk_score=risk_score,
                source_ip=event.source_ip,
                dest_ip=event.dest_ip,
                dest_port=event.dest_port,
                protocol=event.protocol,
                description=f"{rule.name} triggered for {event.source_ip}",
                explanation=res["explanation"],
                status="NEW",
                assigned_analyst="Unassigned",
                rule_id=rule.rule_code
            )
            db.add(alert)

            # Update event risk status
            event.status = "SUSPICIOUS"
            event.risk_score = risk_score

            # Update Asset risk score if asset exists
            if event.dest_ip:
                asset = db.query(Asset).filter(Asset.ip_address == event.dest_ip).first()
                if asset:
                    asset.alerts_count += 1
                    asset.risk_score = min(100.0, asset.risk_score + 15.0)

            db.commit()
            db.refresh(alert)

            # Real-Time WebSocket Publishing
            publish_detection(detection)
            publish_alert(alert)

    return created_detections

def evaluate_batch(
    db: Session,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    source_ip: Optional[str] = None,
    rule_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Evaluates database events in bounded batch queries for manual evaluation request.
    """
    query = db.query(NetworkEvent)
    if start_time:
        query = query.filter(NetworkEvent.timestamp >= start_time)
    if end_time:
        query = query.filter(NetworkEvent.timestamp <= end_time)
    if source_ip:
        query = query.filter(NetworkEvent.source_ip == source_ip)

    events = query.order_by(NetworkEvent.timestamp.desc()).limit(500).all()
    detections_created = []

    for evt in events:
        dets = evaluate_event(db, evt)
        detections_created.extend(dets)

    return {
        "events_evaluated": len(events),
        "detections_created": len(detections_created),
        "status": "SUCCESS"
    }
