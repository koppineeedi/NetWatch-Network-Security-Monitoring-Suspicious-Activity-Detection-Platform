import time
import json
from datetime import datetime, timedelta
from typing import List, Dict, Any
from sqlalchemy.orm import Session

from app.models.event import NetworkEvent
from app.models.alert import Alert
from app.models.detection import Detection
from app.sigma.models import SigmaRule, SigmaRuleMatch, SigmaRuleExecution
from app.sigma.evaluator import SigmaEvaluator
from app.realtime.publisher import publish_alert, publish_detection
from app.threat_intelligence.services.ioc_matcher import ioc_matcher_service
from app.analytics.models import Entity, Anomaly

def evaluate_sigma_live(db: Session, event: NetworkEvent) -> List[Dict[str, Any]]:
    """
    Evaluates an ingested real NetworkEvent against all ENABLED Sigma rules.
    Runs Threat Intelligence and UEBA enrichment, creates SOC Alerts with deduplication,
    and publishes real-time WebSocket events.
    """
    if not event:
        return []

    enabled_rules = db.query(SigmaRule).filter(
        SigmaRule.enabled == True
    ).all()

    if not enabled_rules:
        return []

    created_matches = []

    for rule in enabled_rules:
        start_t = time.time()
        rule_dict = rule.normalized_rule
        if isinstance(rule_dict, str):
            try:
                rule_dict = json.loads(rule_dict)
            except Exception:
                rule_dict = None
        if not rule_dict and rule.raw_yaml:
            try:
                from app.sigma.parser import parse_sigma_yaml
                rule_dict = parse_sigma_yaml(rule.raw_yaml)[0]
            except Exception:
                rule_dict = None

        if not rule_dict:
            continue

        eval_res = SigmaEvaluator.evaluate_rule(rule_dict, event)
        exec_ms = round((time.time() - start_t) * 1000, 2)

        # Log live execution record
        db.add(SigmaRuleExecution(
            rule_id=rule.rule_id,
            execution_type="LIVE",
            execution_time_ms=exec_ms,
            events_evaluated=1,
            matches_found=1 if eval_res["matched"] else 0,
            status="SUCCESS"
        ))

        if eval_res["matched"]:
            # Check Deduplication (10-minute window)
            dedup_window = datetime.utcnow() - timedelta(minutes=10)
            existing_alert = db.query(Alert).filter(
                Alert.rule_id == rule.rule_id,
                Alert.source_ip == event.source_ip,
                Alert.timestamp >= dedup_window
            ).first()

            if existing_alert:
                db.commit()
                continue

            # Threat Intelligence IOC Enrichment
            ioc_matches = ioc_matcher_service.match_event(db, event)
            risk_score = 50.0
            if rule.level == "critical":
                risk_score = 90.0
            elif rule.level == "high":
                risk_score = 75.0
            elif rule.level == "medium":
                risk_score = 50.0
            else:
                risk_score = 25.0

            if ioc_matches:
                risk_score = min(100.0, risk_score + 15.0)

            # UEBA Entity Context Enrichment
            entity_risk = None
            if event.source_ip:
                ent = db.query(Entity).filter(Entity.entity_id == event.source_ip).first()
                if ent:
                    entity_risk = ent.current_risk_score

            # Create SigmaRuleMatch record
            match_record = SigmaRuleMatch(
                rule_id=rule.rule_id,
                event_id=event.id,
                matched_fields=eval_res["matched_fields"],
                evidence=eval_res["evidence"],
                explanation=eval_res["explanation"],
                severity=eval_res["severity"],
                mitre_techniques=eval_res["mitre_techniques"]
            )
            db.add(match_record)

            # Create Detection record
            detection = Detection(
                timestamp=datetime.utcnow(),
                rule_code=rule.rule_id,
                rule_name=rule.title,
                source_ip=event.source_ip,
                target_ip=event.dest_ip,
                mitre_tactic="SIGMA_DETECTION",
                mitre_technique=", ".join(eval_res["mitre_techniques"]) if eval_res["mitre_techniques"] else "UNKNOWN",
                action_taken="ALERTED",
                details=eval_res["explanation"],
                evidence=json.dumps({"matched_fields": eval_res["matched_fields"], "sigma_rule_id": rule.rule_id}),
                risk_score=risk_score
            )
            db.add(detection)
            db.commit()
            db.refresh(detection)

            # Create Alert record
            alert = Alert(
                timestamp=datetime.utcnow(),
                detection_id=detection.id,
                detection_type=f"Sigma: {rule.title}",
                severity=eval_res["severity"],
                confidence=0.9,
                risk_score=risk_score,
                source_ip=event.source_ip,
                dest_ip=event.dest_ip,
                dest_port=event.dest_port,
                protocol=event.protocol,
                description=f"Sigma rule '{rule.title}' ({rule.rule_id}) matched real network event.",
                explanation=eval_res["explanation"],
                status="NEW",
                assigned_analyst="Unassigned",
                rule_id=rule.rule_id
            )
            db.add(alert)
            db.commit()
            db.refresh(alert)

            # Publish real-time WebSocket alerts
            publish_detection(detection)
            publish_alert(alert)

            created_matches.append(eval_res)

        db.commit()

    return created_matches
