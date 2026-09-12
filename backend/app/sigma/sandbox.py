import time
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session

from app.models.event import NetworkEvent
from app.sigma.models import SigmaRule, SigmaRuleExecution
from app.sigma.parser import parse_sigma_yaml
from app.sigma.validator import validate_sigma_rule
from app.sigma.evaluator import SigmaEvaluator
from app.sigma.mapper import SigmaFieldMapper

def run_sigma_sandbox(
    db: Session,
    raw_yaml: Optional[str] = None,
    rule_id: Optional[str] = None,
    hours: int = 24,
    log_source: Optional[str] = None
) -> Dict[str, Any]:
    """
    Executes a Sigma rule in sandbox mode against REAL historical NetworkEvent records.
    Returns preview metrics and explainability without activating the rule or creating production alerts.
    """
    start_time = time.time()

    rule_dict = None
    if raw_yaml:
        try:
            parsed_list = parse_sigma_yaml(raw_yaml)
            rule_dict = parsed_list[0]
        except Exception as e:
            return {
                "status": "ERROR",
                "valid": False,
                "warnings": [f"YAML parsing error: {str(e)}"],
                "matches": [],
                "execution_time_ms": 0.0
            }
    elif rule_id:
        db_rule = db.query(SigmaRule).filter(SigmaRule.rule_id == rule_id).first()
        if not db_rule:
            return {
                "status": "ERROR",
                "valid": False,
                "warnings": [f"Rule with ID '{rule_id}' not found."],
                "matches": [],
                "execution_time_ms": 0.0
            }
        rule_dict = db_rule.normalized_rule or parse_sigma_yaml(db_rule.raw_yaml)[0]

    if not rule_dict:
        return {
            "status": "ERROR",
            "valid": False,
            "warnings": ["No rule definition or YAML provided."],
            "matches": [],
            "execution_time_ms": 0.0
        }

    # Validate Rule
    validation = validate_sigma_rule(rule_dict, db=db)
    if not validation["valid"]:
        return {
            "status": "ERROR",
            "valid": False,
            "warnings": validation["errors"],
            "unsupported_fields": validation["unsupported_features"],
            "matches": [],
            "execution_time_ms": 0.0
        }

    # Fetch Real Historical Events
    cutoff_time = datetime.utcnow() - timedelta(hours=hours)
    query = db.query(NetworkEvent).filter(NetworkEvent.timestamp >= cutoff_time)
    if log_source:
        query = query.filter(NetworkEvent.source == log_source)

    events = query.order_by(NetworkEvent.timestamp.desc()).limit(1000).all()

    if not events:
        exec_ms = round((time.time() - start_time) * 1000, 2)
        # Log execution
        if rule_id:
            db.add(SigmaRuleExecution(
                rule_id=rule_id,
                execution_type="SANDBOX",
                execution_time_ms=exec_ms,
                events_evaluated=0,
                matches_found=0,
                status="INSUFFICIENT_DATA"
            ))
            db.commit()

        return {
            "status": "INSUFFICIENT_DATA",
            "rule_id": rule_dict.get("rule_id"),
            "rule_title": rule_dict.get("title"),
            "valid": True,
            "mapped_fields_count": len([f for f in rule_dict.get("detection", {}).keys() if f != "condition"]),
            "unsupported_fields": validation["unsupported_features"],
            "historical_matches_count": 0,
            "execution_time_ms": exec_ms,
            "matches": [],
            "warnings": ["No historical telemetry events found in selected time range."]
        }

    # Evaluate against Real Historical Events
    matches = []
    for evt in events:
        eval_res = SigmaEvaluator.evaluate_rule(rule_dict, evt)
        if eval_res["matched"]:
            matches.append({
                "event_id": evt.id,
                "timestamp": evt.timestamp.isoformat() if evt.timestamp else None,
                "source": evt.source,
                "source_ip": evt.source_ip,
                "dest_ip": evt.dest_ip,
                "dest_port": evt.dest_port,
                "matched_fields": eval_res["matched_fields"],
                "explanation": eval_res["explanation"],
                "severity": eval_res["severity"],
                "mitre_techniques": eval_res["mitre_techniques"]
            })

    exec_ms = round((time.time() - start_time) * 1000, 2)

    # Audit execution record
    if rule_id:
        db.add(SigmaRuleExecution(
            rule_id=rule_id,
            execution_type="SANDBOX",
            execution_time_ms=exec_ms,
            events_evaluated=len(events),
            matches_found=len(matches),
            status="SUCCESS"
        ))
        db.commit()

    return {
        "status": "SUCCESS",
        "rule_id": rule_dict.get("rule_id"),
        "rule_title": rule_dict.get("title"),
        "valid": True,
        "mapped_fields_count": len([f for f in rule_dict.get("detection", {}).keys() if f != "condition"]),
        "unsupported_fields": validation["unsupported_features"],
        "historical_matches_count": len(matches),
        "events_evaluated": len(events),
        "execution_time_ms": exec_ms,
        "matches": matches,
        "warnings": validation["warnings"]
    }
