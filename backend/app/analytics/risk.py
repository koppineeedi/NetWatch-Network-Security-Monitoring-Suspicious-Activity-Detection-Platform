import os
import datetime
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from app.models.alert import Alert
from app.models.threat_intel import IOCMatch
from app.analytics.models import Entity, Anomaly, EntityRiskHistory, CampaignEvent

class EntityRiskEngine:
    def __init__(self):
        self.decay_hours = float(os.getenv("NETWATCH_RISK_DECAY_HOURS", "24"))

    def get_risk_level(self, risk_score: float) -> str:
        if risk_score >= 75.0:
            return "CRITICAL"
        elif risk_score >= 50.0:
            return "HIGH"
        elif risk_score >= 25.0:
            return "MEDIUM"
        return "LOW"

    def recalculate_entity_risk(
        self, db: Session, entity_id: str, entity_type: str = "IP", contributing_factor: str = "SCHEDULED_RECALCULATION"
    ) -> Entity:
        """
        Calculates bounded (0-100) entity risk score combining Alerts, Anomalies, TI Matches, and Campaigns.
        Applies deterministic time-decay if no recent malicious activity has occurred.
        """
        now = datetime.datetime.utcnow()
        entity = db.query(Entity).filter(
            Entity.entity_id == entity_id, Entity.entity_type == entity_type
        ).first()

        if not entity:
            entity = Entity(
                entity_id=entity_id,
                entity_type=entity_type,
                first_seen=now,
                last_seen=now,
                current_risk_score=0.0
            )
            db.add(entity)
            db.commit()
            db.refresh(entity)

        prev_score = entity.current_risk_score

        # 1. Active Alerts contribution (last 48 hours)
        two_days_ago = now - datetime.timedelta(hours=48)
        alerts = db.query(Alert).filter(
            (Alert.source_ip == entity_id) | (Alert.dest_ip == entity_id),
            Alert.status.in_(["NEW", "INVESTIGATING", "TRUE_POSITIVE"]),
            Alert.timestamp >= two_days_ago
        ).all()

        alert_score = 0.0
        for alt in alerts:
            weight = 25.0 if alt.severity == "CRITICAL" else (18.0 if alt.severity == "HIGH" else 10.0)
            alert_score += weight

        # 2. Anomalies contribution (last 24 hours)
        one_day_ago = now - datetime.timedelta(hours=24)
        anomalies = db.query(Anomaly).filter(
            Anomaly.entity_id == entity_id,
            Anomaly.entity_type == entity_type,
            Anomaly.timestamp >= one_day_ago
        ).all()

        anomaly_score = sum(a.anomaly_score * 0.25 for a in anomalies)

        # 3. Threat Intelligence IOC Matches (last 48 hours)
        ti_matches = db.query(IOCMatch).filter(
            IOCMatch.ioc_value == entity_id,
            IOCMatch.timestamp >= two_days_ago
        ).all()

        ti_score = sum(m.confidence * 0.30 for m in ti_matches)

        # Raw combined risk
        raw_risk = alert_score + anomaly_score + ti_score

        # 4. Risk Decay logic
        # If no activity in the last decay_hours, decay existing score by 20%
        most_recent = entity.last_seen or entity.first_seen
        hours_since_activity = (now - most_recent).total_seconds() / 3600.0 if most_recent else 0.0

        if raw_risk == 0.0 and prev_score > 0.0:
            decay_factor = max(0.0, 1.0 - (hours_since_activity / self.decay_hours) * 0.20)
            new_risk = prev_score * decay_factor
        else:
            new_risk = raw_risk

        bounded_risk = float(round(min(100.0, max(0.0, new_risk)), 1))

        # Update entity counts and status
        entity.current_risk_score = bounded_risk
        entity.anomaly_count = len(anomalies)
        entity.high_risk_count = sum(1 for a in anomalies if a.severity in ["HIGH", "CRITICAL"])
        entity.updated_at = now

        # Record Risk History entry if score changed meaningfully
        if abs(bounded_risk - prev_score) >= 0.5:
            history = EntityRiskHistory(
                entity_type=entity_type,
                entity_id=entity_id,
                previous_score=prev_score,
                new_score=bounded_risk,
                contributing_factor=contributing_factor,
                created_at=now
            )
            db.add(history)

        db.commit()
        db.refresh(entity)
        return entity

risk_engine = EntityRiskEngine()

def compute_entity_risk(
    db: Session, entity_id: str, entity_type: str = "IP", decay_hours: int = 24
) -> Dict[str, Any]:
    """
    Convenience wrapper for computing bounded entity risk score and returning risk details dictionary.
    """
    risk_engine.decay_hours = float(decay_hours)
    entity = risk_engine.recalculate_entity_risk(db, entity_id, entity_type)
    return {
        "entity_id": entity.entity_id,
        "entity_type": entity.entity_type,
        "risk_score": entity.current_risk_score,
        "baseline_status": entity.baseline_status,
        "anomaly_count": entity.anomaly_count,
        "high_risk_count": entity.high_risk_count
    }

