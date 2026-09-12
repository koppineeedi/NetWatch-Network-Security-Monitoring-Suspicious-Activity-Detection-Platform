"""
NetWatch Enterprise Enhancement Cycle 2 - Analytics & UEBA Manager
Orchestrates baseline calculation, anomaly detection, entity risk scoring, campaign clustering, and real-time WebSocket publications.
"""

import os
import datetime
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.analytics.models import BehaviorBaseline, Entity, Anomaly, Campaign, EntityRiskHistory
from app.analytics.baseline import update_entity_baselines
from app.analytics.anomaly import detect_anomalies_for_entity
from app.analytics.risk import compute_entity_risk
from app.analytics.clustering import cluster_campaigns
from app.analytics.correlation import evaluate_entity_correlations
from app.realtime.publisher import publish_anomaly, publish_entity_risk, publish_campaign_update

MIN_EVENTS_THRESHOLD = int(os.getenv("NETWATCH_UEBA_MIN_EVENTS", "20"))
BASELINE_WINDOW_HOURS = int(os.getenv("NETWATCH_UEBA_WINDOW_HOURS", "168"))
REFRESH_MINUTES = int(os.getenv("NETWATCH_UEBA_REFRESH_MINUTES", "15"))
RISK_DECAY_HOURS = int(os.getenv("NETWATCH_UEBA_RISK_DECAY_HOURS", "24"))

class AnalyticsManager:
    @staticmethod
    def process_entity(db: Session, entity_id: str, entity_type: str = "IP") -> Dict[str, Any]:
        """
        Runs the full analytics lifecycle for a given entity:
        1. Updates statistical baseline.
        2. Evaluates features and detects anomalies.
        3. Recalculates risk score with decay.
        4. Broadcasts updates over WebSocket if anomalies or high risk occur.
        """
        # Ensure entity record exists
        entity = db.query(Entity).filter(Entity.entity_id == entity_id).first()
        if not entity:
            entity = Entity(
                entity_id=entity_id,
                entity_type=entity_type,
                first_seen=datetime.datetime.utcnow(),
                last_seen=datetime.datetime.utcnow(),
                event_count=0,
                current_risk_score=0.0,
                baseline_status="INSUFFICIENT_DATA"
            )
            db.add(entity)
            db.commit()
            db.refresh(entity)

        # 1. Update Baselines
        baselines = update_entity_baselines(db, entity_id, entity_type, min_events=MIN_EVENTS_THRESHOLD, window_hours=BASELINE_WINDOW_HOURS)
        active_baselines = [b for b in baselines.values() if b.status == "ACTIVE"]
        
        if len(active_baselines) > 0:
            entity.baseline_status = "ACTIVE"
        else:
            entity.baseline_status = "INSUFFICIENT_DATA"
            
        entity.last_seen = datetime.datetime.utcnow()
        db.commit()

        # 2. Detect Anomalies
        new_anomalies = detect_anomalies_for_entity(db, entity_id, entity_type)
        for anomaly in new_anomalies:
            publish_anomaly(anomaly)
            
        entity.anomaly_count = db.query(Anomaly).filter(Anomaly.entity_id == entity_id).count()

        # 3. Calculate Risk Score with Decay
        risk_result = compute_entity_risk(db, entity_id, entity_type, decay_hours=RISK_DECAY_HOURS)
        old_score = entity.current_risk_score
        new_score = risk_result["risk_score"]
        
        entity.current_risk_score = new_score
        if new_score >= 70.0:
            entity.high_risk_count += 1
            
        db.commit()
        db.refresh(entity)
        
        if abs(new_score - old_score) >= 1.0:
            publish_entity_risk(entity)

        return {
            "entity_id": entity_id,
            "baseline_status": entity.baseline_status,
            "active_baselines_count": len(active_baselines),
            "anomalies_detected": len(new_anomalies),
            "risk_score": new_score
        }

    @staticmethod
    def run_cycle(db: Session) -> Dict[str, Any]:
        """
        Executes a full analytics processing cycle across all tracked entities and triggers campaign clustering.
        """
        entities = db.query(Entity).all()
        processed_count = 0
        
        for entity in entities:
            AnalyticsManager.process_entity(db, entity.entity_id, entity.entity_type)
            processed_count += 1
            
        # Run Campaign Clustering
        updated_campaigns = cluster_campaigns(db)
        for campaign in updated_campaigns:
            publish_campaign_update(campaign)

        return {
            "entities_processed": processed_count,
            "campaigns_updated": len(updated_campaigns),
            "timestamp": datetime.datetime.utcnow().isoformat()
        }

    @staticmethod
    def get_status(db: Session) -> Dict[str, Any]:
        """Returns the current operational status of the UEBA / Behavioral Analytics subsystem."""
        monitored_entities_count = db.query(Entity).count()
        active_baselines_count = db.query(BehaviorBaseline).filter(BehaviorBaseline.status == "ACTIVE").count()
        insufficient_data_count = db.query(Entity).filter(Entity.baseline_status == "INSUFFICIENT_DATA").count()

        return {
            "enabled": True,
            "baseline_window_hours": BASELINE_WINDOW_HOURS,
            "min_events_threshold": MIN_EVENTS_THRESHOLD,
            "refresh_minutes": REFRESH_MINUTES,
            "risk_decay_hours": RISK_DECAY_HOURS,
            "monitored_entities_count": monitored_entities_count,
            "active_baselines_count": active_baselines_count,
            "insufficient_data_entities_count": insufficient_data_count
        }

    @staticmethod
    def get_stats(db: Session) -> Dict[str, Any]:
        """Returns aggregated UEBA & Behavioral Analytics summary statistics for dashboard display."""
        total_entities = db.query(Entity).count()
        entities_with_anomalies = db.query(func.count(func.distinct(Anomaly.entity_id))).scalar() or 0
        high_risk_entities = db.query(Entity).filter(Entity.current_risk_score >= 60.0, Entity.current_risk_score < 80.0).count()
        critical_entities = db.query(Entity).filter(Entity.current_risk_score >= 80.0).count()
        active_campaigns = db.query(Campaign).filter(Campaign.status == "ACTIVE").count()
        total_anomalies = db.query(Anomaly).count()

        active_count = db.query(Entity).filter(Entity.baseline_status == "ACTIVE").count()
        insufficient_count = db.query(Entity).filter(Entity.baseline_status == "INSUFFICIENT_DATA").count()
        stale_count = db.query(Entity).filter(Entity.baseline_status == "STALE").count()

        return {
            "total_entities": total_entities,
            "entities_with_anomalies": entities_with_anomalies,
            "high_risk_entities": high_risk_entities,
            "critical_entities": critical_entities,
            "active_campaigns": active_campaigns,
            "total_anomalies": total_anomalies,
            "baseline_status_breakdown": {
                "ACTIVE": active_count,
                "INSUFFICIENT_DATA": insufficient_count,
                "STALE": stale_count
            }
        }
