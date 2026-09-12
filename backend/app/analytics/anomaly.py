import os
import datetime
import json
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from app.models.event import NetworkEvent
from app.analytics.models import BehaviorBaseline, Anomaly
from app.analytics.feature_engineering import calculate_entity_features

class AnomalyDetector:
    def __init__(self):
        self.thresh_low = float(os.getenv("NETWATCH_ANOMALY_LOW", "30"))
        self.thresh_medium = float(os.getenv("NETWATCH_ANOMALY_MEDIUM", "60"))
        self.thresh_high = float(os.getenv("NETWATCH_ANOMALY_HIGH", "80"))
        self.thresh_critical = float(os.getenv("NETWATCH_ANOMALY_CRITICAL", "90"))

    def get_severity(self, anomaly_score: float) -> str:
        if anomaly_score >= self.thresh_critical:
            return "CRITICAL"
        elif anomaly_score >= self.thresh_high:
            return "HIGH"
        elif anomaly_score >= self.thresh_medium:
            return "MEDIUM"
        return "LOW"

    def evaluate_entity_anomalies(
        self, db: Session, entity_id: str, entity_type: str = "IP", recent_events: Optional[List[NetworkEvent]] = None
    ) -> List[Anomaly]:
        """
        Evaluates observed entity features against ACTIVE statistical baselines.
        Generates explainable Anomaly records when deviations occur.
        """
        baselines = db.query(BehaviorBaseline).filter(
            BehaviorBaseline.entity_type == entity_type,
            BehaviorBaseline.entity_id == entity_id,
            BehaviorBaseline.status == "ACTIVE"
        ).all()

        if not baselines:
            return []

        # If recent_events not supplied, fetch last 1-hour events
        if recent_events is None:
            one_hour_ago = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
            recent_events = db.query(NetworkEvent).filter(
                (NetworkEvent.source_ip == entity_id) | (NetworkEvent.dest_ip == entity_id),
                NetworkEvent.timestamp >= one_hour_ago
            ).all()

        if not recent_events:
            return []

        observed_features = calculate_entity_features(recent_events, entity_id, entity_type)
        anomalies_detected = []
        now = datetime.datetime.utcnow()

        for b in baselines:
            fname = b.feature_name
            if fname not in observed_features:
                continue

            obs_val = observed_features[fname]
            mean_val = b.mean_value
            std_dev = b.standard_deviation if b.standard_deviation > 0.01 else 1.0

            # Calculate z-score & percentile deviation
            z_score = (obs_val - mean_val) / std_dev
            percentile_95 = b.percentile_95 if b.percentile_95 > 0 else (mean_val * 1.5)

            # We care primarily about positive abnormal spikes (e.g. port scan, connection flooding)
            if obs_val <= mean_val and obs_val <= percentile_95:
                continue

            # Calculate Anomaly Score (0 to 100)
            if z_score <= 1.5:
                anomaly_score = 0.0
            else:
                # Scale z-score linearly: z=1.5 -> 30, z=3.0 -> 70, z>=5.0 -> 95+
                raw_score = min(100.0, 20.0 + (z_score * 15.0))
                anomaly_score = float(round(raw_score, 1))

            if anomaly_score < self.thresh_low:
                continue

            deviation_pct = round(((obs_val - mean_val) / mean_val * 100.0) if mean_val > 0 else 100.0, 1)
            severity = self.get_severity(anomaly_score)

            # Determine MITRE Technique mapping if applicable
            mitre = None
            if fname in ("unique_port_count", "destination_port_entropy"):
                mitre = "T1046"  # Network Service Discovery
            elif fname in ("failed_connection_count", "connection_rate"):
                mitre = "T1110"  # Brute Force / Password Spraying

            # Human readable explanation
            explanation = (
                f"Observed '{fname}' value of {obs_val} for entity '{entity_id}' "
                f"deviated by +{deviation_pct}% from historical baseline mean of {mean_val} "
                f"(95th percentile: {b.percentile_95}, Z-score: {round(z_score, 2)})."
            )

            evidence_json = json.dumps({
                "feature": fname,
                "observed": obs_val,
                "baseline_mean": mean_val,
                "baseline_std": std_dev,
                "baseline_p95": b.percentile_95,
                "z_score": round(z_score, 2),
                "event_sample_size": len(recent_events)
            })

            anomaly = Anomaly(
                entity_type=entity_type,
                entity_id=entity_id,
                feature=fname,
                observed_value=obs_val,
                baseline_value=mean_val,
                deviation=deviation_pct,
                anomaly_score=anomaly_score,
                confidence=min(1.0, round(0.70 + (b.sample_count / 100.0) * 0.25, 2)),
                severity=severity,
                explanation=explanation,
                evidence=evidence_json,
                mitre_technique=mitre,
                timestamp=now
            )

            db.add(anomaly)
            anomalies_detected.append(anomaly)

        if anomalies_detected:
            db.commit()
            for a in anomalies_detected:
                db.refresh(a)

        return anomalies_detected

anomaly_detector = AnomalyDetector()

def detect_anomalies_for_entity(
    db: Session, entity_id: str, entity_type: str = "IP", recent_events: Optional[List[NetworkEvent]] = None
) -> List[Anomaly]:
    """
    Convenience wrapper for detecting anomalies on an entity using anomaly_detector instance.
    """
    return anomaly_detector.evaluate_entity_anomalies(db, entity_id, entity_type, recent_events)

