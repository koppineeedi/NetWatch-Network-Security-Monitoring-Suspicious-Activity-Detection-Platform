"""
NetWatch Enterprise Enhancement Cycle 2 - Multi-Event Sequence Correlation
Detects multi-stage attack patterns by correlating temporal sequences of alerts and anomalies on entities.
"""

import datetime
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session

from app.analytics.models import Anomaly, Entity
from app.models.alert import Alert
from app.models.threat_intel import IOCMatch

class CorrelatedPattern:
    def __init__(self, rule_id: str, name: str, severity: str, entity_id: str, risk_boost: float, description: str, evidence: Dict[str, Any]):
        self.rule_id = rule_id
        self.name = name
        self.severity = severity
        self.entity_id = entity_id
        self.risk_boost = risk_boost
        self.description = description
        self.evidence = evidence

def evaluate_entity_correlations(db: Session, entity_id: str, window_minutes: int = 30) -> List[CorrelatedPattern]:
    """
    Evaluates multi-event correlation rules for a specific entity within a sliding time window.
    """
    cutoff_time = datetime.datetime.utcnow() - datetime.timedelta(minutes=window_minutes)
    
    # Fetch recent anomalies for entity
    anomalies = db.query(Anomaly).filter(
        Anomaly.entity_id == entity_id,
        Anomaly.timestamp >= cutoff_time
    ).all()
    
    # Fetch recent alerts involving entity
    alerts = db.query(Alert).filter(
        Alert.source_ip == entity_id,
        Alert.timestamp >= cutoff_time
    ).all()
    
    # Fetch recent Threat Intel matches involving entity
    ti_matches = db.query(ThreatIntelMatch).filter(
        ThreatIntelMatch.matched_value == entity_id,
        ThreatIntelMatch.created_at >= cutoff_time
    ).all()
    
    results: List[CorrelatedPattern] = []
    
    # Feature map from anomalies
    anomaly_features = {a.feature: a for a in anomalies}
    
    # Rule R-CORR-01: Multi-Stage Recon & Probing (Port Entropy / High Unique Ports + Failed Connections)
    if ("destination_port_entropy" in anomaly_features or "unique_port_count" in anomaly_features) and \
       ("failed_connection_count" in anomaly_features or len(alerts) > 0):
        results.append(CorrelatedPattern(
            rule_id="R-CORR-01",
            name="Multi-Stage Reconnaissance & Exploitation Probe",
            severity="HIGH",
            entity_id=entity_id,
            risk_boost=25.0,
            description=f"Entity '{entity_id}' performed high-entropy port scanning immediately followed by failed authentication or alert generation.",
            evidence={
                "anomalies": [a.feature for a in anomalies],
                "alerts_count": len(alerts),
                "ti_matches_count": len(ti_matches),
                "window_minutes": window_minutes
            }
        ))
        
    # Rule R-CORR-02: Threat Intel Indicator + High Volume Anomaly
    if len(ti_matches) > 0 and len(anomalies) >= 2:
        results.append(CorrelatedPattern(
            rule_id="R-CORR-02",
            name="Confirmed IOC Trigger with Behavioral Anomaly Cascade",
            severity="CRITICAL",
            entity_id=entity_id,
            risk_boost=35.0,
            description=f"Entity '{entity_id}' matches known Threat Intelligence IOC and exhibited {len(anomalies)} distinct statistical anomalies.",
            evidence={
                "ti_matches": [t.matched_value for t in ti_matches],
                "anomalies": [a.feature for a in anomalies],
                "window_minutes": window_minutes
            }
        ))

    # Rule R-CORR-03: Multi-Feature Anomaly Burst (>=3 anomalous metrics concurrently)
    if len(anomalies) >= 3:
        results.append(CorrelatedPattern(
            rule_id="R-CORR-03",
            name="Multi-Metric Behavioral Anomaly Burst",
            severity="HIGH",
            entity_id=entity_id,
            risk_boost=20.0,
            description=f"Entity '{entity_id}' breached 95th percentile baseline across {len(anomalies)} separate metrics simultaneously.",
            evidence={
                "anomalies": [a.feature for a in anomalies],
                "window_minutes": window_minutes
            }
        ))
        
    return results
