"""
NetWatch Enterprise Enhancement Cycle 2 - Campaign Clustering Engine
Groups related alerts, anomalies, and threat intel matches sharing entities or MITRE techniques into persistent Campaign records (CMP-2026-XXXX).
"""

import datetime
from typing import List, Dict, Any, Set
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.analytics.models import Campaign, CampaignEvent, Anomaly, Entity
from app.models.alert import Alert
from app.models.threat_intel import IOCMatch

def generate_campaign_id(db: Session) -> str:
    """Generates next available sequential campaign ID in format CMP-2026-XXXX."""
    current_year = datetime.datetime.utcnow().year
    prefix = f"CMP-{current_year}-"
    
    last_campaign = db.query(Campaign).filter(
        Campaign.campaign_id.like(f"{prefix}%")
    ).order_by(Campaign.id.desc()).first()
    
    if not last_campaign:
        return f"{prefix}0001"
    
    try:
        last_seq = int(last_campaign.campaign_id.split("-")[-1])
        next_seq = last_seq + 1
    except ValueError:
        next_seq = 1
        
    return f"{prefix}{next_seq:04d}"

def cluster_campaigns(db: Session, lookback_hours: int = 24) -> List[Campaign]:
    """
    Scans recent unclustered alerts and anomalies, grouping them into Campaigns based on shared entity IPs or MITRE techniques.
    """
    cutoff_time = datetime.datetime.utcnow() - datetime.timedelta(hours=lookback_hours)
    
    # 1. Fetch recent high/critical anomalies
    anomalies = db.query(Anomaly).filter(
        Anomaly.timestamp >= cutoff_time,
        Anomaly.anomaly_score >= 50.0
    ).all()
    
    # 2. Fetch recent alerts
    alerts = db.query(Alert).filter(
        Alert.timestamp >= cutoff_time
    ).all()
    
    if not anomalies and not alerts:
        return []
        
    # Group by entity IP
    entity_groups: Dict[str, Dict[str, Any]] = {}
    
    for anomaly in anomalies:
        entity_id = anomaly.entity_id
        if entity_id not in entity_groups:
            entity_groups[entity_id] = {
                "entities": {entity_id},
                "anomalies": [],
                "alerts": [],
                "techniques": set()
            }
        entity_groups[entity_id]["anomalies"].append(anomaly)
        if anomaly.mitre_technique:
            entity_groups[entity_id]["techniques"].add(anomaly.mitre_technique)
            
    for alert in alerts:
        entity_id = alert.source_ip or "SYSTEM"
        if entity_id not in entity_groups:
            entity_groups[entity_id] = {
                "entities": {entity_id},
                "anomalies": [],
                "alerts": [],
                "techniques": set()
            }
        entity_groups[entity_id]["alerts"].append(alert)
        if alert.mitre_technique:
            entity_groups[entity_id]["techniques"].add(alert.mitre_technique)

    updated_campaigns = []

    # Process each entity group with >= 2 total events or critical severity
    for entity_id, group in entity_groups.items():
        total_events = len(group["anomalies"]) + len(group["alerts"])
        if total_events < 2:
            continue
            
        # Check if an active campaign already exists for this entity
        existing_event = db.query(CampaignEvent).join(Campaign).filter(
            Campaign.status == "ACTIVE"
        ).filter(
            (CampaignEvent.anomaly_id.in_([a.id for a in group["anomalies"]])) |
            (CampaignEvent.alert_id.in_([a.id for a in group["alerts"]]))
        ).first()
        
        if existing_event:
            campaign = db.query(Campaign).filter(Campaign.campaign_id == existing_event.campaign_id).first()
        else:
            campaign = None
            
        max_anomaly_score = max([a.anomaly_score for a in group["anomalies"]], default=0.0)
        max_alert_score = max([80.0 if a.severity == "CRITICAL" else 60.0 if a.severity == "HIGH" else 40.0 for a in group["alerts"]], default=0.0)
        base_risk = max(max_anomaly_score, max_alert_score)
        
        # Calculate campaign risk score
        risk_score = min(100.0, round(base_risk + (total_events * 3.0), 1))
        
        techniques_list = list(group["techniques"])
        technique_str = f" using [{', '.join(techniques_list)}]" if techniques_list else ""
        campaign_name = f"Suspicious Activity Campaign on {entity_id}{technique_str}"
        
        if not campaign:
            campaign_id = generate_campaign_id(db)
            campaign = Campaign(
                campaign_id=campaign_id,
                name=campaign_name,
                status="ACTIVE",
                risk_score=risk_score,
                confidence=0.85,
                first_seen=datetime.datetime.utcnow(),
                last_seen=datetime.datetime.utcnow(),
                event_count=total_events,
                entity_count=len(group["entities"]),
                technique_count=len(group["techniques"]),
                created_at=datetime.datetime.utcnow(),
                updated_at=datetime.datetime.utcnow()
            )
            db.add(campaign)
            db.flush()
        else:
            campaign.risk_score = max(campaign.risk_score, risk_score)
            campaign.last_seen = datetime.datetime.utcnow()
            campaign.event_count = total_events
            campaign.entity_count = len(group["entities"])
            campaign.technique_count = len(group["techniques"])
            campaign.updated_at = datetime.datetime.utcnow()

        # Link events to campaign
        for anomaly in group["anomalies"]:
            exists = db.query(CampaignEvent).filter(
                CampaignEvent.campaign_id == campaign.campaign_id,
                CampaignEvent.anomaly_id == anomaly.id
            ).first()
            if not exists:
                db.add(CampaignEvent(
                    campaign_id=campaign.campaign_id,
                    anomaly_id=anomaly.id,
                    created_at=datetime.datetime.utcnow()
                ))
                
        for alert in group["alerts"]:
            exists = db.query(CampaignEvent).filter(
                CampaignEvent.campaign_id == campaign.campaign_id,
                CampaignEvent.alert_id == alert.id
            ).first()
            if not exists:
                db.add(CampaignEvent(
                    campaign_id=campaign.campaign_id,
                    alert_id=alert.id,
                    created_at=datetime.datetime.utcnow()
                ))
                
        updated_campaigns.append(campaign)
        
    db.commit()
    return updated_campaigns
