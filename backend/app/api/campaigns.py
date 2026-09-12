"""
NetWatch Enterprise Enhancement Cycle 2 - Campaigns API Router
Provides campaign discovery, status filtering, details, events correlation, and manual clustering triggers.
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any

from app.database.connection import get_db
from app.api.deps import get_current_user, require_role
from app.models.user import User
from app.analytics.models import Campaign, CampaignEvent, Anomaly
from app.models.alert import Alert
from app.analytics.clustering import cluster_campaigns

router = APIRouter(prefix="/api/campaigns", tags=["Campaign Clustering"])

@router.get("")
def get_campaigns(
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status (ACTIVE, MONITORING, RESOLVED, CLOSED)"),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieves list of clustered attack campaigns sorted by risk score and recency."""
    query = db.query(Campaign)
    if status_filter:
        query = query.filter(Campaign.status == status_filter.upper())
        
    campaigns = query.order_by(Campaign.risk_score.desc(), Campaign.last_seen.desc()).limit(limit).all()
    
    return [
        {
            "id": c.id,
            "campaign_id": c.campaign_id,
            "name": c.name,
            "status": c.status,
            "risk_score": c.risk_score,
            "confidence": c.confidence,
            "first_seen": c.first_seen.isoformat() if c.first_seen else None,
            "last_seen": c.last_seen.isoformat() if c.last_seen else None,
            "event_count": c.event_count,
            "entity_count": c.entity_count,
            "technique_count": c.technique_count,
            "created_at": c.created_at.isoformat() if c.created_at else None,
            "updated_at": c.updated_at.isoformat() if c.updated_at else None
        }
        for c in campaigns
    ]

@router.get("/{campaign_id}")
def get_campaign_by_id(
    campaign_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieves specific campaign details by campaign_id (e.g. CMP-2026-0001)."""
    campaign = db.query(Campaign).filter(Campaign.campaign_id == campaign_id).first()
    if not campaign:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Campaign '{campaign_id}' not found")
        
    return {
        "id": campaign.id,
        "campaign_id": campaign.campaign_id,
        "name": campaign.name,
        "status": campaign.status,
        "risk_score": campaign.risk_score,
        "confidence": campaign.confidence,
        "first_seen": campaign.first_seen.isoformat() if campaign.first_seen else None,
        "last_seen": campaign.last_seen.isoformat() if campaign.last_seen else None,
        "event_count": campaign.event_count,
        "entity_count": campaign.entity_count,
        "technique_count": campaign.technique_count,
        "created_at": campaign.created_at.isoformat() if campaign.created_at else None,
        "updated_at": campaign.updated_at.isoformat() if campaign.updated_at else None
    }

@router.get("/{campaign_id}/events")
def get_campaign_events(
    campaign_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieves all correlated alerts and anomalies linked to a specific campaign."""
    campaign_events = db.query(CampaignEvent).filter(CampaignEvent.campaign_id == campaign_id).all()
    
    alerts = []
    anomalies = []
    
    for ce in campaign_events:
        if ce.alert_id:
            alert = db.query(Alert).filter(Alert.id == ce.alert_id).first()
            if alert:
                alerts.append({
                    "id": alert.id,
                    "detection_type": alert.detection_type,
                    "severity": alert.severity,
                    "risk_score": alert.risk_score,
                    "source_ip": alert.source_ip,
                    "dest_ip": alert.dest_ip,
                    "description": alert.description,
                    "timestamp": alert.timestamp.isoformat() if alert.timestamp else None
                })
        if ce.anomaly_id:
            anomaly = db.query(Anomaly).filter(Anomaly.id == ce.anomaly_id).first()
            if anomaly:
                anomalies.append({
                    "id": anomaly.id,
                    "entity_id": anomaly.entity_id,
                    "feature": anomaly.feature,
                    "severity": anomaly.severity,
                    "anomaly_score": anomaly.anomaly_score,
                    "explanation": anomaly.explanation,
                    "timestamp": anomaly.timestamp.isoformat() if anomaly.timestamp else None
                })
                
    return {
        "campaign_id": campaign_id,
        "alerts_count": len(alerts),
        "anomalies_count": len(anomalies),
        "alerts": alerts,
        "anomalies": anomalies
    }

@router.post("/trigger-cluster")
def trigger_campaign_clustering(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("ADMIN", "ANALYST"))
):
    """Manually triggers campaign clustering evaluation across unclustered events."""
    updated = cluster_campaigns(db)
    return {
        "message": "Campaign clustering completed",
        "updated_campaigns_count": len(updated),
        "campaign_ids": [c.campaign_id for c in updated]
    }
