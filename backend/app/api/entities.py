"""
NetWatch Enterprise Enhancement Cycle 2 - Entities API Router
Provides entity discovery, risk histories, baseline status, and peer group analysis.
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any

from app.database.connection import get_db
from app.api.deps import get_current_user
from app.models.user import User
from app.analytics.models import Entity, EntityRiskHistory, Anomaly, BehaviorBaseline
from app.analytics.schemas import EntityResponse, EntityRiskHistoryResponse, AnomalyResponse, BehaviorBaselineResponse
from app.analytics.peer_groups import get_peer_group_comparison

router = APIRouter(prefix="/api/entities", tags=["Entities & Risk Scoring"])

@router.get("", response_model=List[EntityResponse])
def get_entities(
    min_risk: Optional[float] = Query(None, description="Filter entities with risk score >= min_risk"),
    baseline_status: Optional[str] = Query(None, description="Filter by baseline status (ACTIVE, INSUFFICIENT_DATA, STALE)"),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieves tracked entity list with risk scores and baseline statuses."""
    query = db.query(Entity)
    if min_risk is not None:
        query = query.filter(Entity.current_risk_score >= min_risk)
    if baseline_status:
        query = query.filter(Entity.baseline_status == baseline_status)
        
    return query.order_by(Entity.current_risk_score.desc(), Entity.last_seen.desc()).limit(limit).all()

@router.get("/{entity_id}", response_model=EntityResponse)
def get_entity_by_id(
    entity_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieves specific entity details by entity_id (IP, Hostname, etc.)."""
    entity = db.query(Entity).filter(Entity.entity_id == entity_id).first()
    if not entity:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Entity '{entity_id}' not found")
    return entity

@router.get("/{entity_id}/risk-history")
def get_entity_risk_history(
    entity_id: str,
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieves historical risk score trajectory and decay logs for an entity."""
    history = db.query(EntityRiskHistory).filter(
        EntityRiskHistory.entity_id == entity_id
    ).order_by(EntityRiskHistory.created_at.desc()).limit(limit).all()
    
    return [
        {
            "id": h.id,
            "entity_type": h.entity_type,
            "entity_id": h.entity_id,
            "previous_score": h.previous_score,
            "new_score": h.new_score,
            "contributing_factor": h.contributing_factor,
            "evidence_id": h.evidence_id,
            "created_at": h.created_at.isoformat() if h.created_at else None
        }
        for h in history
    ]

@router.get("/{entity_id}/baselines", response_model=List[BehaviorBaselineResponse])
def get_entity_baselines(
    entity_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieves 168-hour statistical feature baselines for an entity."""
    baselines = db.query(BehaviorBaseline).filter(BehaviorBaseline.entity_id == entity_id).all()
    return baselines

@router.get("/{entity_id}/peer-group")
def get_peer_group_analysis(
    entity_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Compares entity's behavioral metrics against peer group subnet/cohort averages."""
    return get_peer_group_comparison(db, entity_id)

@router.get("/{entity_id}/anomalies")
def get_entity_anomalies(
    entity_id: str,
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieves statistical anomalies detected for a specific entity."""
    anomalies = db.query(Anomaly).filter(
        Anomaly.entity_id == entity_id
    ).order_by(Anomaly.timestamp.desc()).limit(limit).all()
    
    return [
        {
            "id": a.id,
            "entity_type": a.entity_type,
            "entity_id": a.entity_id,
            "feature": a.feature,
            "observed_value": a.observed_value,
            "baseline_value": a.baseline_value,
            "deviation": a.deviation,
            "anomaly_score": a.anomaly_score,
            "confidence": a.confidence,
            "severity": a.severity,
            "explanation": a.explanation,
            "evidence": a.evidence,
            "mitre_technique": a.mitre_technique,
            "timestamp": a.timestamp.isoformat() if a.timestamp else None
        }
        for a in anomalies
    ]
