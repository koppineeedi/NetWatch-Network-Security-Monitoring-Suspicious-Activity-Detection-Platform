"""
NetWatch Enterprise Enhancement Cycle 2 - Anomalies API Router
Provides listing, filtering, and detailed statistical evidence for behavioral anomalies.
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from typing import List, Optional

from app.database.connection import get_db
from app.api.deps import get_current_user
from app.models.user import User
from app.analytics.models import Anomaly

router = APIRouter(prefix="/api/anomalies", tags=["Behavioral Anomalies"])

@router.get("")
def get_anomalies(
    severity: Optional[str] = Query(None, description="Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)"),
    entity_id: Optional[str] = Query(None, description="Filter by entity_id"),
    min_score: Optional[float] = Query(None, description="Filter by minimum anomaly score"),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieves list of statistical behavioral anomalies sorted by timestamp."""
    query = db.query(Anomaly)
    if severity:
        query = query.filter(Anomaly.severity == severity.upper())
    if entity_id:
        query = query.filter(Anomaly.entity_id == entity_id)
    if min_score is not None:
        query = query.filter(Anomaly.anomaly_score >= min_score)

    anomalies = query.order_by(Anomaly.timestamp.desc()).limit(limit).all()
    
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

@router.get("/{anomaly_id}")
def get_anomaly_by_id(
    anomaly_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieves specific anomaly detail and evidence breakdown."""
    anomaly = db.query(Anomaly).filter(Anomaly.id == anomaly_id).first()
    if not anomaly:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Anomaly ID {anomaly_id} not found")
        
    return {
        "id": anomaly.id,
        "entity_type": anomaly.entity_type,
        "entity_id": anomaly.entity_id,
        "feature": anomaly.feature,
        "observed_value": anomaly.observed_value,
        "baseline_value": anomaly.baseline_value,
        "deviation": anomaly.deviation,
        "anomaly_score": anomaly.anomaly_score,
        "confidence": anomaly.confidence,
        "severity": anomaly.severity,
        "explanation": anomaly.explanation,
        "evidence": anomaly.evidence,
        "mitre_technique": anomaly.mitre_technique,
        "timestamp": anomaly.timestamp.isoformat() if anomaly.timestamp else None
    }
