from pydantic import BaseModel
from typing import List, Optional, Dict, Any

class BehaviorBaselineResponse(BaseModel):
    id: int
    entity_type: str
    entity_id: str
    feature_name: str
    mean_value: float
    standard_deviation: float
    median_value: float
    percentile_95: float
    minimum_value: float
    maximum_value: float
    sample_count: int
    baseline_window_start: Optional[Any] = None
    baseline_window_end: Optional[Any] = None
    last_updated: Optional[Any] = None
    status: str

    class Config:
        from_attributes = True

class EntityResponse(BaseModel):
    id: int
    entity_id: str
    entity_type: str
    first_seen: Optional[Any] = None
    last_seen: Optional[Any] = None
    event_count: int
    current_risk_score: float
    baseline_status: str
    anomaly_count: int
    high_risk_count: int
    updated_at: Optional[Any] = None

    class Config:
        from_attributes = True

class EntityRiskHistoryResponse(BaseModel):
    id: int
    entity_type: str
    entity_id: str
    previous_score: float
    new_score: float
    contributing_factor: Optional[str] = None
    evidence_id: Optional[str] = None
    created_at: Any

    class Config:
        from_attributes = True

class AnomalyResponse(BaseModel):
    id: int
    entity_type: str
    entity_id: str
    feature: str
    observed_value: float
    baseline_value: float
    deviation: float
    anomaly_score: float
    confidence: float
    severity: str
    explanation: str
    evidence: Optional[str] = None
    mitre_technique: Optional[str] = None
    timestamp: Any

    class Config:
        from_attributes = True

class CampaignResponse(BaseModel):
    id: int
    campaign_id: str
    name: str
    status: str
    risk_score: float
    confidence: float
    first_seen: Optional[Any] = None
    last_seen: Optional[Any] = None
    event_count: int
    entity_count: int
    technique_count: int
    created_at: Any
    updated_at: Any

    class Config:
        from_attributes = True

class AnalyticsStatsResponse(BaseModel):
    total_entities: int
    entities_with_anomalies: int
    high_risk_entities: int
    critical_entities: int
    active_campaigns: int
    total_anomalies: int
    baseline_status_breakdown: Dict[str, int]

class UEBAStatusResponse(BaseModel):
    enabled: bool
    baseline_window_hours: int
    min_events_threshold: int
    refresh_minutes: int
    risk_decay_hours: int
    monitored_entities_count: int
    active_baselines_count: int
    insufficient_data_entities_count: int
