"""
NetWatch Enterprise Enhancement Cycle 2 - Explainability Engine
Generates human-readable, mathematically grounded explanations for anomalies and entity risk.
"""

from typing import Dict, Any, List, Optional

FEATURE_DESCRIPTIONS = {
    "connection_count": "total network connection volume",
    "unique_destination_count": "distinct target IP addresses contacted",
    "unique_port_count": "distinct target port count",
    "failed_connection_count": "unsuccessful connection attempts",
    "dns_query_count": "DNS resolution query volume",
    "destination_port_entropy": "destination port distribution randomness (entropy)",
    "connection_rate": "connection attempt frequency per minute",
    "data_transfer_volume": "total network payload volume (bytes)",
}

FEATURE_MITRE_MAPPING = {
    "connection_count": "T1046",
    "unique_destination_count": "T1046",
    "unique_port_count": "T1046",
    "failed_connection_count": "T1110",
    "dns_query_count": "T1071.004",
    "destination_port_entropy": "T1046",
    "connection_rate": "T1498",
    "data_transfer_volume": "T1048",
}

def generate_anomaly_explanation(
    entity_id: str,
    feature_name: str,
    observed_value: float,
    baseline_mean: float,
    baseline_p95: float,
    z_score: float,
    sample_count: int
) -> str:
    """
    Generates a structured, mathematically rigorous explanation for a detected behavioral anomaly.
    """
    friendly_name = FEATURE_DESCRIPTIONS.get(feature_name, feature_name)
    
    if baseline_mean > 0:
        percent_increase = ((observed_value - baseline_mean) / baseline_mean) * 100.0
        diff_str = f"+{percent_increase:.1f}% above mean baseline ({baseline_mean:.2f})"
    else:
        diff_str = f"observed value {observed_value:.2f} vs zero baseline mean"
        
    p95_diff = observed_value - baseline_p95
    p95_str = f"exceeds 95th percentile ({baseline_p95:.2f}) by +{p95_diff:.2f}" if p95_diff > 0 else f"below 95th percentile ({baseline_p95:.2f})"

    explanation = (
        f"Entity '{entity_id}' exhibited anomalous {friendly_name} [{feature_name} = {observed_value:.2f}]. "
        f"This parameter {diff_str} and {p95_str} "
        f"(Z-score: +{z_score:.2f}, baseline derived from {sample_count} observed historical events)."
    )
    return explanation

def get_mitre_technique_for_feature(feature_name: str) -> str:
    """Returns the MITRE ATT&CK technique code associated with a given feature anomaly."""
    return FEATURE_MITRE_MAPPING.get(feature_name, "T1046")

def generate_risk_explanation(
    entity_id: str,
    risk_score: float,
    alerts_count: int,
    anomalies_count: int,
    ti_matches_count: int,
    decay_applied: float = 0.0
) -> str:
    """
    Generates an explanatory summary of an entity's risk score breakdown.
    """
    factors = []
    if ti_matches_count > 0:
        factors.append(f"{ti_matches_count} Threat Intelligence IOC match(es)")
    if alerts_count > 0:
        factors.append(f"{alerts_count} active SOC alert(s)")
    if anomalies_count > 0:
        factors.append(f"{anomalies_count} behavioral statistical anomaly(ies)")
    
    if not factors:
        return f"Entity '{entity_id}' maintains baseline risk score of {risk_score:.1f}/100 (no active threat indicators)."
    
    factors_str = ", ".join(factors)
    decay_str = f" (includes {decay_applied:.1f} pts 24h temporal decay)" if decay_applied > 0 else ""
    return f"Entity '{entity_id}' risk score escalated to {risk_score:.1f}/100 based on: {factors_str}{decay_str}."
