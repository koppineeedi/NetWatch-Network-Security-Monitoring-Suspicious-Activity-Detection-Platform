import json
from typing import Dict, Any, List, Tuple

class RiskCalculator:
    """
    Calculates evidence-based, deterministic risk scores (0.0 - 100.0)
    and structures evidence objects without fabricating threat intelligence.
    """

    @staticmethod
    def calculate_risk(
        event_count: int,
        unique_ports: int,
        severity: str,
        correlation_factor: float = 1.0,
        has_failed_states: bool = False
    ) -> Tuple[float, float, List[str]]:
        """
        Calculates risk score, confidence rating, and risk factor breakdown.
        """
        # Severity base weight
        severity_weights = {
            "CRITICAL": 40.0,
            "HIGH": 30.0,
            "MEDIUM": 20.0,
            "LOW": 10.0,
            "INFO": 5.0
        }
        base_severity = severity_weights.get(severity.upper(), 15.0)

        # Frequency & Uniqueness Factors
        freq_score = min(30.0, event_count * 1.5)
        port_score = min(30.0, unique_ports * 3.5)
        failure_bonus = 10.0 if has_failed_states else 0.0

        # Calculate total raw risk score clamped between 0 and 100
        raw_risk = (base_severity + freq_score + port_score + failure_bonus) * correlation_factor
        risk_score = round(min(100.0, max(0.0, raw_risk)), 1)

        # Evidence-Based Confidence Rating (0.0 - 1.0)
        # Represents confidence that rule criteria were satisfied by real telemetry
        if event_count >= 10 and unique_ports >= 5:
            confidence = 0.95
        elif event_count >= 5 or unique_ports >= 3:
            confidence = 0.85
        elif event_count >= 2:
            confidence = 0.70
        else:
            confidence = 0.50

        # Structured Risk Factors
        risk_factors = [
            f"Base Severity Rating: {severity}",
            f"Observed Event Volume: {event_count} events",
            f"Unique Ports Contacted: {unique_ports} ports"
        ]
        if has_failed_states:
            risk_factors.append("Explicit Connection Failure States Observed")

        return risk_score, confidence, risk_factors

    @staticmethod
    def format_evidence(
        source_ip: str,
        target_ip: str,
        unique_ports: List[int],
        time_window_seconds: int,
        event_count: int,
        event_ids: List[int],
        risk_factors: List[str]
    ) -> str:
        """
        Serializes structured evidence JSON for storage in database.
        """
        evidence_dict = {
            "source_ip": source_ip,
            "target_ip": target_ip,
            "unique_destination_ports": unique_ports,
            "time_window_seconds": time_window_seconds,
            "event_count": event_count,
            "source_event_ids": event_ids,
            "risk_factors": risk_factors
        }
        return json.dumps(evidence_dict)
