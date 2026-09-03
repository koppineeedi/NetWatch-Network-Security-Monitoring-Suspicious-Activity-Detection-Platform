from typing import Dict, Any, Optional, List
from app.models.event import NetworkEvent
from app.detection.correlator import EventCorrelator

# Authoritative Rule Definitions
DEFAULT_RULES = [
    {
        "rule_code": "R-SCAN-01",
        "name": "Possible Port Scan",
        "category": "RECONNAISSANCE",
        "condition_desc": "Triggered when a single source IP contacts unusually high unique destination ports within time window.",
        "severity": "HIGH",
        "threshold": 8,  # unique ports
        "time_window": 30,  # seconds
        "enabled": True
    },
    {
        "rule_code": "R-CONN-01",
        "name": "Excessive Connection Attempts",
        "category": "ANOMALY",
        "condition_desc": "Triggered when connection attempts from a source IP exceed volume threshold within time window.",
        "severity": "MEDIUM",
        "threshold": 20,  # total events
        "time_window": 60,  # seconds
        "enabled": True
    },
    {
        "rule_code": "R-FAIL-01",
        "name": "Repeated Failed Connections",
        "category": "ANOMALY",
        "condition_desc": "Triggered when telemetry explicitly indicates repeated failed or refused connection states.",
        "severity": "HIGH",
        "threshold": 5,  # failed connection states
        "time_window": 60,  # seconds
        "enabled": True
    },
    {
        "rule_code": "R-PORT-01",
        "name": "Unusual Destination Port",
        "category": "ANOMALY",
        "condition_desc": "Triggered when connections target non-standard or unusual destination ports.",
        "severity": "MEDIUM",
        "threshold": 1,  # count
        "time_window": 60,  # seconds
        "enabled": True
    },
    {
        "rule_code": "R-DNS-01",
        "name": "Unusual DNS Activity",
        "category": "COMMAND_AND_CONTROL",
        "condition_desc": "Triggered when high-volume or anomalous DNS protocol queries are observed.",
        "severity": "MEDIUM",
        "threshold": 15,  # DNS query events
        "time_window": 60,  # seconds
        "enabled": True
    }
]

UNUSUAL_PORTS_LIST = {4444, 6667, 31337, 1337, 5555, 9001, 8888}

class RuleEvaluator:
    """
    Evaluates individual detection rules against correlated database event streams.
    Returns evaluation result containing triggered status, evidence breakdown, and explanation.
    """

    @staticmethod
    def evaluate_rule(rule_code: str, threshold: int, window: int, events: List[NetworkEvent]) -> Dict[str, Any]:
        if not events:
            return {"triggered": False, "reason": "No events in time window"}

        analysis = EventCorrelator.analyze_connection_states(events)
        source_ip = events[0].source_ip or "UNKNOWN"
        target_ip = events[0].dest_ip or "UNKNOWN"

        # Rule 1: POSSIBLE PORT SCAN (R-SCAN-01)
        if rule_code == "R-SCAN-01":
            if analysis["unique_ports_count"] >= threshold:
                return {
                    "triggered": True,
                    "rule_code": "R-SCAN-01",
                    "rule_name": "Possible Port Scan",
                    "explanation": f"Possible port scanning behavior observed: Host {source_ip} contacted {analysis['unique_ports_count']} unique destination ports within {window} seconds.",
                    "mitre_tactic": "Reconnaissance",
                    "mitre_technique": "T1046 - Network Service Discovery",
                    "severity": "HIGH",
                    "event_count": len(events),
                    "unique_ports": analysis["unique_ports"],
                    "event_ids": analysis["event_ids"],
                    "has_failed_states": analysis["has_failed_states"]
                }

        # Rule 2: EXCESSIVE CONNECTION ATTEMPTS (R-CONN-01)
        elif rule_code == "R-CONN-01":
            if analysis["total_events"] >= threshold:
                return {
                    "triggered": True,
                    "rule_code": "R-CONN-01",
                    "rule_name": "Excessive Connection Attempts",
                    "explanation": f"Excessive connection attempts observed: Host {source_ip} initiated {analysis['total_events']} connections within {window} seconds.",
                    "mitre_tactic": "Initial Access",
                    "mitre_technique": "T1190 - Exploit Public-Facing Application",
                    "severity": "MEDIUM",
                    "event_count": len(events),
                    "unique_ports": analysis["unique_ports"],
                    "event_ids": analysis["event_ids"],
                    "has_failed_states": analysis["has_failed_states"]
                }

        # Rule 3: REPEATED FAILED CONNECTIONS (R-FAIL-01)
        elif rule_code == "R-FAIL-01":
            if not analysis["has_failed_states"]:
                return {"triggered": False, "reason": "Insufficient evidence: No explicit connection failure state telemetry present."}

            if analysis["failed_count"] >= threshold:
                return {
                    "triggered": True,
                    "rule_code": "R-FAIL-01",
                    "rule_name": "Repeated Failed Connections",
                    "explanation": f"Repeated connection failures observed: Host {source_ip} accumulated {analysis['failed_count']} failed/refused connection states within {window} seconds.",
                    "mitre_tactic": "Credential Access",
                    "mitre_technique": "T1110 - Brute Force",
                    "severity": "HIGH",
                    "event_count": len(events),
                    "unique_ports": analysis["unique_ports"],
                    "event_ids": analysis["event_ids"],
                    "has_failed_states": True
                }

        # Rule 4: UNUSUAL DESTINATION PORT (R-PORT-01)
        elif rule_code == "R-PORT-01":
            unusual_found = [e for e in events if e.dest_port and e.dest_port in UNUSUAL_PORTS_LIST]
            if len(unusual_found) >= threshold:
                ports_hit = list(set(e.dest_port for e in unusual_found if e.dest_port is not None))
                return {
                    "triggered": True,
                    "rule_code": "R-PORT-01",
                    "rule_name": "Unusual Destination Port",
                    "explanation": f"Unusual destination port observed: Connections from {source_ip} to non-standard ports {ports_hit}.",
                    "mitre_tactic": "Command and Control",
                    "mitre_technique": "T1095 - Non-Application Layer Protocol",
                    "severity": "MEDIUM",
                    "event_count": len(unusual_found),
                    "unique_ports": ports_hit,
                    "event_ids": [e.id for e in unusual_found],
                    "has_failed_states": analysis["has_failed_states"]
                }

        # Rule 5: UNUSUAL DNS ACTIVITY (R-DNS-01)
        elif rule_code == "R-DNS-01":
            dns_events = [e for e in events if (e.protocol and e.protocol.upper() == "DNS") or e.dest_port == 53]
            if not dns_events:
                return {"triggered": False, "reason": "No DNS protocol telemetry present in event stream."}

            if len(dns_events) >= threshold:
                return {
                    "triggered": True,
                    "rule_code": "R-DNS-01",
                    "rule_name": "Unusual DNS Activity",
                    "explanation": f"Unusual DNS query volume observed: Host {source_ip} generated {len(dns_events)} DNS queries within {window} seconds.",
                    "mitre_tactic": "Command and Control",
                    "mitre_technique": "T1071.004 - DNS Protocol Tunneling",
                    "severity": "MEDIUM",
                    "event_count": len(dns_events),
                    "unique_ports": [53],
                    "event_ids": [e.id for e in dns_events],
                    "has_failed_states": analysis["has_failed_states"]
                }

        return {"triggered": False, "reason": "Threshold criteria not met"}
