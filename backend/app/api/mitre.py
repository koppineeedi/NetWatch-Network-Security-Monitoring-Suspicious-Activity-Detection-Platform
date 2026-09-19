from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import Dict, Any, List
import json

from app.database.connection import get_db
from app.models.rule import DetectionRule
from app.models.alert import Alert
from app.models.investigation import Investigation
from app.sigma.models import SigmaRule

router = APIRouter(prefix="/api/mitre", tags=["MITRE ATT&CK"])

MITRE_TACTICS_CATALOG = [
    {
        "id": "TA0001",
        "name": "Initial Access",
        "key": "initial-access",
        "techniques": [
            {"id": "T1190", "name": "Exploit Public-Facing Application"},
            {"id": "T1566", "name": "Phishing"},
            {"id": "T1078", "name": "Valid Accounts"}
        ]
    },
    {
        "id": "TA0002",
        "name": "Execution",
        "key": "execution",
        "techniques": [
            {"id": "T1059", "name": "Command and Scripting Interpreter"},
            {"id": "T1204", "name": "User Execution"}
        ]
    },
    {
        "id": "TA0003",
        "name": "Persistence",
        "key": "persistence",
        "techniques": [
            {"id": "T1053", "name": "Scheduled Task/Job"},
            {"id": "T1543", "name": "Create or Modify System Process"}
        ]
    },
    {
        "id": "TA0004",
        "name": "Privilege Escalation",
        "key": "privilege-escalation",
        "techniques": [
            {"id": "T1068", "name": "Exploitation for Privilege Escalation"},
            {"id": "T1548", "name": "Abuse Elevation Control Mechanism"}
        ]
    },
    {
        "id": "TA0005",
        "name": "Defense Evasion",
        "key": "defense-evasion",
        "techniques": [
            {"id": "T1070", "name": "Indicator Removal"},
            {"id": "T1562", "name": "Impair Defenses"}
        ]
    },
    {
        "id": "TA0006",
        "name": "Credential Access",
        "key": "credential-access",
        "techniques": [
            {"id": "T1110", "name": "Brute Force"},
            {"id": "T1003", "name": "OS Credential Dumping"}
        ]
    },
    {
        "id": "TA0007",
        "name": "Discovery",
        "key": "discovery",
        "techniques": [
            {"id": "T1046", "name": "Network Service Discovery"},
            {"id": "T1018", "name": "Remote System Discovery"}
        ]
    },
    {
        "id": "TA0008",
        "name": "Lateral Movement",
        "key": "lateral-movement",
        "techniques": [
            {"id": "T1021", "name": "Remote Services"},
            {"id": "T1570", "name": "Lateral Tool Transfer"}
        ]
    },
    {
        "id": "TA0009",
        "name": "Collection",
        "key": "collection",
        "techniques": [
            {"id": "T1005", "name": "Data from Local System"},
            {"id": "T1041", "name": "Data Staged"}
        ]
    },
    {
        "id": "TA0011",
        "name": "Command and Control",
        "key": "command-and-control",
        "techniques": [
            {"id": "T1071", "name": "Application Layer Protocol"},
            {"id": "T1071.004", "name": "DNS Protocol"},
            {"id": "T1573", "name": "Encrypted Channel"}
        ]
    },
    {
        "id": "TA0010",
        "name": "Exfiltration",
        "key": "exfiltration",
        "techniques": [
            {"id": "T1041", "name": "Exfiltration Over C2 Channel"},
            {"id": "T1048", "name": "Exfiltration Over Alternative Protocol"}
        ]
    },
    {
        "id": "TA0040",
        "name": "Impact",
        "key": "impact",
        "techniques": [
            {"id": "T1486", "name": "Data Encrypted for Impact"},
            {"id": "T1499", "name": "Endpoint Denial of Service"}
        ]
    }
]

from app.api.auth import get_current_user
from app.models.user import User

@router.get("/coverage")
def get_mitre_attack_coverage(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Calculate MITRE ATT&CK matrix coverage dynamically based on active rules, firing alerts, and active investigations.
    """
    rules = db.query(DetectionRule).filter(DetectionRule.enabled == True).all()
    sigma_rules = db.query(SigmaRule).filter(SigmaRule.status == "ENABLED").all()
    alerts = db.query(Alert).all()
    incidents = db.query(Investigation).all()

    # Collect mapped techniques from rules
    rule_technique_map: Dict[str, List[str]] = {}

    # Standard rule mappings
    for r in rules:
        t_id = "T1000"
        if "BRUTE_FORCE" in r.category or "AUTHENTICATION" in r.category:
            t_id = "T1110"
        elif "RECONNAISSANCE" in r.category or "SCAN" in r.category:
            t_id = "T1046"
        elif "COMMAND_AND_CONTROL" in r.category or "C2" in r.category:
            t_id = "T1071"
        elif "EXFILTRATION" in r.category:
            t_id = "T1048"

        rule_technique_map.setdefault(t_id, []).append(r.name)

    # Sigma rule mappings
    for s in sigma_rules:
        tags = s.tags if isinstance(s.tags, list) else (json.loads(s.tags) if s.tags and isinstance(s.tags, str) and s.tags.startswith("[") else [])
        for tag in tags:
            if tag.startswith("attack.t"):
                tech_id = tag.replace("attack.", "").upper()
                rule_technique_map.setdefault(tech_id, []).append(s.title)

    # Calculate coverage per tactic
    tactics_summary = []
    covered_tactics_count = 0

    for tactic in MITRE_TACTICS_CATALOG:
        tactic_rules = set()
        tactic_alerts = 0
        technique_details = []

        for tech in tactic["techniques"]:
            t_id = tech["id"]
            mapped_rules = rule_technique_map.get(t_id, [])
            firing_alerts = [a for a in alerts if (a.description and t_id in a.description) or (a.explanation and t_id in a.explanation) or (a.detection_type and t_id in a.detection_type)]
            
            for mr in mapped_rules:
                tactic_rules.add(mr)
            tactic_alerts += len(firing_alerts)

            technique_details.append({
                "id": t_id,
                "name": tech["name"],
                "mapped_rules_count": len(mapped_rules),
                "mapped_rules": mapped_rules,
                "firing_alerts_count": len(firing_alerts),
                "covered": len(mapped_rules) > 0
            })

        tactic_covered = len(tactic_rules) > 0
        if tactic_covered:
            covered_tactics_count += 1

        tactics_summary.append({
            "id": tactic["id"],
            "name": tactic["name"],
            "key": tactic["key"],
            "covered": tactic_covered,
            "rules_count": len(tactic_rules),
            "alerts_count": tactic_alerts,
            "techniques": technique_details
        })

    coverage_percent = round((covered_tactics_count / len(MITRE_TACTICS_CATALOG)) * 100, 1)

    return {
        "overall_coverage_percentage": coverage_percent,
        "covered_tactics_count": covered_tactics_count,
        "total_tactics_count": len(MITRE_TACTICS_CATALOG),
        "active_rules_analyzed": len(rules) + len(sigma_rules),
        "total_alerts_analyzed": len(alerts),
        "tactics": tactics_summary
    }
