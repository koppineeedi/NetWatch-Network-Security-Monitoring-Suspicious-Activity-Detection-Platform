import os
import yaml
import hashlib
from typing import Dict, Any, List, Tuple

MAX_RULE_SIZE_MB = float(os.getenv("NETWATCH_SIGMA_MAX_RULE_SIZE_MB", "1.0"))
MAX_BYTES = int(MAX_RULE_SIZE_MB * 1024 * 1024)

def parse_sigma_yaml(raw_yaml: str) -> List[Dict[str, Any]]:
    """
    Safely parses raw Sigma YAML content (single or multi-document).
    Enforces maximum payload size restrictions and returns normalized rule dicts.
    """
    if not raw_yaml or not raw_yaml.strip():
        raise ValueError("Empty YAML content provided.")

    raw_bytes = raw_yaml.encode('utf-8')
    if len(raw_bytes) > MAX_BYTES:
        raise ValueError(f"Sigma YAML exceeds maximum allowed size of {MAX_RULE_SIZE_MB}MB.")

    try:
        documents = list(yaml.safe_load_all(raw_yaml))
    except Exception as e:
        raise ValueError(f"Malformed or unsafe YAML syntax: {str(e)}")

    parsed_rules = []
    for doc in documents:
        if not doc or not isinstance(doc, dict):
            continue

        title = doc.get("title", "Untitled Sigma Rule")
        rule_id = doc.get("id")
        if not rule_id:
            # Deterministically derive rule ID from title
            rule_id = "SIGMA-" + hashlib.md5(title.encode('utf-8')).hexdigest()[:8].upper()

        level = str(doc.get("level", "medium")).lower()
        tags = doc.get("tags", [])
        if isinstance(tags, str):
            tags = [tags]

        mitre_techniques = []
        for tag in tags:
            tag_str = str(tag).lower()
            if tag_str.startswith("attack.t"):
                tech_id = tag_str.replace("attack.", "").upper()
                mitre_techniques.append(tech_id)

        normalized = {
            "rule_id": str(rule_id),
            "title": str(title),
            "description": doc.get("description", ""),
            "level": level,
            "author": doc.get("author", "unknown"),
            "date": str(doc.get("date", "")),
            "modified": str(doc.get("modified", "")),
            "logsource": doc.get("logsource", {}),
            "detection": doc.get("detection", {}),
            "tags": tags,
            "mitre_techniques": mitre_techniques,
            "references": doc.get("references", []),
            "falsepositives": doc.get("falsepositives", []),
            "raw_yaml": yaml.safe_dump(doc)
        }
        parsed_rules.append(normalized)

    if not parsed_rules:
        raise ValueError("No valid Sigma rule dictionaries found in YAML content.")

    return parsed_rules
