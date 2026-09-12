from typing import Dict, Any, List
from sqlalchemy.orm import Session
from app.sigma.models import SigmaRule
from app.sigma.mapper import SigmaFieldMapper

def validate_sigma_rule(rule_dict: Dict[str, Any], db: Session = None) -> Dict[str, Any]:
    """
    Validates a parsed Sigma rule dictionary against NetWatch requirements.
    Categorizes status as VALID, INVALID, UNSUPPORTED, or DUPLICATE.
    """
    errors: List[str] = []
    warnings: List[str] = []
    unsupported_features: List[str] = []

    rule_id = rule_dict.get("rule_id")
    title = rule_dict.get("title")
    logsource = rule_dict.get("logsource")
    detection = rule_dict.get("detection")

    # Required field checks
    if not title:
        errors.append("Missing required field: 'title'")
    if not logsource or not isinstance(logsource, dict):
        errors.append("Missing or invalid required field: 'logsource'")
    if not detection or not isinstance(detection, dict):
        errors.append("Missing or invalid required field: 'detection'")
    elif "condition" not in detection:
        errors.append("Missing required field 'condition' inside 'detection'")

    if errors:
        return {
            "valid": False,
            "status": "INVALID",
            "errors": errors,
            "warnings": warnings,
            "unsupported_features": unsupported_features,
            "rule_id": rule_id,
            "title": title
        }

    # Duplicate check
    if db and rule_id:
        existing = db.query(SigmaRule).filter(SigmaRule.rule_id == rule_id).first()
        if existing:
            warnings.append(f"Rule with ID '{rule_id}' already exists in database.")

    # Inspect field mappings and detection selections
    for sel_key, sel_val in detection.items():
        if sel_key == "condition":
            continue
        if isinstance(sel_val, dict):
            for field_key in sel_val.keys():
                base_field = field_key.split("|")[0]
                if not SigmaFieldMapper.is_field_supported(base_field):
                    unsupported_features.append(f"Unsupported field: '{base_field}'")

    status = "VALID"
    if unsupported_features:
        status = "UNSUPPORTED"

    return {
        "valid": len(errors) == 0,
        "status": status,
        "errors": errors,
        "warnings": warnings,
        "unsupported_features": unsupported_features,
        "rule_id": rule_id,
        "title": title
    }
