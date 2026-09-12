import fnmatch
import re
from typing import Dict, Any, List, Optional, Union
from app.models.event import NetworkEvent
from app.sigma.mapper import SigmaFieldMapper

SEVERITY_MAPPING = {
    "informational": "LOW",
    "low": "LOW",
    "medium": "MEDIUM",
    "high": "HIGH",
    "critical": "CRITICAL"
}

def match_value(observed: Any, expected: Any, modifiers: List[str]) -> bool:
    """
    Compares an observed telemetry value against an expected Sigma pattern using modifiers and wildcards.
    """
    if observed is None:
        return False

    obs_str = str(observed).lower().strip()
    exp_str = str(expected).lower().strip()

    if "contains" in modifiers:
        if "*" in exp_str or "?" in exp_str:
            return fnmatch.fnmatch(obs_str, exp_str) or exp_str.replace("*", "").replace("?", "") in obs_str
        return exp_str in obs_str
    elif "startswith" in modifiers:
        if "*" in exp_str or "?" in exp_str:
            return fnmatch.fnmatch(obs_str, exp_str)
        return obs_str.startswith(exp_str)
    elif "endswith" in modifiers:
        if "*" in exp_str or "?" in exp_str:
            return fnmatch.fnmatch(obs_str, exp_str)
        return obs_str.endswith(exp_str)
    else:
        # Check wildcard pattern matching
        if "*" in exp_str or "?" in exp_str:
            return fnmatch.fnmatch(obs_str, exp_str)
        # Numerical exact or string exact
        if isinstance(observed, (int, float)) and str(expected).isdigit():
            try:
                return float(observed) == float(expected)
            except ValueError:
                pass
        return obs_str == exp_str

def evaluate_selection(selection_dict: Dict[str, Any], event: Any) -> Tuple_Eval:
    """
    Evaluates a single selection block against an event.
    Returns (matched: bool, matched_fields: list of dicts).
    """
    matched_fields = []

    # Selections can contain key-value pairs or lists of key-value pairs
    for key, expected_val in selection_dict.items():
        parts = key.split("|")
        base_field = parts[0]
        modifiers = [p.lower() for p in parts[1:]]

        netwatch_field = SigmaFieldMapper.map_field(base_field)
        if not netwatch_field:
            return False, []

        observed_val = getattr(event, netwatch_field, None) if hasattr(event, netwatch_field) else event.get(netwatch_field) if isinstance(event, dict) else None

        field_matched = False
        if isinstance(expected_val, list):
            if "all" in modifiers:
                field_matched = all(match_value(observed_val, item, modifiers) for item in expected_val)
            else:
                field_matched = any(match_value(observed_val, item, modifiers) for item in expected_val)
        else:
            field_matched = match_value(observed_val, expected_val, modifiers)

        if field_matched:
            matched_fields.append({
                "sigma_field": base_field,
                "netwatch_field": netwatch_field,
                "observed": observed_val,
                "expected": expected_val
            })
        else:
            return False, []

    return True, matched_fields

class Tuple_Eval:
    def __init__(self, matched: bool, matched_fields: List[Dict[str, Any]]):
        self.matched = matched
        self.matched_fields = matched_fields

class SigmaEvaluator:
    @staticmethod
    def evaluate_rule(rule_dict: Dict[str, Any], event: Any) -> Dict[str, Any]:
        """
        Evaluates a normalized Sigma rule against a NetworkEvent.
        """
        rule_id = rule_dict.get("rule_id", "UNKNOWN")
        detection = rule_dict.get("detection", {})
        condition_str = detection.get("condition", "selection").strip()
        level = rule_dict.get("level", "medium")
        severity = SEVERITY_MAPPING.get(level.lower(), "MEDIUM")
        mitre_techniques = rule_dict.get("mitre_techniques", [])

        selections = {}
        for k, v in detection.items():
            if k != "condition" and isinstance(v, (dict, list)):
                selections[k] = v

        selection_results = {}
        all_matched_fields = []

        for sel_name, sel_content in selections.items():
            if isinstance(sel_content, dict):
                is_match, fields = evaluate_selection(sel_content, event)
                selection_results[sel_name] = is_match
                if is_match:
                    all_matched_fields.extend(fields)
            elif isinstance(sel_content, list):
                # List of maps treated as OR between items
                list_match = False
                list_fields = []
                for item in sel_content:
                    if isinstance(item, dict):
                        m, f = evaluate_selection(item, event)
                        if m:
                            list_match = True
                            list_fields.extend(f)
                            break
                selection_results[sel_name] = list_match
                if list_match:
                    all_matched_fields.extend(list_fields)

        # Evaluate condition string
        overall_matched = False
        cond_lower = condition_str.lower()

        if cond_lower == "selection":
            overall_matched = selection_results.get("selection", False)
        elif cond_lower == "1 of selection*" or cond_lower == "1 of them":
            overall_matched = any(val for k, val in selection_results.items() if k.startswith("selection") or cond_lower == "1 of them")
        elif cond_lower == "all of selection*" or cond_lower == "all of them":
            overall_matched = all(val for k, val in selection_results.items() if k.startswith("selection") or cond_lower == "all of them") and len(selection_results) > 0
        elif " and " in cond_lower:
            parts = [p.strip() for p in cond_lower.split(" and ")]
            overall_matched = all(selection_results.get(p, False) for p in parts if p in selection_results)
        elif " or " in cond_lower:
            parts = [p.strip() for p in cond_lower.split(" or ")]
            overall_matched = any(selection_results.get(p, False) for p in parts if p in selection_results)
        elif cond_lower.startswith("not "):
            target = cond_lower.replace("not ", "").strip()
            overall_matched = not selection_results.get(target, False)
        else:
            # Fallback evaluation
            overall_matched = any(selection_results.values()) if selection_results else False

        explanation = ""
        if overall_matched:
            field_summaries = [f"{mf['sigma_field']} ({mf['netwatch_field']}) = '{mf['observed']}'" for mf in all_matched_fields]
            explanation = f"Sigma rule '{rule_dict.get('title')}' matched condition '{condition_str}'. Observed: {', '.join(field_summaries)}"

        event_id = getattr(event, "id", 0) if hasattr(event, "id") else event.get("id", 0) if isinstance(event, dict) else 0

        return {
            "matched": overall_matched,
            "rule_id": rule_id,
            "rule_title": rule_dict.get("title", ""),
            "event_id": event_id,
            "matched_fields": all_matched_fields,
            "evidence": {
                "condition": condition_str,
                "matched_selections": [k for k, v in selection_results.items() if v],
                "mitre_techniques": mitre_techniques
            },
            "explanation": explanation,
            "severity": severity,
            "confidence": 0.9,
            "mitre_techniques": mitre_techniques
        }
