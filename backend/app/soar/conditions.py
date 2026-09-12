from typing import Dict, Any, Union

class ConditionEvaluator:
    @staticmethod
    def evaluate_condition(condition_spec: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """
        Evaluates deterministic structured condition specification against event/alert context.
        Does NOT execute arbitrary Python code.

        Supported operators: ==, !=, >, >=, <, <=, in, contains, true, false
        """
        if not condition_spec:
            return True

        field = condition_spec.get("field")
        op = condition_spec.get("operator", "==").lower()
        expected = condition_spec.get("value")

        if not field:
            return True

        # Extract actual value from context
        actual = context.get(field)
        if actual is None and "." in field:
            parts = field.split(".")
            val = context
            for p in parts:
                if isinstance(val, dict):
                    val = val.get(p)
                else:
                    val = None
                    break
            actual = val

        if op == "==" or op == "eq":
            return str(actual).lower() == str(expected).lower() if isinstance(actual, str) and isinstance(expected, str) else actual == expected
        elif op == "!=" or op == "neq":
            return str(actual).lower() != str(expected).lower() if isinstance(actual, str) and isinstance(expected, str) else actual != expected
        elif op == ">" or op == "gt":
            try:
                return float(actual) > float(expected)
            except (ValueError, TypeError):
                return False
        elif op == ">=" or op == "gte":
            try:
                return float(actual) >= float(expected)
            except (ValueError, TypeError):
                return False
        elif op == "<" or op == "lt":
            try:
                return float(actual) < float(expected)
            except (ValueError, TypeError):
                return False
        elif op == "<=" or op == "lte":
            try:
                return float(actual) <= float(expected)
            except (ValueError, TypeError):
                return False
        elif op == "in":
            if isinstance(expected, list):
                return actual in expected
            return str(actual) in str(expected)
        elif op == "contains":
            if isinstance(actual, (list, str)):
                return str(expected).lower() in str(actual).lower()
            return False
        elif op == "true":
            return bool(actual) is True
        elif op == "false":
            return bool(actual) is False

        return False

    @staticmethod
    def evaluate_all(conditions: Union[Dict[str, Any], list], context: Dict[str, Any]) -> bool:
        """
        Evaluates list or map of conditions (AND logic).
        """
        if not conditions:
            return True

        if isinstance(conditions, dict):
            if "field" in conditions:
                return ConditionEvaluator.evaluate_condition(conditions, context)
            # Map of field -> expected value
            for k, v in conditions.items():
                cond_spec = {"field": k, "operator": "==", "value": v}
                if not ConditionEvaluator.evaluate_condition(cond_spec, context):
                    return False
            return True

        elif isinstance(conditions, list):
            for cond in conditions:
                if isinstance(cond, dict):
                    if not ConditionEvaluator.evaluate_condition(cond, context):
                        return False
            return True

        return True
