from typing import Dict, Any
from app.soar.conditions import ConditionEvaluator

class TriggerEvaluator:
    @staticmethod
    def match_trigger(
        playbook_trigger_type: str,
        playbook_trigger_config: Dict[str, Any],
        event_trigger_type: str,
        context: Dict[str, Any]
    ) -> bool:
        """
        Determines whether an event trigger matches a playbook's trigger criteria.
        """
        if playbook_trigger_type.upper() == "MANUAL":
            return event_trigger_type.upper() == "MANUAL"

        if playbook_trigger_type.upper() != event_trigger_type.upper():
            return False

        if not playbook_trigger_config:
            return True

        # Check conditions within trigger config if provided
        return ConditionEvaluator.evaluate_all(playbook_trigger_config, context)
