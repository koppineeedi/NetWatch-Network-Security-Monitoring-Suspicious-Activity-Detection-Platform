from typing import Dict, Any, Tuple, Callable
from app.soar.integrations import (
    LocalFirewallIntegration,
    HostIsolationIntegration,
    ProcessControlIntegration,
    IdentityProviderIntegration,
    NotificationIntegration
)

ACTION_HANDLERS: Dict[str, Callable[[str, Dict[str, Any]], Tuple[str, Dict[str, Any]]]] = {
    "BLOCK_IP": lambda target, params: LocalFirewallIntegration.block_ip(target),
    "UNBLOCK_IP": lambda target, params: LocalFirewallIntegration.unblock_ip(target),
    "ADD_FIREWALL_RULE": lambda target, params: LocalFirewallIntegration.block_ip(target),
    "REMOVE_FIREWALL_RULE": lambda target, params: LocalFirewallIntegration.unblock_ip(target),
    "ISOLATE_HOST": lambda target, params: HostIsolationIntegration.isolate_host(target),
    "RESTORE_HOST": lambda target, params: HostIsolationIntegration.restore_host(target),
    "KILL_PROCESS": lambda target, params: ProcessControlIntegration.kill_process(target),
    "DISABLE_ACCOUNT": lambda target, params: IdentityProviderIntegration.disable_account(target),
    "ENABLE_ACCOUNT": lambda target, params: IdentityProviderIntegration.enable_account(target),
    "NOTIFY_ANALYST": lambda target, params: NotificationIntegration.notify_analyst(
        target,
        params.get("message", "SOAR Automated Notification"),
        params
    )
}

SUPPORTED_ACTIONS = list(ACTION_HANDLERS.keys())

def execute_action_handler(action_type: str, target: str, parameters: Dict[str, Any] = None) -> Tuple[str, Dict[str, Any]]:
    """
    Executes the registered handler for the given action_type and target.
    Returns tuple: (status_code, result_dict)
    Possible status codes: SUCCESS, FAILED, NOT_CONFIGURED
    """
    if parameters is None:
        parameters = {}

    action_type_upper = action_type.upper()
    if action_type_upper not in ACTION_HANDLERS:
        return "FAILED", {"error": f"Action type '{action_type}' is not supported."}

    handler = ACTION_HANDLERS[action_type_upper]
    try:
        return handler(target, parameters)
    except Exception as e:
        return "FAILED", {"error": f"Exception during action execution: {str(e)}"}
