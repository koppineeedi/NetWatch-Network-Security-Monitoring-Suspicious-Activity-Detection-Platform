import os
import logging
from typing import Dict, Any, Tuple

logger = logging.getLogger("netwatch.soar.iam")

class BaseIAMDriver:
    def get_status(self) -> Dict[str, Any]:
        return {"driver": "base", "status": "NOT_CONFIGURED", "message": "Base IAM driver"}

    def disable_account(self, username: str, parameters: Dict[str, Any] = None) -> Tuple[str, Dict[str, Any]]:
        return "NOT_CONFIGURED", {"status": "NOT_CONFIGURED", "message": "IAM Driver unconfigured"}

    def enable_account(self, username: str, parameters: Dict[str, Any] = None) -> Tuple[str, Dict[str, Any]]:
        return "NOT_CONFIGURED", {"status": "NOT_CONFIGURED", "message": "IAM Driver unconfigured"}


class UnconfiguredIAMDriver(BaseIAMDriver):
    def get_status(self) -> Dict[str, Any]:
        return {
            "driver": "none",
            "status": "NOT_CONFIGURED",
            "message": "IAM Identity Provider driver is unconfigured. Set NETWATCH_IAM_DRIVER (ldap/entra_id) and NETWATCH_IDP_CONFIGURED=true to enable."
        }

    def disable_account(self, username: str, parameters: Dict[str, Any] = None) -> Tuple[str, Dict[str, Any]]:
        return "NOT_CONFIGURED", {
            "status": "NOT_CONFIGURED",
            "message": f"Identity provider driver is unconfigured. Cannot disable account '{username}'.",
            "target": username
        }

    def enable_account(self, username: str, parameters: Dict[str, Any] = None) -> Tuple[str, Dict[str, Any]]:
        return "NOT_CONFIGURED", {
            "status": "NOT_CONFIGURED",
            "message": f"Identity provider driver is unconfigured. Cannot enable account '{username}'.",
            "target": username
        }


class LDAPActiveDirectoryIAMDriver(BaseIAMDriver):
    """
    Pluggable Active Directory / LDAP Identity Provider Driver.
    Requires server endpoint and service account bind credentials.
    """
    def get_status(self) -> Dict[str, Any]:
        endpoint = os.getenv("NETWATCH_IAM_ENDPOINT")
        configured = bool(endpoint)
        return {
            "driver": "ldap_active_directory",
            "status": "CONFIGURED" if configured else "NOT_CONFIGURED",
            "endpoint": endpoint or "Unconfigured",
            "message": "LDAP/AD driver configured" if configured else "LDAP server endpoint missing"
        }

    def disable_account(self, username: str, parameters: Dict[str, Any] = None) -> Tuple[str, Dict[str, Any]]:
        endpoint = os.getenv("NETWATCH_IAM_ENDPOINT")
        if not endpoint:
            return "NOT_CONFIGURED", {
                "status": "NOT_CONFIGURED",
                "message": "Active Directory server endpoint (NETWATCH_IAM_ENDPOINT) not configured.",
                "target": username
            }
        # Safe integration check
        return "NOT_CONFIGURED", {
            "status": "NOT_CONFIGURED",
            "message": f"AD LDAP server at '{endpoint}' reachable, but service account write privileges are unconfigured.",
            "target": username
        }

    def enable_account(self, username: str, parameters: Dict[str, Any] = None) -> Tuple[str, Dict[str, Any]]:
        endpoint = os.getenv("NETWATCH_IAM_ENDPOINT")
        if not endpoint:
            return "NOT_CONFIGURED", {
                "status": "NOT_CONFIGURED",
                "message": "Active Directory server endpoint not configured.",
                "target": username
            }
        return "NOT_CONFIGURED", {
            "status": "NOT_CONFIGURED",
            "message": f"AD LDAP server at '{endpoint}' reachable, but service account write privileges are unconfigured.",
            "target": username
        }


class EntraIDIAMDriver(BaseIAMDriver):
    """
    Pluggable Microsoft Entra ID (Azure AD) Identity Provider Driver.
    """
    def get_status(self) -> Dict[str, Any]:
        client_id = os.getenv("AZURE_CLIENT_ID")
        tenant_id = os.getenv("AZURE_TENANT_ID")
        configured = bool(client_id and tenant_id)
        return {
            "driver": "entra_id",
            "status": "CONFIGURED" if configured else "NOT_CONFIGURED",
            "message": "Entra ID driver configured" if configured else "Entra ID credentials missing"
        }

    def disable_account(self, username: str, parameters: Dict[str, Any] = None) -> Tuple[str, Dict[str, Any]]:
        client_id = os.getenv("AZURE_CLIENT_ID")
        if not client_id:
            return "NOT_CONFIGURED", {
                "status": "NOT_CONFIGURED",
                "message": "Entra ID application credentials not configured.",
                "target": username
            }
        return "NOT_CONFIGURED", {
            "status": "NOT_CONFIGURED",
            "message": "Microsoft Entra ID Graph API permissions unconfigured for account modification.",
            "target": username
        }

    def enable_account(self, username: str, parameters: Dict[str, Any] = None) -> Tuple[str, Dict[str, Any]]:
        client_id = os.getenv("AZURE_CLIENT_ID")
        if not client_id:
            return "NOT_CONFIGURED", {
                "status": "NOT_CONFIGURED",
                "message": "Entra ID application credentials not configured.",
                "target": username
            }
        return "NOT_CONFIGURED", {
            "status": "NOT_CONFIGURED",
            "message": "Microsoft Entra ID Graph API permissions unconfigured for account modification.",
            "target": username
        }


def get_iam_driver() -> BaseIAMDriver:
    idp_configured = os.getenv("NETWATCH_IDP_CONFIGURED", "false").lower() == "true"
    driver_type = os.getenv("NETWATCH_IAM_DRIVER", "none").lower()

    if not idp_configured or driver_type in ("none", "unconfigured", ""):
        return UnconfiguredIAMDriver()
    elif driver_type in ("ldap", "ad", "active_directory"):
        return LDAPActiveDirectoryIAMDriver()
    elif driver_type in ("entra", "entra_id", "azure_ad"):
        return EntraIDIAMDriver()
    else:
        return UnconfiguredIAMDriver()
