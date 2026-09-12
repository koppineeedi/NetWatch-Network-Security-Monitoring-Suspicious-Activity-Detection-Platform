import os
import logging
from typing import Dict, Any
from app.connectors.base import BaseConnectorAdapter

logger = logging.getLogger("netwatch.connectors.azure")

class AzureActivityLogConnector(BaseConnectorAdapter):
    def __init__(self):
        super().__init__(
            connector_id="azure_activity",
            name="Azure Activity Log Connector",
            connector_type="AZURE_ACTIVITY"
        )

    def redact_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        redacted = dict(config or {})
        if "client_secret" in redacted:
            redacted["client_secret"] = "********"
        if "tenant_id" in redacted:
            val = str(redacted["tenant_id"])
            redacted["tenant_id"] = val[:4] + "****" if len(val) >= 4 else "****"
        return redacted

    def test_connection(self, config: Dict[str, Any] = None) -> Dict[str, Any]:
        config = config or {}
        tenant_id = config.get("tenant_id") or os.getenv("AZURE_TENANT_ID")
        client_id = config.get("client_id") or os.getenv("AZURE_CLIENT_ID")
        client_secret = config.get("client_secret") or os.getenv("AZURE_CLIENT_SECRET")
        subscription_id = config.get("subscription_id") or os.getenv("AZURE_SUBSCRIPTION_ID")

        if not tenant_id or not client_id or not client_secret:
            return {
                "connector_id": self.connector_id,
                "status": "NOT_CONFIGURED",
                "message": "Azure Activity Log service principal credentials not configured",
                "details": {"credentials_present": False}
            }

        try:
            import requests
            token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
            data = {
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": "https://management.azure.com/.default"
            }
            resp = requests.post(token_url, data=data, timeout=5)
            if resp.status_code == 200:
                return {
                    "connector_id": self.connector_id,
                    "status": "CONNECTED",
                    "message": "Successfully authenticated with Microsoft Entra / Azure Management API",
                    "details": {"tenant_id_prefix": tenant_id[:4], "subscription_id": subscription_id}
                }
            else:
                err_msg = resp.json().get("error_description", f"HTTP {resp.status_code}")
                return {
                    "connector_id": self.connector_id,
                    "status": "ERROR",
                    "message": f"Azure authentication failed: {err_msg}",
                    "details": {"status_code": resp.status_code}
                }
        except Exception as e:
            logger.warning(f"Azure Activity Log connection test error: {e}")
            return {
                "connector_id": self.connector_id,
                "status": "ERROR",
                "message": f"Azure connection test failed: {str(e)}",
                "details": {}
            }

    def get_status(self) -> Dict[str, Any]:
        tenant_id = os.getenv("AZURE_TENANT_ID")
        client_id = os.getenv("AZURE_CLIENT_ID")
        configured = bool(tenant_id and client_id)
        return {
            "connector_id": self.connector_id,
            "status": "CONFIGURED" if configured else "NOT_CONFIGURED",
            "message": "Azure Activity Log Connector status check"
        }
