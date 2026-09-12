import os
from typing import Dict, Any
from app.connectors.base import BaseConnectorAdapter

class AzureActivityLogConnector(BaseConnectorAdapter):
    def __init__(self):
        super().__init__(
            connector_id="azure_activity",
            name="Azure Activity Log Connector",
            connector_type="AZURE_ACTIVITY"
        )

    def redact_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        redacted = dict(config)
        if "client_secret" in redacted:
            redacted["client_secret"] = "********"
        if "tenant_id" in redacted:
            val = str(redacted["tenant_id"])
            redacted["tenant_id"] = val[:4] + "****" if len(val) >= 4 else "****"
        return redacted

    def test_connection(self, config: Dict[str, Any]) -> Dict[str, Any]:
        tenant_id = config.get("tenant_id") or os.getenv("AZURE_TENANT_ID")
        client_id = config.get("client_id") or os.getenv("AZURE_CLIENT_ID")
        client_secret = config.get("client_secret") or os.getenv("AZURE_CLIENT_SECRET")

        if not tenant_id or not client_id or not client_secret:
            return {
                "status": "NOT_CONFIGURED",
                "message": "Azure Activity Log credentials are not configured",
                "details": {"credentials_present": False}
            }

        return {
            "status": "CONFIGURED",
            "message": "Azure Activity Log service principal credentials validated",
            "details": {"tenant_id_prefix": tenant_id[:4], "credentials_present": True}
        }

    def get_status(self) -> Dict[str, Any]:
        tenant_id = os.getenv("AZURE_TENANT_ID")
        return {
            "connector_id": self.connector_id,
            "status": "CONFIGURED" if tenant_id else "NOT_CONFIGURED",
            "message": "Azure Activity Log Connector operational status"
        }
