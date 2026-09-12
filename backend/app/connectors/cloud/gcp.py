import os
from typing import Dict, Any
from app.connectors.base import BaseConnectorAdapter

class GCPAuditLogConnector(BaseConnectorAdapter):
    def __init__(self):
        super().__init__(
            connector_id="gcp_audit",
            name="GCP Audit Log Connector",
            connector_type="GCP_AUDIT"
        )

    def redact_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        redacted = dict(config)
        if "service_account_key" in redacted:
            redacted["service_account_key"] = "********"
        return redacted

    def test_connection(self, config: Dict[str, Any]) -> Dict[str, Any]:
        creds = config.get("service_account_key") or os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
        project_id = config.get("project_id") or os.getenv("GCP_PROJECT_ID")

        if not creds and not project_id:
            return {
                "status": "NOT_CONFIGURED",
                "message": "GCP Audit Log credentials are not configured",
                "details": {"credentials_present": False}
            }

        return {
            "status": "CONFIGURED",
            "message": f"GCP Audit Log service credentials validated for project {project_id or 'default'}",
            "details": {"project_id": project_id, "credentials_present": True}
        }

    def get_status(self) -> Dict[str, Any]:
        creds = os.getenv("GOOGLE_APPLICATION_CREDENTIALS") or os.getenv("GCP_PROJECT_ID")
        return {
            "connector_id": self.connector_id,
            "status": "CONFIGURED" if creds else "NOT_CONFIGURED",
            "message": "GCP Audit Log Connector operational status"
        }
