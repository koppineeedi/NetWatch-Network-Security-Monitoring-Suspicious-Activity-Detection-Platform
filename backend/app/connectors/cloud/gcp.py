import os
import logging
from typing import Dict, Any
from app.connectors.base import BaseConnectorAdapter

logger = logging.getLogger("netwatch.connectors.gcp")

class GCPAuditLogConnector(BaseConnectorAdapter):
    def __init__(self):
        super().__init__(
            connector_id="gcp_audit",
            name="GCP Audit Log Connector",
            connector_type="GCP_AUDIT"
        )

    def redact_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        redacted = dict(config or {})
        if "service_account_key" in redacted:
            redacted["service_account_key"] = "********"
        if "gcp_credentials_json" in redacted:
            redacted["gcp_credentials_json"] = "********"
        return redacted

    def test_connection(self, config: Dict[str, Any] = None) -> Dict[str, Any]:
        config = config or {}
        creds_path = config.get("service_account_key") or os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
        creds_json = config.get("gcp_credentials_json") or os.getenv("GCP_CREDENTIALS_JSON")
        project_id = config.get("project_id") or os.getenv("GCP_PROJECT_ID")

        if not creds_path and not creds_json and not project_id:
            return {
                "connector_id": self.connector_id,
                "status": "NOT_CONFIGURED",
                "message": "GCP Audit Log credentials not configured (GOOGLE_APPLICATION_CREDENTIALS / GCP_PROJECT_ID)",
                "details": {"credentials_present": False}
            }

        try:
            from google.auth import default as google_default_auth
            from google.auth.exceptions import GoogleAuthError
            credentials, project = google_default_auth(scopes=["https://www.googleapis.com/auth/logging.read"])
            return {
                "connector_id": self.connector_id,
                "status": "CONNECTED",
                "message": f"Successfully validated GCP Application Default Credentials for project '{project or project_id}'",
                "details": {"project_id": project or project_id, "credentials_valid": True}
            }
        except ImportError:
            # Fallback syntax validation if google-auth library is absent
            if (creds_path and os.path.exists(creds_path)) or creds_json or project_id:
                return {
                    "connector_id": self.connector_id,
                    "status": "CONFIGURED",
                    "message": "GCP credentials configured; google-auth SDK not installed in local environment",
                    "details": {"project_id": project_id, "credentials_present": True}
                }
            return {
                "connector_id": self.connector_id,
                "status": "ERROR",
                "message": "GCP credential file path does not exist",
                "details": {"creds_path": creds_path}
            }
        except Exception as e:
            logger.warning(f"GCP Audit Log connection test failed: {e}")
            return {
                "connector_id": self.connector_id,
                "status": "ERROR",
                "message": f"GCP authentication failed: {str(e)}",
                "details": {"project_id": project_id}
            }

    def get_status(self) -> Dict[str, Any]:
        creds = os.getenv("GOOGLE_APPLICATION_CREDENTIALS") or os.getenv("GCP_PROJECT_ID") or os.getenv("GCP_CREDENTIALS_JSON")
        return {
            "connector_id": self.connector_id,
            "status": "CONFIGURED" if creds else "NOT_CONFIGURED",
            "message": "GCP Audit Log Connector status check"
        }
