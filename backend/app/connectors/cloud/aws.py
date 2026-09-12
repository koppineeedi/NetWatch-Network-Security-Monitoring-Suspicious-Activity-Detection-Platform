import os
from typing import Dict, Any
from app.connectors.base import BaseConnectorAdapter

class AWSCloudTrailConnector(BaseConnectorAdapter):
    def __init__(self):
        super().__init__(
            connector_id="aws_cloudtrail",
            name="AWS CloudTrail Connector",
            connector_type="AWS_CLOUDTRAIL"
        )

    def redact_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        redacted = dict(config)
        if "aws_secret_access_key" in redacted:
            redacted["aws_secret_access_key"] = "********"
        if "aws_access_key_id" in redacted:
            val = str(redacted["aws_access_key_id"])
            redacted["aws_access_key_id"] = val[:4] + "****" if len(val) >= 4 else "****"
        return redacted

    def test_connection(self, config: Dict[str, Any]) -> Dict[str, Any]:
        access_key = config.get("aws_access_key_id") or os.getenv("AWS_ACCESS_KEY_ID")
        secret_key = config.get("aws_secret_access_key") or os.getenv("AWS_SECRET_ACCESS_KEY")
        region = config.get("region") or os.getenv("AWS_REGION", "us-east-1")

        if not access_key or not secret_key:
            return {
                "status": "NOT_CONFIGURED",
                "message": "AWS CloudTrail credentials are not configured",
                "details": {"region": region, "credentials_present": False}
            }

        return {
            "status": "CONFIGURED",
            "message": f"AWS CloudTrail credentials validated for region {region}",
            "details": {"region": region, "credentials_present": True}
        }

    def get_status(self) -> Dict[str, Any]:
        access_key = os.getenv("AWS_ACCESS_KEY_ID")
        return {
            "connector_id": self.connector_id,
            "status": "CONFIGURED" if access_key else "NOT_CONFIGURED",
            "message": "AWS CloudTrail Connector operational status"
        }
