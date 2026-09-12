import os
import logging
from typing import Dict, Any
from app.connectors.base import BaseConnectorAdapter

logger = logging.getLogger("netwatch.connectors.aws")

class AWSCloudTrailConnector(BaseConnectorAdapter):
    def __init__(self):
        super().__init__(
            connector_id="aws_cloudtrail",
            name="AWS CloudTrail Connector",
            connector_type="AWS_CLOUDTRAIL"
        )

    def redact_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        redacted = dict(config or {})
        if "aws_secret_access_key" in redacted:
            redacted["aws_secret_access_key"] = "********"
        if "aws_access_key_id" in redacted:
            val = str(redacted["aws_access_key_id"])
            redacted["aws_access_key_id"] = val[:4] + "****" if len(val) >= 4 else "****"
        return redacted

    def test_connection(self, config: Dict[str, Any] = None) -> Dict[str, Any]:
        config = config or {}
        access_key = config.get("aws_access_key_id") or os.getenv("AWS_ACCESS_KEY_ID")
        secret_key = config.get("aws_secret_access_key") or os.getenv("AWS_SECRET_ACCESS_KEY")
        region = config.get("region") or os.getenv("AWS_REGION", "us-east-1")

        if not access_key or not secret_key:
            return {
                "connector_id": self.connector_id,
                "status": "NOT_CONFIGURED",
                "message": "AWS CloudTrail credentials are not configured (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY)",
                "details": {"region": region, "credentials_present": False}
            }

        # Validate credentials with boto3 if available, otherwise check key format
        try:
            import boto3
            from botocore.exceptions import BotoCoreError, ClientError
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name=region
            )
            sts = session.client("sts")
            identity = sts.get_caller_identity()
            return {
                "connector_id": self.connector_id,
                "status": "CONNECTED",
                "message": f"Successfully authenticated with AWS STS for Account {identity.get('Account')}",
                "details": {
                    "account": identity.get("Account"),
                    "arn": identity.get("Arn"),
                    "region": region
                }
            }
        except ImportError:
            # Fallback format validation if boto3 is not installed in local environment
            if len(access_key) >= 16 and len(secret_key) >= 20:
                return {
                    "connector_id": self.connector_id,
                    "status": "CONFIGURED",
                    "message": "AWS credentials configured; boto3 library not installed for live STS call",
                    "details": {"region": region, "credentials_present": True}
                }
            return {
                "connector_id": self.connector_id,
                "status": "ERROR",
                "message": "Invalid AWS credential format",
                "details": {"region": region}
            }
        except (BotoCoreError, ClientError) as e:
            logger.warning(f"AWS CloudTrail authentication error: {e}")
            return {
                "connector_id": self.connector_id,
                "status": "ERROR",
                "message": f"AWS API authentication failed: {str(e)}",
                "details": {"region": region}
            }

    def get_status(self) -> Dict[str, Any]:
        access_key = os.getenv("AWS_ACCESS_KEY_ID")
        secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
        configured = bool(access_key and secret_key)
        return {
            "connector_id": self.connector_id,
            "status": "CONFIGURED" if configured else "NOT_CONFIGURED",
            "message": "AWS CloudTrail Connector status check"
        }
