import os
from typing import Dict, Any
from app.connectors.base import BaseConnectorAdapter
from app.collectors.syslog_collector import syslog_collector_instance

class SyslogConnectorAdapter(BaseConnectorAdapter):
    def __init__(self):
        super().__init__(
            connector_id="syslog_receiver",
            name="Remote Syslog Collector",
            connector_type="SYSLOG"
        )

    def redact_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        return dict(config)  # No secret keys in Syslog listener configuration

    def test_connection(self, config: Dict[str, Any]) -> Dict[str, Any]:
        status = syslog_collector_instance.get_status()
        if status.get("running"):
            return {
                "status": "CONNECTED",
                "message": f"Syslog UDP listener bound and active on {status['host']}:{status['port']}",
                "details": status
            }
        elif status.get("enabled"):
            return {
                "status": "CONFIGURED",
                "message": f"Syslog collector configured for {status['host']}:{status['port']}",
                "details": status
            }
        else:
            return {
                "status": "DISABLED",
                "message": "Syslog collector is disabled (NETWATCH_SYSLOG_ENABLED=false)",
                "details": status
            }

    def get_status(self) -> Dict[str, Any]:
        return syslog_collector_instance.get_status()
