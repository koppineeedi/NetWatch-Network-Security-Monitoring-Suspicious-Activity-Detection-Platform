import json
import datetime
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from app.models.connector import Connector
from app.connectors.syslog.syslog_connector import SyslogConnectorAdapter
from app.connectors.cloud.aws import AWSCloudTrailConnector
from app.connectors.cloud.azure import AzureActivityLogConnector
from app.connectors.cloud.gcp import GCPAuditLogConnector
from app.collectors.syslog_collector import syslog_collector_instance

class ConnectorManager:
    def __init__(self):
        self.adapters = {
            "syslog_receiver": SyslogConnectorAdapter(),
            "aws_cloudtrail": AWSCloudTrailConnector(),
            "azure_activity": AzureActivityLogConnector(),
            "gcp_audit": GCPAuditLogConnector()
        }

    def seed_default_connectors(self, db: Session):
        """Seeds default connector entries in database if not present."""
        existing = {c.connector_id for c in db.query(Connector).all()}
        defaults = [
            ("syslog_receiver", "Remote Syslog Receiver", "SYSLOG", "DISABLED"),
            ("aws_cloudtrail", "AWS CloudTrail", "AWS_CLOUDTRAIL", "NOT_CONFIGURED"),
            ("azure_activity", "Azure Activity Log", "AZURE_ACTIVITY", "NOT_CONFIGURED"),
            ("gcp_audit", "GCP Audit Log", "GCP_AUDIT", "NOT_CONFIGURED")
        ]

        for cid, name, ctype, default_status in defaults:
            if cid not in existing:
                c = Connector(
                    connector_id=cid,
                    name=name,
                    connector_type=ctype,
                    status=default_status,
                    config_json=json.dumps({"seeded": True})
                )
                db.add(c)
        db.commit()

    def get_all_connectors(self, db: Session) -> List[Dict[str, Any]]:
        self.seed_default_connectors(db)
        connectors = db.query(Connector).all()
        result = []
        for c in connectors:
            adapter = self.adapters.get(c.connector_id) or self.adapters.get(c.connector_type.lower())
            config_dict = json.loads(c.config_json) if c.config_json else {}
            if adapter:
                redacted_config = adapter.redact_config(config_dict)
            else:
                redacted_config = {
                    k: ("*****" if any(s in k.lower() for s in ["secret", "key", "pass", "token"]) else v)
                    for k, v in config_dict.items()
                }
            
            # Dynamic status update for Syslog if active
            status = c.status
            if c.connector_id == "syslog_receiver" and syslog_collector_instance.is_running:
                status = "CONNECTED"

            result.append({
                "id": c.id,
                "connector_id": c.connector_id,
                "name": c.name,
                "connector_type": c.connector_type,
                "status": status,
                "config": redacted_config,
                "last_seen": c.last_seen.isoformat() if c.last_seen else None,
                "last_error": c.last_error,
                "created_at": c.created_at.isoformat() if c.created_at else None,
                "updated_at": c.updated_at.isoformat() if c.updated_at else None
            })
        return result

    def get_connector(self, db: Session, connector_id: str) -> Optional[Dict[str, Any]]:
        self.seed_default_connectors(db)
        c = db.query(Connector).filter((Connector.connector_id == connector_id) | (Connector.id == (int(connector_id) if connector_id.isdigit() else -1))).first()
        if not c:
            return None

        adapter = self.adapters.get(c.connector_id) or self.adapters.get(c.connector_type.lower())
        config_dict = json.loads(c.config_json) if c.config_json else {}
        if adapter:
            redacted_config = adapter.redact_config(config_dict)
        else:
            redacted_config = {
                k: ("*****" if any(s in k.lower() for s in ["secret", "key", "pass", "token"]) else v)
                for k, v in config_dict.items()
            }

        status = c.status
        if c.connector_id == "syslog_receiver" and syslog_collector_instance.is_running:
            status = "CONNECTED"

        return {
            "id": c.id,
            "connector_id": c.connector_id,
            "name": c.name,
            "connector_type": c.connector_type,
            "status": status,
            "config": redacted_config,
            "last_seen": c.last_seen.isoformat() if c.last_seen else None,
            "last_error": c.last_error,
            "created_at": c.created_at.isoformat() if c.created_at else None,
            "updated_at": c.updated_at.isoformat() if c.updated_at else None
        }

    def test_connector(self, db: Session, connector_id: str, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        c_dict = self.get_connector(db, connector_id)
        if not c_dict:
            return {"connector_id": connector_id, "status": "ERROR", "message": "Connector not found"}

        cid = c_dict["connector_id"]
        adapter = self.adapters.get(cid)
        if not adapter:
            return {"connector_id": cid, "status": "ERROR", "message": f"No adapter registered for {cid}"}

        test_cfg = config if config is not None else c_dict["config"] or {}
        return adapter.test_connection(test_cfg)

    def enable_connector(self, db: Session, connector_id: str) -> Dict[str, Any]:
        c = db.query(Connector).filter((Connector.connector_id == connector_id) | (Connector.id == (int(connector_id) if connector_id.isdigit() else -1))).first()
        if not c:
            return {"status": "ERROR", "message": "Connector not found"}

        if c.connector_id == "syslog_receiver":
            syslog_collector_instance.enabled = True
            res = syslog_collector_instance.start()
            c.status = "CONNECTED" if syslog_collector_instance.is_running else "CONFIGURED"
        else:
            c.status = "CONFIGURED"

        c.last_seen = datetime.datetime.utcnow()
        db.commit()
        return self.get_connector(db, c.connector_id)

    def disable_connector(self, db: Session, connector_id: str) -> Dict[str, Any]:
        c = db.query(Connector).filter((Connector.connector_id == connector_id) | (Connector.id == (int(connector_id) if connector_id.isdigit() else -1))).first()
        if not c:
            return {"status": "ERROR", "message": "Connector not found"}

        if c.connector_id == "syslog_receiver":
            syslog_collector_instance.enabled = False
            syslog_collector_instance.stop()

        c.status = "DISABLED"
        db.commit()
        return self.get_connector(db, c.connector_id)

connector_manager = ConnectorManager()
