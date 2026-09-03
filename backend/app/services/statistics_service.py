from sqlalchemy.orm import Session
from sqlalchemy import func
from app.models.event import NetworkEvent
from app.models.alert import Alert
from app.models.investigation import Investigation
from app.models.detection import Detection
from app.models.asset import Asset
from typing import Dict, Any

class StatisticsService:
    @staticmethod
    def get_statistics(db: Session) -> Dict[str, Any]:
        total_events = db.query(NetworkEvent).count()
        suspicious_events = db.query(NetworkEvent).filter(NetworkEvent.status == "SUSPICIOUS").count()
        open_alerts = db.query(Alert).filter(Alert.status.in_(["NEW", "INVESTIGATING"])).count()
        open_investigations = db.query(Investigation).filter(Investigation.status != "CLOSED_RESOLVED").count()
        total_detections = db.query(Detection).count()
        monitored_assets = db.query(Asset).count()
        active_connections = db.query(NetworkEvent.source_ip).distinct().count()

        protocol_query = db.query(NetworkEvent.protocol, func.count(NetworkEvent.id)).group_by(NetworkEvent.protocol).all()
        protocol_distribution = [{"name": p[0] or "UNKNOWN", "value": p[1]} for p in protocol_query]

        port_query = db.query(NetworkEvent.dest_port, func.count(NetworkEvent.id)).group_by(NetworkEvent.dest_port).order_by(func.count(NetworkEvent.id).desc()).limit(5).all()
        top_ports = [{"port": p[0], "count": p[1]} for p in port_query if p[0] is not None]

        return {
            "total_events": total_events,
            "active_connections": active_connections,
            "suspicious_events": suspicious_events,
            "open_alerts": open_alerts,
            "open_investigations": open_investigations,
            "total_detections": total_detections,
            "monitored_assets": monitored_assets,
            "protocol_distribution": protocol_distribution,
            "top_ports": top_ports
        }
