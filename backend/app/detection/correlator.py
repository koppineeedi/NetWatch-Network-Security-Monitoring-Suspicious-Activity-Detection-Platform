from datetime import datetime, timedelta
from typing import List, Dict, Any
from sqlalchemy.orm import Session
from app.models.event import NetworkEvent

class EventCorrelator:
    """
    Performs bounded multi-event temporal and spatial correlation
    queries across real database events without loading entire tables into memory.
    """

    @staticmethod
    def get_source_events_in_window(
        db: Session,
        source_ip: str,
        time_window_seconds: int = 60,
        ref_timestamp: datetime = None
    ) -> List[NetworkEvent]:
        """
        Retrieves database events for a given source IP within a rolling time window.
        """
        if not source_ip:
            return []

        if not ref_timestamp:
            ref_timestamp = datetime.utcnow()

        window_start = ref_timestamp - timedelta(seconds=time_window_seconds)

        return db.query(NetworkEvent).filter(
            NetworkEvent.source_ip == source_ip,
            NetworkEvent.timestamp >= window_start,
            NetworkEvent.timestamp <= ref_timestamp
        ).order_by(NetworkEvent.timestamp.desc()).all()

    @staticmethod
    def analyze_connection_states(events: List[NetworkEvent]) -> Dict[str, Any]:
        """
        Analyzes connection states across correlated events.
        """
        states = [e.connection_state for e in events if e.connection_state]
        failed_states = [s for s in states if s.upper() in ["CLOSED", "REFUSED", "FAILED", "RESET", "REJECTED"]]

        unique_dest_ports = list(set(e.dest_port for e in events if e.dest_port is not None))
        unique_dest_ips = list(set(e.dest_ip for e in events if e.dest_ip is not None))

        return {
            "total_events": len(events),
            "failed_count": len(failed_states),
            "has_failed_states": len(failed_states) > 0,
            "unique_ports": unique_dest_ports,
            "unique_ports_count": len(unique_dest_ports),
            "unique_dest_ips": unique_dest_ips,
            "event_ids": [e.id for e in events]
        }
