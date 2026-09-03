import os
import socket
import datetime
import threading
import time
import psutil
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from app.collectors.base import BaseCollector
from app.database.connection import SessionLocal
from app.models.event import NetworkEvent
from app.realtime.publisher import publish_network_event, publish_telemetry_status
from app.detection.engine import evaluate_event

class LocalNetworkCollector(BaseCollector):
    """
    Real-world defensive local network telemetry collector using psutil.
    Passively observes active local machine network sockets without generating network probes or traffic.
    Publishes newly persisted events in real time to connected WebSocket clients.
    """

    def __init__(self):
        super().__init__(name="LOCAL_NETWORK")
        self.hostname = socket.gethostname()
        self.interval = int(os.getenv("NETWATCH_COLLECTION_INTERVAL", "5"))
        if self.interval < 3:
            self.interval = 3

        self.thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self.events_collected = 0
        self.events_stored = 0
        self.error_count = 0
        self.last_collection_time: Optional[datetime.datetime] = None

    def get_status(self) -> Dict[str, Any]:
        """Returns structured dictionary representing current collector state."""
        return {
            "running": self.is_running,
            "collector": self.name,
            "interval": self.interval,
            "last_collection_time": self.last_collection_time.isoformat() if self.last_collection_time else None,
            "events_collected": self.events_collected,
            "events_stored": self.events_stored,
            "errors": self.error_count
        }

    def start(self, db: Optional[Session] = None) -> Dict[str, Any]:
        """Starts the background telemetry collection loop if not already running."""
        if not self.is_running or not self.thread or not self.thread.is_alive():
            self.is_running = True
            self._stop_event.clear()
            self.thread = threading.Thread(target=self._run_loop, daemon=True)
            self.thread.start()

        status = self.get_status()
        publish_telemetry_status(status)
        return status

    def stop(self) -> Dict[str, Any]:
        """Signals the background collection loop to stop cleanly."""
        self.is_running = False
        self._stop_event.set()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=3.0)

        status = self.get_status()
        publish_telemetry_status(status)
        return status

    def _run_loop(self):
        """Background thread loop running at conservative intervals."""
        while not self._stop_event.is_set():
            try:
                db = SessionLocal()
                try:
                    self.collect_once(db)
                finally:
                    db.close()
            except Exception as e:
                self.error_count += 1

            # Wait for configured interval or until stop requested
            self._stop_event.wait(timeout=self.interval)

    def collect(self) -> List[Dict[str, Any]]:
        """Stateless collection of raw socket connection snapshots."""
        observations = []
        try:
            connections = psutil.net_connections(kind='all')
            now_iso = datetime.datetime.utcnow().isoformat()

            for conn in connections:
                local_ip = conn.laddr.ip if conn.laddr else None
                local_port = conn.laddr.port if conn.laddr else None

                remote_ip = conn.raddr.ip if (conn.raddr and hasattr(conn.raddr, 'ip')) else None
                remote_port = conn.raddr.port if (conn.raddr and hasattr(conn.raddr, 'port')) else None

                # Protocol determination via socket constant inspection
                if conn.type == socket.SOCK_STREAM:
                    protocol = "TCP"
                elif conn.type == socket.SOCK_DGRAM:
                    protocol = "UDP"
                else:
                    protocol = "UNKNOWN"

                conn_state = conn.status if conn.status else "UNKNOWN"

                # Safely resolve process name without crashing or requiring admin privileges
                proc_name = None
                if conn.pid:
                    try:
                        p = psutil.Process(conn.pid)
                        proc_name = p.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        proc_name = f"PID:{conn.pid}"

                observations.append({
                    "timestamp": now_iso,
                    "source": "LOCAL_NETWORK",
                    "collector": self.name,
                    "event_type": "NETWORK_CONNECTION",
                    "source_ip": local_ip,
                    "source_port": local_port,
                    "dest_ip": remote_ip,
                    "dest_port": remote_port,
                    "protocol": protocol,
                    "connection_state": conn_state,
                    "process_name": proc_name,
                    "hostname": self.hostname,
                    "status": "NORMAL",
                    "risk_score": 0.0,
                    "bytes_sent": 0,
                    "bytes_received": 0,
                    "packets": 1,
                    "bytes": 0
                })
        except Exception as e:
            self.error_count += 1

        return observations

    def collect_once(self, db: Session):
        """
        Executes one collection cycle, performs deduplication, persists new real events to SQLite database,
        evaluates detections, and publishes events in real time via WebSocket.
        """
        observations = self.collect()
        self.events_collected += len(observations)
        self.last_collection_time = datetime.datetime.utcnow()

        if not observations:
            publish_telemetry_status(self.get_status())
            return

        # Deduplication Window: Check events inserted in last 30 seconds
        window_start = datetime.datetime.utcnow() - datetime.timedelta(seconds=30)
        recent_records = db.query(NetworkEvent).filter(
            NetworkEvent.source == "LOCAL_NETWORK",
            NetworkEvent.timestamp >= window_start
        ).all()

        # Build stable fingerprint set for existing recent records
        recent_fingerprints = set(
            (r.source_ip, r.source_port, r.dest_ip, r.dest_port, r.protocol, r.connection_state)
            for r in recent_records
        )

        new_events = []
        for obs in observations:
            fingerprint = (
                obs["source_ip"],
                obs["source_port"],
                obs["dest_ip"],
                obs["dest_port"],
                obs["protocol"],
                obs["connection_state"]
            )

            if fingerprint not in recent_fingerprints:
                recent_fingerprints.add(fingerprint)
                evt = NetworkEvent(
                    timestamp=datetime.datetime.utcnow(),
                    source="LOCAL_NETWORK",
                    collector=self.name,
                    event_type=obs["event_type"],
                    source_ip=obs["source_ip"],
                    source_port=obs["source_port"],
                    dest_ip=obs["dest_ip"],
                    dest_port=obs["dest_port"],
                    protocol=obs["protocol"],
                    connection_state=obs["connection_state"],
                    status="NORMAL",
                    risk_score=0.0,
                    process_name=obs["process_name"],
                    hostname=obs["hostname"],
                    bytes_sent=0,
                    bytes_received=0,
                    packets=1,
                    bytes=0
                )
                new_events.append(evt)

        if new_events:
            db.add_all(new_events)
            db.commit()
            self.events_stored += len(new_events)

            # Publish real-time network events and evaluate detections
            for evt in new_events:
                db.refresh(evt)
                publish_network_event(evt)
                evaluate_event(db, evt)

        publish_telemetry_status(self.get_status())

# Global singleton collector instance for backend lifecycle management
local_collector_instance = LocalNetworkCollector()
