import os
import socket
import datetime
import threading
import queue
import re
import logging
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from app.collectors.base import BaseCollector
from app.database.connection import SessionLocal
from app.models.event import NetworkEvent
from app.realtime.publisher import publish_network_event, publish_telemetry_status
from app.detection.engine import evaluate_event

logger = logging.getLogger("netwatch.syslog")

FACILITIES = [
    "kernel", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
    "uucp", "cron", "authpriv", "ftp", "ntp", "security", "console", "solaris-cron",
    "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7"
]

SEVERITIES = [
    "EMERGENCY", "ALERT", "CRITICAL", "ERROR", "WARNING", "NOTICE", "INFORMATIONAL", "DEBUG"
]

class SyslogCollector(BaseCollector):
    """
    Non-blocking, background UDP Syslog receiver for remote log telemetry.
    Parses RFC 3164 / RFC 5424 formatted Syslog payloads, persists events, and triggers detection evaluation.
    """

    def __init__(self):
        super().__init__(name="REMOTE_SYSLOG")
        self.enabled = os.getenv("NETWATCH_SYSLOG_ENABLED", "false").lower() in ("true", "1", "yes")
        self.host = os.getenv("NETWATCH_SYSLOG_HOST", "0.0.0.0")
        self.udp_port = int(os.getenv("NETWATCH_SYSLOG_UDP_PORT", "514"))
        
        self.sock: Optional[socket.socket] = None
        self.thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self.packet_queue: queue.Queue = queue.Queue(maxsize=2000)
        
        self.events_collected = 0
        self.events_stored = 0
        self.error_count = 0
        self.last_error: Optional[str] = None
        self.last_collection_time: Optional[datetime.datetime] = None

    def get_status(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "running": self.is_running,
            "collector": self.name,
            "host": self.host,
            "port": self.udp_port,
            "events_collected": self.events_collected,
            "events_stored": self.events_stored,
            "queue_size": self.packet_queue.qsize(),
            "last_error": self.last_error,
            "errors": self.error_count,
            "last_collection_time": self.last_collection_time.isoformat() if self.last_collection_time else None
        }

    def start(self, db: Optional[Session] = None) -> Dict[str, Any]:
        if not self.enabled:
            logger.info("[SYSLOG] Receiver is disabled in environment (NETWATCH_SYSLOG_ENABLED=false)")
            return self.get_status()

        if self.is_running and self.thread and self.thread.is_alive():
            return self.get_status()

        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.settimeout(1.0)
            self.sock.bind((self.host, self.udp_port))
            
            self.is_running = True
            self.last_error = None
            self._stop_event.clear()
            self.thread = threading.Thread(target=self._listen_loop, daemon=True)
            self.thread.start()
            logger.info(f"[SYSLOG] UDP listener bound cleanly to {self.host}:{self.udp_port}")
        except Exception as e:
            self.is_running = False
            self.last_error = f"Socket bind failed on {self.host}:{self.udp_port} - {str(e)}"
            self.error_count += 1
            logger.warning(f"[SYSLOG] {self.last_error}")

        status = self.get_status()
        publish_telemetry_status(status)
        return status

    def stop(self) -> Dict[str, Any]:
        self.is_running = False
        self._stop_event.set()
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2.0)

        status = self.get_status()
        publish_telemetry_status(status)
        return status

    def _listen_loop(self):
        """Background thread loop receiving raw UDP Syslog packets."""
        while not self._stop_event.is_set() and self.sock:
            try:
                data, addr = self.sock.recvfrom(4096)
                if data:
                    self.events_collected += 1
                    try:
                        self.packet_queue.put_nowait((data.decode("utf-8", errors="ignore"), addr[0]))
                    except queue.Full:
                        self.error_count += 1  # Queue rate limiting drop

                # Process available packets in batch
                self._process_queue()
            except socket.timeout:
                self._process_queue()
            except Exception as e:
                if not self._stop_event.is_set():
                    self.error_count += 1
                    self.last_error = str(e)

    def _process_queue(self):
        """Drains packet queue and persists normalized events to DB."""
        if self.packet_queue.empty():
            return

        db = SessionLocal()
        new_events = []
        try:
            while not self.packet_queue.empty() and len(new_events) < 100:
                raw_msg, client_ip = self.packet_queue.get_nowait()
                parsed = self.parse_syslog_msg(raw_msg, client_ip)
                
                evt = NetworkEvent(
                    timestamp=parsed["timestamp"],
                    source="REMOTE_SYSLOG",
                    collector=self.name,
                    event_type="SYSLOG_EVENT",
                    source_ip=parsed["source_ip"],
                    source_port=None,
                    dest_ip=parsed["dest_ip"],
                    dest_port=None,
                    protocol="UDP",
                    connection_state=parsed["severity"],
                    status="NORMAL",
                    risk_score=0.0,
                    process_name=parsed["process_name"],
                    hostname=parsed["hostname"],
                    payload_summary=parsed["message"][:250]
                )
                new_events.append(evt)

            if new_events:
                db.add_all(new_events)
                db.commit()
                self.events_stored += len(new_events)
                self.last_collection_time = datetime.datetime.utcnow()

                for evt in new_events:
                    db.refresh(evt)
                    publish_network_event(evt)
                    evaluate_event(db, evt)
        except Exception as e:
            self.error_count += 1
            self.last_error = f"Database ingestion error: {str(e)}"
        finally:
            db.close()

    def parse_syslog_msg(self, raw: str, default_ip: str) -> Dict[str, Any]:
        """
        Parses RFC 3164 / RFC 5424 header structures.
        Extracts Priority (Facility/Severity), Timestamp, Hostname, Tag, and Message.
        """
        parsed = parse_syslog_message(raw, default_ip)
        parsed["severity"] = parsed["severity_name"]
        return parsed

    def collect(self) -> List[Dict[str, Any]]:
        """Implementation of abstract collect method for daemon listener."""
        return []

def parse_syslog_message(raw: str, source_ip: str = "127.0.0.1") -> Dict[str, Any]:
    """
    Parses RFC 3164 / RFC 5424 header structures.
    Extracts Priority (Facility/Severity codes), Timestamp, Hostname, and Message payload.
    """
    raw_str = raw.strip()
    facility_code = 1
    severity_code = 6
    facility_name = "user"
    severity_name = "INFORMATIONAL"
    hostname = source_ip

    pri_match = re.match(r'^<(\d{1,3})>', raw_str)
    if pri_match:
        pri = int(pri_match.group(1))
        raw_str = raw_str[pri_match.end():].strip()
        facility_code = pri >> 3
        severity_code = pri & 7
        facility_name = FACILITIES[facility_code] if facility_code < len(FACILITIES) else "user"
        severity_name = SEVERITIES[severity_code] if severity_code < len(SEVERITIES) else "INFORMATIONAL"

    # RFC 3164 timestamp + hostname format: Oct 11 22:14:15 myhost myapp:...
    parts = raw_str.split()
    if len(parts) >= 4 and parts[0] in ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"]:
        hostname = parts[3]

    ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', raw_str)
    src_ip = ip_match.group(1) if ip_match else source_ip
    dst_ip = None
    if ip_match and ip_match.end() < len(raw_str):
        second_ip = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', raw_str[ip_match.end():])
        if second_ip:
            dst_ip = second_ip.group(1)

    proc_name = facility_name
    tag_match = re.search(r'([a-zA-Z0-9_\-\.]+)(?:\[\d+\])?:', raw_str)
    if tag_match:
        proc_name = tag_match.group(1)

    return {
        "timestamp": datetime.datetime.utcnow(),
        "facility": facility_code,
        "facility_name": facility_name,
        "severity": severity_code,
        "severity_name": severity_name,
        "hostname": hostname,
        "source_ip": src_ip,
        "dest_ip": dst_ip,
        "process_name": proc_name,
        "message": raw_str
    }

# Singleton syslog collector instance
syslog_collector_instance = SyslogCollector()

