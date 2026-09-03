import asyncio
from datetime import datetime
from typing import Dict, Any, Optional
from app.realtime.manager import ws_manager

def _run_async(coro):
    """
    Safely executes an asynchronous coroutine from both sync background threads and async event loops.
    """
    try:
        loop = asyncio.get_running_loop()
        if loop.is_running():
            asyncio.create_task(coro)
        else:
            loop.run_until_complete(coro)
    except RuntimeError:
        # No running event loop in current thread
        asyncio.run(coro)

def publish_network_event(event):
    """
    Publishes newly persisted NetworkEvent record to connected WebSocket clients.
    """
    if not ws_manager.active_connections:
        return

    payload = {
        "type": "network_event",
        "timestamp": event.timestamp.isoformat() if hasattr(event, 'timestamp') and event.timestamp else datetime.utcnow().isoformat(),
        "data": {
            "id": event.id,
            "timestamp": event.timestamp.isoformat() if hasattr(event, 'timestamp') and event.timestamp else None,
            "source": getattr(event, "source", "LOCAL_NETWORK"),
            "collector": getattr(event, "collector", "SYSTEM"),
            "source_ip": getattr(event, "source_ip", "UNKNOWN"),
            "source_port": getattr(event, "source_port", 0),
            "dest_ip": getattr(event, "dest_ip", "UNKNOWN"),
            "dest_port": getattr(event, "dest_port", 0),
            "protocol": getattr(event, "protocol", "TCP"),
            "connection_state": getattr(event, "connection_state", "ESTABLISHED"),
            "status": getattr(event, "status", "NORMAL"),
            "risk_score": getattr(event, "risk_score", 0.0),
            "process_name": getattr(event, "process_name", None),
            "hostname": getattr(event, "hostname", None)
        }
    }
    _run_async(ws_manager.broadcast(payload))

def publish_detection(detection):
    """
    Publishes newly generated Detection record to connected WebSocket clients.
    """
    if not ws_manager.active_connections:
        return

    payload = {
        "type": "detection",
        "timestamp": detection.timestamp.isoformat() if hasattr(detection, 'timestamp') and detection.timestamp else datetime.utcnow().isoformat(),
        "data": {
            "id": detection.id,
            "timestamp": detection.timestamp.isoformat() if hasattr(detection, 'timestamp') and detection.timestamp else None,
            "rule_code": getattr(detection, "rule_code", ""),
            "rule_name": getattr(detection, "rule_name", ""),
            "source_ip": getattr(detection, "source_ip", None),
            "target_ip": getattr(detection, "target_ip", None),
            "mitre_tactic": getattr(detection, "mitre_tactic", None),
            "mitre_technique": getattr(detection, "mitre_technique", None),
            "action_taken": getattr(detection, "action_taken", "ALERTED"),
            "details": getattr(detection, "details", None),
            "risk_score": getattr(detection, "risk_score", 0.0)
        }
    }
    _run_async(ws_manager.broadcast(payload))

def publish_alert(alert):
    """
    Publishes newly generated Alert record to connected WebSocket clients.
    """
    if not ws_manager.active_connections:
        return

    payload = {
        "type": "alert",
        "timestamp": alert.timestamp.isoformat() if hasattr(alert, 'timestamp') and alert.timestamp else datetime.utcnow().isoformat(),
        "data": {
            "id": alert.id,
            "timestamp": alert.timestamp.isoformat() if hasattr(alert, 'timestamp') and alert.timestamp else None,
            "detection_id": getattr(alert, "detection_id", None),
            "detection_type": getattr(alert, "detection_type", "Security Alert"),
            "severity": getattr(alert, "severity", "MEDIUM"),
            "confidence": getattr(alert, "confidence", 0.85),
            "risk_score": getattr(alert, "risk_score", 0.0),
            "source_ip": getattr(alert, "source_ip", None),
            "dest_ip": getattr(alert, "dest_ip", None),
            "dest_port": getattr(alert, "dest_port", None),
            "protocol": getattr(alert, "protocol", None),
            "description": getattr(alert, "description", ""),
            "explanation": getattr(alert, "explanation", ""),
            "status": getattr(alert, "status", "NEW"),
            "assigned_analyst": getattr(alert, "assigned_analyst", "Unassigned"),
            "rule_id": getattr(alert, "rule_id", None)
        }
    }
    _run_async(ws_manager.broadcast(payload))

def publish_telemetry_status(status_dict: Dict[str, Any]):
    """
    Publishes telemetry collector status update to connected WebSocket clients.
    """
    if not ws_manager.active_connections:
        return

    payload = {
        "type": "telemetry_status",
        "timestamp": datetime.utcnow().isoformat(),
        "data": status_dict
    }
    _run_async(ws_manager.broadcast(payload))
