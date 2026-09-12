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

def publish_anomaly(anomaly):
    """
    Publishes newly detected behavioral Anomaly record to connected WebSocket clients.
    """
    if not ws_manager.active_connections:
        return

    payload = {
        "type": "anomaly_detected",
        "timestamp": anomaly.timestamp.isoformat() if hasattr(anomaly, 'timestamp') and anomaly.timestamp else datetime.utcnow().isoformat(),
        "data": {
            "id": anomaly.id,
            "entity_id": getattr(anomaly, "entity_id", ""),
            "entity_type": getattr(anomaly, "entity_type", "IP"),
            "feature": getattr(anomaly, "feature", ""),
            "observed_value": getattr(anomaly, "observed_value", 0.0),
            "baseline_value": getattr(anomaly, "baseline_value", 0.0),
            "anomaly_score": getattr(anomaly, "anomaly_score", 0.0),
            "severity": getattr(anomaly, "severity", "MEDIUM"),
            "explanation": getattr(anomaly, "explanation", ""),
            "mitre_technique": getattr(anomaly, "mitre_technique", None)
        }
    }
    _run_async(ws_manager.broadcast(payload))

def publish_entity_risk(entity):
    """
    Publishes updated Entity risk score to connected WebSocket clients.
    """
    if not ws_manager.active_connections:
        return

    payload = {
        "type": "entity_risk_updated",
        "timestamp": datetime.utcnow().isoformat(),
        "data": {
            "id": entity.id,
            "entity_id": getattr(entity, "entity_id", ""),
            "entity_type": getattr(entity, "entity_type", "IP"),
            "current_risk_score": getattr(entity, "current_risk_score", 0.0),
            "baseline_status": getattr(entity, "baseline_status", "INSUFFICIENT_DATA"),
            "anomaly_count": getattr(entity, "anomaly_count", 0),
            "high_risk_count": getattr(entity, "high_risk_count", 0)
        }
    }
    _run_async(ws_manager.broadcast(payload))

def publish_campaign_update(campaign):
    """
    Publishes updated Campaign record to connected WebSocket clients.
    """
    if not ws_manager.active_connections:
        return

    payload = {
        "type": "campaign_updated",
        "timestamp": datetime.utcnow().isoformat(),
        "data": {
            "id": campaign.id,
            "campaign_id": getattr(campaign, "campaign_id", ""),
            "name": getattr(campaign, "name", ""),
            "status": getattr(campaign, "status", "ACTIVE"),
            "risk_score": getattr(campaign, "risk_score", 0.0),
            "event_count": getattr(campaign, "event_count", 0),
            "entity_count": getattr(campaign, "entity_count", 0)
        }
    }
    _run_async(ws_manager.broadcast(payload))

def publish_sigma_match(rule_id: str, rule_title: str, severity: str, event_id: int):
    """Publishes live SIGMA_RULE_MATCHED event to connected WebSocket clients."""
    if not ws_manager.active_connections:
        return
    payload = {
        "type": "SIGMA_RULE_MATCHED",
        "timestamp": datetime.utcnow().isoformat(),
        "rule_id": rule_id,
        "rule_title": rule_title,
        "severity": severity,
        "event_id": event_id
    }
    _run_async(ws_manager.broadcast(payload))

def publish_sigma_rule_update(rule):
    """Publishes SIGMA_RULE_UPDATED event to connected WebSocket clients."""
    if not ws_manager.active_connections:
        return
    payload = {
        "type": "SIGMA_RULE_UPDATED",
        "timestamp": datetime.utcnow().isoformat(),
        "data": {
            "rule_id": getattr(rule, "rule_id", ""),
            "title": getattr(rule, "title", ""),
            "version": getattr(rule, "version", 1),
            "enabled": getattr(rule, "enabled", False)
        }
    }
    _run_async(ws_manager.broadcast(payload))

def publish_sigma_rule_enabled(rule):
    """Publishes SIGMA_RULE_ENABLED event to connected WebSocket clients."""
    if not ws_manager.active_connections:
        return
    payload = {
        "type": "SIGMA_RULE_ENABLED",
        "timestamp": datetime.utcnow().isoformat(),
        "data": {"rule_id": getattr(rule, "rule_id", ""), "title": getattr(rule, "title", "")}
    }
    _run_async(ws_manager.broadcast(payload))

def publish_sigma_rule_disabled(rule):
    """Publishes SIGMA_RULE_DISABLED event to connected WebSocket clients."""
    if not ws_manager.active_connections:
        return
    payload = {
        "type": "SIGMA_RULE_DISABLED",
        "timestamp": datetime.utcnow().isoformat(),
        "data": {"rule_id": getattr(rule, "rule_id", ""), "title": getattr(rule, "title", "")}
    }
    _run_async(ws_manager.broadcast(payload))

def publish_sigma_sandbox_completed(result: Dict[str, Any]):
    """Publishes SIGMA_SANDBOX_COMPLETED event to connected WebSocket clients."""
    if not ws_manager.active_connections:
        return
    payload = {
        "type": "SIGMA_SANDBOX_COMPLETED",
        "timestamp": datetime.utcnow().isoformat(),
        "data": result
    }
    _run_async(ws_manager.broadcast(payload))

def publish_soar_event(event_type: str, data: Dict[str, Any]):
    """
    Publishes real-time SOAR events (PLAYBOOK_STARTED, ACTION_COMPLETED, ACTION_APPROVAL_REQUIRED, etc.)
    to connected WebSocket clients.
    """
    if not ws_manager.active_connections:
        return
    payload = {
        "type": event_type,
        "timestamp": datetime.utcnow().isoformat(),
        "data": data
    }
    _run_async(ws_manager.broadcast(payload))


