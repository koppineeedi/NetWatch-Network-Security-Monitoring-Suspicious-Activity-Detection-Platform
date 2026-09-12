import math
import datetime
from typing import List, Dict, Any, Optional
from app.models.event import NetworkEvent

def calculate_entity_features(events: List[NetworkEvent], entity_id: str, entity_type: str = "IP") -> Dict[str, Any]:
    """
    Deterministically computes feature vector for an entity from a window of real NetworkEvent objects.
    If event list is empty or insufficient, returns empty dict.
    """
    if not events:
        return {}

    total_events = len(events)
    dest_ips = set()
    dest_ports = []
    failed_count = 0
    dns_count = 0
    outbound_count = 0
    inbound_count = 0
    protocols = {}
    external_dest_ips = set()
    timestamps = []

    for evt in events:
        if evt.dest_ip:
            dest_ips.add(evt.dest_ip)
            # Check if external (not 127.x, 10.x, 192.168.x, 172.16.x)
            if not (evt.dest_ip.startswith("127.") or evt.dest_ip.startswith("10.") or 
                    evt.dest_ip.startswith("192.168.") or evt.dest_ip.startswith("172.16.") or evt.dest_ip == "localhost"):
                external_dest_ips.add(evt.dest_ip)

        if evt.dest_port:
            dest_ports.append(evt.dest_port)

        # Connection status / state
        status_str = (evt.connection_state or evt.status or "").upper()
        if "FAIL" in status_str or "REJ" in status_str or "RST" in status_str or "DENY" in status_str:
            failed_count += 1

        if evt.protocol == "DNS" or evt.dest_port == 53:
            dns_count += 1

        if evt.source_ip == entity_id:
            outbound_count += 1
        elif evt.dest_ip == entity_id:
            inbound_count += 1
        else:
            outbound_count += 1

        proto = (evt.protocol or "UNKNOWN").upper()
        protocols[proto] = protocols.get(proto, 0) + 1

        if evt.timestamp:
            timestamps.append(evt.timestamp)

    # Port Entropy calculation
    port_entropy = 0.0
    if dest_ports:
        port_counts = {}
        for p in dest_ports:
            port_counts[p] = port_counts.get(p, 0) + 1
        num_ports = len(dest_ports)
        for p, count in port_counts.items():
            prob = count / num_ports
            port_entropy -= prob * math.log2(prob)

    # Average connection interval calculation
    avg_interval = 0.0
    if len(timestamps) > 1:
        timestamps.sort()
        intervals = [(timestamps[i] - timestamps[i-1]).total_seconds() for i in range(1, len(timestamps))]
        avg_interval = sum(intervals) / len(intervals)

    # Connection rate (events per minute)
    time_span_minutes = 1.0
    if len(timestamps) > 1:
        time_span_seconds = (timestamps[-1] - timestamps[0]).total_seconds()
        time_span_minutes = max(1.0, time_span_seconds / 60.0)
    
    connection_rate = total_events / time_span_minutes

    return {
        "connection_count": float(total_events),
        "unique_destination_count": float(len(dest_ips)),
        "unique_port_count": float(len(set(dest_ports))),
        "failed_connection_count": float(failed_count),
        "dns_query_count": float(dns_count),
        "outbound_connection_count": float(outbound_count),
        "inbound_connection_count": float(inbound_count),
        "average_connection_interval": float(round(avg_interval, 2)),
        "destination_port_entropy": float(round(port_entropy, 3)),
        "connection_rate": float(round(connection_rate, 2)),
        "unique_external_destination_count": float(len(external_dest_ips))
    }

def calculate_entropy(items: List[Any]) -> float:
    """Calculates Shannon entropy of a list of items."""
    if not items:
        return 0.0
    counts = {}
    for item in items:
        counts[item] = counts.get(item, 0) + 1
    total = len(items)
    entropy = 0.0
    for count in counts.values():
        prob = count / total
        entropy -= prob * math.log2(prob)
    return round(entropy, 3)

def extract_entity_features(db: Any, entity_id: str, entity_type: str = "IP", window_hours: int = 1) -> Dict[str, float]:
    """Convenience helper querying DB events and extracting features."""
    cutoff = datetime.datetime.utcnow() - datetime.timedelta(hours=window_hours)
    events = db.query(NetworkEvent).filter(
        (NetworkEvent.source_ip == entity_id) | (NetworkEvent.dest_ip == entity_id),
        NetworkEvent.timestamp >= cutoff
    ).all()
    return calculate_entity_features(events, entity_id, entity_type)

