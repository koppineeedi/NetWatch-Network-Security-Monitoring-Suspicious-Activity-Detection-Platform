import re
from typing import List, Dict, Any, Tuple

def parse_log_text(text: str) -> Tuple[List[Dict[str, Any]], int]:
    """
    Parses generic raw text log lines (Syslog, Zeek, Key-Value pairs).
    Returns (valid_records, rejected_count).
    """
    valid_records = []
    rejected_count = 0
    lines = text.strip().splitlines()

    ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'

    for line in lines:
        line_str = line.strip()
        if not line_str or line_str.startswith("#"):
            continue

        ips = re.findall(ip_pattern, line_str)
        if not ips:
            rejected_count += 1
            continue

        src_ip = ips[0]
        dst_ip = ips[1] if len(ips) > 1 else None

        # Extract port numbers safely
        ports = re.findall(r'\b\d{2,5}\b', line_str)
        src_port = int(ports[0]) if len(ports) > 0 and int(ports[0]) <= 65535 else None
        dst_port = int(ports[1]) if len(ports) > 1 and int(ports[1]) <= 65535 else None

        protocol = "TCP"
        if "UDP" in line_str.upper():
            protocol = "UDP"
        elif "ICMP" in line_str.upper():
            protocol = "ICMP"
        elif "HTTP" in line_str.upper():
            protocol = "HTTP"
        elif "DNS" in line_str.upper():
            protocol = "DNS"

        bytes_val = 0
        bytes_match = re.search(r'bytes=(\d+)|(\d+)\s*bytes', line_str, re.IGNORECASE)
        if bytes_match:
            bytes_val = int(bytes_match.group(1) or bytes_match.group(2))

        valid_records.append({
            "timestamp": None,  # Ingestion time fallback handled at normalizer layer
            "source": "LOG_FILE",
            "source_ip": src_ip,
            "source_port": src_port,
            "dest_ip": dst_ip,
            "dest_port": dst_port,
            "protocol": protocol,
            "connection_state": "ESTABLISHED",
            "process_name": None,
            "hostname": None,
            "bytes_sent": 0,
            "bytes_received": bytes_val,
            "payload_summary": line_str[:200]
        })

    return (valid_records, rejected_count)
