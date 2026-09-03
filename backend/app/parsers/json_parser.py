import json
from typing import List, Dict, Any, Tuple

def parse_json_logs(text: str) -> Tuple[List[Dict[str, Any]], int]:
    """
    Parses JSON array, object, or JSON-lines raw log input.
    Returns (valid_records, rejected_count).
    """
    valid_records = []
    rejected_count = 0
    text_stripped = text.strip()

    if not text_stripped:
        return ([], 0)

    # Try full JSON array or object parsing
    if text_stripped.startswith("[") or text_stripped.startswith("{"):
        try:
            data = json.loads(text_stripped)
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        valid_records.append(_normalize_json_record(item))
                    else:
                        rejected_count += 1
                return (valid_records, rejected_count)
            elif isinstance(data, dict):
                return ([_normalize_json_record(data)], 0)
        except Exception:
            pass  # Fallback to line-by-line NDJSON parsing

    # Line-by-line JSON parsing
    for line in text_stripped.splitlines():
        line_str = line.strip()
        if not line_str:
            continue
        try:
            item = json.loads(line_str)
            if isinstance(item, dict):
                valid_records.append(_normalize_json_record(item))
            else:
                rejected_count += 1
        except Exception:
            rejected_count += 1

    return (valid_records, rejected_count)

def _normalize_json_record(d: Dict[str, Any]) -> Dict[str, Any]:
    source_val = d.get("source") or "LOG_FILE"
    return {
        "timestamp": d.get("timestamp") or d.get("time"),
        "source": source_val,
        "source_ip": d.get("source_ip") or d.get("src_ip") or d.get("src") or d.get("local_ip"),
        "source_port": int(d.get("source_port") or d.get("src_port") or d.get("local_port")) if (d.get("source_port") or d.get("src_port") or d.get("local_port")) else None,
        "dest_ip": d.get("dest_ip") or d.get("dst_ip") or d.get("dst") or d.get("remote_ip"),
        "dest_port": int(d.get("dest_port") or d.get("dst_port") or d.get("port") or d.get("remote_port")) if (d.get("dest_port") or d.get("dst_port") or d.get("port") or d.get("remote_port")) else None,
        "protocol": str(d.get("protocol") or d.get("proto") or "TCP").upper(),
        "connection_state": d.get("connection_state") or d.get("state") or d.get("status") or "ESTABLISHED",
        "process_name": d.get("process_name") or d.get("process") or d.get("proc"),
        "hostname": d.get("hostname") or d.get("host"),
        "bytes_sent": int(d.get("bytes_sent") or 0),
        "bytes_received": int(d.get("bytes_received") or d.get("bytes") or 0),
        "payload_summary": d.get("payload_summary") or d.get("message")
    }
