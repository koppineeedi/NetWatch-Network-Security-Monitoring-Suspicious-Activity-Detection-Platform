import csv
from io import StringIO
from typing import List, Dict, Any, Tuple

def parse_csv_logs(text: str) -> Tuple[List[Dict[str, Any]], int]:
    """
    Parses CSV log input using header dictionary mapping.
    Returns (valid_records, rejected_count).
    """
    valid_records = []
    rejected_count = 0

    if not text.strip():
        return ([], 0)

    try:
        reader = csv.DictReader(StringIO(text))
        for row in reader:
            src_ip = row.get("source_ip") or row.get("src_ip") or row.get("src")
            dst_ip = row.get("dest_ip") or row.get("dst_ip") or row.get("dst")

            if not src_ip and not dst_ip:
                rejected_count += 1
                continue

            src_port = int(row.get("source_port") or row.get("src_port")) if (row.get("source_port") or row.get("src_port")) else None
            dst_port = int(row.get("dest_port") or row.get("dst_port") or row.get("port")) if (row.get("dest_port") or row.get("dst_port") or row.get("port")) else None

            source_val = row.get("source") or "LOG_FILE"

            valid_records.append({
                "timestamp": row.get("timestamp") or row.get("time"),
                "source": source_val,
                "source_ip": src_ip,
                "source_port": src_port,
                "dest_ip": dst_ip,
                "dest_port": dst_port,
                "protocol": (row.get("protocol") or row.get("proto") or "TCP").upper(),
                "connection_state": row.get("connection_state") or row.get("status") or "ESTABLISHED",
                "process_name": row.get("process_name") or row.get("process"),
                "hostname": row.get("hostname") or row.get("host"),
                "bytes_sent": int(row.get("bytes_sent") or 0),
                "bytes_received": int(row.get("bytes_received") or row.get("bytes") or 0),
                "payload_summary": row.get("payload_summary") or row.get("message")
            })
    except Exception:
        rejected_count += len(text.splitlines())

    return (valid_records, rejected_count)
