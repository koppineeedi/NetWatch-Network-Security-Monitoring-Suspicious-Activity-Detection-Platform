from datetime import datetime
from app.parsers.generic_parser import parse_log_text
from app.parsers.json_parser import parse_json_logs
from app.parsers.csv_parser import parse_csv_logs
from app.models.event import NetworkEvent
from app.realtime.publisher import publish_network_event
from app.detection.engine import evaluate_event

def parse_and_store_log_file(db, filepath: str, ext: str, ingestion_record):
    """
    Parses an uploaded log file according to extension (.json, .csv, .log/.txt),
    stores extracted NetworkEvent records in SQLite database, publishes them via WebSocket,
    and runs detection evaluation.
    """
    ext = ext.lower()
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    if ext == ".json":
        records, rejected = parse_json_logs(content)
    elif ext == ".csv":
        records, rejected = parse_csv_logs(content)
    else:
        records, rejected = parse_log_text(content)

    ingestion_record.records_received = len(records) + rejected
    ingestion_record.records_rejected = rejected

    stored_events = []
    for r in records:
        evt = NetworkEvent(
            timestamp=r.get("timestamp") or datetime.utcnow(),
            source=r.get("source") or "LOG_FILE",
            collector="LOG_INGESTION",
            event_type="INGESTED_EVENT",
            source_ip=r.get("source_ip"),
            source_port=r.get("source_port"),
            dest_ip=r.get("dest_ip"),
            dest_port=r.get("dest_port"),
            protocol=r.get("protocol") or "TCP",
            connection_state=r.get("connection_state") or "ESTABLISHED",
            status="NORMAL",
            risk_score=0.0,
            process_name=r.get("process_name"),
            hostname=r.get("hostname"),
            bytes_sent=r.get("bytes_sent") or 0,
            bytes_received=r.get("bytes_received") or 0,
            payload_summary=r.get("payload_summary")
        )
        db.add(evt)
        stored_events.append(evt)

    db.commit()
    ingestion_record.records_stored = len(stored_events)
    ingestion_record.status = "SUCCESS"
    db.commit()

    # Real-time WebSocket publishing and detection evaluation
    for evt in stored_events:
        db.refresh(evt)
        publish_network_event(evt)
        evaluate_event(db, evt)

    return len(stored_events)

__all__ = ["parse_log_text", "parse_json_logs", "parse_csv_logs", "parse_and_store_log_file"]
