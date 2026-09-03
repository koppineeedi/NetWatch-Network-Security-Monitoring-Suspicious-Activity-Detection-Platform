import os
import uuid
import datetime
from typing import Dict, Any, Tuple
from fastapi import UploadFile, HTTPException
from sqlalchemy.orm import Session

from app.parsers.json_parser import parse_json_logs
from app.parsers.csv_parser import parse_csv_logs
from app.parsers.generic_parser import parse_log_text
from app.models.event import NetworkEvent
from app.models.log_ingestion import LogIngestion
from app.detection.engine import evaluate_event

ALLOWED_EXTENSIONS = {".log", ".txt", ".json", ".csv"}

def process_log_file_upload(file: UploadFile, db: Session) -> Dict[str, Any]:
    """
    Validates, saves, parses, deduplicates, and ingests user-uploaded log files securely.
    """
    max_mb = int(os.getenv("NETWATCH_MAX_UPLOAD_MB", "25"))
    max_bytes = max_mb * 1024 * 1024

    # 1. Extension Validation
    filename = os.path.basename(file.filename or "upload.log")
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file format '{ext}'. Allowed extensions: .log, .txt, .json, .csv"
        )

    # 2. Read File Contents & Size Check
    contents = file.file.read()
    file_size = len(contents)

    if file_size == 0:
        raise HTTPException(status_code=400, detail="Uploaded log file is empty.")

    if file_size > max_bytes:
        raise HTTPException(
            status_code=400,
            detail=f"File size ({file_size / (1024*1024):.2f}MB) exceeds configured maximum limit of {max_mb}MB."
        )

    # 3. Secure File Saving under data/raw/
    raw_dir = os.path.join(os.getcwd(), "data", "raw")
    os.makedirs(raw_dir, exist_ok=True)
    ingestion_uuid = str(uuid.uuid4())
    safe_disk_filename = f"{ingestion_uuid}{ext}"
    safe_filepath = os.path.join(raw_dir, safe_disk_filename)

    with open(safe_filepath, "wb") as f:
        f.write(contents)

    # 4. Parser Selection
    text_content = contents.decode("utf-8", errors="replace")

    if ext == ".json":
        raw_records, rejected_count = parse_json_logs(text_content)
    elif ext == ".csv":
        raw_records, rejected_count = parse_csv_logs(text_content)
    else:
        raw_records, rejected_count = parse_log_text(text_content)

    total_received = len(raw_records) + rejected_count
    records_stored = 0
    records_duplicate = 0

    # 5. DB Ingestion & Deduplication Loop
    existing_events = db.query(NetworkEvent).all()
    existing_fingerprints = set(
        (e.source_ip, e.source_port, e.dest_ip, e.dest_port, e.protocol, e.timestamp.strftime("%Y-%m-%dT%H:%M:%S") if e.timestamp else None)
        for e in existing_events
    )

    new_events = []
    for r in raw_records:
        ts_val = r.get("timestamp")
        parsed_ts = None
        if ts_val:
            try:
                dt_obj = datetime.datetime.fromisoformat(str(ts_val).replace("Z", "+00:00"))
                parsed_ts = dt_obj.replace(tzinfo=None)
            except Exception:
                parsed_ts = datetime.datetime.utcnow()
        else:
            parsed_ts = datetime.datetime.utcnow()

        ts_str = parsed_ts.strftime("%Y-%m-%dT%H:%M:%S")
        fp = (r["source_ip"], r["source_port"], r["dest_ip"], r["dest_port"], r["protocol"], ts_str)

        if fp in existing_fingerprints:
            records_duplicate += 1
        else:
            existing_fingerprints.add(fp)
            source_tag = r.get("source") or ("TEST_LOG" if "TEST" in filename.upper() else "LOG_FILE")

            evt = NetworkEvent(
                timestamp=parsed_ts,
                source=source_tag,
                collector="FILE_LOG_COLLECTOR",
                event_type="LOG_EVENT",
                source_ip=r["source_ip"],
                source_port=r["source_port"],
                dest_ip=r["dest_ip"],
                dest_port=r["dest_port"],
                protocol=r["protocol"],
                connection_state=r.get("connection_state", "ESTABLISHED"),
                status="NORMAL",
                risk_score=0.0,
                process_name=r.get("process_name"),
                hostname=r.get("hostname"),
                bytes_sent=r.get("bytes_sent", 0),
                bytes_received=r.get("bytes_received", 0),
                payload_summary=r.get("payload_summary")
            )
            new_events.append(evt)

    # Persist & trigger detection engine
    if new_events:
        db.add_all(new_events)
        db.commit()
        records_stored = len(new_events)

        for evt in new_events:
            evaluate_event(db, evt)

    # 6. Record Log Ingestion History
    ingestion_id = f"ING-{datetime.datetime.utcnow().strftime('%Y%m%d')}-{ingestion_uuid[:6].upper()}"
    status_str = "SUCCESS" if rejected_count == 0 else "PARTIAL_SUCCESS"

    history_entry = LogIngestion(
        ingestion_id=ingestion_id,
        filename=filename,
        file_type=ext,
        file_size_bytes=file_size,
        source="TEST_LOG" if "TEST" in filename.upper() else "LOG_FILE",
        timestamp=datetime.datetime.utcnow(),
        status=status_str,
        records_received=total_received,
        records_stored=records_stored,
        records_rejected=rejected_count,
        records_duplicate=records_duplicate
    )
    db.add(history_entry)
    db.commit()

    return {
        "ingestion_id": ingestion_id,
        "filename": filename,
        "file_type": ext,
        "file_size_bytes": file_size,
        "status": status_str,
        "records_received": total_received,
        "records_stored": records_stored,
        "records_rejected": rejected_count,
        "records_duplicate": records_duplicate
    }
