import os
import uuid
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.orm import Session
from app.database.connection import get_db
from app.models.log_ingestion import LogIngestion
from app.parsers import parse_and_store_log_file
from app.api.deps import get_current_user, require_role
from app.models.user import User

router = APIRouter(prefix="/api/logs", tags=["logs"])

RAW_DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "data", "raw"))
MAX_UPLOAD_MB = int(os.getenv("NETWATCH_MAX_UPLOAD_MB", "25"))
ALLOWED_EXTENSIONS = {".log", ".txt", ".json", ".csv"}

@router.get("")
def get_log_history(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns history of ingested log files. Requires authentication.
    """
    logs = db.query(LogIngestion).order_by(LogIngestion.timestamp.desc()).all()
    return [
        {
            "id": l.id,
            "ingestion_id": l.ingestion_id,
            "filename": l.filename,
            "file_type": l.file_type,
            "file_size_bytes": l.file_size_bytes,
            "source": l.source,
            "timestamp": l.timestamp.isoformat() if l.timestamp else None,
            "status": l.status,
            "records_received": l.records_received,
            "records_stored": l.records_stored,
            "records_rejected": l.records_rejected,
            "records_duplicate": l.records_duplicate
        }
        for l in logs
    ]

@router.post("/upload")
async def upload_log_file(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("ADMIN", "ANALYST"))
):
    """
    Uploads and parses an authorized log file. ADMIN and ANALYST only.
    """
    safe_filename = os.path.basename(file.filename)
    ext = os.path.splitext(safe_filename)[1].lower()

    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file format '{ext}'. Allowed formats: {', '.join(ALLOWED_EXTENSIONS)}"
        )

    content = await file.read()
    file_size = len(content)

    if file_size > MAX_UPLOAD_MB * 1024 * 1024:
        raise HTTPException(
            status_code=400,
            detail=f"File exceeds maximum upload size of {MAX_UPLOAD_MB}MB."
        )

    os.makedirs(RAW_DATA_DIR, exist_ok=True)
    ingest_uuid = str(uuid.uuid4())
    stored_path = os.path.join(RAW_DATA_DIR, f"{ingest_uuid}{ext}")

    with open(stored_path, "wb") as f:
        f.write(content)

    ingest_record = LogIngestion(
        ingestion_id=ingest_uuid,
        filename=safe_filename,
        file_type=ext[1:].upper(),
        file_size_bytes=file_size,
        source="LOG_FILE",
        timestamp=datetime.utcnow(),
        status="PROCESSING",
        records_received=0,
        records_stored=0,
        records_rejected=0,
        records_duplicate=0
    )
    db.add(ingest_record)
    db.commit()
    db.refresh(ingest_record)

    # Parse and extract NetworkEvent records
    parse_and_store_log_file(db, stored_path, ext, ingest_record)

    return {
        "id": ingest_record.id,
        "ingestion_id": ingest_record.ingestion_id,
        "filename": ingest_record.filename,
        "file_type": ingest_record.file_type,
        "file_size_bytes": ingest_record.file_size_bytes,
        "source": ingest_record.source,
        "timestamp": ingest_record.timestamp.isoformat(),
        "status": ingest_record.status,
        "records_received": ingest_record.records_received,
        "records_stored": ingest_record.records_stored,
        "records_rejected": ingest_record.records_rejected,
        "records_duplicate": ingest_record.records_duplicate
    }
