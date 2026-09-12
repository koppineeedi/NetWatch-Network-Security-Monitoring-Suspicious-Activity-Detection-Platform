import os
import uuid
import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Query
from sqlalchemy.orm import Session
from app.database.connection import get_db
from app.models.threat_intel import IOC, IOCMatch
from app.threat_intelligence.schemas import IOCCreate, IOCResponse, IOCMatchResponse
from app.threat_intelligence.services.ioc_matcher import ioc_matcher_service, normalize_ioc_value
from app.threat_intelligence.manager import threat_intel_manager
from app.api.deps import get_current_user, require_role
from app.models.user import User

router = APIRouter(prefix="/api/iocs", tags=["iocs"])
MAX_IOC_UPLOAD_MB = int(os.getenv("NETWATCH_MAX_IOC_UPLOAD_MB", "15"))

@router.get("", response_model=List[IOCResponse])
def get_iocs(
    search: Optional[str] = Query(None),
    ioc_type: Optional[str] = Query(None),
    source: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns paginated list of Indicators of Compromise (IOCs) with filtering.
    """
    query = db.query(IOC)
    if search:
        s = f"%{search.strip().lower()}%"
        query = query.filter((IOC.ioc_value.like(s)) | (IOC.normalized_value.like(s)) | (IOC.tags.like(s)))
    if ioc_type and ioc_type.upper() != "ALL":
        query = query.filter(IOC.ioc_type == ioc_type.upper())
    if source and source.upper() != "ALL":
        query = query.filter(IOC.source == source)
    if severity and severity.upper() != "ALL":
        query = query.filter(IOC.severity == severity.upper())

    iocs = query.order_by(IOC.id.desc()).offset(skip).limit(limit).all()
    return iocs

@router.post("", response_model=IOCResponse)
def create_ioc(
    payload: IOCCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("ADMIN", "ANALYST"))
):
    """
    Creates a new Indicator of Compromise (IOC) record. ADMIN and ANALYST only.
    """
    norm_val = normalize_ioc_value(payload.ioc_value, payload.ioc_type)
    existing = db.query(IOC).filter(IOC.normalized_value == norm_val, IOC.ioc_type == payload.ioc_type.upper()).first()
    if existing:
        raise HTTPException(status_code=400, detail=f"IOC '{payload.ioc_value}' already exists")

    now = datetime.datetime.utcnow()
    ioc = IOC(
        ioc_value=payload.ioc_value.strip(),
        normalized_value=norm_val,
        ioc_type=payload.ioc_type.upper(),
        source=payload.source,
        confidence=payload.confidence,
        severity=payload.severity.upper(),
        first_seen=now,
        last_seen=now,
        expiration=payload.expiration,
        tags=payload.tags,
        raw_metadata=payload.raw_metadata
    )
    db.add(ioc)
    db.commit()
    db.refresh(ioc)
    return ioc

@router.get("/match/{value}")
def match_ioc_value(
    value: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Looks up exact matches for a target string value against active IOC records.
    """
    matches = ioc_matcher_service.match_value(db, value)
    if matches:
        ioc = matches[0]
        return {
            "matched": True,
            "match": {
                "id": ioc.id,
                "ioc_value": ioc.ioc_value,
                "ioc_type": ioc.ioc_type,
                "provider": ioc.source,
                "confidence": ioc.confidence,
                "severity": ioc.severity,
                "tags": ioc.tags
            },
            "matches": [
                {
                    "id": m.id,
                    "ioc_value": m.ioc_value,
                    "ioc_type": m.ioc_type,
                    "confidence": m.confidence,
                    "severity": m.severity
                } for m in matches
            ]
        }
    return {
        "matched": False,
        "matches": []
    }

@router.get("/{id}", response_model=IOCResponse)
def get_ioc_by_id(
    id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    ioc = db.query(IOC).filter(IOC.id == id).first()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC record not found")
    return ioc

@router.delete("/{id}")
def delete_ioc(
    id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("ADMIN"))
):
    """
    Deletes an IOC record. ADMIN only.
    """
    ioc = db.query(IOC).filter(IOC.id == id).first()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC record not found")

    db.delete(ioc)
    db.commit()
    return {"status": "SUCCESS", "message": f"IOC record #{id} deleted successfully"}

@router.post("/import")
@router.post("/upload")
async def upload_ioc_feed(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("ADMIN", "ANALYST"))
):
    """
    Uploads and imports a Threat Intelligence IOC feed file (.txt, .json, .csv). ADMIN and ANALYST allowed.
    Path traversal protected and file size limited.
    """
    safe_filename = os.path.basename(file.filename)
    ext = os.path.splitext(safe_filename)[1].lower()

    if ext not in {".txt", ".json", ".csv", ".log"}:
        raise HTTPException(status_code=400, detail="Unsupported IOC feed format. Allowed: .txt, .json, .csv")

    content_bytes = await file.read()
    if len(content_bytes) > MAX_IOC_UPLOAD_MB * 1024 * 1024:
        raise HTTPException(status_code=400, detail=f"IOC feed file exceeds maximum size of {MAX_IOC_UPLOAD_MB}MB")

    content = content_bytes.decode("utf-8", errors="ignore")
    res = threat_intel_manager.import_ioc_feed_file(db, safe_filename, content, source_label=f"FILE_IMPORT:{safe_filename}")
    return res
