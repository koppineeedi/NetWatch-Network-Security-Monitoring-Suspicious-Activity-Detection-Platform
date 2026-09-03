from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from app.database.connection import get_db
from app.services.event_service import EventService
from app.api.deps import get_current_user
from app.models.user import User

router = APIRouter(prefix="/api/events", tags=["events"])

@router.get("")
def get_events(
    search: Optional[str] = None,
    protocol: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns normalized network events. Requires authentication.
    """
    events = EventService.get_events(
        db=db,
        search=search,
        protocol=protocol,
        status=status,
        limit=limit,
        offset=offset
    )
    return [
        {
            "id": e.id,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            "source": e.source,
            "collector": e.collector,
            "source_ip": e.source_ip,
            "source_port": e.source_port,
            "dest_ip": e.dest_ip,
            "dest_port": e.dest_port,
            "protocol": e.protocol,
            "connection_state": e.connection_state,
            "status": e.status,
            "risk_score": e.risk_score,
            "process_name": e.process_name,
            "hostname": e.hostname,
            "bytes_sent": e.bytes_sent,
            "bytes_received": e.bytes_received,
            "payload_summary": e.payload_summary
        }
        for e in events
    ]
