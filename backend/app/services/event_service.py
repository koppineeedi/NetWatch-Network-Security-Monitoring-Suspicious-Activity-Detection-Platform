from sqlalchemy.orm import Session
from app.models.event import NetworkEvent
from typing import Optional, List

class EventService:
    @staticmethod
    def get_events(db: Session, limit: int = 50, offset: int = 0) -> List[NetworkEvent]:
        return db.query(NetworkEvent).order_by(NetworkEvent.timestamp.desc()).offset(offset).limit(limit).all()

    @staticmethod
    def get_event_by_id(db: Session, event_id: int) -> Optional[NetworkEvent]:
        return db.query(NetworkEvent).filter(NetworkEvent.id == event_id).first()
