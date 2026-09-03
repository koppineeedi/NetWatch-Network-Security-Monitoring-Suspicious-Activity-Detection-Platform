from sqlalchemy.orm import Session
from app.models.detection import Detection
from typing import List

class DetectionService:
    @staticmethod
    def get_detections(db: Session) -> List[Detection]:
        return db.query(Detection).order_by(Detection.timestamp.desc()).all()
