from sqlalchemy.orm import Session
from datetime import datetime
from app.models.audit import AuditLog

class AuditService:
    @staticmethod
    def log(
        db: Session,
        user: str,
        action: str,
        resource_type: str,
        resource_id: str,
        result: str = "SUCCESS",
        details: str = None
    ) -> AuditLog:
        entry = AuditLog(
            timestamp=datetime.utcnow(),
            user=user or "SOC Analyst",
            action=action,
            resource_type=resource_type,
            resource_id=str(resource_id),
            result=result,
            details=details
        )
        db.add(entry)
        db.commit()
        return entry
