from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from app.models.audit import AuditLog

SECRET_KEYS = {"password", "secret", "token", "api_key", "key", "authorization", "bearer"}

def sanitize_details(details: Any) -> Any:
    """
    Recursively redacts sensitive credential keys from log details.
    """
    if isinstance(details, dict):
        sanitized = {}
        for k, v in details.items():
            if k.lower() in SECRET_KEYS:
                sanitized[k] = "***REDACTED***"
            else:
                sanitized[k] = sanitize_details(v)
        return sanitized
    elif isinstance(details, list):
        return [sanitize_details(item) for item in details]
    return details

def log_soar_audit(
    db: Session,
    user: str,
    action: str,
    resource_id: str,
    details: Any = None,
    resource_type: str = "SOAR_ACTION"
):
    """
    Records a sanitized SOAR audit entry into the database.
    """
    clean_details = sanitize_details(details)
    detail_str = str(clean_details) if not isinstance(clean_details, str) else clean_details

    audit_entry = AuditLog(
        user=user,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=detail_str
    )
    db.add(audit_entry)
    db.commit()
