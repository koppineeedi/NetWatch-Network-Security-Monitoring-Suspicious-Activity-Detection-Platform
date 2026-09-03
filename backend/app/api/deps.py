from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from typing import List, Callable
from app.database.connection import get_db
from app.models.user import User
from app.core.security import decode_access_token
from app.services.audit_service import AuditService

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)

def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> User:
    """
    Validates JWT access token and returns current active User.
    Raises HTTP 401 if unauthenticated, expired, or user is disabled.
    """
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication claims",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = db.query(User).filter(User.id == int(user_id)).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is disabled",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user

def require_role(*allowed_roles: str):
    """
    Returns a dependency enforcing that current user has one of the allowed roles.
    Logs UNAUTHORIZED_ACCESS_ATTEMPT in AuditLog and raises HTTP 403 Forbidden if not authorized.
    """
    def role_checker(
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
    ) -> User:
        if current_user.role not in allowed_roles:
            AuditService.log(
                db=db,
                user=current_user.username,
                action="UNAUTHORIZED_ACCESS_ATTEMPT",
                resource_type="ROLE_CHECK",
                resource_id=current_user.role,
                result="DENIED",
                details=f"User '{current_user.username}' with role '{current_user.role}' attempted action requiring roles: {list(allowed_roles)}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden: Action requires one of roles {list(allowed_roles)}"
            )
        return current_user

    return role_checker
