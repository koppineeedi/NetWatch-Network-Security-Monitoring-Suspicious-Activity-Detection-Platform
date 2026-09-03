from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from datetime import datetime
from app.database.connection import get_db
from app.models.user import User
from app.core.security import verify_password, hash_password, create_access_token
from app.schemas.user import LoginRequest, TokenResponse, UserResponse, ChangePasswordRequest
from app.services.audit_service import AuditService
from app.api.deps import get_current_user

router = APIRouter(prefix="/api/auth", tags=["auth"])

@router.post("/login", response_model=TokenResponse)
def login(req: LoginRequest, db: Session = Depends(get_db)):
    """
    Authenticates user by username or email and password.
    Updates last_login_at, logs LOGIN_SUCCESS or LOGIN_FAILURE in AuditLog.
    Returns signed JWT access token and safe user details.
    """
    identifier = (req.username or req.email or "").strip()
    if not identifier or not req.password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username/email or password"
        )

    # Search user by username or email
    user = db.query(User).filter(
        (User.username == identifier) | (User.email == identifier)
    ).first()

    if not user or not verify_password(req.password, user.password_hash):
        AuditService.log(
            db=db,
            user=identifier,
            action="LOGIN_FAILURE",
            resource_type="USER",
            resource_id=str(user.id) if user else "UNKNOWN",
            result="FAILURE",
            details=f"Failed login attempt for identifier: {identifier}"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username/email or password"
        )

    if not user.is_active:
        AuditService.log(
            db=db,
            user=user.username,
            action="LOGIN_FAILURE",
            resource_type="USER",
            resource_id=str(user.id),
            result="FAILURE",
            details="Attempted login on disabled account"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is disabled"
        )

    user.last_login_at = datetime.utcnow()
    db.commit()

    token = create_access_token(data={"sub": str(user.id), "username": user.username, "role": user.role})

    AuditService.log(
        db=db,
        user=user.username,
        action="LOGIN_SUCCESS",
        resource_type="USER",
        resource_id=str(user.id),
        result="SUCCESS",
        details=f"User '{user.username}' logged in successfully with role '{user.role}'"
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": user
    }

@router.post("/logout")
def logout(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Logs user logout event. Frontend clears local token state.
    """
    AuditService.log(
        db=db,
        user=current_user.username,
        action="LOGOUT",
        resource_type="USER",
        resource_id=str(current_user.id),
        result="SUCCESS",
        details=f"User '{current_user.username}' logged out"
    )
    return {"message": "Logged out successfully"}

@router.get("/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)):
    """
    Returns current authenticated user details. Never returns password_hash!
    """
    return current_user

@router.post("/change-password")
def change_password(
    req: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Changes current user password after verifying current password.
    Logs PASSWORD_CHANGED without revealing passwords.
    """
    if not verify_password(req.current_password, current_user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password incorrect"
        )

    if len(req.new_password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be at least 8 characters long"
        )

    current_user.password_hash = hash_password(req.new_password)
    current_user.updated_at = datetime.utcnow()
    db.commit()

    AuditService.log(
        db=db,
        user=current_user.username,
        action="PASSWORD_CHANGED",
        resource_type="USER",
        resource_id=str(current_user.id),
        result="SUCCESS",
        details=f"User '{current_user.username}' changed password successfully"
    )

    return {"message": "Password changed successfully"}
