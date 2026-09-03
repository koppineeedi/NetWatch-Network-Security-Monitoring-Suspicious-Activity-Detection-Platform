from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime
from app.database.connection import get_db
from app.models.user import User
from app.core.security import hash_password
from app.schemas.user import UserCreate, UserUpdate, RoleUpdate, StatusUpdate, UserResponse
from app.services.audit_service import AuditService
from app.api.deps import require_role

router = APIRouter(prefix="/api/users", tags=["users"])

VALID_ROLES = ["ADMIN", "ANALYST", "VIEWER"]

def count_active_admins(db: Session) -> int:
    return db.query(User).filter(User.role == "ADMIN", User.is_active == True).count()

@router.get("", response_model=List[UserResponse])
def get_users(
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_role("ADMIN"))
):
    """
    Returns list of all registered system users. ADMIN only.
    """
    return db.query(User).order_by(User.created_at.desc()).all()

@router.get("/{user_id}", response_model=UserResponse)
def get_user_by_id(
    user_id: int,
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_role("ADMIN"))
):
    """
    Returns single user profile details. ADMIN only.
    """
    u = db.query(User).filter(User.id == user_id).first()
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    return u

@router.post("", response_model=UserResponse)
def create_user(
    req: UserCreate,
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_role("ADMIN"))
):
    """
    Creates a new user account with specified role. ADMIN only.
    """
    username = req.username.strip()
    email = req.email.strip().lower()
    role = (req.role or "ANALYST").upper()

    if role not in VALID_ROLES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid role '{role}'. Allowed roles: {VALID_ROLES}"
        )

    if len(req.password) < 8:
        raise HTTPException(
            status_code=400,
            detail="Password must be at least 8 characters long"
        )

    if db.query(User).filter(User.username == username).first():
        raise HTTPException(status_code=400, detail="Username already registered")

    if db.query(User).filter(User.email == email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    user = User(
        username=username,
        email=email,
        password_hash=hash_password(req.password),
        role=role,
        is_active=True,
        created_at=datetime.utcnow()
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    AuditService.log(
        db=db,
        user=admin_user.username,
        action="USER_CREATED",
        resource_type="USER",
        resource_id=str(user.id),
        result="SUCCESS",
        details=f"Created user '{username}' with role '{role}'"
    )

    return user

@router.patch("/{user_id}", response_model=UserResponse)
def update_user(
    user_id: int,
    req: UserUpdate,
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_role("ADMIN"))
):
    """
    Updates user details. ADMIN only.
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if req.email:
        email = req.email.strip().lower()
        existing = db.query(User).filter(User.email == email, User.id != user_id).first()
        if existing:
            raise HTTPException(status_code=400, detail="Email already in use")
        user.email = email

    if req.role and req.role.upper() != user.role:
        new_role = req.role.upper()
        if new_role not in VALID_ROLES:
            raise HTTPException(status_code=400, detail=f"Invalid role: {new_role}")
        if user.role == "ADMIN" and new_role != "ADMIN" and count_active_admins(db) <= 1:
            raise HTTPException(status_code=400, detail="Cannot demote the final active administrator account")
        user.role = new_role

    if req.is_active is not None and req.is_active != user.is_active:
        if user.role == "ADMIN" and not req.is_active and count_active_admins(db) <= 1:
            raise HTTPException(status_code=400, detail="Cannot disable the final active administrator account")
        user.is_active = req.is_active

    user.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(user)
    return user

@router.patch("/{user_id}/role", response_model=UserResponse)
def update_user_role(
    user_id: int,
    req: RoleUpdate,
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_role("ADMIN"))
):
    """
    Updates user role (ADMIN, ANALYST, VIEWER). Prevents demoting final active ADMIN.
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    new_role = req.role.upper()
    if new_role not in VALID_ROLES:
        raise HTTPException(status_code=400, detail=f"Invalid role '{new_role}'. Allowed: {VALID_ROLES}")

    if user.role == "ADMIN" and new_role != "ADMIN":
        if count_active_admins(db) <= 1:
            raise HTTPException(status_code=400, detail="Cannot demote the final active administrator account")

    old_role = user.role
    user.role = new_role
    user.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(user)

    AuditService.log(
        db=db,
        user=admin_user.username,
        action="USER_ROLE_CHANGED",
        resource_type="USER",
        resource_id=str(user.id),
        result="SUCCESS",
        details=f"Changed role of user '{user.username}' from {old_role} to {new_role}"
    )

    return user

@router.patch("/{user_id}/status", response_model=UserResponse)
def update_user_status(
    user_id: int,
    req: StatusUpdate,
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_role("ADMIN"))
):
    """
    Enables or disables user account. Prevents disabling final active ADMIN.
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.role == "ADMIN" and not req.is_active:
        if count_active_admins(db) <= 1:
            raise HTTPException(status_code=400, detail="Cannot disable the final active administrator account")

    user.is_active = req.is_active
    user.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(user)

    action = "USER_ENABLED" if req.is_active else "USER_DISABLED"
    AuditService.log(
        db=db,
        user=admin_user.username,
        action=action,
        resource_type="USER",
        resource_id=str(user.id),
        result="SUCCESS",
        details=f"{'Enabled' if req.is_active else 'Disabled'} user '{user.username}'"
    )

    return user
