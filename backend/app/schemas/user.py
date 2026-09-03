from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime

class UserBase(BaseModel):
    username: str
    email: str
    role: str = "ANALYST"
    is_active: bool = True

class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    role: Optional[str] = "ANALYST"

class UserUpdate(BaseModel):
    email: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None

class RoleUpdate(BaseModel):
    role: str

class StatusUpdate(BaseModel):
    is_active: bool

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    role: str
    is_active: bool
    created_at: datetime
    last_login_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class LoginRequest(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str
