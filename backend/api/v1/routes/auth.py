"""CTI Platform — Authentication API Routes

Endpoints:
    POST /auth/login    — Authenticate and receive JWT tokens
    POST /auth/register — Create a new user account
    POST /auth/refresh  — Exchange refresh token for new access token
    GET  /auth/me       — Retrieve current authenticated user
"""

import logging
from datetime import timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlmodel import Session, select

from backend.api.v1.dependencies import get_current_active_user, get_db_session_dep
from backend.core.config import settings
from backend.models import User
from backend.schemas import LoginRequest, Token, UserCreate, UserResponse
from backend.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    get_password_hash,
    verify_password,
)

logger = logging.getLogger("cti_platform.api.auth")
router = APIRouter(prefix="/auth", tags=["Authentication"])


# ---------------------------------------------------------------------------
# Register
# ---------------------------------------------------------------------------
@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(
    user_in: UserCreate,
    session: Session = Depends(get_db_session_dep),
) -> UserResponse:
    """Register a new user account."""
    stmt = select(User).where(
        (User.username == user_in.username) | (User.email == user_in.email)
    )
    existing: Optional[User] = session.exec(stmt).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email already registered",
        )

    db_user = User(
        username=user_in.username,
        email=user_in.email,
        full_name=user_in.full_name,
        hashed_password=get_password_hash(user_in.password),
        role=user_in.role,
        is_active=True,
        is_superuser=False,
    )
    session.add(db_user)
    session.commit()
    session.refresh(db_user)

    logger.info("User registered | user_id=%s username=%s", db_user.id, db_user.username)
    return UserResponse.model_validate(db_user)


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------
@router.post("/login", response_model=Token)
async def login(
    form_data: LoginRequest,
    session: Session = Depends(get_db_session_dep),
) -> dict:
    """Authenticate with username/password and receive access + refresh tokens."""
    statement = select(User).where(User.username == form_data.username)
    user: Optional[User] = session.exec(statement).first()

    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled",
        )

    token_data = {"sub": user.id}
    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)

    logger.info("User login | user_id=%s username=%s", user.id, user.username)
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    }


# ---------------------------------------------------------------------------
# Refresh Token
# ---------------------------------------------------------------------------
class _RefreshRequest(BaseModel):
    refresh_token: str


@router.post("/refresh", response_model=Token)
async def refresh_token(body: _RefreshRequest) -> dict:
    """Exchange a valid refresh token for a new access/refresh token pair."""
    payload = decode_token(body.refresh_token)
    if payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type",
            headers={"WWW-Authenticate": "Bearer"},
        )

    _sub = payload.get("sub")
    try:
        user_id: Optional[int] = int(_sub) if _sub is not None else None
    except (ValueError, TypeError):
        user_id = None
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
            headers={"WWW-Authenticate": "Bearer"},
        )

    from backend.database import get_db_context
    from sqlmodel import select
    with get_db_context() as session:
        row = session.exec(select(User.id, User.is_active).where(User.id == user_id)).first()

    if row is None or not row.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token_data = {"sub": user_id}
    access_token = create_access_token(token_data)
    new_refresh = create_refresh_token(token_data)

    logger.info("Token refresh | user_id=%s", user_id)
    return {
        "access_token": access_token,
        "refresh_token": new_refresh,
        "token_type": "bearer",
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    }


# ---------------------------------------------------------------------------
# Current User
# ---------------------------------------------------------------------------
@router.get("/me", response_model=UserResponse)
async def read_users_me(
    current_user: User = Depends(get_current_active_user),
) -> UserResponse:
    """Return the currently authenticated user's profile."""
    # Explicitly convert while session is still open to avoid DetachedInstanceError
    return UserResponse.model_validate(current_user)
