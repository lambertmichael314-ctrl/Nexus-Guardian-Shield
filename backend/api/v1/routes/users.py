"""CTI Platform — User Management Routes

Endpoints:
    POST   /users/           — Register a new user
    GET    /users/           — List users (paginated, admin only)
    GET    /users/{id}       — Retrieve a user by ID
    PUT    /users/{id}       — Update a user (self or admin)
    DELETE /users/{id}       — Deactivate a user (admin only)
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlmodel import Session, desc, func, select

from backend.api.v1.dependencies import (
    get_current_active_user,
    get_db_session_dep,
    require_role,
)
from backend.core.config import settings
from backend.models import User, UserRole
from backend.schemas import UserCreate, UserResponse, UserUpdate
from backend.security import get_password_hash

router = APIRouter(prefix="/users", tags=["Users"])


# ---------------------------------------------------------------------------
# CREATE (Register)
# ---------------------------------------------------------------------------
@router.post("/", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create_user(
    *,
    session: Session = Depends(get_db_session_dep),
    user: UserCreate,
    current_user: Optional[User] = Depends(get_current_active_user),
) -> UserResponse:
    """Register a new user.

    * Open registration: anyone can create an analyst account.
    * Privilege escalation protection: only admins may create admin accounts.
    * If ``role=admin`` is requested by a non-admin, it is silently downgraded
      to ``analyst``.
    """
    # 1. Uniqueness check
    statement = select(User).where(
        (User.username == user.username) | (User.email == user.email)
    )
    existing = session.exec(statement).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email already registered",
        )

    # 2. Anti-privilege-escalation: only admins may create admin/superuser
    requested_role = user.role
    is_admin_creator = current_user is not None and current_user.role == UserRole.ADMIN
    if requested_role == UserRole.ADMIN and not is_admin_creator:
        requested_role = UserRole.ANALYST  # silently downgrade

    db_user = User(
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        hashed_password=get_password_hash(user.password),
        role=requested_role,
        is_active=True,
        is_superuser=False,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    return UserResponse.model_validate(db_user)


# ---------------------------------------------------------------------------
# LIST (admin only)
# ---------------------------------------------------------------------------
@router.get("/", response_model=Dict[str, Any])
def list_users(
    *,
    session: Session = Depends(get_db_session_dep),
    limit: int = Query(default=20, ge=1, le=settings.MAX_PAGE_SIZE),
    offset: int = Query(default=0, ge=0),
    role: Optional[UserRole] = Query(None),
    is_active: Optional[bool] = Query(None),
    current_user: User = Depends(require_role(UserRole.ADMIN)),
) -> Dict[str, Any]:
    """List all users with pagination.  Admin-only."""
    stmt = select(User)
    if role:
        stmt = stmt.where(User.role == role)
    if is_active is not None:
        stmt = stmt.where(User.is_active == is_active)

    total = session.exec(select(func.count()).select_from(stmt.subquery())).one()
    stmt = stmt.order_by(desc(User.created_at)).offset(offset).limit(limit)
    rows = session.exec(stmt).all()

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": rows,
    }


# ---------------------------------------------------------------------------
# READ single
# ---------------------------------------------------------------------------
@router.get("/{user_id}", response_model=UserResponse)
def read_user(
    *,
    session: Session = Depends(get_db_session_dep),
    user_id: int,
    current_user: User = Depends(get_current_active_user),
) -> UserResponse:
    """Get a user by ID.

    * Admins can view any user.
    * Non-admins can only view themselves.
    """
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    if current_user.role != UserRole.ADMIN and current_user.id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only view your own profile",
        )

    return UserResponse.model_validate(user)


# ---------------------------------------------------------------------------
# UPDATE
# ---------------------------------------------------------------------------
@router.put("/{user_id}", response_model=UserResponse)
def update_user(
    *,
    session: Session = Depends(get_db_session_dep),
    user_id: int,
    update: UserUpdate,
    current_user: User = Depends(get_current_active_user),
) -> UserResponse:
    """Update a user.

    * Admins can update any user (including role changes).
    * Non-admins can only update themselves and cannot change role.
    * Password changes are handled via a separate endpoint (not yet built).
    """
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    is_admin = current_user.role == UserRole.ADMIN
    is_self = current_user.id == user_id

    if not is_admin and not is_self:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only update your own profile",
        )

    # Non-admins cannot change role or active status
    if not is_admin:
        if update.role is not None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only admins can change user roles",
            )
        if update.is_active is not None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only admins can deactivate accounts",
            )

    update_data = update.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(user, field, value)

    user.updated_at = datetime.now(timezone.utc)
    session.add(user)
    session.commit()
    session.refresh(user)
    return UserResponse.model_validate(user)


# ---------------------------------------------------------------------------
# DELETE (soft — deactivate)
# ---------------------------------------------------------------------------
@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    *,
    session: Session = Depends(get_db_session_dep),
    user_id: int,
    current_user: User = Depends(require_role(UserRole.ADMIN)),
) -> None:
    """Deactivate a user account.  Admin-only.

    Prevents self-deactivation to avoid locking out the last admin.
    """
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    if user.id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Admins cannot deactivate their own account via this endpoint",
        )

    user.is_active = False
    user.updated_at = datetime.now(timezone.utc)
    session.add(user)
    session.commit()
