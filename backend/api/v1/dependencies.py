"""CTI Platform — FastAPI Dependencies

Reusable dependency injectors for database sessions, authentication,
and role-based access control.
"""

from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlmodel import Session

from backend.models import User, UserRole
from backend.security import decode_token

# ---------------------------------------------------------------------------
# OAuth2 scheme — tells FastAPI to look for "Authorization: Bearer <token>"
# ---------------------------------------------------------------------------
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


# ---------------------------------------------------------------------------
# Database Session
# ---------------------------------------------------------------------------
def get_db_session_dep():
    """Yield a SQLModel session for FastAPI dependency injection.

    Usage::
        async def endpoint(session: Session = Depends(get_db_session_dep)):
            ...
    """
    from backend.database import get_engine
    engine = get_engine()
    session = Session(engine)
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Current User
# ---------------------------------------------------------------------------
def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    """Decode the JWT and load the matching User row from the DB.

    Raises 401 if the token is invalid, expired, or the user no longer exists.
    Manages its own session to avoid DetachedInstanceError with nested deps.
    """
    payload = decode_token(token)
    _sub = payload.get("sub")
    try:
        user_id: Optional[int] = int(_sub) if _sub is not None else None
    except (ValueError, TypeError):
        user_id = None
    token_type: Optional[str] = payload.get("type")

    if user_id is None or token_type != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
            headers={"WWW-Authenticate": "Bearer"},
        )

    from backend.database import get_db_context
    with get_db_context() as db:
        user: Optional[User] = db.get(User, user_id)
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found",
                headers={"WWW-Authenticate": "Bearer"},
            )
        # Eagerly access all scalar attributes while session is open.
        # This populates the instance state so it survives after expunge.
        _ = user.id
        _ = user.username
        _ = user.email
        _ = user.full_name
        _ = user.role
        _ = user.is_active
        _ = user.is_superuser
        _ = user.created_at
        _ = user.updated_at
        db.expunge(user)
        return user


def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    """Ensure the authenticated user account is active (not disabled)."""
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user account",
        )
    return current_user


# ---------------------------------------------------------------------------
# Role-based Access Control
# ---------------------------------------------------------------------------
def require_role(*roles: UserRole):
    """Factory that returns a dependency enforcing one or more UserRoles.

    Usage::
        @router.delete("/{user_id}")
        async def delete_user(
            user_id: int,
            current_user: User = Depends(require_role(UserRole.ADMIN)),
        ):
            ...
    """
    def _checker(current_user: User = Depends(get_current_active_user)) -> User:
        if current_user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return current_user

    return _checker
