"""CTI Platform — Security Utilities

Password hashing (bcrypt) and JWT token creation/verification.
"""

import bcrypt
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from fastapi import HTTPException, status
from jose import JWTError, jwt

from backend.core.config import settings

ALGORITHM = settings.ALGORITHM
SECRET_KEY = settings.SECRET_KEY


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Password Hashing (bcrypt directly — passlib is incompatible with bcrypt>=5.0)
# ---------------------------------------------------------------------------
def verify_password(plain: str, hashed: str) -> bool:
    """Verify a plaintext password against a bcrypt hash."""
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))


def get_password_hash(plain: str) -> str:
    """Hash a plaintext password with bcrypt (cost=12)."""
    hashed = bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt(rounds=12))
    return hashed.decode("utf-8")


# ---------------------------------------------------------------------------
# JWT
# ---------------------------------------------------------------------------
def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Create a short-lived access token (default 30 min)."""
    to_encode = data.copy()
    if expires_delta is None:
        expires_delta = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    expire = _now() + expires_delta
    # JWT claims are conventionally strings; coerce sub to str for python-jose compat
    if "sub" in to_encode and to_encode["sub"] is not None:
        to_encode["sub"] = str(to_encode["sub"])
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Create a long-lived refresh token (default 7 days)."""
    to_encode = data.copy()
    if expires_delta is None:
        expires_delta = timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES)
    expire = _now() + expires_delta
    if "sub" in to_encode and to_encode["sub"] is not None:
        to_encode["sub"] = str(to_encode["sub"])
    to_encode.update({"exp": expire, "type": "refresh"})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> Dict[str, Any]:
    """Decode and validate a JWT.  Raises HTTPException(401) on failure."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    return payload