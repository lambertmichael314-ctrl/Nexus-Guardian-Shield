from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from backend.models import IOCType, ScanStatus, Severity, UserRole


# ---------------------------------------------------------------------------
# Shared / Utility Schemas
# ---------------------------------------------------------------------------
class PaginatedResponse(BaseModel):
    """Standard paginated list wrapper."""

    total: int = Field(description="Total number of items matching the query")
    limit: int = Field(description="Items per page")
    offset: int = Field(description="Current page offset")
    items: List[Any]


class HTTPErrorResponse(BaseModel):
    """Standard error envelope (mirrors main.py exception handlers)."""

    error: Dict[str, Any]


# ---------------------------------------------------------------------------
# User Schemas
# ---------------------------------------------------------------------------
class UserBase(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=50)
    full_name: Optional[str] = Field(default=None, max_length=255)
    role: UserRole = UserRole.ANALYST
    is_active: bool = True


class UserCreate(UserBase):
    password: str = Field(min_length=12, max_length=128)

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.islower() for c in v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in v):
            raise ValueError("Password must contain at least one special character")
        return v


class UserUpdate(BaseModel):
    """Partial update schema — all fields optional."""

    email: Optional[EmailStr] = None
    full_name: Optional[str] = Field(default=None, max_length=255)
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None


class UserResponse(UserBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime
    updated_at: datetime


class UserInDB(UserResponse):
    """Internal schema including hashed_password — NEVER return via API."""

    hashed_password: str


# ---------------------------------------------------------------------------
# Authentication Schemas
# ---------------------------------------------------------------------------
class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = Field(description="Access token TTL in seconds")


class TokenPayload(BaseModel):
    sub: Optional[int] = Field(default=None, description="User ID (subject)")
    exp: Optional[datetime] = None
    type: Optional[str] = Field(default="access", description="access or refresh")


class LoginRequest(BaseModel):
    username: str
    password: str


# ---------------------------------------------------------------------------
# Indicator (IOC) Schemas
# ---------------------------------------------------------------------------
class IndicatorBase(BaseModel):
    ioc_type: IOCType
    value: str = Field(min_length=1, max_length=4096)
    source: Optional[str] = Field(default=None, max_length=255)
    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    tags: Optional[str] = Field(default=None, max_length=1000)
    is_active: bool = True
    notes: Optional[str] = None


class IndicatorCreate(IndicatorBase):
    pass


class IndicatorUpdate(BaseModel):
    """Partial update for indicators."""

    ioc_type: Optional[IOCType] = None
    value: Optional[str] = Field(default=None, min_length=1, max_length=4096)
    source: Optional[str] = Field(default=None, max_length=255)
    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    tags: Optional[str] = Field(default=None, max_length=1000)
    is_active: Optional[bool] = None
    notes: Optional[str] = None


class IndicatorResponse(IndicatorBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime
    updated_at: datetime


# ---------------------------------------------------------------------------
# Malware Analysis Schemas
# ---------------------------------------------------------------------------
class ScanCreate(BaseModel):
    """
    Metadata-only request for initiating a malware scan.

    IMPORTANT: The actual file bytes are transmitted via multipart/form-data
    (FastAPI UploadFile) in the endpoint, NOT inside this JSON schema.
    Never embed binary file content in a Pydantic/Base64 string — it
    corrupts encoding and balloons memory for large samples.
    """

    filename: str = Field(min_length=1, max_length=255)
    content_type: Optional[str] = Field(default="application/octet-stream", max_length=100)
    notes: Optional[str] = Field(default=None, max_length=2000)

    @field_validator("filename")
    @classmethod
    def validate_filename(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Filename cannot be empty")
        # Prevent directory traversal in uploaded filenames
        if ".." in v or "/" in v or "\\" in v:
            raise ValueError("Filename contains invalid characters")
        return v


class DetectorHit(BaseModel):
    """Individual detector result payload."""

    name: str = Field(description="Detector module name, e.g. 'adware_detector'")
    detected: bool
    confidence: float = Field(ge=0.0, le=1.0)
    details: Optional[Dict[str, Any]] = None


class ScanResultResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    file_hash: str = Field(description="SHA-256 of the submitted sample")
    filename: str
    file_size: int
    content_type: Optional[str]
    status: ScanStatus
    severity: Optional[Severity]
    is_malware: Optional[bool]
    confidence: Optional[float]

    # Derived from detector_results JSON
    detector_hits: Optional[List[DetectorHit]] = Field(
        default=None, description="Parsed detector_results JSON"
    )
    analysis_summary: Optional[str]
    celery_task_id: Optional[str]

    scanned_by: Optional[int] = Field(description="User ID who submitted the scan")
    notes: Optional[str]
    created_at: datetime
    updated_at: datetime


class ScanSummary(BaseModel):
    """Lightweight schema for scan history lists."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    file_hash: str
    filename: str
    status: ScanStatus
    severity: Optional[Severity]
    is_malware: Optional[bool]
    confidence: Optional[float]
    created_at: datetime


class IndicatorListPaginated(PaginatedResponse):
    items: List[IndicatorResponse]


class ScanHistoryPaginated(PaginatedResponse):
    items: List[ScanSummary]
