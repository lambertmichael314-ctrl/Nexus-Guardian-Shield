import enum
from datetime import datetime
from typing import List, Optional

from sqlalchemy import Column, DateTime, Enum, ForeignKey, func, Text, JSON
from sqlalchemy.orm import relationship
from sqlmodel import Field, Relationship, SQLModel


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------
class IOCType(str, enum.Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL = "email"
    FILE_PATH = "file_path"
    MUTEX = "mutex"
    YARA = "yara"


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    ANALYZING = "analyzing"
    COMPLETED = "completed"
    FAILED = "failed"
    QUARANTINED = "quarantined"


class UserRole(str, enum.Enum):
    ANALYST = "analyst"
    ADMIN = "admin"
    READONLY = "readonly"


# ---------------------------------------------------------------------------
# User Model
# ---------------------------------------------------------------------------
class User(SQLModel, table=True):
    __tablename__ = "user"

    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(index=True, unique=True, max_length=255)
    username: str = Field(index=True, unique=True, max_length=50)
    full_name: Optional[str] = Field(default=None, max_length=255)
    hashed_password: str = Field(max_length=255)
    role: UserRole = Field(default=UserRole.ANALYST, sa_column=Column(Enum(UserRole)))
    is_active: bool = Field(default=True)
    is_superuser: bool = Field(default=False)

    created_at: Optional[datetime] = Field(
        default=None,
        sa_column=Column(DateTime, default=func.now(), nullable=False)
    )
    updated_at: Optional[datetime] = Field(
        default=None,
        sa_column=Column(
            DateTime, default=func.now(), onupdate=func.now(), nullable=False
        )
    )

    # Relationships
    scan_results: List["ScanResult"] = Relationship(back_populates="analyst")


# ---------------------------------------------------------------------------
# Indicator (IOC) Model
# ---------------------------------------------------------------------------
class Indicator(SQLModel, table=True):
    __tablename__ = "indicator"

    id: Optional[int] = Field(default=None, primary_key=True)
    ioc_type: IOCType = Field(sa_column=Column(Enum(IOCType), nullable=False))
    value: str = Field(index=True, max_length=4096)
    source: Optional[str] = Field(default=None, max_length=255)
    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    first_seen: Optional[datetime] = Field(
        default=None, sa_column=Column(DateTime, nullable=True)
    )
    last_seen: Optional[datetime] = Field(
        default=None, sa_column=Column(DateTime, nullable=True)
    )
    tags: Optional[str] = Field(default=None, max_length=1000)  # CSV or JSON list
    is_active: bool = Field(default=True)
    notes: Optional[str] = Field(default=None, sa_column=Column(Text))

    created_at: Optional[datetime] = Field(
        default=None,
        sa_column=Column(DateTime, default=func.now(), nullable=False)
    )
    updated_at: Optional[datetime] = Field(
        default=None,
        sa_column=Column(
            DateTime, default=func.now(), onupdate=func.now(), nullable=False
        )
    )


# ---------------------------------------------------------------------------
# Scan Result (Malware Analysis) Model
# ---------------------------------------------------------------------------
class ScanResult(SQLModel, table=True):
    __tablename__ = "scan_result"

    id: Optional[int] = Field(default=None, primary_key=True)

    # --- File Metadata ---
    file_hash: str = Field(index=True, max_length=64)  # SHA-256
    filename: str = Field(max_length=255)
    file_size: int = Field(ge=0)
    content_type: Optional[str] = Field(default="application/octet-stream", max_length=100)

    # --- Storage & Containment (Live Virus Safety) ---
    # Randomized internal storage path; never expose raw filesystem paths via API
    storage_path: Optional[str] = Field(default=None, max_length=512)
    # Encrypted-at-rest flag; encryption key managed externally (e.g., Vault, KMS)
    encrypted: bool = Field(default=False)
    encryption_key_id: Optional[str] = Field(default=None, max_length=255)

    # --- Analysis State ---
    status: ScanStatus = Field(
        default=ScanStatus.PENDING, sa_column=Column(Enum(ScanStatus), nullable=False)
    )
    severity: Optional[Severity] = Field(
        default=None, sa_column=Column(Enum(Severity), nullable=True)
    )
    is_malware: Optional[bool] = Field(default=None)
    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)

    # --- Detector Output ---
    # Structured JSON output from all analysis modules (adware, trojan, etc.)
    detector_results: Optional[dict] = Field(
        default=None, sa_column=Column(JSON, nullable=True)
    )
    # Human-readable summary generated by the analysis engine
    analysis_summary: Optional[str] = Field(default=None, sa_column=Column(Text))
    # Raw sandbox / detonation logs (truncated if necessary)
    sandbox_output: Optional[str] = Field(default=None, sa_column=Column(Text))

    # --- Job Orchestration ---
    # Celery / background job ID for async tracking
    celery_task_id: Optional[str] = Field(default=None, max_length=155)

    # --- Provenance ---
    scanned_by: Optional[int] = Field(
        default=None, foreign_key="user.id", nullable=True
    )
    notes: Optional[str] = Field(default=None, max_length=2000)

    created_at: Optional[datetime] = Field(
        default=None,
        sa_column=Column(DateTime, default=func.now(), nullable=False)
    )
    updated_at: Optional[datetime] = Field(
        default=None,
        sa_column=Column(
            DateTime, default=func.now(), onupdate=func.now(), nullable=False
        )
    )

    # Relationships
    analyst: Optional["User"] = Relationship(back_populates="scan_results")
