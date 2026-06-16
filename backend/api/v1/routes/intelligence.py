"""CTI Platform — Threat Intelligence (IOC) Routes

Endpoints:
    POST   /intelligence/           — Create a new IOC
    POST   /intelligence/bulk       — Bulk-create IOCs
    GET    /intelligence/           — List IOCs (paginated, filterable, searchable)
    GET    /intelligence/{id}       — Retrieve single IOC
    PUT    /intelligence/{id}       — Update an IOC
    DELETE /intelligence/{id}       — Soft-delete (deactivate) an IOC
"""

import ipaddress
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, field_validator
from sqlmodel import Session, desc, func, select

from backend.api.v1.dependencies import (
    get_current_active_user,
    get_db_session_dep,
    require_role,
)
from backend.core.config import settings
from backend.models import IOCType, Indicator, User, UserRole
from backend.schemas import (
    IndicatorCreate,
    IndicatorListPaginated,
    IndicatorResponse,
    IndicatorUpdate,
)

router = APIRouter(prefix="/intelligence", tags=["Threat Intelligence"])

# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------
_RE_IPV4 = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
_RE_IPV6 = re.compile(r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$")
_RE_MD5 = re.compile(r"^[a-fA-F0-9]{32}$")
_RE_SHA1 = re.compile(r"^[a-fA-F0-9]{40}$")
_RE_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
_RE_DOMAIN = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
_RE_EMAIL = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
_RE_MUTEX = re.compile(r"^Global\\[A-Za-z0-9_]+$")


def _validate_ioc_value(ioc_type: IOCType, value: str) -> None:
    """Raise ValueError if *value* does not match the expected format for *ioc_type*."""
    checks = {
        IOCType.IPV4: (_RE_IPV4, "Invalid IPv4 address"),
        IOCType.IPV6: (_RE_IPV6, "Invalid IPv6 address"),
        IOCType.DOMAIN: (_RE_DOMAIN, "Invalid domain name"),
        IOCType.URL: (None, None),  # URLs are too varied; rely on min-length
        IOCType.MD5: (_RE_MD5, "Invalid MD5 hash (must be 32 hex chars)"),
        IOCType.SHA1: (_RE_SHA1, "Invalid SHA1 hash (must be 40 hex chars)"),
        IOCType.SHA256: (_RE_SHA256, "Invalid SHA256 hash (must be 64 hex chars)"),
        IOCType.EMAIL: (_RE_EMAIL, "Invalid email address"),
        IOCType.FILE_PATH: (None, None),
        IOCType.MUTEX: (_RE_MUTEX, "Invalid mutex name (expected Global\\Name)"),
        IOCType.YARA: (None, None),
    }
    pattern, msg = checks.get(ioc_type, (None, None))
    if pattern is not None and not pattern.match(value):
        raise ValueError(msg or f"Invalid format for {ioc_type.value}")


# ---------------------------------------------------------------------------
# Bulk-create schema
# ---------------------------------------------------------------------------
class _BulkCreateRequest(BaseModel):
    indicators: List[IndicatorCreate]

    @field_validator("indicators")
    @classmethod
    def validate_indicators(cls, v: List[IndicatorCreate]) -> List[IndicatorCreate]:
        if len(v) > 1000:
            raise ValueError("Bulk create limited to 1000 indicators per request")
        return v


# ---------------------------------------------------------------------------
# CREATE
# ---------------------------------------------------------------------------
@router.post("/", response_model=IndicatorResponse, status_code=status.HTTP_201_CREATED)
def create_indicator(
    *,
    session: Session = Depends(get_db_session_dep),
    indicator: IndicatorCreate,
    current_user: User = Depends(get_current_active_user),
) -> IndicatorResponse:
    """Create a new Indicator of Compromise.

    Validates that the *value* matches the expected syntax for the
    selected *ioc_type* (e.g. IPv4 regex for ``ipv4``).
    """
    try:
        _validate_ioc_value(indicator.ioc_type, indicator.value)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    db_indicator = Indicator(
        ioc_type=indicator.ioc_type,
        value=indicator.value,
        source=indicator.source,
        confidence=indicator.confidence,
        first_seen=indicator.first_seen,
        last_seen=indicator.last_seen,
        tags=indicator.tags,
        is_active=indicator.is_active if indicator.is_active is not None else True,
        notes=indicator.notes,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    session.add(db_indicator)
    session.commit()
    session.refresh(db_indicator)
    return IndicatorResponse.model_validate(db_indicator)


@router.post("/bulk", response_model=List[IndicatorResponse], status_code=status.HTTP_201_CREATED)
def create_indicators_bulk(
    *,
    session: Session = Depends(get_db_session_dep),
    body: _BulkCreateRequest,
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
) -> List[IndicatorResponse]:
    """Bulk-create up to 1,000 IOCs in a single transaction."""
    created: List[Indicator] = []
    for item in body.indicators:
        try:
            _validate_ioc_value(item.ioc_type, item.value)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Validation failed for value '{item.value}': {exc}",
            ) from exc
        db_indicator = Indicator(
            ioc_type=item.ioc_type,
            value=item.value,
            source=item.source,
            confidence=item.confidence,
            first_seen=item.first_seen,
            last_seen=item.last_seen,
            tags=item.tags,
            is_active=item.is_active if item.is_active is not None else True,
            notes=item.notes,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        session.add(db_indicator)
        created.append(db_indicator)

    session.commit()
    for db_indicator in created:
        session.refresh(db_indicator)
    return [IndicatorResponse.model_validate(i) for i in created]


# ---------------------------------------------------------------------------
# LIST (paginated + filterable)
# ---------------------------------------------------------------------------
@router.get("/", response_model=IndicatorListPaginated)
def read_indicators(
    *,
    session: Session = Depends(get_db_session_dep),
    limit: int = Query(default=20, ge=1, le=settings.MAX_PAGE_SIZE),
    offset: int = Query(default=0, ge=0),
    ioc_type: Optional[IOCType] = Query(None),
    is_active: Optional[bool] = Query(None),
    search: Optional[str] = Query(None, max_length=255, description="Substring search on value"),
) -> Dict[str, Any]:
    """List IOCs with optional filtering and pagination."""
    stmt = select(Indicator)
    if ioc_type:
        stmt = stmt.where(Indicator.ioc_type == ioc_type)
    if is_active is not None:
        stmt = stmt.where(Indicator.is_active == is_active)
    if search:
        stmt = stmt.where(Indicator.value.ilike(f"%{search}%"))

    total = session.exec(select(func.count()).select_from(stmt.subquery())).one()
    stmt = stmt.order_by(desc(Indicator.created_at)).offset(offset).limit(limit)
    indicators = session.exec(stmt).all()

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": indicators,
    }


# ---------------------------------------------------------------------------
# READ single
# ---------------------------------------------------------------------------
@router.get("/{indicator_id}", response_model=IndicatorResponse)
def read_indicator(
    *,
    session: Session = Depends(get_db_session_dep),
    indicator_id: int,
) -> IndicatorResponse:
    """Retrieve a single IOC by ID."""
    indicator = session.get(Indicator, indicator_id)
    if not indicator:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Indicator not found")
    return IndicatorResponse.model_validate(indicator)


# ---------------------------------------------------------------------------
# UPDATE
# ---------------------------------------------------------------------------
@router.put("/{indicator_id}", response_model=IndicatorResponse)
def update_indicator(
    *,
    session: Session = Depends(get_db_session_dep),
    indicator_id: int,
    update: IndicatorUpdate,
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
) -> IndicatorResponse:
    """Update an existing IOC.  Only analysts and admins may modify."""
    indicator = session.get(Indicator, indicator_id)
    if not indicator:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Indicator not found")

    # If type or value changed, re-validate
    new_type = update.ioc_type or indicator.ioc_type
    new_value = update.value or indicator.value
    if update.ioc_type is not None or update.value is not None:
        try:
            _validate_ioc_value(new_type, new_value)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
            ) from exc

    update_data = update.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(indicator, field, value)

    indicator.updated_at = datetime.now(timezone.utc)
    session.add(indicator)
    session.commit()
    session.refresh(indicator)
    return IndicatorResponse.model_validate(indicator)


# ---------------------------------------------------------------------------
# DELETE (soft — deactivate)
# ---------------------------------------------------------------------------
@router.delete("/{indicator_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_indicator(
    *,
    session: Session = Depends(get_db_session_dep),
    indicator_id: int,
    current_user: User = Depends(require_role(UserRole.ADMIN)),
) -> None:
    """Soft-delete (deactivate) an IOC.  Only admins may delete."""
    indicator = session.get(Indicator, indicator_id)
    if not indicator:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Indicator not found")
    indicator.is_active = False
    indicator.updated_at = datetime.now(timezone.utc)
    session.add(indicator)
    session.commit()
