"""CTI Platform — Malware Analysis API Routes

Endpoints:
    POST /analysis/upload       — Upload sample, run analysis, return results
    GET  /analysis/jobs/{id}    — Retrieve scan status and results
    GET  /analysis/jobs         — List scan history (paginated)
    GET  /analysis/yara/rules   — List compiled YARA rule names
"""

import asyncio
import hashlib
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import (
    APIRouter,
    File,
    HTTPException,
    Query,
    Request,
    UploadFile,
    status,
)
from fastapi.responses import StreamingResponse
from sqlmodel import desc, func, select

from backend.analysis_engine.tasks import run_analysis
from backend.core.config import settings
from backend.core.events import event_stream
from backend.database import get_db_context
from backend.models import ScanResult, ScanStatus, Severity
from backend.schemas import (
    DetectorHit,
    ScanHistoryPaginated,
    ScanResultResponse,
    ScanSummary,
)


def _build_response(scan_id: int) -> ScanResultResponse:
    """Build a ScanResultResponse Pydantic model from a DB row.

    Uses a raw SQLAlchemy session with expire_on_commit=False so that
    accessing lazy-loaded / JSON columns never raises DetachedInstanceError.
    """
    from sqlalchemy.orm import Session as SASession
    from backend.database import get_engine

    engine = get_engine()
    session = SASession(engine, expire_on_commit=False)
    try:
        scan: Optional[ScanResult] = session.get(ScanResult, scan_id)
        if scan is None:
            raise HTTPException(status_code=404, detail="Scan not found")

        # Eagerly extract every scalar while the session is still open
        _id = scan.id
        _file_hash = scan.file_hash
        _filename = scan.filename
        _file_size = scan.file_size
        _content_type = scan.content_type
        _status = scan.status
        _severity = scan.severity
        _is_malware = scan.is_malware
        _confidence = scan.confidence
        _analysis_summary = scan.analysis_summary
        _celery_task_id = scan.celery_task_id
        _scanned_by = scan.scanned_by
        _notes = scan.notes
        _created_at = scan.created_at
        _updated_at = scan.updated_at

        detector_hits: Optional[List[DetectorHit]] = None
        if scan.detector_results and isinstance(scan.detector_results, dict):
            detector_hits = []
            for name, res in scan.detector_results.items():
                if isinstance(res, dict):
                    detector_hits.append(
                        DetectorHit(
                            name=name,
                            detected=res.get("detected", False),
                            confidence=res.get("confidence", 0.0),
                            details=res.get("details"),
                        )
                    )
    finally:
        session.close()

    return ScanResultResponse(
        id=_id,
        file_hash=_file_hash,
        filename=_filename,
        file_size=_file_size,
        content_type=_content_type,
        status=_status,
        severity=_severity,
        is_malware=_is_malware,
        confidence=_confidence,
        detector_hits=detector_hits,
        analysis_summary=_analysis_summary,
        celery_task_id=_celery_task_id,
        scanned_by=_scanned_by,
        notes=_notes,
        created_at=_created_at,
        updated_at=_updated_at,
    )

logger = logging.getLogger("cti_platform.api.analysis")

router = APIRouter(prefix="/analysis", tags=["Analysis"])

# Ensure upload directory exists at import time
_UPLOAD_DIR = Path(settings.UPLOAD_DIR)
_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

_MAX_BYTES = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024


def _hash_file(path: Path) -> str:
    """Compute SHA-256 of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _sanitize_filename(name: str) -> str:
    """Strip directory traversal and control characters."""
    name = name.strip()
    if ".." in name or "/" in name or "\\" in name:
        raise ValueError("Invalid filename")
    if any(ord(c) < 32 for c in name):
        raise ValueError("Invalid characters in filename")
    return name





# ---------------------------------------------------------------------------
# Upload & Analyze
# ---------------------------------------------------------------------------
@router.post("/upload", response_model=ScanResultResponse, status_code=status.HTTP_201_CREATED)
async def upload_sample(
    request: Request,
    file: UploadFile = File(..., description="Malware sample to analyze"),
    notes: Optional[str] = Query(None, max_length=2000),
) -> ScanResultResponse:
    """Upload a file and synchronously run the full analysis pipeline."""
    try:
        filename = _sanitize_filename(file.filename or "unknown")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Bad filename: {exc}")

    internal_name = f"{uuid.uuid4().hex}_{filename}"
    target_path = _UPLOAD_DIR / internal_name
    total = 0

    try:
        with open(target_path, "wb") as out:
            while True:
                chunk = await file.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > _MAX_BYTES:
                    raise HTTPException(
                        status_code=413,
                        detail=f"File exceeds {settings.MAX_UPLOAD_SIZE_MB} MB limit",
                    )
                out.write(chunk)
    except HTTPException:
        target_path.unlink(missing_ok=True)
        raise
    except Exception as exc:
        target_path.unlink(missing_ok=True)
        logger.exception("Upload save failed")
        raise HTTPException(status_code=500, detail="Failed to save uploaded file") from exc
    finally:
        await file.close()

    try:
        file_hash = _hash_file(target_path)
        file_size = target_path.stat().st_size
    except Exception as exc:
        target_path.unlink(missing_ok=True)
        raise HTTPException(status_code=500, detail="Failed to hash file") from exc

    with get_db_context() as db:
        scan = ScanResult(
            file_hash=file_hash,
            filename=filename,
            file_size=file_size,
            content_type=file.content_type or "application/octet-stream",
            storage_path=str(target_path),
            status=ScanStatus.PENDING,
            notes=notes,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        scan_id = scan.id

    try:
        analysis_result = await asyncio.wait_for(
            asyncio.to_thread(run_analysis, scan_id, str(target_path)),
            timeout=300,
        )
    except asyncio.TimeoutError:
        logger.error("Analysis timed out for scan %s", scan_id)
        with get_db_context() as db:
            scan = db.get(ScanResult, scan_id)
            if scan:
                scan.status = ScanStatus.FAILED
                scan.analysis_summary = "Analysis timed out after 300 seconds"
                scan.updated_at = datetime.now(timezone.utc)
                db.add(scan)
                db.commit()
                db.refresh(scan)
        return _build_response(scan_id)
    except Exception as exc:
        logger.exception("Analysis failed for scan %s", scan_id)
        with get_db_context() as db:
            scan = db.get(ScanResult, scan_id)
            if scan:
                scan.status = ScanStatus.FAILED
                scan.analysis_summary = f"Analysis error: {exc}"
                scan.updated_at = datetime.now(timezone.utc)
                db.add(scan)
                db.commit()
                db.refresh(scan)
        return _build_response(scan_id)

    logger.info(
        "Upload+analysis complete | scan_id=%s detected=%s confidence=%s",
        scan_id,
        analysis_result.get("detected"),
        analysis_result.get("confidence"),
    )

    return _build_response(scan_id)


# ---------------------------------------------------------------------------
# Retrieve Single Scan
# ---------------------------------------------------------------------------
@router.get("/jobs/{scan_id}", response_model=ScanResultResponse)
async def get_job_status(scan_id: int) -> ScanResultResponse:
    """Get full scan results by ID."""
    with get_db_context() as db:
        scan = db.get(ScanResult, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _build_response(scan_id)


# ---------------------------------------------------------------------------
# List Scans (Paginated)
# ---------------------------------------------------------------------------
@router.get("/jobs", response_model=ScanHistoryPaginated)
async def list_scans(
    limit: int = Query(default=20, ge=1, le=settings.MAX_PAGE_SIZE),
    offset: int = Query(default=0, ge=0),
    status_filter: Optional[ScanStatus] = Query(None, alias="status"),
    severity_filter: Optional[Severity] = Query(None, alias="severity"),
) -> Dict[str, Any]:
    """List scan history with optional filters."""
    with get_db_context() as db:
        stmt = select(ScanResult)
        if status_filter:
            stmt = stmt.where(ScanResult.status == status_filter)
        if severity_filter:
            stmt = stmt.where(ScanResult.severity == severity_filter)

        total = db.exec(
            select(func.count()).select_from(stmt.subquery())
        ).one()

        stmt = stmt.order_by(desc(ScanResult.created_at)).offset(offset).limit(limit)
        rows = db.exec(stmt).all()

        # Build summaries while session is still open
        items = [_to_summary(r) for r in rows]

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": items,
    }


# ---------------------------------------------------------------------------
# YARA Diagnostics
# ---------------------------------------------------------------------------
@router.get("/yara/rules")
async def list_yara_rules() -> Dict[str, Any]:
    """List compiled YARA rule files and their internal rule names."""
    from backend.analysis_engine.yara_scanner import YaraScanner
    scanner = YaraScanner()
    return {
        "yara_available": scanner.rules is not None,
        "rule_files": scanner.rule_names,
    }


# ---------------------------------------------------------------------------
# Real-Time Progress — Server-Sent Events
# ---------------------------------------------------------------------------
@router.get("/jobs/{scan_id}/events")
async def scan_events(
    scan_id: int,
    request: Request,
    token: Optional[str] = Query(None),
):
    """Live analysis progress stream for a given scan job.

    Connect via EventSource; receives ``status`` and ``analyzer`` events
    throughout the scan lifecycle. Connection closes automatically after
    inactivity TTL (10 min) on the server side.

    SECURITY:
        EventSource cannot set custom headers, so the JWT Bearer token may be
        passed as a ``token`` query parameter. It is consumed immediately and
        never logged or stored.
    """
    # Validate token from query param (SSE limitation)
    from backend.security import verify_token
    if token:
        try:
            verify_token(token)
        except Exception:
            raise HTTPException(status_code=401, detail="Invalid token")
    else:
        # Fallback to normal header auth if proxy/WebSocket bridge is used
        auth = request.headers.get("authorization", "")
        if not auth.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Missing authentication")
        try:
            verify_token(auth.replace("Bearer ", ""))
        except Exception:
            raise HTTPException(status_code=401, detail="Invalid token")

    return StreamingResponse(
        event_stream(scan_id),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


def _to_summary(scan: ScanResult) -> ScanSummary:
    """Build a lightweight summary dict."""
    return ScanSummary(
        id=scan.id,
        file_hash=scan.file_hash,
        filename=scan.filename,
        status=scan.status,
        severity=scan.severity,
        is_malware=scan.is_malware,
        confidence=scan.confidence,
        created_at=scan.created_at,
    )
