import os
import time
import uuid
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Dict

import uvicorn
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from backend.core.config import settings
from backend.api.v1.api import api_router
from backend.database import init_db, dispose_engine
from backend.seed import seed_default_admin

# ---------------------------------------------------------------------------
# Logging Configuration
# ---------------------------------------------------------------------------
LOG_LEVEL = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)
logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("cti_platform")

# ---------------------------------------------------------------------------
# Lifespan (Startup / Shutdown)
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events.

    Handles startup initialization and graceful shutdown cleanup.
    Extend this block to initialise DB connection pools, Redis, Celery,
    or any external resource.
    """
    logger.info("CTI Platform starting up | version=%s", settings.PROJECT_VERSION)
    # --- Startup ---
    init_db()
    seed_default_admin()
    # Example: await redis_pool.open()
    yield
    # --- Shutdown ---
    logger.info("CTI Platform shutting down")
    dispose_engine()
    # Example: await redis_pool.close()

# ---------------------------------------------------------------------------
# Application Instance
# ---------------------------------------------------------------------------
app = FastAPI(
    title=settings.PROJECT_NAME,
    description=settings.PROJECT_DESCRIPTION,
    version=settings.PROJECT_VERSION,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# ---------------------------------------------------------------------------
# Middleware Stack (order matters: last added = outermost)
# ---------------------------------------------------------------------------

# 1. GZip compression for responses > 1KB
app.add_middleware(GZipMiddleware, minimum_size=1024)

# 2. CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=[str(origin) for origin in settings.BACKEND_CORS_ORIGINS],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID"],
    max_age=600,
)

# 3. Request ID & Timing Middleware
@app.middleware("http")
async def add_request_metadata(request: Request, call_next):
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id
    start_time = time.perf_counter()

    response = await call_next(request)

    process_time = time.perf_counter() - start_time
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Process-Time"] = f"{process_time:.4f}"

    # Slow-request warning threshold: 1.0s
    if process_time > 1.0:
        logger.warning(
            "Slow request | method=%s path=%s time=%.4fs request_id=%s",
            request.method,
            request.url.path,
            process_time,
            request_id,
        )
    else:
        logger.info(
            "Request | method=%s path=%s status=%d time=%.4fs request_id=%s",
            request.method,
            request.url.path,
            response.status_code,
            process_time,
            request_id,
        )

    return response

# 4. Security Headers Middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    # Prevent MIME-sniffing
    response.headers["X-Content-Type-Options"] = "nosniff"
    # Frame protection
    response.headers["X-Frame-Options"] = "DENY"
    # Legacy XSS filter
    response.headers["X-XSS-Protection"] = "1; mode=block"
    # HSTS
    response.headers["Strict-Transport-Security"] = (
        "max-age=31536000; includeSubDomains; preload"
    )
    # Referrer policy
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    # Permissions policy
    response.headers["Permissions-Policy"] = (
        "accelerometer=(), camera=(), geolocation=(), gyroscope=(), "
        "magnetometer=(), microphone=(), payment=(), usb=()"
    )
    # Content Security Policy
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; frame-ancestors 'none'; base-uri 'self';"
    )
    return response

# ---------------------------------------------------------------------------
# Global Exception Handlers
# ---------------------------------------------------------------------------
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    request_id = getattr(request.state, "request_id", "unknown")
    logger.error(
        "HTTPException | status=%d detail=%s request_id=%s",
        exc.status_code,
        exc.detail,
        request_id,
    )
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "code": exc.status_code,
                "message": exc.detail,
                "request_id": request_id,
            }
        },
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    request_id = getattr(request.state, "request_id", "unknown")
    logger.warning(
        "ValidationError | errors=%s request_id=%s",
        exc.errors(),
        request_id,
    )
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": {
                "code": 422,
                "message": "Request validation failed",
                "details": exc.errors(),
                "request_id": request_id,
            }
        },
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    request_id = getattr(request.state, "request_id", "unknown")
    logger.exception(
        "UnhandledException | type=%s request_id=%s",
        type(exc).__name__,
        request_id,
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": {
                "code": 500,
                "message": "An unexpected internal error occurred." if not settings.DEBUG else str(exc),
                "request_id": request_id,
            }
        },
    )

# ---------------------------------------------------------------------------
# API Routes
# ---------------------------------------------------------------------------
app.include_router(api_router, prefix=settings.API_V1_STR)

# ---------------------------------------------------------------------------
# System Endpoints
# ---------------------------------------------------------------------------
@app.get("/", tags=["System"], include_in_schema=False)
async def root() -> Dict[str, Any]:
    return {
        "project": settings.PROJECT_NAME,
        "version": settings.PROJECT_VERSION,
        "description": settings.PROJECT_DESCRIPTION,
        "docs": "/docs",
        "health": "/health",
        "api_version": "v1",
        "api_prefix": settings.API_V1_STR,
    }


@app.get("/health", tags=["System"])
async def health_check() -> Dict[str, Any]:
    """Platform health probe."""
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": settings.PROJECT_VERSION,
        "environment": "development" if settings.DEBUG else "production",
    }


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    uvicorn.run(
        "backend.main:app",
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", "8000")),
        reload=settings.DEBUG,
        log_level=settings.LOG_LEVEL.lower(),
        access_log=False,
    )