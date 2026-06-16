import logging
from contextlib import contextmanager
from typing import Generator

from sqlalchemy import event
from sqlalchemy.engine import Engine
from sqlmodel import Session, SQLModel, create_engine

from backend.core.config import settings

logger = logging.getLogger("cti_platform")

# ---------------------------------------------------------------------------
# Engine Configuration
# ---------------------------------------------------------------------------
_engine = None


def _build_engine() -> Engine:
    """Lazily build and configure the SQLAlchemy engine."""
    global _engine
    if _engine is not None:
        return _engine

    engine_kwargs: dict = {
        "echo": settings.DEBUG,
        # Pooling: recycle connections after 30 min (prevents stale DB handles)
        "pool_recycle": 1800,
        # Verify connection validity before checkout (critical for production)
        "pool_pre_ping": True,
    }

    if settings.DATABASE_URL and settings.DATABASE_URL.startswith("sqlite"):
        # SQLite-specific: allow same-thread access for async/concurrent readers
        engine_kwargs["connect_args"] = {"check_same_thread": False}
    else:
        # PostgreSQL / MySQL production pool settings
        engine_kwargs.update(
            {
                "pool_size": 10,
                "max_overflow": 20,
            }
        )

    _engine = create_engine(settings.DATABASE_URL, **engine_kwargs)

    # SQLite WAL mode for better concurrency (production SQLite)
    if settings.DATABASE_URL and settings.DATABASE_URL.startswith("sqlite"):

        @event.listens_for(_engine, "connect")
        def _set_sqlite_pragma(dbapi_conn, connection_record):
            cursor = dbapi_conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL;")
            cursor.execute("PRAGMA foreign_keys=ON;")
            cursor.close()

    logger.info("Database engine created | url=%s", settings.DATABASE_URL)
    return _engine


def get_engine() -> Engine:
    """Return the configured SQLAlchemy engine."""
    return _build_engine()


# ---------------------------------------------------------------------------
# Session Management
# ---------------------------------------------------------------------------
def get_session() -> Generator[Session, None, None]:
    """FastAPI dependency that yields a transactional session.

    Automatically rolls back on unhandled exceptions to prevent
    partial commits and dangling transactions.
    """
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


@contextmanager
def get_db_context() -> Generator[Session, None, None]:
    """Synchronous context-manager version of get_session.

    Use this in background tasks, Celery workers, or CLI scripts
    where FastAPI dependency injection is unavailable.
    """
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
# Schema Lifecycle
# ---------------------------------------------------------------------------
def init_db() -> None:
    """Create all tables defined by SQLModel metadata.

    Safe to run multiple times (SQLAlchemy uses CREATE IF NOT EXISTS
    semantics). Call this at application startup or via scripts/init_db.py.
    """
    engine = get_engine()
    SQLModel.metadata.create_all(engine)
    logger.info("Database tables initialized")


def dispose_engine() -> None:
    """Dispose the engine connection pool.

    Call during graceful shutdown to release all DB connections.
    """
    global _engine
    if _engine is not None:
        _engine.dispose()
        _engine = None
        logger.info("Database engine disposed")
