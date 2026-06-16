"""CTI Platform — General Utilities

Helper functions for hashing, sanitization, filesystem ops, and data transformation.
"""

import hashlib
import json
import logging
import os
import secrets
import string
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger("cti_platform.utils")


# ---------------------------------------------------------------------------
# Randomness / Secrets
# ---------------------------------------------------------------------------
def generate_random_string(length: int = 32) -> str:
    """Generate a cryptographically secure URL-safe random string."""
    return secrets.token_urlsafe(length)


def generate_api_key() -> str:
    """Generate a secure API key prefix with random suffix."""
    return f"sk_{generate_random_string(40)}"


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------
def hash_content(content: Union[str, bytes], algorithm: str = "sha256") -> str:
    """Generate a hex digest of *content* using the specified hash algorithm."""
    if isinstance(content, str):
        content = content.encode("utf-8")
    hasher = hashlib.new(algorithm)
    hasher.update(content)
    return hasher.hexdigest()


def hash_file(file_path: Union[str, Path], algorithm: str = "sha256", chunk_size: int = 8192) -> str:
    """Stream-hash a file on disk. Defaults to SHA-256."""
    hasher = hashlib.new(algorithm)
    with open(file_path, "rb") as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
    return hasher.hexdigest()


# ---------------------------------------------------------------------------
# Sanitization
# ---------------------------------------------------------------------------
def sanitize_filename(filename: str) -> str:
    """Sanitize a filename to prevent directory traversal and remove dangerous chars.

    Returns a safe basename (no path separators).
    """
    filename = Path(filename).name
    safe_chars = set(string.ascii_letters + string.digits + "._-")
    filename = "".join(c for c in filename if c in safe_chars)
    return filename or "unnamed_file"


def sanitize_path(user_path: str, base_dir: Union[str, Path]) -> Path:
    """Resolve *user_path* relative to *base_dir* and prevent traversal above it.

    Raises ValueError if the resolved path escapes *base_dir*.
    """
    base = Path(base_dir).resolve()
    target = (base / user_path).resolve()
    if not str(target).startswith(str(base)):
        raise ValueError("Path traversal detected")
    return target


# ---------------------------------------------------------------------------
# Date/Time
# ---------------------------------------------------------------------------
def utc_now() -> datetime:
    """Return timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def format_timestamp(ts: Optional[datetime] = None) -> str:
    """Format a datetime to ISO 8601 string. Defaults to now(UTC)."""
    if ts is None:
        ts = utc_now()
    return ts.isoformat()


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------
def safe_json_loads(data: Union[str, bytes], default: Any = None) -> Any:
    """Safely load JSON with error handling. Returns *default* on failure."""
    if isinstance(data, bytes):
        data = data.decode("utf-8")
    try:
        return json.loads(data)
    except (json.JSONDecodeError, TypeError) as exc:
        logger.warning("Failed to parse JSON: %s", exc)
        return default


def safe_json_dumps(obj: Any, default: str = "{}") -> str:
    """Safely dump an object to JSON string. Returns *default* on failure."""
    try:
        return json.dumps(obj, default=str)
    except (TypeError, ValueError) as exc:
        logger.warning("Failed to serialize JSON: %s", exc)
        return default


# ---------------------------------------------------------------------------
# Filesystem
# ---------------------------------------------------------------------------
def get_file_size(file_path: Union[str, Path]) -> int:
    """Return file size in bytes, or 0 on error."""
    try:
        return os.path.getsize(file_path)
    except OSError as exc:
        logger.error("Error getting file size for %s: %s", file_path, exc)
        return 0


def is_file_type_supported(filename: str, supported_types: List[str]) -> bool:
    """Check if the file extension is in the supported types list (case-insensitive)."""
    _, ext = os.path.splitext(filename)
    return ext.lower() in [t.lower() for t in supported_types]


def ensure_directory(directory_path: Union[str, Path]) -> bool:
    """Create directory if it doesn't exist. Returns True on success, False on error."""
    try:
        os.makedirs(directory_path, exist_ok=True)
        return True
    except OSError as exc:
        logger.error("Error creating directory %s: %s", directory_path, exc)
        return False


def cleanup_file(file_path: Union[str, Path]) -> bool:
    """Safely remove a file. Returns True if removed or didn't exist, False on error."""
    try:
        path = Path(file_path)
        if path.exists():
            path.unlink()
        return True
    except OSError as exc:
        logger.error("Error removing file %s: %s", file_path, exc)
        return False


# ---------------------------------------------------------------------------
# Data transformation
# ---------------------------------------------------------------------------
def flatten_dict(d: Dict[str, Any], parent_key: str = "", sep: str = "_") -> Dict[str, Any]:
    """Flatten a nested dictionary into a single-level dict with separated keys."""
    items: List[tuple] = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)


def truncate_text(text: str, max_length: int = 100, suffix: str = "...") -> str:
    """Truncate text to *max_length* characters, appending *suffix* if truncated."""
    if len(text) <= max_length:
        return text
    return text[: max_length - len(suffix)] + suffix


# ---------------------------------------------------------------------------
# Request / Logging helpers
# ---------------------------------------------------------------------------
def generate_request_id() -> str:
    """Generate a short random request/correlation ID."""
    return secrets.token_hex(8)
