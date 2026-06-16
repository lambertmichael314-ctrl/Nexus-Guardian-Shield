import json
import logging
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from sqlmodel import select

from backend.core.events import publish_event
from backend.database import get_db_context
from backend.models import ScanResult, ScanStatus, Severity

logger = logging.getLogger("cti_platform.analysis_engine")

# ---------------------------------------------------------------------------
# Security Allowlist
# ---------------------------------------------------------------------------
# Only these module names may be dynamically imported.  This prevents an
# attacker who controls the DB from loading arbitrary Python code.
_ANALYZER_ALLOWLIST: frozenset[str] = frozenset({
    "adware_detector",
    "trojan_analyzer",
    "ddos_analyzer",
    "keylogger_analyzer",
    "logic_bomb_analyzer",
    "ransomware_analyzer",
    "rootkit_analyzer",
    "spyware_analyzer",
    "virus_analyzer",
    "worm_analyzer",
    "yara_scanner",
})

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _now() -> datetime:
    """Return timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


def _is_safe_module_name(name: str) -> bool:
    """Validate that *name* is a simple Python module identifier."""
    if not name:
        return False
    # Must be alphanumeric + underscores only (no paths, no shell metacharacters)
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
        return False
    return name in _ANALYZER_ALLOWLIST


def _serialize_result(obj: Any) -> Any:
    """Recursively coerce non-JSON types to strings."""
    if isinstance(obj, dict):
        return {k: _serialize_result(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_serialize_result(v) for v in obj]
    try:
        json.dumps(obj)
        return obj
    except (TypeError, ValueError):
        return str(obj)


# ---------------------------------------------------------------------------
# Core Analysis Task
# ---------------------------------------------------------------------------
def run_analysis(
    scan_result_id: int,
    target_path: str,
    analyzers: Optional[List[str]] = None,
    timeout_seconds: int = 300,
) -> Dict[str, Any]:
    """Execute malware analysis for a given ScanResult.

    This function is designed to run as a Celery task or a background
    thread.  It reads the sample from *target_path*, runs every enabled
    analyzer (or the subset listed in *analyzers*), aggregates the
    results, and updates the ScanResult row in the database.

    SECURITY:
        - *target_path* is assumed to be a randomized, quarantined
          storage path managed by the upload endpoint.
        - Each analyzer is executed in a **subprocess** so that
          runaway CPU / memory / blocking IO cannot freeze the worker.
        - Module names are validated against a hard-coded allowlist.

    Args:
        scan_result_id: PK of the ScanResult row to update.
        target_path: Absolute path to the file on disk.
        analyzers: Optional list of analyzer module names to run.
                   Defaults to the full allowlist.
        timeout_seconds: Max wall-clock time per analyzer.

    Returns:
        A dict summarising the outcome: ``{"status": "...", "scan_result_id": N}``
    """
    if not analyzers:
        analyzers = sorted(_ANALYZER_ALLOWLIST)

    logger.info(
        "Starting analysis | scan_result_id=%s target=%s analyzers=%s",
        scan_result_id, target_path, analyzers,
    )

    # ------------------------------------------------------------------
    # 1. Load scan row and mark ANALYZING
    # ------------------------------------------------------------------
    publish_event(scan_result_id, "status", {"status": "ANALYZING", "message": "Starting analysis pipeline", "total_analyzers": len(analyzers)})
    with get_db_context() as db:
        scan: Optional[ScanResult] = db.get(ScanResult, scan_result_id)
        if scan is None:
            logger.error("ScanResult %s not found", scan_result_id)
            publish_event(scan_result_id, "status", {"status": "FAILED", "error": "ScanResult not found"})
            return {"status": "failed", "error": "ScanResult not found", "scan_result_id": scan_result_id}

        scan.status = ScanStatus.ANALYZING
        scan.updated_at = _now()
        db.add(scan)
        db.commit()

    # ------------------------------------------------------------------
    # 2. Run each analyzer in an isolated subprocess
    # ------------------------------------------------------------------
    detector_results: Dict[str, Any] = {}
    overall_detected = False
    max_confidence = 0.0
    failed_analyzers: List[str] = []

    for mod_name in analyzers:
        if not _is_safe_module_name(mod_name):
            logger.warning("Skipping disallowed analyzer: %s", mod_name)
            failed_analyzers.append(f"{mod_name}: disallowed")
            publish_event(scan_result_id, "analyzer", {"name": mod_name, "status": "skipped", "reason": "disallowed"})
            continue

        publish_event(scan_result_id, "analyzer", {"name": mod_name, "status": "running"})
        result = _run_analyzer_subprocess(
            module_name=mod_name,
            target_path=target_path,
            timeout=timeout_seconds,
        )

        detector_results[mod_name] = result
        evt = {
            "name": mod_name,
            "status": "complete",
            "detected": bool(result.get("detected")),
            "confidence": result.get("confidence", 0.0),
        }
        if result.get("error"):
            evt["status"] = "error"
            evt["error"] = result["error"]
            failed_analyzers.append(f"{mod_name}: {result['error']}")
        publish_event(scan_result_id, "analyzer", evt)

        if result.get("detected"):
            overall_detected = True
        conf = result.get("confidence", 0.0)
        if isinstance(conf, (int, float)) and conf > max_confidence:
            max_confidence = conf

    # ------------------------------------------------------------------
    # 3. Determine final severity
    # ------------------------------------------------------------------
    severity = _severity_from_confidence(max_confidence, overall_detected)

    # ------------------------------------------------------------------
    # 4. Persist results
    # ------------------------------------------------------------------
    with get_db_context() as db:
        scan = db.get(ScanResult, scan_result_id)
        if scan is None:
            logger.error("ScanResult %s disappeared during analysis", scan_result_id)
            publish_event(scan_result_id, "status", {"status": "FAILED", "error": "Race condition: row missing"})
            return {"status": "failed", "error": "Race condition: row missing", "scan_result_id": scan_result_id}

        scan.status = ScanStatus.COMPLETED
        scan.is_malware = overall_detected
        scan.confidence = round(max_confidence, 4)
        scan.severity = severity
        scan.detector_results = _serialize_result(detector_results)
        scan.analysis_summary = _build_summary(detector_results, failed_analyzers)
        scan.updated_at = _now()
        db.add(scan)
        db.commit()

    logger.info(
        "Analysis completed | scan_result_id=%s detected=%s confidence=%s severity=%s",
        scan_result_id, overall_detected, max_confidence, severity,
    )

    publish_event(scan_result_id, "status", {
        "status": "COMPLETED",
        "detected": overall_detected,
        "confidence": max_confidence,
        "severity": severity.value if severity else None,
        "failed_analyzers": failed_analyzers or None,
    })

    return {
        "status": "completed",
        "scan_result_id": scan_result_id,
        "detected": overall_detected,
        "confidence": max_confidence,
        "severity": severity.value if severity else None,
        "failed_analyzers": failed_analyzers or None,
    }


def _run_analyzer_subprocess(
    module_name: str,
    target_path: str,
    timeout: int,
) -> Dict[str, Any]:
    """Spawn an analyzer in a separate Python process with a hard timeout.

    Returns a dict with keys: ``detected`` (bool), ``confidence`` (float),
    ``details`` (dict|None), ``error`` (str|None).
    """
    logger.debug("Running analyzer %s on %s (timeout=%ss)", module_name, target_path, timeout)

    # Build a minimal Python script that imports the module and calls analyze()
    if module_name == "yara_scanner":
        import_line = "from backend.analysis_engine.yara_scanner import analyze"
    else:
        import_line = f"from backend.analysis_engine.modules.{module_name} import analyze"
    script = (
        "import sys, json, traceback\n"
        f"{import_line}\n"
        "target = sys.argv[1]\n"
        "try:\n"
        "    result = analyze(target)\n"
        "    print(json.dumps(result, default=str))\n"
        "except Exception as e:\n"
        "    print(json.dumps({\"error\": str(e), \"traceback\": traceback.format_exc()}, default=str))\n"
    )

    try:
        proc = subprocess.run(
            [sys.executable, "-c", script, target_path],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=os.path.dirname(os.path.dirname(os.path.dirname(__file__))),  # project root
        )
    except subprocess.TimeoutExpired:
        logger.error("Analyzer %s timed out after %s seconds", module_name, timeout)
        return {"detected": False, "confidence": 0.0, "details": None, "error": f"timeout after {timeout}s"}
    except Exception as exc:
        logger.exception("Failed to spawn analyzer %s", module_name)
        return {"detected": False, "confidence": 0.0, "details": None, "error": str(exc)}

    if proc.returncode != 0:
        stderr = proc.stderr.strip()[:2000]
        logger.error("Analyzer %s exited %s: %s", module_name, proc.returncode, stderr)
        return {"detected": False, "confidence": 0.0, "details": None, "error": stderr}

    try:
        output = json.loads(proc.stdout.strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError) as exc:
        stdout = proc.stdout.strip()[:2000]
        logger.error("Analyzer %s returned invalid JSON: %s", module_name, stdout)
        return {"detected": False, "confidence": 0.0, "details": None, "error": f"invalid JSON: {exc}"}

    # Normalise the output shape
    if isinstance(output, dict) and output.get("error"):
        logger.error("Analyzer %s raised error: %s", module_name, output["error"])
        return {"detected": False, "confidence": 0.0, "details": None, "error": output["error"]}

    if not isinstance(output, dict):
        output = {"result": output}

    return {
        "detected": bool(output.get("detected", False)),
        "confidence": float(output.get("confidence", 0.0)),
        "details": output.get("details") or output,
        "error": None,
    }


def _severity_from_confidence(confidence: float, detected: bool) -> Optional[Severity]:
    """Map confidence score to a Severity enum."""
    if not detected:
        return None
    if confidence >= 0.9:
        return Severity.CRITICAL
    if confidence >= 0.7:
        return Severity.HIGH
    if confidence >= 0.5:
        return Severity.MEDIUM
    if confidence >= 0.3:
        return Severity.LOW
    return Severity.INFO


def _build_summary(
    detector_results: Dict[str, Any],
    failed_analyzers: List[str],
) -> str:
    """Generate a human-readable analysis summary."""
    lines: List[str] = []
    lines.append(f"Analyzed by {len(detector_results)} module(s).")

    hits = [name for name, res in detector_results.items() if res.get("detected")]
    if hits:
        lines.append(f"Positive detections: {', '.join(hits)}")
    else:
        lines.append("No positive detections.")

    if failed_analyzers:
        lines.append(f"Failures: {len(failed_analyzers)}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Celery-compatible wrapper (optional — uncomment when Celery is configured)
# ---------------------------------------------------------------------------
# try:
#     from celery import shared_task
#
#     @shared_task(bind=True, max_retries=2, default_retry_delay=30)
#     def celery_analyze_sample(self, scan_result_id: int, target_path: str, **kwargs):
#         try:
#             return run_analysis(scan_result_id, target_path, **kwargs)
#         except Exception as exc:
#             logger.exception("Celery task failed for scan_result_id=%s", scan_result_id)
#             raise self.retry(exc=exc)
# except ImportError:
#     celery_analyze_sample = None
