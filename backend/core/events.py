"""Scan-progress event bus — in-memory pub/sub for Server-Sent Events.

SECURITY:
    - TTL eviction prevents unbounded memory growth (10 min after last write).
    - Per-scan isolation: clients can only subscribe to scan IDs they know.
    - No PII or file contents ever flow through events; only status + detector names.
"""

import asyncio
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator, Dict, List, Optional

# scan_id → list of {ts, event, data}
_events: Dict[int, List[dict]] = defaultdict(list)
_last_write: Dict[int, float] = {}

_TTL_SECONDS = 600  # 10 min
_HOUSEKEEPING_INTERVAL = 30  # seconds


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def publish_event(scan_id: int, event: str, data: Optional[Any] = None) -> None:
    """Append a progress event for *scan_id*. Thread-safe / sync-safe."""
    payload = {
        "ts": time.time(),
        "event": event,
        "data": data or {},
    }
    _events[scan_id].append(payload)
    _last_write[scan_id] = payload["ts"]


def get_history(scan_id: int) -> List[dict]:
    """Return all events previously published for *scan_id*."""
    return list(_events.get(scan_id, []))


async def event_stream(
    scan_id: int,
    heartbeat: float = 15.0,
) -> AsyncGenerator[str, None]:
    """Async generator yielding SSE-formatted strings for *scan_id*.

    Automatically replays prior events (so late subscribers see context)
    then yields new events as they arrive.
    """
    # Replay buffer
    history = get_history(scan_id)
    seen = len(history)
    for ev in history:
        yield _sse_line(ev)

    while True:
        current = _events.get(scan_id, [])
        if len(current) > seen:
            for ev in current[seen:]:
                yield _sse_line(ev)
            seen = len(current)
            _last_write[scan_id] = time.time()
        # Heartbeat comment to keep nginx/connection alive
        yield f":heartbeat\n\n"
        await asyncio.sleep(1.0)


# ---------------------------------------------------------------------------
# Housekeeping
# ---------------------------------------------------------------------------
async def housekeeping_loop() -> None:
    """Background coroutine that purges stale scan buffers."""
    cutoff = time.time() - _TTL_SECONDS
    stale = [
        sid for sid, last in _last_write.items()
        if last < cutoff
    ]
    for sid in stale:
        _events.pop(sid, None)
        _last_write.pop(sid, None)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _sse_line(ev: dict) -> str:
    """Format a dict as an SSE event string."""
    lines = [f"event: {ev['event']}", f"data: {__import__('json').dumps(ev['data'])}"]
    return "\n".join(lines) + "\n\n"
