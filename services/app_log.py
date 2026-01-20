import datetime
from collections import deque
from typing import Any, Deque, Dict, List, Optional


# Lightweight in-process audit log for the admin console.
# This is separate from Python logging and is intended to be shown in the UI.
_LOG_BUFFER: Deque[Dict[str, Any]] = deque(maxlen=500)


def add_event(event_type: str, message: str, meta: Optional[Dict[str, Any]] = None, level: str = "INFO") -> None:
    _LOG_BUFFER.append({
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "level": level,
        "type": event_type,
        "message": message,
        "meta": meta or {},
    })


def list_events(limit: int = 100) -> List[Dict[str, Any]]:
    if limit <= 0:
        return []
    items = list(_LOG_BUFFER)
    return items[-limit:]


def clear_events() -> None:
    _LOG_BUFFER.clear()

