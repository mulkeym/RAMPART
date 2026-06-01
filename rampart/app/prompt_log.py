"""In-memory prompt audit log.

Captures full details of every prompt evaluation — API, gateway, and playground.
Designed for eventual forwarding to syslog/Splunk (structured JSON entries).
"""
from __future__ import annotations

import json
from collections import deque
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field


class PromptLogEntry(BaseModel):
    timestamp: str = ""
    source: str = ""  # "api", "gateway", "playground"
    user: Optional[str] = None
    client_id: Optional[str] = None
    owner: Optional[str] = None
    source_ip: Optional[str] = None
    model: Optional[str] = None
    messages: list[dict[str, Any]] = Field(default_factory=list)
    decision: str = ""  # "accept" or "fail"
    violations: list[dict[str, Any]] = Field(default_factory=list)
    applied_policies: list[str] = Field(default_factory=list)
    eval_ms: Optional[int] = None
    warnings: list[str] = Field(default_factory=list)


# Module-level ring buffer
_buffer: deque[PromptLogEntry] = deque(maxlen=10000)


def log_prompt(entry: PromptLogEntry) -> None:
    """Append a prompt log entry to the in-memory buffer."""
    if not entry.timestamp:
        entry.timestamp = datetime.now(timezone.utc).isoformat()
    _buffer.append(entry)


def get_entries(limit: int = 200, offset: int = 0) -> list[PromptLogEntry]:
    """Return entries in reverse chronological order (newest first)."""
    entries = list(reversed(_buffer))
    return entries[offset:offset + limit]


def get_entry_count() -> int:
    return len(_buffer)


def clear() -> None:
    _buffer.clear()


def set_max_size(size: int) -> None:
    """Resize the buffer. Existing entries beyond the new max are dropped (oldest first)."""
    global _buffer
    old = list(_buffer)
    _buffer = deque(old, maxlen=size)


def to_json(entry: PromptLogEntry) -> str:
    """Serialize entry to JSON string (syslog/Splunk-ready)."""
    return json.dumps(entry.model_dump(), sort_keys=True, ensure_ascii=True)
