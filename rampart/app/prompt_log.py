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


class PolicyResult(BaseModel):
    policy_id: str = ""
    status: str = ""  # "pass" or "fail"
    severity: str = ""
    action: str = ""  # "block" or "warn"
    message: str = ""  # violation message if failed


class PromptLogEntry(BaseModel):
    timestamp: str = ""
    source: str = ""  # "api", "gateway", "playground"
    user: Optional[str] = None
    client_id: Optional[str] = None
    owner: Optional[str] = None
    source_ip: Optional[str] = None
    model: Optional[str] = None
    messages: list[dict[str, Any]] = Field(default_factory=list)
    resolved_groups: list[str] = Field(default_factory=list)  # external groups from identity provider
    mapped_rampart_groups: list[str] = Field(default_factory=list)  # RAMPART groups after mapping
    decision: str = ""  # "accept" or "fail"
    policy_results: list[PolicyResult] = Field(default_factory=list)
    violations: list[dict[str, Any]] = Field(default_factory=list)
    applied_policies: list[str] = Field(default_factory=list)
    eval_ms: Optional[int] = None
    warnings: list[str] = Field(default_factory=list)


# Module-level ring buffer
_buffer: deque[PromptLogEntry] = deque(maxlen=10000)
_total_appended: int = 0


def log_prompt(entry: PromptLogEntry) -> None:
    """Append a prompt log entry to the in-memory buffer."""
    global _total_appended
    if not entry.timestamp:
        entry.timestamp = datetime.now(timezone.utc).isoformat()
    _buffer.append(entry)
    _total_appended += 1


def get_entries(limit: int = 200, offset: int = 0) -> list[PromptLogEntry]:
    """Return entries in reverse chronological order (newest first)."""
    entries = list(reversed(_buffer))
    return entries[offset:offset + limit]


def get_entry_count() -> int:
    return len(_buffer)


def get_entries_since(cursor: int) -> tuple[list[PromptLogEntry], int]:
    """Return entries added since cursor position. Returns (entries, new_cursor).

    Cursor is the total number of entries ever appended. If the buffer has
    wrapped past the cursor, returns all current entries and resets cursor.
    """
    total_appended = _total_appended
    if cursor >= total_appended:
        return [], cursor
    buf_list = list(_buffer)
    available = total_appended - cursor
    if available > len(buf_list):
        return buf_list, total_appended
    return buf_list[-available:], total_appended


def clear() -> None:
    global _total_appended
    _buffer.clear()
    _total_appended = 0


def set_max_size(size: int) -> None:
    """Resize the buffer. Existing entries beyond the new max are dropped (oldest first)."""
    global _buffer
    old = list(_buffer)
    _buffer = deque(old, maxlen=size)


def build_policy_results(policies: list, violations: list) -> list[PolicyResult]:
    """Build per-policy pass/fail results from policies and violations."""
    violation_map: dict[str, list] = {}
    for v in violations:
        pid = v.policy_id if hasattr(v, "policy_id") else v.get("policy_id", "")
        violation_map.setdefault(pid, []).append(v)

    results = []
    for policy in policies:
        pid = policy.id if hasattr(policy, "id") else policy.get("id", "")
        severity = policy.severity if hasattr(policy, "severity") else policy.get("severity", "")
        action = policy.action if hasattr(policy, "action") else policy.get("action", "")
        matched = violation_map.get(pid, [])
        if matched:
            v = matched[0]
            msg = v.message if hasattr(v, "message") else v.get("message", "")
            results.append(PolicyResult(policy_id=pid, status="fail", severity=severity, action=action, message=msg))
        else:
            results.append(PolicyResult(policy_id=pid, status="pass", severity=severity, action=action))
    return results


def to_json(entry: PromptLogEntry) -> str:
    """Serialize entry to JSON string (syslog/Splunk-ready)."""
    return json.dumps(entry.model_dump(), sort_keys=True, ensure_ascii=True)
