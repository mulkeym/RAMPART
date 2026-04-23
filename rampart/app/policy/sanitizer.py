from __future__ import annotations

from copy import deepcopy
import re
from typing import Any, Optional

SECRET_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|password|secret|token)\s*[:=]\s*['\"]?[^'\"\s,}]+"),
    re.compile(r"sk-[A-Za-z0-9_\-]{16,}"),
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
]


def redact_text(value: str) -> str:
    redacted = value
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)
    return redacted


def sanitize_request(request: dict[str, Any], denied_tools: Optional[set[str]] = None) -> dict[str, Any]:
    sanitized = deepcopy(request)
    for message in sanitized.get("messages") or []:
        content = message.get("content")
        if isinstance(content, str):
            message["content"] = redact_text(content)
        elif isinstance(content, list):
            for part in content:
                if isinstance(part, dict) and isinstance(part.get("text"), str):
                    part["text"] = redact_text(part["text"])

    if denied_tools and isinstance(sanitized.get("tools"), list):
        sanitized["tools"] = [
            tool
            for tool in sanitized["tools"]
            if _tool_name(tool) not in denied_tools
        ]

    return sanitized


def _tool_name(tool: Any) -> Optional[str]:
    if not isinstance(tool, dict):
        return None
    function = tool.get("function")
    if isinstance(function, dict) and isinstance(function.get("name"), str):
        return function["name"]
    name = tool.get("name")
    return name if isinstance(name, str) else None
