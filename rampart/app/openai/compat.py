from __future__ import annotations

from typing import Any, Optional


def iter_message_text(request: dict[str, Any]):
    for index, message in enumerate(request.get("messages") or []):
        content = message.get("content")
        path = f"messages[{index}].content"
        if isinstance(content, str):
            yield path, content
        elif isinstance(content, list):
            for part_index, part in enumerate(content):
                if isinstance(part, dict) and isinstance(part.get("text"), str):
                    yield f"{path}[{part_index}].text", part["text"]


def extract_tool_names(request: dict[str, Any]) -> list[str]:
    names: list[str] = []
    for tool in request.get("tools") or []:
        if not isinstance(tool, dict):
            continue
        function = tool.get("function")
        if isinstance(function, dict) and isinstance(function.get("name"), str):
            names.append(function["name"])
        elif isinstance(tool.get("name"), str):
            names.append(tool["name"])
    return names


def extract_model(request: dict[str, Any]) -> Optional[str]:
    model = request.get("model")
    return model if isinstance(model, str) else None


def extract_user(request: dict[str, Any]) -> Optional[str]:
    user = request.get("user")
    return user if isinstance(user, str) else None
