from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from fastapi import Request

from rampart.app.config import get_config


def audit_event(
    request: Optional[Request],
    action: str,
    actor: Optional[str] = None,
    target: Optional[str] = None,
    result: str = "success",
    detail: Optional[str] = None,
) -> None:
    config = get_config().auth
    path = Path(config.audit_log_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    event: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "actor": actor or "anonymous",
        "action": action,
        "target": target,
        "result": result,
        "detail": detail,
    }
    if request is not None:
        event["ip"] = request.client.host if request.client else None
        event["user_agent"] = request.headers.get("user-agent")
    with path.open("a", encoding="utf-8") as audit_log:
        audit_log.write(json.dumps(event, sort_keys=True) + "\n")
    # Forward to syslog if enabled
    try:
        from rampart.app.syslog_forwarder import get_shared_sender, format_cef_audit
        sender = get_shared_sender()
        if sender:
            sender.send(format_cef_audit(event))
    except Exception:
        pass  # syslog failure must not break audit logging
