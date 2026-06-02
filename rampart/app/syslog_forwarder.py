"""CEF syslog forwarder for prompt evaluation events."""
from __future__ import annotations

import json
import logging
import socket
from datetime import datetime, timezone
from typing import Optional

from rampart.app.prompt_log import PolicyResult, PromptLogEntry

logger = logging.getLogger(__name__)

_SEVERITY_MAP = {"low": 3, "medium": 5, "high": 7, "critical": 9}
_VERSION = "0.1.0"


def map_severity(decision: str, policy_results: list[PolicyResult]) -> int:
    if decision == "accept":
        has_warnings = any(pr.status == "fail" for pr in policy_results)
        return 3 if has_warnings else 1
    highest = "medium"
    for pr in policy_results:
        if pr.status == "fail" and _SEVERITY_MAP.get(pr.severity, 0) > _SEVERITY_MAP.get(highest, 0):
            highest = pr.severity
    return _SEVERITY_MAP.get(highest, 5)


def format_cef(entry: PromptLogEntry) -> str:
    severity = map_severity(entry.decision, entry.policy_results)
    extensions = _build_extensions(entry)
    return f"CEF:0|Engineering|RAMPART|{_VERSION}|prompt-eval|Prompt Evaluation|{severity}|{extensions}"


def _build_extensions(entry: PromptLogEntry) -> str:
    parts: list[str] = []
    if entry.timestamp:
        try:
            dt = datetime.fromisoformat(entry.timestamp)
            parts.append(f"rt={int(dt.timestamp() * 1000)}")
        except (ValueError, OSError):
            parts.append(f"rt={entry.timestamp}")
    if entry.source_ip:
        parts.append(f"src={_esc(entry.source_ip)}")
    if entry.user:
        parts.append(f"duser={_esc(entry.user)}")
    parts.append(f"cs1={_esc(entry.decision)}")
    parts.append("cs1Label=decision")
    parts.append(f"cs2={_esc(entry.source)}")
    parts.append("cs2Label=source")
    if entry.model:
        parts.append(f"cs3={_esc(entry.model)}")
        parts.append("cs3Label=model")
    if entry.policy_results:
        pr_json = json.dumps(
            [{"id": pr.policy_id, "s": pr.status, "sev": pr.severity} for pr in entry.policy_results],
            separators=(",", ":"),
        )
        parts.append(f"cs4={_esc(pr_json)}")
        parts.append("cs4Label=policyResults")
    if entry.resolved_groups:
        parts.append(f"cs5={_esc(','.join(entry.resolved_groups))}")
        parts.append("cs5Label=resolvedGroups")
    if entry.mapped_rampart_groups:
        parts.append(f"cs6={_esc(','.join(entry.mapped_rampart_groups))}")
        parts.append("cs6Label=rampartGroups")
    msg = _extract_user_message(entry.messages)
    if msg:
        parts.append(f"msg={_esc(msg[:1024])}")
    parts.append(f"outcome={_esc(entry.decision)}")
    return " ".join(parts)


def _extract_user_message(messages: list) -> str:
    for msg in messages:
        if not isinstance(msg, dict) or msg.get("role") != "user":
            continue
        content = msg.get("content", "")
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            for part in content:
                if isinstance(part, dict) and isinstance(part.get("text"), str):
                    return part["text"]
    return ""


def _esc(value: str) -> str:
    """Escape CEF special characters."""
    return value.replace("\\", "\\\\").replace("|", "\\|").replace("=", "\\=").replace("\n", "\\n").replace("\r", "\\r")


def format_cef_audit(event: dict) -> str:
    """Format an audit event (admin action) as CEF."""
    action = event.get("action", "unknown")
    result = event.get("result", "unknown")
    severity = 3 if result == "success" else 7
    parts: list[str] = []
    ts = event.get("timestamp", "")
    if ts:
        try:
            dt = datetime.fromisoformat(ts)
            parts.append(f"rt={int(dt.timestamp() * 1000)}")
        except (ValueError, OSError):
            parts.append(f"rt={_esc(ts)}")
    if event.get("ip"):
        parts.append(f"src={_esc(event['ip'])}")
    if event.get("actor"):
        parts.append(f"suser={_esc(event['actor'])}")
    parts.append(f"act={_esc(action)}")
    if event.get("target"):
        parts.append(f"duser={_esc(event['target'])}")
    parts.append(f"outcome={_esc(result)}")
    if event.get("detail"):
        parts.append(f"msg={_esc(str(event['detail'])[:1024])}")
    return f"CEF:0|Engineering|RAMPART|{_VERSION}|audit|Admin Action|{severity}|{' '.join(parts)}"


def format_cef_tracking(event: dict) -> str:
    """Format an evaluation tracking event as CEF."""
    decision = event.get("decision", "unknown")
    violations = event.get("violations", [])
    severity = 1
    if decision == "fail":
        severities = [v.get("severity", "medium") for v in violations]
        highest = "medium"
        for s in severities:
            if _SEVERITY_MAP.get(s, 0) > _SEVERITY_MAP.get(highest, 0):
                highest = s
        severity = _SEVERITY_MAP.get(highest, 5)
    parts: list[str] = []
    ts = event.get("timestamp", "")
    if ts:
        try:
            dt = datetime.fromisoformat(ts)
            parts.append(f"rt={int(dt.timestamp() * 1000)}")
        except (ValueError, OSError):
            parts.append(f"rt={_esc(ts)}")
    if event.get("client_id"):
        parts.append(f"duser={_esc(event['client_id'])}")
    if event.get("user"):
        parts.append(f"suser={_esc(event['user'])}")
    if event.get("customer"):
        parts.append(f"cs1={_esc(event['customer'])}")
        parts.append("cs1Label=customer")
    parts.append(f"outcome={_esc(decision)}")
    if violations:
        v_json = json.dumps([{"id": v.get("policy_id"), "sev": v.get("severity")} for v in violations], separators=(",", ":"))
        parts.append(f"cs2={_esc(v_json)}")
        parts.append("cs2Label=violations")
    policies = event.get("applied_policies", [])
    if policies:
        parts.append(f"cs3={_esc(','.join(policies))}")
        parts.append("cs3Label=appliedPolicies")
    return f"CEF:0|Engineering|RAMPART|{_VERSION}|eval-track|Evaluation Event|{severity}|{' '.join(parts)}"


# Module-level sender for direct forwarding from audit/tracking writers
_shared_sender: Optional["SyslogSender"] = None


def get_shared_sender() -> Optional["SyslogSender"]:
    """Return the shared sender if syslog is enabled, or None."""
    return _shared_sender


def init_shared_sender(host: str, port: int, protocol: str) -> None:
    """Initialize the shared sender (called from main.py startup)."""
    global _shared_sender
    _shared_sender = SyslogSender(host, port, protocol)


class SyslogSender:
    """Sends CEF messages over TCP or UDP."""

    def __init__(self, host: str, port: int, protocol: str = "udp"):
        self.host = host
        self.port = port
        self.protocol = protocol.lower()
        self._tcp_sock: Optional[socket.socket] = None

    def send(self, message: str) -> None:
        data = message.encode("utf-8")
        if self.protocol == "tcp":
            self._send_tcp(data)
        else:
            self._send_udp(data)

    def _send_udp(self, data: bytes) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(data, (self.host, self.port))

    def _send_tcp(self, data: bytes) -> None:
        try:
            if self._tcp_sock is None:
                self._tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._tcp_sock.settimeout(5.0)
                self._tcp_sock.connect((self.host, self.port))
            self._tcp_sock.sendall(data + b"\n")
        except OSError:
            self._close_tcp()
            raise

    def _close_tcp(self) -> None:
        if self._tcp_sock:
            try:
                self._tcp_sock.close()
            except OSError:
                pass
            self._tcp_sock = None

    def close(self) -> None:
        self._close_tcp()
