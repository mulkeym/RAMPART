from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel

from rampart.app.config import TrackingConfig
from rampart.app.models import EvaluationResponse


class ClientContext(BaseModel):
    customer: str = "default"
    client_id: str = "default-client"
    owner: Optional[str] = None
    request_id: Optional[str] = None
    user: Optional[str] = None


class CustomerSummary(BaseModel):
    customer: str
    client_id: str
    failed_requests: int = 0
    violation_count: int = 0
    high_critical_count: int = 0
    last_seen: Optional[str] = None


class PolicySummary(BaseModel):
    customer: str
    client_id: str
    policy_id: str
    severity: str
    category: str
    count: int = 0
    last_seen: Optional[str] = None


def write_evaluation_event(
    config: TrackingConfig,
    client: ClientContext,
    response: EvaluationResponse,
    applied_policies: list[str],
) -> None:
    if not config.enabled:
        return
    if response.decision == "accept" and not config.log_accepted_requests:
        return

    path = Path(config.log_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    event: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "customer": client.customer,
        "client_id": client.client_id,
        "owner": client.owner,
        "request_id": client.request_id,
        "user": client.user,
        "decision": response.decision,
        "applied_policies": applied_policies,
        "violations": [
            {
                "policy_id": violation.policy_id,
                "severity": violation.severity,
                "category": violation.category,
                "source": violation.source,
            }
            for violation in response.violations
        ],
    }
    if config.include_sanitized_prompt and response.sanitized_request:
        event["sanitized_request"] = response.sanitized_request

    with path.open("a", encoding="utf-8") as event_log:
        event_log.write(json.dumps(event, sort_keys=True) + "\n")
    # Forward to syslog if enabled
    try:
        from rampart.app.syslog_forwarder import get_shared_sender, format_cef_tracking
        sender = get_shared_sender()
        if sender:
            sender.send(format_cef_tracking(event))
    except Exception:
        pass  # syslog failure must not break evaluation tracking


def load_evaluation_events(path: str) -> list[dict[str, Any]]:
    import logging
    logger = logging.getLogger(__name__)
    event_path = Path(path)
    if not event_path.exists():
        return []
    events: list[dict[str, Any]] = []
    corrupted = 0
    with event_path.open("r", encoding="utf-8") as event_log:
        for line_num, line in enumerate(event_log, 1):
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                corrupted += 1
                if corrupted <= 10:
                    logger.warning("Corrupted JSONL at %s:%d — skipping line", path, line_num)
    if corrupted:
        logger.warning("Loaded %d events from %s, skipped %d corrupted lines", len(events), path, corrupted)
    return events


def summarize_customers(events: list[dict[str, Any]]) -> list[CustomerSummary]:
    summaries: dict[tuple[str, str], CustomerSummary] = {}
    for event in events:
        if event.get("decision") != "fail":
            continue
        customer = str(event.get("customer") or "default")
        client_id = str(event.get("client_id") or "default-client")
        key = (customer, client_id)
        summary = summaries.setdefault(key, CustomerSummary(customer=customer, client_id=client_id))
        violations = event.get("violations") if isinstance(event.get("violations"), list) else []
        summary.failed_requests += 1
        summary.violation_count += len(violations)
        summary.high_critical_count += sum(
            1 for violation in violations if violation.get("severity") in {"high", "critical"}
        )
        summary.last_seen = _latest(summary.last_seen, event.get("timestamp"))
    return sorted(summaries.values(), key=lambda item: (item.last_seen or "", item.customer, item.client_id), reverse=True)


def summarize_policies(events: list[dict[str, Any]], customer: Optional[str] = None, client_id: Optional[str] = None) -> list[PolicySummary]:
    summaries: dict[tuple[str, str, str, str, str], PolicySummary] = {}
    for event in events:
        if event.get("decision") != "fail":
            continue
        event_customer = str(event.get("customer") or "default")
        event_client_id = str(event.get("client_id") or "default-client")
        if customer and event_customer != customer:
            continue
        if client_id and event_client_id != client_id:
            continue
        violations = event.get("violations") if isinstance(event.get("violations"), list) else []
        for violation in violations:
            policy_id = str(violation.get("policy_id") or "unknown")
            severity = str(violation.get("severity") or "unknown")
            category = str(violation.get("category") or "policy")
            key = (event_customer, event_client_id, policy_id, severity, category)
            summary = summaries.setdefault(
                key,
                PolicySummary(
                    customer=event_customer,
                    client_id=event_client_id,
                    policy_id=policy_id,
                    severity=severity,
                    category=category,
                ),
            )
            summary.count += 1
            summary.last_seen = _latest(summary.last_seen, event.get("timestamp"))
    return sorted(summaries.values(), key=lambda item: (item.count, item.last_seen or ""), reverse=True)


def _latest(current: Optional[str], candidate: Any) -> Optional[str]:
    if not isinstance(candidate, str):
        return current
    if current is None or candidate > current:
        return candidate
    return current
