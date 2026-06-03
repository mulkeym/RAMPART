from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse

from rampart.app.config import get_config
from rampart.app.security.auth import read_session_user, require_ui_user

router = APIRouter(include_in_schema=False)


def aggregate_dashboard_data(log_path: str, range_hours: int = 24) -> Dict[str, Any]:
    """Read evaluations.jsonl and compute all dashboard metrics.

    Parameters
    ----------
    log_path:
        Path to the JSONL evaluation log file.
    range_hours:
        Number of hours into the past to consider as the *current* window.
        A prior window of the same length is used for change-% calculations.

    Returns
    -------
    dict  matching the dashboard JSON spec.
    """

    now = datetime.now(timezone.utc)
    window_start = now - timedelta(hours=range_hours)
    prior_start = window_start - timedelta(hours=range_hours)

    # ── load events ─────────────────────────────────────────────────────
    path = Path(log_path)
    current_events: List[Dict[str, Any]] = []
    prior_count = 0

    if path.exists():
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                ts_str = event.get("timestamp")
                if not ts_str:
                    continue
                try:
                    ts = datetime.fromisoformat(ts_str)
                except (ValueError, TypeError):
                    continue
                # Ensure timezone-aware
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                if ts >= window_start:
                    event["_ts"] = ts
                    current_events.append(event)
                elif ts >= prior_start:
                    prior_count += 1

    # ── stats ───────────────────────────────────────────────────────────
    total_requests = len(current_events)
    total_violations = sum(
        1 for e in current_events if e.get("decision") == "fail"
    )
    block_rate = (
        round(total_violations / total_requests * 100, 2) if total_requests else 0.0
    )

    # active users: prefer "user" field, fall back to "client_id"
    active_user_set: set[str] = set()
    for e in current_events:
        user = e.get("user")
        if user:
            active_user_set.add(str(user))
        else:
            cid = e.get("client_id")
            if cid:
                active_user_set.add(str(cid))
    active_users = len(active_user_set)

    eval_times = [e["eval_ms"] for e in current_events if isinstance(e.get("eval_ms"), (int, float))]
    avg_eval_ms = round(sum(eval_times) / len(eval_times), 2) if eval_times else 0.0
    if eval_times:
        sorted_times = sorted(eval_times)
        p95_idx = max(0, int(len(sorted_times) * 0.95) - 1)
        p95_eval_ms = sorted_times[p95_idx]
    else:
        p95_eval_ms = 0.0

    change_pct = (
        round((total_requests - prior_count) / prior_count * 100, 2)
        if prior_count
        else 0.0
    )

    stats = {
        "total_requests": total_requests,
        "total_violations": total_violations,
        "block_rate": block_rate,
        "active_users": active_users,
        "avg_eval_ms": avg_eval_ms,
        "p95_eval_ms": p95_eval_ms,
        "change_pct": change_pct,
    }

    # ── volume buckets ──────────────────────────────────────────────────
    if range_hours <= 1:
        bucket_minutes = 10
    elif range_hours <= 6:
        bucket_minutes = 30
    else:
        bucket_minutes = 60

    bucket_delta = timedelta(minutes=bucket_minutes)
    volume: List[Dict[str, Any]] = []
    bucket_start = window_start
    while bucket_start < now:
        bucket_end = bucket_start + bucket_delta
        accepted = 0
        failed = 0
        for e in current_events:
            ts = e["_ts"]
            if bucket_start <= ts < bucket_end:
                if e.get("decision") == "fail":
                    failed += 1
                else:
                    accepted += 1
        volume.append({
            "time": bucket_start.isoformat(),
            "accepted": accepted,
            "failed": failed,
        })
        bucket_start = bucket_end

    # ── policy hits (from violations, top 10) ───────────────────────────
    policy_counter: Dict[str, Dict[str, Any]] = {}
    for e in current_events:
        violations = e.get("violations")
        if not isinstance(violations, list):
            continue
        for v in violations:
            pid = v.get("policy_id", "unknown")
            if pid not in policy_counter:
                policy_counter[pid] = {
                    "policy_id": pid,
                    "count": 0,
                    "severity": v.get("severity", "unknown"),
                }
            policy_counter[pid]["count"] += 1

    policy_hits = sorted(policy_counter.values(), key=lambda x: x["count"], reverse=True)[:10]

    # ── eval sources ────────────────────────────────────────────────────
    eval_sources: Dict[str, int] = defaultdict(int)
    for e in current_events:
        violations = e.get("violations")
        if not isinstance(violations, list):
            continue
        for v in violations:
            source = v.get("source", "unknown")
            eval_sources[source] += 1
    eval_sources = dict(eval_sources)

    # ── model usage ─────────────────────────────────────────────────────
    model_usage: Dict[str, int] = defaultdict(int)
    for e in current_events:
        model = e.get("model")
        if model:
            model_usage[str(model)] += 1
    model_usage = dict(model_usage)

    # ── top users (top 10 by request count) ─────────────────────────────
    user_counter: Dict[str, int] = defaultdict(int)
    for e in current_events:
        user = e.get("user")
        if user:
            user_counter[str(user)] += 1
    top_users = sorted(
        [{"user": u, "count": c} for u, c in user_counter.items()],
        key=lambda x: x["count"],
        reverse=True,
    )[:10]

    # ── top clients (top 10 by request count) ───────────────────────────
    client_counter: Dict[str, int] = defaultdict(int)
    for e in current_events:
        cid = e.get("client_id")
        if cid:
            client_counter[str(cid)] += 1
    top_clients = sorted(
        [{"client_id": c, "count": n} for c, n in client_counter.items()],
        key=lambda x: x["count"],
        reverse=True,
    )[:10]

    # ── flagged users (top 10 by violation count) ───────────────────────
    flagged_counter: Dict[str, int] = defaultdict(int)
    for e in current_events:
        if e.get("decision") != "fail":
            continue
        user = e.get("user")
        if user:
            flagged_counter[str(user)] += 1
        else:
            cid = e.get("client_id")
            if cid:
                flagged_counter[str(cid)] += 1
    flagged_users = sorted(
        [{"user": u, "count": c} for u, c in flagged_counter.items()],
        key=lambda x: x["count"],
        reverse=True,
    )[:10]

    # ── group activity (from resolved_groups if present) ────────────────
    group_counter: Dict[str, int] = defaultdict(int)
    for e in current_events:
        groups = e.get("resolved_groups")
        if isinstance(groups, list):
            for g in groups:
                if g:
                    group_counter[str(g)] += 1
    group_activity = dict(group_counter)

    # ── recent violations (last 20) ────────────────────────────────────
    violation_events = [e for e in current_events if e.get("decision") == "fail"]
    violation_events.sort(key=lambda e: e.get("_ts", now), reverse=True)
    recent_violations: List[Dict[str, Any]] = []
    for e in violation_events[:20]:
        recent_violations.append({
            "timestamp": e.get("timestamp"),
            "client_id": e.get("client_id"),
            "user": e.get("user"),
            "model": e.get("model"),
            "violations": e.get("violations", []),
        })

    return {
        "stats": stats,
        "volume": volume,
        "policy_hits": policy_hits,
        "eval_sources": eval_sources,
        "model_usage": model_usage,
        "top_users": top_users,
        "top_clients": top_clients,
        "flagged_users": flagged_users,
        "group_activity": group_activity,
        "recent_violations": recent_violations,
    }
