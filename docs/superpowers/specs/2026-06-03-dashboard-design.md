# RAMPART Dashboard — Design Spec

**Date:** 2026-06-03
**Status:** Draft
**Scope:** Analytics dashboard as the landing page for the RAMPART admin UI

---

## Problem

RAMPART has no at-a-glance view of how AI is being used, what's being blocked, or who the most active users are. Admins must dig through the Prompt Log or Violations page to understand usage patterns. A dashboard provides immediate operational awareness.

## Overview

A rich analytics dashboard at `/ui/dashboard` becomes the landing page after login. It aggregates data from the evaluation JSONL log file and displays interactive charts (Chart.js bundled inline for air-gapped environments), stat cards, and leaderboard tables. Auto-refreshes every 30 seconds with selectable time ranges (1h / 6h / 24h).

## Data Source

**Primary:** `logs/evaluations.jsonl` — persistent, append-only evaluation events.

**Change required:** Default `log_accepted_requests` to `true` so accepted requests are also tracked. Without this, the dashboard only shows failures.

**User identity:** Use the `user` field when available, fall back to `client_id` for unique user counting and leaderboards.

## Route

- **URL:** `/ui/dashboard`
- **Landing page:** Login redirect changes from `/ui/policies` to `/ui/dashboard`
- **Nav:** First item in navigation bar

## Layout

### Row 1 — Stat Cards (4 across)

| Card | Value | Subtitle |
|------|-------|----------|
| Total Requests | count | % change vs prior period |
| Violations | count | block rate % |
| Active Users | unique count | user field or client_id fallback |
| Avg Eval Time | milliseconds | p95 value |

### Row 2 — Primary Charts (2 columns, 60/40 split)

**Left (wide): Request Volume**
- Stacked bar chart
- Bucketed by hour (24h), 10min (1h), or 30min (6h)
- Green bars = accepted, red bars = failed
- X-axis: time labels, Y-axis: request count

**Right: Policy Violation Breakdown**
- Horizontal bar chart
- Ranked by hit count, top 10
- Colored by severity (critical=red, high=orange, medium=yellow, low=gray)

### Row 3 — Secondary Charts (2 columns, 50/50)

**Left: Eval Source Breakdown**
- Pie/doughnut chart
- Segments: deterministic, LLM, vision
- Shows where violations are being caught

**Right: Model Usage**
- Pie/doughnut chart
- Segments by model name from requests
- Shows which LLMs users are requesting

### Row 4 — Tables (3 columns)

**Top Users** (by request count)
- Rank, user/client_id, request count
- Top 10

**Top Clients** (by request count)
- Rank, client_id, request count
- Top 10

**Flagged Users** (by violation count)
- Rank, user/client_id, violation count
- Top 10, red-highlighted

### Row 5 — Full Width

**Group Activity**
- Horizontal bar chart
- Requests per resolved Keycloak group (from `resolved_groups` or mapped RAMPART groups in tracking data)
- Only shows if group data is present

**Recent Violations Feed**
- Last 20 blocked requests
- Scrollable, compact rows
- Shows: time, user, policy, severity
- Live-updating on auto-refresh

## Time Range & Auto-Refresh

**Time range selector:** Pill buttons at top right: `1h` | `6h` | `24h`
- Default: 24h
- Clicking triggers immediate reload
- URL parameter: `?range=1h`

**Auto-refresh:** Every 30 seconds via JS
- Fetches `/ui/dashboard/data?range=24h` (JSON endpoint)
- Updates all charts and stats without full page reload
- Pause indicator when user hovers over charts

## Charting

**Library:** Chart.js v4 minified, bundled inline as a JS string constant in the Python source. No CDN dependency — works air-gapped.

**Theme:** Dark theme matching RAMPART UI:
- Background: transparent (inherits page bg)
- Grid lines: rgba(255,255,255,0.05)
- Text: #8b949e
- Accept color: #3fb950
- Fail color: #f85149
- Severity colors: critical=#f85149, high=#d29922, medium=#e3b341, low=#8b949e

## Data Aggregation

**JSON data endpoint:** `GET /ui/dashboard/data?range=24h`

Returns pre-aggregated data for all widgets:

```json
{
  "stats": {
    "total_requests": 12847,
    "total_violations": 342,
    "block_rate": 2.7,
    "active_users": 89,
    "avg_eval_ms": 45,
    "p95_eval_ms": 210,
    "change_pct": 18.2
  },
  "volume": {
    "labels": ["12am", "1am", ...],
    "accepted": [120, 95, ...],
    "failed": [5, 3, ...]
  },
  "policy_hits": [
    {"policy_id": "no-pii", "count": 142, "severity": "high"},
    ...
  ],
  "eval_sources": {"deterministic": 180, "llm": 140, "vision": 22},
  "model_usage": {"gpt-4": 8000, "gpt-3.5": 3000, ...},
  "top_users": [{"user": "jsmith@dha.mil", "count": 234}, ...],
  "top_clients": [{"client_id": "ask-sage", "count": 8421}, ...],
  "flagged_users": [{"user": "bad.actor", "violations": 23}, ...],
  "group_activity": [{"group": "DHA-Clinical", "count": 3400}, ...],
  "recent_violations": [
    {"timestamp": "...", "user": "...", "policy_id": "...", "severity": "..."},
    ...
  ]
}
```

The data endpoint reads the JSONL file, filters by time range, and aggregates. This is called on page load and every 30 seconds.

## New Files

| File | Purpose |
|------|---------|
| `rampart/app/dashboard.py` | Route, data aggregation, HTML rendering, Chart.js bundle |

## Modified Files

| File | Change |
|------|--------|
| `rampart/app/ui.py` | Add Dashboard to nav (first position), change login redirect to `/ui/dashboard` |
| `rampart/app/config.py` | Default `log_accepted_requests` to `true` |
| `rampart/app/main.py` | Include dashboard router |

## Performance

The JSONL file is read and aggregated on each data request. For files with thousands of events this is fast (< 50ms). For very large files (100K+ events), we may need to add:
- File size monitoring
- Log rotation (keep last 24h, archive older)
- Pre-aggregated cache

These are not needed for v1 — the 24h time range naturally limits the data processed.
