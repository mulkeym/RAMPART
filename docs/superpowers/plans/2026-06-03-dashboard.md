# RAMPART Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an analytics dashboard as the RAMPART landing page showing request volume, policy violations, user activity, and real-time metrics with interactive Chart.js charts.

**Architecture:** A new `dashboard.py` module handles the dashboard route and a JSON data endpoint. Data is aggregated from `evaluations.jsonl` on each request, filtered by time range. Chart.js is bundled inline (no CDN). Auto-refresh via JS setInterval calling the JSON endpoint every 30 seconds.

**Tech Stack:** Python (FastAPI), Chart.js v4 (bundled inline), existing RAMPART HTML/CSS patterns, JSONL file reading.

---

## File Structure

**New files:**
| File | Responsibility |
|------|---------------|
| `rampart/app/dashboard.py` | Dashboard route, JSON data endpoint, data aggregation, Chart.js HTML rendering |

**Modified files:**
| File | Change |
|------|--------|
| `rampart/app/tracking.py` | Add `model` and `eval_ms` fields to evaluation events |
| `rampart/app/main.py` | Pass `model` and `eval_ms` to tracking, include dashboard router, change login redirect |
| `rampart/app/config.py` | Default `log_accepted_requests` to `true` |
| `rampart/app/ui.py` | Add Dashboard to nav (first position), update home redirect |

---

### Task 1: Add model and eval_ms to tracking events

**Files:**
- Modify: `rampart/app/tracking.py`
- Modify: `rampart/app/main.py`

- [ ] **Step 1: Update `write_evaluation_event` signature and event dict in `tracking.py`**

Add `model` and `eval_ms` parameters to `write_evaluation_event` and include them in the event dict:

```python
def write_evaluation_event(
    config: TrackingConfig,
    client: ClientContext,
    response: EvaluationResponse,
    applied_policies: list[str],
    model: str = "",
    eval_ms: int = 0,
) -> None:
```

Add to the event dict (after `"user":`):

```python
        "model": model,
        "eval_ms": eval_ms,
```

- [ ] **Step 2: Update `_track_evaluation` in `main.py` to pass model and eval_ms**

The `_track_evaluation` function needs `openai_request` and `eval_ms` parameters. Update its signature:

```python
def _track_evaluation(config, request: Request, response: EvaluationResponse, client_record: Optional[ClientRecord], policies: list[PolicyConfig], user: Optional[str] = None, model: str = "", eval_ms: int = 0) -> None:
```

Pass them through to `write_evaluation_event`:

```python
    write_evaluation_event(config.tracking, client, response, applied_policies, model=model, eval_ms=eval_ms)
```

- [ ] **Step 3: Update callers of `_track_evaluation` in both endpoints**

In `/v1/rampart/evaluate`:
```python
    _track_evaluation(config, request, response, client_record, policies, user=user, model=payload.request.get("model", ""), eval_ms=eval_ms)
```

In `/v1/chat/completions`:
```python
    _track_evaluation(config, request, response, client_record, policies, user=user, model=payload.get("model", ""), eval_ms=eval_ms)
```

- [ ] **Step 4: Change `log_accepted_requests` default to `true` in `config.py`**

```python
    log_accepted_requests: bool = True
```

- [ ] **Step 5: Run all tests**

Run: `python -m pytest tests/ -x -q --ignore=tests/test_gateway.py`
Expected: All pass

- [ ] **Step 6: Commit**

```bash
git add rampart/app/tracking.py rampart/app/main.py rampart/app/config.py
git commit -m "feat: add model and eval_ms to tracking events, default log_accepted_requests to true"
```

---

### Task 2: Dashboard data aggregation

**Files:**
- Create: `rampart/app/dashboard.py`
- Test: `tests/test_dashboard.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_dashboard.py
import json
import pytest
from pathlib import Path
from rampart.app.dashboard import aggregate_dashboard_data


@pytest.fixture
def events_file(tmp_path):
    path = tmp_path / "events.jsonl"
    events = [
        {"timestamp": "2026-06-03T10:00:00+00:00", "client_id": "ask-sage", "user": "alice@test.com", "decision": "accept", "applied_policies": ["no-pii"], "violations": [], "model": "gpt-4", "eval_ms": 30},
        {"timestamp": "2026-06-03T10:05:00+00:00", "client_id": "ask-sage", "user": "bob@test.com", "decision": "fail", "applied_policies": ["no-pii", "no-creds"], "violations": [{"policy_id": "no-pii", "severity": "high", "category": "pii", "source": "deterministic"}], "model": "gpt-4", "eval_ms": 5},
        {"timestamp": "2026-06-03T11:00:00+00:00", "client_id": "internal", "user": "alice@test.com", "decision": "fail", "applied_policies": ["harmful-content"], "violations": [{"policy_id": "harmful-content", "severity": "high", "category": "harmful", "source": "llm"}], "model": "gpt-3.5", "eval_ms": 150},
        {"timestamp": "2026-06-03T11:30:00+00:00", "client_id": "ask-sage", "user": None, "decision": "accept", "applied_policies": ["no-pii"], "violations": [], "model": "gpt-4", "eval_ms": 25},
    ]
    with path.open("w") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")
    return str(path)


def test_aggregate_stats(events_file):
    data = aggregate_dashboard_data(events_file, range_hours=24)
    assert data["stats"]["total_requests"] == 4
    assert data["stats"]["total_violations"] == 2
    assert data["stats"]["active_users"] >= 2  # alice, bob (None falls back to client_id)


def test_aggregate_policy_hits(events_file):
    data = aggregate_dashboard_data(events_file, range_hours=24)
    hits = {h["policy_id"]: h["count"] for h in data["policy_hits"]}
    assert hits["no-pii"] == 1
    assert hits["harmful-content"] == 1


def test_aggregate_model_usage(events_file):
    data = aggregate_dashboard_data(events_file, range_hours=24)
    assert data["model_usage"]["gpt-4"] == 3
    assert data["model_usage"]["gpt-3.5"] == 1


def test_aggregate_eval_sources(events_file):
    data = aggregate_dashboard_data(events_file, range_hours=24)
    assert data["eval_sources"]["deterministic"] == 1
    assert data["eval_sources"]["llm"] == 1


def test_aggregate_top_users(events_file):
    data = aggregate_dashboard_data(events_file, range_hours=24)
    top = {u["user"]: u["count"] for u in data["top_users"]}
    assert top["alice@test.com"] == 2


def test_aggregate_empty_file(tmp_path):
    path = str(tmp_path / "empty.jsonl")
    data = aggregate_dashboard_data(path, range_hours=24)
    assert data["stats"]["total_requests"] == 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_dashboard.py -v`
Expected: FAIL — module not found

- [ ] **Step 3: Create `rampart/app/dashboard.py` with aggregation function**

```python
"""RAMPART Analytics Dashboard."""
from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse

from rampart.app.config import get_config
from rampart.app.security.auth import read_session_user, require_ui_user


router = APIRouter(include_in_schema=False)


def aggregate_dashboard_data(log_path: str, range_hours: int = 24) -> dict[str, Any]:
    """Read evaluation JSONL and aggregate metrics for the dashboard."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=range_hours)
    cutoff_iso = cutoff.isoformat()
    prior_cutoff_iso = (cutoff - timedelta(hours=range_hours)).isoformat()

    events: list[dict] = []
    prior_count = 0
    path = Path(log_path)
    if path.exists():
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                ts = event.get("timestamp", "")
                if ts >= cutoff_iso:
                    events.append(event)
                elif ts >= prior_cutoff_iso:
                    prior_count += 1

    total = len(events)
    failed = [e for e in events if e.get("decision") == "fail"]
    total_violations = len(failed)
    block_rate = round((total_violations / total * 100), 1) if total else 0
    change_pct = round(((total - prior_count) / prior_count * 100), 1) if prior_count else 0

    # Active users (user field, fallback to client_id)
    users = set()
    for e in events:
        user = e.get("user") or e.get("client_id") or "unknown"
        users.add(user)

    # Eval time stats
    eval_times = [e.get("eval_ms", 0) for e in events if e.get("eval_ms")]
    avg_eval = int(sum(eval_times) / len(eval_times)) if eval_times else 0
    p95_eval = int(sorted(eval_times)[int(len(eval_times) * 0.95)] if eval_times else 0)

    # Volume over time (bucketed)
    if range_hours <= 1:
        bucket_minutes = 10
    elif range_hours <= 6:
        bucket_minutes = 30
    else:
        bucket_minutes = 60
    volume = _bucket_volume(events, cutoff, range_hours, bucket_minutes)

    # Policy hits
    policy_counts: dict[str, dict] = {}
    for e in failed:
        for v in e.get("violations") or []:
            pid = v.get("policy_id", "unknown")
            if pid not in policy_counts:
                policy_counts[pid] = {"policy_id": pid, "count": 0, "severity": v.get("severity", "medium")}
            policy_counts[pid]["count"] += 1
    policy_hits = sorted(policy_counts.values(), key=lambda x: x["count"], reverse=True)[:10]

    # Eval sources
    eval_sources: dict[str, int] = defaultdict(int)
    for e in failed:
        for v in e.get("violations") or []:
            eval_sources[v.get("source", "deterministic")] += 1

    # Model usage
    model_usage: dict[str, int] = defaultdict(int)
    for e in events:
        model = e.get("model") or "unknown"
        model_usage[model] += 1

    # Top users
    user_counts: dict[str, int] = defaultdict(int)
    for e in events:
        user = e.get("user") or e.get("client_id") or "unknown"
        user_counts[user] += 1
    top_users = [{"user": u, "count": c} for u, c in sorted(user_counts.items(), key=lambda x: x[1], reverse=True)[:10]]

    # Top clients
    client_counts: dict[str, int] = defaultdict(int)
    for e in events:
        client_counts[e.get("client_id", "unknown")] += 1
    top_clients = [{"client_id": c, "count": n} for c, n in sorted(client_counts.items(), key=lambda x: x[1], reverse=True)[:10]]

    # Flagged users (most violations)
    flagged_counts: dict[str, int] = defaultdict(int)
    for e in failed:
        user = e.get("user") or e.get("client_id") or "unknown"
        flagged_counts[user] += 1
    flagged_users = [{"user": u, "violations": c} for u, c in sorted(flagged_counts.items(), key=lambda x: x[1], reverse=True)[:10]]

    # Group activity
    group_counts: dict[str, int] = defaultdict(int)
    for e in events:
        for g in e.get("resolved_groups") or []:
            group_counts[g] += 1
    group_activity = [{"group": g, "count": c} for g, c in sorted(group_counts.items(), key=lambda x: x[1], reverse=True)[:10]]

    # Recent violations
    recent = []
    for e in reversed(failed[-20:]):
        for v in e.get("violations") or []:
            recent.append({
                "timestamp": e.get("timestamp", ""),
                "user": e.get("user") or e.get("client_id") or "unknown",
                "policy_id": v.get("policy_id", ""),
                "severity": v.get("severity", ""),
            })
            if len(recent) >= 20:
                break
        if len(recent) >= 20:
            break

    return {
        "stats": {
            "total_requests": total,
            "total_violations": total_violations,
            "block_rate": block_rate,
            "active_users": len(users),
            "avg_eval_ms": avg_eval,
            "p95_eval_ms": p95_eval,
            "change_pct": change_pct,
        },
        "volume": volume,
        "policy_hits": policy_hits,
        "eval_sources": dict(eval_sources),
        "model_usage": dict(model_usage),
        "top_users": top_users,
        "top_clients": top_clients,
        "flagged_users": flagged_users,
        "group_activity": group_activity,
        "recent_violations": recent,
    }


def _bucket_volume(events: list[dict], cutoff: datetime, range_hours: int, bucket_minutes: int) -> dict:
    """Bucket events into time slots for the volume chart."""
    num_buckets = (range_hours * 60) // bucket_minutes
    labels = []
    accepted = [0] * num_buckets
    failed_arr = [0] * num_buckets

    for i in range(num_buckets):
        bucket_time = cutoff + timedelta(minutes=i * bucket_minutes)
        if bucket_minutes >= 60:
            labels.append(bucket_time.strftime("%-I%p").lower())
        else:
            labels.append(bucket_time.strftime("%-I:%M"))

    for e in events:
        try:
            ts = datetime.fromisoformat(e["timestamp"])
        except (ValueError, KeyError):
            continue
        offset = ts - cutoff
        bucket_idx = int(offset.total_seconds() / 60 / bucket_minutes)
        if 0 <= bucket_idx < num_buckets:
            if e.get("decision") == "fail":
                failed_arr[bucket_idx] += 1
            else:
                accepted[bucket_idx] += 1

    return {"labels": labels, "accepted": accepted, "failed": failed_arr}
```

- [ ] **Step 4: Run tests**

Run: `python -m pytest tests/test_dashboard.py -v`
Expected: All 7 tests pass

- [ ] **Step 5: Commit**

```bash
git add rampart/app/dashboard.py tests/test_dashboard.py
git commit -m "feat: add dashboard data aggregation from JSONL"
```

---

### Task 3: Dashboard JSON endpoint

**Files:**
- Modify: `rampart/app/dashboard.py`
- Modify: `rampart/app/main.py`

- [ ] **Step 1: Add the JSON data endpoint to `dashboard.py`**

After the `aggregate_dashboard_data` function, add:

```python
@router.get("/ui/dashboard/data")
async def dashboard_data(request: Request, range: str = "24h"):
    if not read_session_user(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    hours = {"1h": 1, "6h": 6, "24h": 24}.get(range, 24)
    config = get_config()
    data = aggregate_dashboard_data(config.tracking.log_path, range_hours=hours)
    return JSONResponse(data)
```

- [ ] **Step 2: Register the dashboard router in `main.py`**

Add import and include after the existing routers:

```python
from rampart.app.dashboard import router as dashboard_router
```

```python
app.include_router(dashboard_router)
```

- [ ] **Step 3: Run all tests**

Run: `python -m pytest tests/ -x -q --ignore=tests/test_gateway.py`
Expected: All pass

- [ ] **Step 4: Commit**

```bash
git add rampart/app/dashboard.py rampart/app/main.py
git commit -m "feat: add dashboard JSON data endpoint"
```

---

### Task 4: Dashboard HTML page with Chart.js

**Files:**
- Modify: `rampart/app/dashboard.py`

This is the biggest task — the full dashboard page with embedded Chart.js.

- [ ] **Step 1: Download Chart.js v4 minified and store as a constant**

Run:
```bash
curl -sL https://cdn.jsdelivr.net/npm/chart.js@4.4.8/dist/chart.umd.min.js > /tmp/chart.min.js
wc -c /tmp/chart.min.js
```

Then add to the top of `dashboard.py`:
```python
# Read at module load — Chart.js v4 minified (~200KB)
from pathlib import Path as _P
_CHARTJS_PATH = _P(__file__).parent / "chartjs.min.js"
```

Copy the file:
```bash
cp /tmp/chart.min.js rampart/app/chartjs.min.js
```

- [ ] **Step 2: Add the dashboard HTML route**

Add the `GET /ui/dashboard` route to `dashboard.py`. This renders the full page with:
- Time range selector (1h/6h/24h pill buttons)
- Stat cards row
- Chart canvases (Chart.js renders into `<canvas>` elements)
- Table sections
- Recent violations feed
- JavaScript that fetches `/ui/dashboard/data` and populates all charts

The route serves the HTML page with placeholder `<canvas>` elements. The JS on page load calls the data endpoint and creates the charts.

```python
@router.get("/ui/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request, range: str = "24h"):
    redirect = require_ui_user(request)
    if redirect:
        return redirect
    from rampart.app.ui import _page
    actor = read_session_user(request)
    body = _dashboard_body(range)
    return HTMLResponse(_page("RAMPART Dashboard", body, actor))


def _dashboard_body(range_val: str) -> str:
    ranges = {"1h": "1h", "6h": "6h", "24h": "24h"}
    range_buttons = " ".join(
        f'<button class="button small {"primary" if r == range_val else ""}" onclick="location.href=\'/ui/dashboard?range={r}\'">{r}</button>'
        for r in ranges
    )
    return f"""
      <section class="toolbar">
        <div><h1>Dashboard</h1><p>AI usage analytics and security insights</p></div>
        <div style="display:flex;gap:4px;align-items:center">
          <span class="muted" style="font-size:12px" id="refresh-indicator">Auto-refresh: 30s</span>
          {range_buttons}
        </div>
      </section>

      <div id="dash-stats" class="stats-grid" style="margin-bottom:16px"></div>

      <div style="display:grid;grid-template-columns:3fr 2fr;gap:16px;margin-bottom:16px">
        <div class="panel" style="padding:16px">
          <div style="font-size:11px;text-transform:uppercase;letter-spacing:0.5px;color:var(--muted);margin-bottom:8px">Request Volume</div>
          <canvas id="chart-volume" height="200"></canvas>
        </div>
        <div class="panel" style="padding:16px">
          <div style="font-size:11px;text-transform:uppercase;letter-spacing:0.5px;color:var(--muted);margin-bottom:8px">Policy Violations</div>
          <canvas id="chart-policies" height="200"></canvas>
        </div>
      </div>

      <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px">
        <div class="panel" style="padding:16px">
          <div style="font-size:11px;text-transform:uppercase;letter-spacing:0.5px;color:var(--muted);margin-bottom:8px">Eval Source Breakdown</div>
          <canvas id="chart-sources" height="180"></canvas>
        </div>
        <div class="panel" style="padding:16px">
          <div style="font-size:11px;text-transform:uppercase;letter-spacing:0.5px;color:var(--muted);margin-bottom:8px">Model Usage</div>
          <canvas id="chart-models" height="180"></canvas>
        </div>
      </div>

      <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;margin-bottom:16px">
        <div class="panel" style="padding:16px">
          <div style="font-size:11px;text-transform:uppercase;letter-spacing:0.5px;color:var(--muted);margin-bottom:8px">Top Users</div>
          <div id="dash-top-users" style="font-size:13px"></div>
        </div>
        <div class="panel" style="padding:16px">
          <div style="font-size:11px;text-transform:uppercase;letter-spacing:0.5px;color:var(--muted);margin-bottom:8px">Top Clients</div>
          <div id="dash-top-clients" style="font-size:13px"></div>
        </div>
        <div class="panel" style="padding:16px">
          <div style="font-size:11px;text-transform:uppercase;letter-spacing:0.5px;color:var(--muted);margin-bottom:8px">Flagged Users</div>
          <div id="dash-flagged" style="font-size:13px"></div>
        </div>
      </div>

      <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px">
        <div class="panel" style="padding:16px">
          <div style="font-size:11px;text-transform:uppercase;letter-spacing:0.5px;color:var(--muted);margin-bottom:8px">Group Activity</div>
          <canvas id="chart-groups" height="150"></canvas>
        </div>
        <div class="panel" style="padding:16px;max-height:300px;overflow-y:auto">
          <div style="font-size:11px;text-transform:uppercase;letter-spacing:0.5px;color:var(--muted);margin-bottom:8px">Recent Violations</div>
          <div id="dash-recent" style="font-size:12px"></div>
        </div>
      </div>

      <script src="/ui/dashboard/chartjs"></script>
      <script>{_dashboard_js(range_val)}</script>
    """
```

- [ ] **Step 3: Add the Chart.js serving endpoint**

```python
@router.get("/ui/dashboard/chartjs")
async def serve_chartjs():
    from fastapi.responses import Response
    if _CHARTJS_PATH.exists():
        return Response(content=_CHARTJS_PATH.read_text(), media_type="application/javascript")
    return Response(content="// Chart.js not found", media_type="application/javascript")
```

- [ ] **Step 4: Add the dashboard JavaScript function**

```python
def _dashboard_js(range_val: str) -> str:
    return """
var charts = {};
var currentRange = '""" + range_val + """';

function fetchDashboard() {
  fetch('/ui/dashboard/data?range=' + currentRange)
    .then(function(r) { return r.json(); })
    .then(function(d) { renderDashboard(d); })
    .catch(function(e) { console.error('Dashboard fetch error:', e); });
}

function renderDashboard(d) {
  // Stats
  var s = d.stats;
  var changeColor = s.change_pct >= 0 ? 'var(--success)' : 'var(--danger)';
  var changeSign = s.change_pct >= 0 ? '+' : '';
  document.getElementById('dash-stats').innerHTML =
    '<div class="stat-card"><div class="stat-label">Total Requests</div><div class="stat-value">' + s.total_requests.toLocaleString() + '</div><div class="stat-sub" style="color:' + changeColor + '">' + changeSign + s.change_pct + '% vs prior</div></div>' +
    '<div class="stat-card"><div class="stat-label">Violations</div><div class="stat-value" style="color:' + (s.total_violations > 0 ? 'var(--danger)' : 'var(--text)') + '">' + s.total_violations.toLocaleString() + '</div><div class="stat-sub muted">' + s.block_rate + '% block rate</div></div>' +
    '<div class="stat-card"><div class="stat-label">Active Users</div><div class="stat-value">' + s.active_users + '</div><div class="stat-sub muted">unique in period</div></div>' +
    '<div class="stat-card"><div class="stat-label">Avg Eval Time</div><div class="stat-value">' + s.avg_eval_ms + 'ms</div><div class="stat-sub muted">p95: ' + s.p95_eval_ms + 'ms</div></div>';

  // Volume chart
  renderChart('chart-volume', 'bar', {
    labels: d.volume.labels,
    datasets: [
      {label: 'Accepted', data: d.volume.accepted, backgroundColor: '#3fb950', borderRadius: 2},
      {label: 'Failed', data: d.volume.failed, backgroundColor: '#f85149', borderRadius: 2}
    ]
  }, {plugins:{legend:{display:true,labels:{color:'#8b949e',font:{size:10}}}}, scales:{x:{stacked:true,ticks:{color:'#8b949e',font:{size:9}},grid:{color:'rgba(255,255,255,0.03)'}},y:{stacked:true,ticks:{color:'#8b949e',font:{size:9}},grid:{color:'rgba(255,255,255,0.05)'}}}});

  // Policy hits
  var phLabels = d.policy_hits.map(function(p){return p.policy_id});
  var phData = d.policy_hits.map(function(p){return p.count});
  var sevColors = {critical:'#f85149',high:'#d29922',medium:'#e3b341',low:'#8b949e'};
  var phColors = d.policy_hits.map(function(p){return sevColors[p.severity]||'#8b949e'});
  renderChart('chart-policies', 'bar', {
    labels: phLabels,
    datasets: [{data: phData, backgroundColor: phColors, borderRadius: 2}]
  }, {indexAxis:'y',plugins:{legend:{display:false}},scales:{x:{ticks:{color:'#8b949e',font:{size:9}},grid:{color:'rgba(255,255,255,0.05)'}},y:{ticks:{color:'#8b949e',font:{size:10}},grid:{display:false}}}});

  // Eval sources
  var srcLabels = Object.keys(d.eval_sources);
  var srcData = Object.values(d.eval_sources);
  var srcColors = {deterministic:'#3b82f6',llm:'#8b5cf6',vision:'#06b6d4'};
  renderChart('chart-sources', 'doughnut', {
    labels: srcLabels,
    datasets: [{data: srcData, backgroundColor: srcLabels.map(function(l){return srcColors[l]||'#8b949e'})}]
  }, {plugins:{legend:{position:'bottom',labels:{color:'#8b949e',font:{size:11},padding:12}}}});

  // Model usage
  var modLabels = Object.keys(d.model_usage);
  var modData = Object.values(d.model_usage);
  var palette = ['#3b82f6','#8b5cf6','#06b6d4','#f59e0b','#ec4899','#10b981','#f87171'];
  renderChart('chart-models', 'doughnut', {
    labels: modLabels,
    datasets: [{data: modData, backgroundColor: modLabels.map(function(_,i){return palette[i%palette.length]})}]
  }, {plugins:{legend:{position:'bottom',labels:{color:'#8b949e',font:{size:11},padding:12}}}});

  // Group activity
  if (d.group_activity.length > 0) {
    renderChart('chart-groups', 'bar', {
      labels: d.group_activity.map(function(g){return g.group}),
      datasets: [{data: d.group_activity.map(function(g){return g.count}), backgroundColor: '#3b82f6', borderRadius: 2}]
    }, {indexAxis:'y',plugins:{legend:{display:false}},scales:{x:{ticks:{color:'#8b949e'},grid:{color:'rgba(255,255,255,0.05)'}},y:{ticks:{color:'#8b949e',font:{size:10}},grid:{display:false}}}});
  } else {
    document.getElementById('chart-groups').parentElement.querySelector('div').textContent += ' (no group data)';
  }

  // Tables
  document.getElementById('dash-top-users').innerHTML = d.top_users.map(function(u,i){
    return '<div style="display:flex;justify-content:space-between;padding:3px 0;border-bottom:1px solid rgba(255,255,255,0.03)"><span>' + (i+1) + '. ' + escH(u.user) + '</span><span class="muted">' + u.count + '</span></div>';
  }).join('') || '<span class="muted">No data</span>';

  document.getElementById('dash-top-clients').innerHTML = d.top_clients.map(function(c,i){
    return '<div style="display:flex;justify-content:space-between;padding:3px 0;border-bottom:1px solid rgba(255,255,255,0.03)"><span>' + (i+1) + '. ' + escH(c.client_id) + '</span><span class="muted">' + c.count + '</span></div>';
  }).join('') || '<span class="muted">No data</span>';

  document.getElementById('dash-flagged').innerHTML = d.flagged_users.map(function(u,i){
    return '<div style="display:flex;justify-content:space-between;padding:3px 0;border-bottom:1px solid rgba(255,255,255,0.03)"><span style="color:var(--danger)">' + (i+1) + '. ' + escH(u.user) + '</span><span style="color:var(--danger)">' + u.violations + '</span></div>';
  }).join('') || '<span class="muted">No flagged users</span>';

  // Recent violations
  document.getElementById('dash-recent').innerHTML = d.recent_violations.map(function(v){
    var sevColor = sevColors[v.severity] || '#8b949e';
    var time = v.timestamp ? v.timestamp.substring(11,19) : '';
    return '<div style="display:flex;gap:8px;padding:4px 0;border-bottom:1px solid rgba(255,255,255,0.03);align-items:center"><span class="muted" style="font-size:11px;min-width:55px">' + time + '</span><span style="color:' + sevColor + ';font-size:11px;min-width:60px">' + escH(v.severity) + '</span><code style="font-size:11px">' + escH(v.policy_id) + '</code><span class="muted" style="font-size:11px;margin-left:auto">' + escH(v.user) + '</span></div>';
  }).join('') || '<span class="muted">No recent violations</span>';
}

function renderChart(id, type, data, options) {
  var ctx = document.getElementById(id);
  if (!ctx) return;
  if (charts[id]) charts[id].destroy();
  charts[id] = new Chart(ctx, {type: type, data: data, options: Object.assign({responsive:true,maintainAspectRatio:false,animation:{duration:300}}, options||{})});
}

function escH(s) { var d=document.createElement('div');d.textContent=s||'';return d.innerHTML; }

// Initial load + auto-refresh
fetchDashboard();
setInterval(fetchDashboard, 30000);
"""
```

- [ ] **Step 5: Run all tests**

Run: `python -m pytest tests/ -x -q --ignore=tests/test_gateway.py`
Expected: All pass

- [ ] **Step 6: Commit**

```bash
git add rampart/app/dashboard.py rampart/app/chartjs.min.js
git commit -m "feat: add dashboard page with Chart.js and auto-refresh"
```

---

### Task 5: Wire up nav and login redirect

**Files:**
- Modify: `rampart/app/ui.py`

- [ ] **Step 1: Add Dashboard to nav (first position)**

Find the nav links section in `_page()` and add Dashboard before Policies:

```python
        f'<a class="{_nav_class("Dashboard")}" href="/ui/dashboard">Dashboard</a>'
        f'<a class="{_nav_class("Policies")}" href="/ui/policies">Policies</a>'
```

Add the nav class check:

```python
        if label == "Dashboard" and "dashboard" in t:
            return "active"
```

- [ ] **Step 2: Change login redirect from `/ui/policies` to `/ui/dashboard`**

In `ui.py`, replace all occurrences of the default redirect:

- `redirect_home`: change to `/ui/dashboard`
- `login_form` default `next`: change to `/ui/dashboard`
- `login` POST handler default next: change to `/ui/dashboard`
- `keycloak_login` default next: change to `/ui/dashboard`
- `keycloak_callback` default state: change to `/ui/dashboard`

- [ ] **Step 3: Run all tests**

Run: `python -m pytest tests/ -x -q --ignore=tests/test_gateway.py`
Expected: All pass

- [ ] **Step 4: Commit and push**

```bash
git add rampart/app/ui.py
git commit -m "feat: add Dashboard to nav and make it the landing page"
git push origin master
```
