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

    # ── eval time over time ──────────────────────────────────────────────
    eval_time_series: List[Dict[str, Any]] = []
    bucket_start = window_start
    while bucket_start < now:
        bucket_end = bucket_start + bucket_delta
        times = []
        for e in current_events:
            ts = e["_ts"]
            if bucket_start <= ts < bucket_end:
                ms = e.get("eval_ms")
                if ms and isinstance(ms, (int, float)):
                    times.append(ms)
        avg = int(sum(times) / len(times)) if times else 0
        eval_time_series.append({
            "time": bucket_start.isoformat(),
            "avg_ms": avg,
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
        "eval_time_series": eval_time_series,
    }


@router.get("/ui/dashboard/data")
async def dashboard_data(request: Request, range: str = "24h"):
    if not read_session_user(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    hours = {"1h": 1, "6h": 6, "24h": 24}.get(range, 24)
    config = get_config()
    data = aggregate_dashboard_data(config.tracking.log_path, range_hours=hours)
    return JSONResponse(data)


# ── Chart.js serving endpoint ──────────────────────────────────────────────

@router.get("/ui/dashboard/chartjs")
async def serve_chartjs():
    from fastapi.responses import Response
    from pathlib import Path as _P
    chartjs_path = _P(__file__).parent / "chartjs.min.js"
    if chartjs_path.exists():
        return Response(content=chartjs_path.read_bytes(), media_type="application/javascript")
    return Response(content=b"// Chart.js not found", media_type="application/javascript")


# ── Dashboard HTML page ────────────────────────────────────────────────────

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
    """Return the full HTML body for the dashboard page."""
    ranges = [("1h", "1h"), ("6h", "6h"), ("24h", "24h")]
    pills = ""
    for label, val in ranges:
        cls = "button small primary" if val == range_val else "button small"
        pills += (
            f'<button class="{cls}" '
            f"onclick=\"location.href='/ui/dashboard?range={val}'\">"
            f"{label}</button> "
        )

    return f"""
<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;flex-wrap:wrap;gap:8px">
  <h2 style="margin:0">Dashboard</h2>
  <div style="display:flex;align-items:center;gap:8px">
    {pills}
    <span style="color:var(--muted);font-size:0.85em;margin-left:8px"
          id="dash-refresh-indicator">Auto-refresh: 30s</span>
  </div>
</div>

<div id="dash-stats" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-bottom:20px"></div>

<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:20px">
  <div class="panel" style="padding:16px">
    <h3 style="margin:0 0 8px">Request Volume</h3>
    <canvas id="chart-volume"></canvas>
  </div>
  <div class="panel" style="padding:16px">
    <h3 style="margin:0 0 8px">Policy Violations</h3>
    <canvas id="chart-policies"></canvas>
  </div>
</div>

<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:20px">
  <div class="panel" style="padding:16px">
    <h3 style="margin:0 0 8px">Eval Source Breakdown</h3>
    <canvas id="chart-sources"></canvas>
  </div>
  <div class="panel" style="padding:16px">
    <h3 style="margin:0 0 8px">Model Usage</h3>
    <canvas id="chart-models"></canvas>
  </div>
</div>

<div style="margin-bottom:20px">
  <div class="panel" style="padding:16px">
    <h3 style="margin:0 0 8px">Avg Evaluation Time</h3>
    <div style="height:200px"><canvas id="chart-eval-time"></canvas></div>
  </div>
</div>

<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;margin-bottom:20px">
  <div class="panel" style="padding:16px">
    <h3 style="margin:0 0 8px">Top Users</h3>
    <div id="dash-top-users" style="color:var(--muted);font-size:0.9em">Loading&hellip;</div>
  </div>
  <div class="panel" style="padding:16px">
    <h3 style="margin:0 0 8px">Top Clients</h3>
    <div id="dash-top-clients" style="color:var(--muted);font-size:0.9em">Loading&hellip;</div>
  </div>
  <div class="panel" style="padding:16px">
    <h3 style="margin:0 0 8px">Flagged Users</h3>
    <div id="dash-flagged" style="color:var(--muted);font-size:0.9em">Loading&hellip;</div>
  </div>
</div>

<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:20px">
  <div class="panel" style="padding:16px">
    <h3 style="margin:0 0 8px">Group Activity</h3>
    <canvas id="chart-groups"></canvas>
  </div>
  <div class="panel" style="padding:16px">
    <h3 style="margin:0 0 8px">Recent Violations</h3>
    <div id="dash-recent" style="color:var(--muted);font-size:0.9em;max-height:400px;overflow-y:auto">Loading&hellip;</div>
  </div>
</div>

<script src="/ui/dashboard/chartjs"></script>
<script>
{_dashboard_js(range_val)}
</script>
"""


def _dashboard_js(range_val: str) -> str:
    """Return inline JavaScript for the dashboard."""
    return """
(function() {
  var currentRange = """ + json.dumps(range_val) + """;
  var charts = {};

  function escH(s) {
    if (s == null) return '';
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  var darkThemeDefaults = {
    responsive: true,
    maintainAspectRatio: true,
    plugins: {
      legend: { labels: { color: '#8b949e' } }
    },
    scales: {
      x: {
        ticks: { color: '#8b949e' },
        grid: { color: 'rgba(255,255,255,0.05)' }
      },
      y: {
        ticks: { color: '#8b949e' },
        grid: { color: 'rgba(255,255,255,0.05)' }
      }
    }
  };

  function renderChart(id, type, data, options) {
    if (charts[id]) {
      charts[id].destroy();
    }
    var ctx = document.getElementById(id);
    if (!ctx) return;
    var merged = Object.assign({}, darkThemeDefaults, options || {});
    charts[id] = new Chart(ctx.getContext('2d'), {
      type: type,
      data: data,
      options: merged
    });
  }

  function renderDashboard(d) {
    // ── Stats cards ─────────────────────────────────────────────────
    var s = d.stats || {};
    var statsHtml = '';
    var statItems = [
      { label: 'Total Requests', value: s.total_requests || 0, color: '' },
      { label: 'Violations', value: s.total_violations || 0, color: (s.total_violations > 0 ? 'var(--danger)' : '') },
      { label: 'Active Users', value: s.active_users || 0, color: '' },
      { label: 'Avg Eval (ms)', value: s.avg_eval_ms || 0, color: '' },
      { label: 'P95 Eval (ms)', value: s.p95_eval_ms || 0, color: '' }
    ];
    for (var i = 0; i < statItems.length; i++) {
      var si = statItems[i];
      var colorStyle = si.color ? 'color:' + si.color + ';' : '';
      statsHtml += '<div class="panel" style="padding:16px;text-align:center">' +
        '<div style="font-size:0.85em;color:var(--muted);margin-bottom:4px">' + escH(si.label) + '</div>' +
        '<div style="font-size:1.6em;font-weight:700;' + colorStyle + '">' + escH(String(si.value)) + '</div>' +
        '</div>';
    }
    var statsEl = document.getElementById('dash-stats');
    if (statsEl) statsEl.innerHTML = statsHtml;

    // ── Volume chart (stacked bar) ──────────────────────────────────
    var vol = d.volume || [];
    var volLabels = vol.map(function(v) {
      var dt = new Date(v.time);
      return dt.toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'});
    });
    renderChart('chart-volume', 'bar', {
      labels: volLabels,
      datasets: [
        { label: 'Accepted', data: vol.map(function(v){ return v.accepted; }), backgroundColor: '#3fb950' },
        { label: 'Failed', data: vol.map(function(v){ return v.failed; }), backgroundColor: '#f85149' }
      ]
    }, {
      responsive: true,
      plugins: { legend: { labels: { color: '#8b949e' } } },
      scales: {
        x: { stacked: true, ticks: { color: '#8b949e' }, grid: { color: 'rgba(255,255,255,0.05)' } },
        y: { stacked: true, beginAtZero: true, ticks: { color: '#8b949e' }, grid: { color: 'rgba(255,255,255,0.05)' } }
      }
    });

    // ── Policy hits (horizontal bar) ────────────────────────────────
    var ph = d.policy_hits || [];
    var severityColors = { critical: '#f85149', high: '#d29922', medium: '#e3b341', low: '#8b949e' };
    renderChart('chart-policies', 'bar', {
      labels: ph.map(function(p){ return p.policy_id; }),
      datasets: [{
        label: 'Hits',
        data: ph.map(function(p){ return p.count; }),
        backgroundColor: ph.map(function(p){ return severityColors[p.severity] || '#8b949e'; })
      }]
    }, {
      indexAxis: 'y',
      responsive: true,
      plugins: { legend: { display: false } },
      scales: {
        x: { beginAtZero: true, ticks: { color: '#8b949e' }, grid: { color: 'rgba(255,255,255,0.05)' } },
        y: { ticks: { color: '#8b949e' }, grid: { color: 'rgba(255,255,255,0.05)' } }
      }
    });

    // ── Eval sources (doughnut) ─────────────────────────────────────
    var es = d.eval_sources || {};
    var esLabels = Object.keys(es);
    var esColors = { deterministic: '#3b82f6', llm: '#8b5cf6', vision: '#06b6d4', cache: '#f59e0b' };
    var esBg = esLabels.map(function(l){ return esColors[l] || '#8b949e'; });
    renderChart('chart-sources', 'doughnut', {
      labels: esLabels,
      datasets: [{ data: esLabels.map(function(l){ return es[l]; }), backgroundColor: esBg }]
    }, {
      responsive: true,
      plugins: { legend: { labels: { color: '#8b949e' } } },
      scales: {}
    });

    // ── Model usage (doughnut) ──────────────────────────────────────
    var mu = d.model_usage || {};
    var muLabels = Object.keys(mu);
    var palette = ['#3b82f6','#8b5cf6','#06b6d4','#f59e0b','#10b981','#ef4444','#ec4899','#6366f1','#14b8a6','#f97316'];
    var muBg = muLabels.map(function(_, i){ return palette[i % palette.length]; });
    renderChart('chart-models', 'doughnut', {
      labels: muLabels,
      datasets: [{ data: muLabels.map(function(l){ return mu[l]; }), backgroundColor: muBg }]
    }, {
      responsive: true,
      plugins: { legend: { labels: { color: '#8b949e' } } },
      scales: {}
    });

    // ── Eval time over time (line chart) ──────────────────────────
    var ets = d.eval_time_series || [];
    var etLabels = ets.map(function(b){
      var t = b.time || '';
      try { var d2 = new Date(t); return d2.getHours() + ':' + String(d2.getMinutes()).padStart(2,'0'); } catch(e){ return t; }
    });
    var etData = ets.map(function(b){ return b.avg_ms; });
    renderChart('chart-eval-time', 'line', {
      labels: etLabels,
      datasets: [{
        label: 'Avg eval time (ms)',
        data: etData,
        borderColor: '#8b5cf6',
        backgroundColor: 'rgba(139,92,246,0.1)',
        fill: true,
        tension: 0.3,
        pointRadius: 2,
        pointHoverRadius: 5
      }]
    }, {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { labels: { color: '#8b949e' } } },
      scales: {
        x: { ticks: { color: '#8b949e', font: { size: 9 } }, grid: { color: 'rgba(255,255,255,0.03)' } },
        y: { beginAtZero: true, min: 0, ticks: { color: '#8b949e', callback: function(v){ return v + 'ms'; } }, grid: { color: 'rgba(255,255,255,0.05)' } }
      }
    });

    // ── Group activity (horizontal bar) ─────────────────────────────
    var ga = d.group_activity || {};
    var gaLabels = Object.keys(ga);
    renderChart('chart-groups', 'bar', {
      labels: gaLabels,
      datasets: [{
        label: 'Requests',
        data: gaLabels.map(function(l){ return ga[l]; }),
        backgroundColor: '#3b82f6'
      }]
    }, {
      indexAxis: 'y',
      responsive: true,
      plugins: { legend: { display: false } },
      scales: {
        x: { beginAtZero: true, ticks: { color: '#8b949e' }, grid: { color: 'rgba(255,255,255,0.05)' } },
        y: { ticks: { color: '#8b949e' }, grid: { color: 'rgba(255,255,255,0.05)' } }
      }
    });

    // ── Top users table ─────────────────────────────────────────────
    var tu = d.top_users || [];
    var tuHtml = '';
    for (var i = 0; i < tu.length; i++) {
      tuHtml += '<div style="display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid var(--border)">' +
        '<span>' + (i+1) + '. ' + escH(tu[i].user) + '</span>' +
        '<span style="color:var(--muted)">' + escH(String(tu[i].count)) + '</span></div>';
    }
    var tuEl = document.getElementById('dash-top-users');
    if (tuEl) tuEl.innerHTML = tuHtml || '<span style="color:var(--muted)">No data</span>';

    // ── Top clients table ───────────────────────────────────────────
    var tc = d.top_clients || [];
    var tcHtml = '';
    for (var i = 0; i < tc.length; i++) {
      tcHtml += '<div style="display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid var(--border)">' +
        '<span>' + (i+1) + '. ' + escH(tc[i].client_id) + '</span>' +
        '<span style="color:var(--muted)">' + escH(String(tc[i].count)) + '</span></div>';
    }
    var tcEl = document.getElementById('dash-top-clients');
    if (tcEl) tcEl.innerHTML = tcHtml || '<span style="color:var(--muted)">No data</span>';

    // ── Flagged users ───────────────────────────────────────────────
    var fu = d.flagged_users || [];
    var fuHtml = '';
    for (var i = 0; i < fu.length; i++) {
      fuHtml += '<div style="display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid var(--border)">' +
        '<span style="color:var(--danger)">' + (i+1) + '. ' + escH(fu[i].user) + '</span>' +
        '<span style="color:var(--danger)">' + escH(String(fu[i].count)) + '</span></div>';
    }
    var fuEl = document.getElementById('dash-flagged');
    if (fuEl) fuEl.innerHTML = fuHtml || '<span style="color:var(--muted)">No data</span>';

    // ── Recent violations ───────────────────────────────────────────
    var rv = d.recent_violations || [];
    var rvHtml = '';
    var sevColors = { critical: '#f85149', high: '#d29922', medium: '#e3b341', low: '#8b949e' };
    for (var i = 0; i < rv.length; i++) {
      var r = rv[i];
      var ts = r.timestamp ? new Date(r.timestamp).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit', second:'2-digit'}) : '??';
      var vList = r.violations || [];
      for (var j = 0; j < vList.length; j++) {
        var v = vList[j];
        var sev = v.severity || 'unknown';
        var sevColor = sevColors[sev] || '#8b949e';
        rvHtml += '<div style="display:flex;gap:8px;padding:4px 0;border-bottom:1px solid var(--border);font-size:0.85em;flex-wrap:wrap">' +
          '<span style="color:var(--muted)">' + escH(ts) + '</span>' +
          '<span style="color:' + sevColor + ';font-weight:600">' + escH(sev) + '</span>' +
          '<span>' + escH(v.policy_id || '') + '</span>' +
          '<span style="color:var(--muted)">' + escH(r.user || r.client_id || '') + '</span>' +
          '</div>';
      }
    }
    var rvEl = document.getElementById('dash-recent');
    if (rvEl) rvEl.innerHTML = rvHtml || '<span style="color:var(--muted)">No violations</span>';
  }

  function fetchDashboard() {
    fetch('/ui/dashboard/data?range=' + encodeURIComponent(currentRange))
      .then(function(res) { return res.json(); })
      .then(function(data) {
        if (!data.error) renderDashboard(data);
      })
      .catch(function(err) { console.error('Dashboard fetch error:', err); });
  }

  fetchDashboard();
  setInterval(fetchDashboard, 30000);
})();
"""
