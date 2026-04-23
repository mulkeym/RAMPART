# RAMPART UI Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Transform the RAMPART admin UI from a light/teal theme to a dark "Command Center" aesthetic with enhanced UX (stats cards, severity badges, confirmation dialogs, inline validation).

**Architecture:** All changes are in-place within `rampart/app/ui.py`. The file contains all HTML generation via Python f-strings and embedded CSS/JS. No new files, no build tools, no CDN dependencies. The approach replaces the CSS custom properties, updates HTML patterns in helper functions, and adds a small inline `<script>` block.

**Tech Stack:** Python/FastAPI server-rendered HTML, embedded CSS with custom properties, minimal vanilla JavaScript (~60 lines for confirms + validation).

**Spec:** `docs/superpowers/specs/2026-04-22-ui-redesign-design.md`

---

### Task 1: Replace CSS theme and update `_page()` layout

**Files:**
- Modify: `rampart/app/ui.py:833-954` (the `_page()` function)

This task replaces the entire CSS block and header HTML in `_page()`. This is the foundation — every page inherits from `_page()`.

- [ ] **Step 1: Replace the CSS custom properties and full style block**

Replace the entire `<style>` block inside `_page()` (lines 845-948) with the Command Center Dark theme. The new CSS block:

```python
  <style>
    :root {{
      color-scheme: dark;
      --bg: #0b0f14;
      --bg-header: #111820;
      --panel: #151d27;
      --panel-hover: #1c2737;
      --text: #e2e8f0;
      --text-secondary: #94a3b8;
      --muted: #64748b;
      --border: rgba(255,255,255,0.08);
      --border-strong: rgba(255,255,255,0.12);
      --primary: #38bdf8;
      --primary-hover: #22d3ee;
      --primary-text: #0b0f14;
      --success: #4ade80;
      --success-bg: rgba(74,222,128,0.08);
      --success-border: rgba(74,222,128,0.2);
      --danger: #f87171;
      --danger-bg: rgba(248,113,113,0.08);
      --danger-border: rgba(248,113,113,0.2);
      --warning: #fbbf24;
      --warning-bg: rgba(251,191,36,0.08);
      --warning-border: rgba(251,191,36,0.2);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      font-size: 14px;
      line-height: 1.5;
    }}
    header {{
      background: var(--bg-header);
      color: #ffffff;
      padding: 14px 28px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid rgba(56,189,248,0.15);
    }}
    header a {{ color: rgba(255,255,255,0.55); text-decoration: none; font-size: 13px; transition: color 0.15s; }}
    header a:hover {{ color: var(--primary); }}
    header a.active {{ color: var(--primary); font-weight: 600; border-bottom: 2px solid var(--primary); padding-bottom: 2px; }}
    .brand {{ display: flex; gap: 10px; align-items: baseline; }}
    .brand-name {{ color: var(--primary); font-weight: 700; letter-spacing: 1.5px; font-size: 15px; }}
    .brand-full {{ color: rgba(255,255,255,0.4); font-size: 12px; font-weight: 400; }}
    header nav {{ display: flex; gap: 18px; align-items: center; }}
    header form {{ margin: 0; display: flex; gap: 12px; align-items: center; }}
    header button {{ background: transparent; color: rgba(255,255,255,0.55); border: 1px solid rgba(255,255,255,0.15); border-radius: 6px; padding: 6px 10px; cursor: pointer; font-size: 12px; transition: filter 0.15s; }}
    header button:hover {{ filter: brightness(1.3); }}
    .nav-links {{ display: flex; gap: 12px; align-items: center; }}
    main {{ max-width: 1180px; margin: 0 auto; padding: 28px; }}
    h1 {{ margin: 0; font-size: 26px; font-weight: 700; letter-spacing: 0; color: var(--text); }}
    p {{ margin: 6px 0 0; color: var(--muted); }}
    .toolbar {{ display: flex; justify-content: space-between; align-items: center; gap: 16px; margin-bottom: 18px; }}
    .toolbar.secondary {{ margin-top: 28px; }}
    .panel {{ background: var(--panel); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ padding: 12px 14px; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.04); vertical-align: top; }}
    th {{ font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; color: var(--muted); background: var(--panel-hover); }}
    tr:last-child td {{ border-bottom: 0; }}
    tbody tr {{ transition: background 0.15s; }}
    tbody tr:nth-child(even) {{ background: rgba(255,255,255,0.02); }}
    tbody tr:hover {{ background: rgba(255,255,255,0.04); }}
    code {{ font-family: "SFMono-Regular", Consolas, monospace; font-size: 13px; color: var(--primary); }}
    .muted {{ color: var(--muted); margin-top: 4px; max-width: 520px; }}
    .button {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 36px;
      padding: 7px 14px;
      border: 1px solid rgba(255,255,255,0.1);
      border-radius: 6px;
      background: rgba(255,255,255,0.06);
      color: var(--text-secondary);
      text-decoration: none;
      font: inherit;
      cursor: pointer;
      white-space: nowrap;
      transition: filter 0.15s;
    }}
    .button:hover {{ filter: brightness(1.15); }}
    .button.primary {{ background: var(--primary); border-color: var(--primary); color: var(--primary-text); font-weight: 600; }}
    .button.small {{ min-height: 30px; padding: 5px 10px; font-size: 12px; }}
    .button.danger {{ background: var(--danger-bg); color: var(--danger); border-color: var(--danger-border); }}
    .button.success {{ background: var(--success-bg); color: var(--success); border-color: var(--success-border); }}
    .row-actions {{ display: flex; gap: 6px; align-items: center; justify-content: flex-end; }}
    .row-actions form {{ margin: 0; }}
    .pill {{ display: inline-flex; padding: 3px 10px; border-radius: 999px; font-size: 11px; font-weight: 600; }}
    .pill.enabled {{ color: var(--success); background: rgba(74,222,128,0.12); }}
    .pill.disabled {{ color: var(--muted); background: rgba(100,116,139,0.15); }}
    .pill.severity-critical {{ color: var(--danger); background: rgba(248,113,113,0.12); }}
    .pill.severity-high {{ color: var(--warning); background: rgba(251,191,36,0.12); }}
    .pill.severity-medium {{ color: var(--text-secondary); background: rgba(148,163,184,0.1); }}
    .pill.severity-low {{ color: var(--muted); background: rgba(100,116,139,0.1); }}
    .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; margin-bottom: 18px; }}
    .stat-card {{ background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }}
    .stat-label {{ font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; color: var(--muted); }}
    .stat-value {{ font-size: 28px; font-weight: 700; margin-top: 4px; }}
    .stat-sub {{ font-size: 12px; margin-top: 4px; }}
    .stat-sub.success {{ color: var(--success); }}
    .stat-sub.danger {{ color: var(--danger); }}
    .stat-sub.warning {{ color: var(--warning); }}
    .stat-sub.muted {{ color: var(--muted); }}
    .form {{ padding: 20px; display: grid; gap: 16px; }}
    label {{ display: grid; gap: 5px; font-weight: 600; font-size: 13px; color: var(--text-secondary); }}
    .checkbox {{ display: flex; align-items: center; gap: 8px; }}
    .policy-option {{ align-items: flex-start; font-weight: 400; }}
    .policy-option input {{ width: auto; margin-top: 3px; }}
    .fieldset {{ border: 1px solid var(--border); border-radius: 6px; padding: 12px; display: grid; gap: 10px; }}
    .fieldset legend {{ font-weight: 600; padding: 0 6px; color: var(--text-secondary); }}
    input, select, textarea {{
      width: 100%;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 9px 10px;
      font: inherit;
      background: var(--bg);
      color: var(--text);
      transition: border-color 0.15s, box-shadow 0.15s;
    }}
    input:focus, select:focus, textarea:focus {{
      outline: none;
      border-color: rgba(56,189,248,0.5);
      box-shadow: 0 0 0 3px rgba(56,189,248,0.08);
    }}
    input.invalid, textarea.invalid {{
      border-color: rgba(248,113,113,0.5);
      box-shadow: 0 0 0 3px rgba(248,113,113,0.08);
    }}
    .field-error {{ color: var(--danger); font-size: 12px; font-weight: 400; }}
    textarea {{ resize: vertical; font-family: "SFMono-Regular", Consolas, monospace; font-size: 13px; }}
    .actions {{ display: flex; justify-content: flex-end; }}
    .hint {{ color: var(--muted); font-size: 13px; margin-top: -8px; }}
    .notice {{ padding: 11px 13px; border-radius: 6px; margin-bottom: 16px; animation: fadeIn 0.2s ease-out; }}
    .notice.success {{ background: var(--success-bg); border: 1px solid var(--success-border); color: var(--success); }}
    .notice.error {{ background: var(--danger-bg); border: 1px solid var(--danger-border); color: var(--danger); white-space: pre-wrap; }}
    .login {{ max-width: 420px; margin: 48px auto; }}
    .login h1 {{ color: var(--primary); }}
    .modal-overlay {{ display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.6); z-index: 1000; align-items: center; justify-content: center; animation: fadeIn 0.15s ease-out; }}
    .modal-overlay.active {{ display: flex; }}
    .modal {{ background: var(--panel); border: 1px solid var(--border-strong); border-radius: 10px; padding: 24px; max-width: 400px; width: 90%; animation: fadeIn 0.15s ease-out; }}
    .modal h2 {{ font-size: 16px; margin: 0; }}
    .modal p {{ color: var(--text-secondary); font-size: 13px; }}
    .modal .actions {{ margin-top: 20px; gap: 8px; }}
    @keyframes fadeIn {{ from {{ opacity: 0; }} to {{ opacity: 1; }} }}
    @media (max-width: 760px) {{
      main {{ padding: 18px; }}
      .toolbar {{ align-items: stretch; flex-direction: column; }}
      table {{ display: block; overflow-x: auto; }}
      .row-actions {{ justify-content: flex-start; }}
      .stats-grid {{ grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); }}
    }}
  </style>
```

- [ ] **Step 2: Add `_page_script()` stub**

Add this function right before `_page()` — it returns an empty string for now and will be replaced with the full JS in Task 5:

```python
def _page_script() -> str:
    return ""
```

- [ ] **Step 3: Update the header HTML in `_page()` to support active nav links**

Replace the `auth_nav` variable construction and the `<header>` line in `_page()`. The current code (line 834-836) builds `auth_nav` as a single string. Replace the entire `_page()` function body from the `auth_nav` assignment through the closing `</html>` return.

The new `_page()` function needs a `current_path` parameter to highlight the active nav link. Since all callers pass a title that contains the page name, we can derive the active page from the title. Replace the full function:

```python
def _page(title: str, body: str, actor: Optional[str] = None) -> str:
    def _nav_class(label: str) -> str:
        lower_title = title.lower()
        if label == "Policies" and "polic" in lower_title:
            return "active"
        if label == "API Keys" and ("api key" in lower_title or "client" in lower_title):
            return "active"
        if label == "Violations" and "violation" in lower_title:
            return "active"
        if label == "Settings" and "setting" in lower_title:
            return "active"
        return ""

    if actor:
        nav_links = "".join(
            f'<a class="{_nav_class(label)}" href="{href}">{label}</a>'
            for label, href in [
                ("Policies", "/ui/policies"),
                ("API Keys", "/ui/clients"),
                ("Violations", "/ui/violations"),
                ("Settings", "/ui/settings"),
            ]
        )
        auth_nav = f'<div class="nav-links">{nav_links}</div><form method="post" action="/logout"><span style="color:var(--muted);font-size:13px">{escape(actor)}</span><button type="submit">Log Out</button></form>'
    else:
        auth_nav = '<a href="/login">Log In</a>'
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{escape(title)} - RAMPART</title>
  <style>
    ...CSS FROM STEP 1...
  </style>
</head>
<body>
  <header><a class="brand" href="/ui/policies"><span class="brand-name">RAMPART</span><span class="brand-full">Request And Model Prompt Analysis &amp; Routing Tool</span></a><nav>{auth_nav}</nav></header>
  <main>{body}</main>
  {_page_script()}
</body>
</html>"""
```

Note: the `<style>` block is the full CSS from Step 1. The `{_page_script()}` calls the stub from Step 2 (replaced with full JS in Task 5).

- [ ] **Step 4: Run the app and verify visually**

Run: `python3 -m uvicorn rampart.app.main:app --reload --host 0.0.0.0 --port 8080`

Open `http://localhost:8080/login` — verify dark background, cyan brand name, dark input fields. Open the policies page after login — verify dark panels, dark table.

- [ ] **Step 5: Commit**

```bash
git add rampart/app/ui.py
git commit -m "feat(ui): replace light theme with Command Center Dark CSS and header"
```

---

### Task 2: Add severity badge helper and update `_policy_row()`

**Files:**
- Modify: `rampart/app/ui.py:572-589` (`_policy_row` function)
- Add new helper function `_severity_pill()` near line 770

- [ ] **Step 1: Add the `_severity_pill()` helper function**

Add this function right after `_empty_row()` (after line 769):

```python
def _severity_pill(severity: str) -> str:
    return f'<span class="pill severity-{escape(severity)}">{escape(severity)}</span>'
```

- [ ] **Step 2: Update `_policy_row()` to use severity badges and new button styles**

Replace the entire `_policy_row()` function:

```python
def _policy_row(policy: PolicyConfig) -> str:
    status = "enabled" if policy.enabled else "disabled"
    return f"""
      <tr>
        <td><code>{escape(policy.id)}</code><div class="muted">{escape(policy.description)}</div></td>
        <td><span class="pill {status}">{status}</span></td>
        <td>{_severity_pill(policy.severity)}</td>
        <td>{escape(policy.category)}</td>
        <td>{escape(policy.action)}</td>
        <td>{len(policy.checks)}</td>
        <td class="row-actions">
          <a class="button small" href="/ui/policies/{escape(policy.id)}">Edit</a>
          <form class="confirm-action" method="post" action="/ui/policies/{escape(policy.id)}/delete" data-confirm-title="Delete Policy?" data-confirm-message="Are you sure you want to delete {escape(policy.id)}? This cannot be undone.">
            <button class="button small danger" type="submit">Delete</button>
          </form>
        </td>
      </tr>
    """
```

- [ ] **Step 3: Verify visually**

Reload `http://localhost:8080/ui/policies` — severity column should show color-coded pills (critical=red, high=amber, medium=gray, low=dim gray).

- [ ] **Step 4: Commit**

```bash
git add rampart/app/ui.py
git commit -m "feat(ui): add severity badges and confirmation data attrs to policy rows"
```

---

### Task 3: Update `_client_row()` with new button styles and confirmation attrs

**Files:**
- Modify: `rampart/app/ui.py:592-613` (`_client_row` function)

- [ ] **Step 1: Replace `_client_row()`**

```python
def _client_row(client: ClientRecord) -> str:
    status = "enabled" if client.enabled else "disabled"
    toggle_label = "Disable" if client.enabled else "Enable"
    toggle_class = "button small danger" if client.enabled else "button small success"
    owner = client.owner_email or client.owner_name
    return f"""
      <tr>
        <td><code>{escape(client.id)}</code><div class="muted">{escape(client.team)}</div></td>
        <td>{escape(client.customer)}</td>
        <td>{escape(client.app_name)}<div class="muted">{escape(client.environment)}</div></td>
        <td>{escape(owner)}</td>
        <td><span class="pill {status}">{status}</span></td>
        <td><code>{escape(client.last_used_at or "")}</code></td>
        <td class="row-actions">
          <a class="button small" href="/ui/clients/{escape(client.id)}">Edit</a>
          <form class="confirm-action" method="post" action="/ui/clients/{escape(client.id)}/toggle" data-confirm-title="{toggle_label} Client?" data-confirm-message="Are you sure you want to {toggle_label.lower()} client {escape(client.id)}?">
            <button class="{toggle_class}" type="submit">{toggle_label}</button>
          </form>
          <form class="confirm-action" method="post" action="/ui/clients/{escape(client.id)}/rotate" data-confirm-title="Rotate API Key?" data-confirm-message="This will invalidate the current API key for {escape(client.id)}. The new key will be shown only once.">
            <button class="button small danger" type="submit">Rotate</button>
          </form>
        </td>
      </tr>
    """
```

- [ ] **Step 2: Verify visually**

Reload `http://localhost:8080/ui/clients` — rows should show the dark theme, status pills in green/gray, and enable/disable button colors.

- [ ] **Step 3: Commit**

```bash
git add rampart/app/ui.py
git commit -m "feat(ui): update client rows with confirmation attrs and toggle styling"
```

---

### Task 4: Add stats cards to policies and violations pages

**Files:**
- Modify: `rampart/app/ui.py:104-138` (`policies_index` route)
- Modify: `rampart/app/ui.py:141-202` (`violations_index` route)
- Add new helper functions `_policy_stats_cards()` and `_violation_stats_cards()`

- [ ] **Step 1: Add `_policy_stats_cards()` helper**

Add this function near the other helper functions (after `_severity_pill()`):

```python
def _policy_stats_cards(config, events: list) -> str:
    from rampart.app.client_store import list_clients

    total_policies = len(config.policies)
    enabled_policies = sum(1 for p in config.policies if p.enabled)
    clients = list_clients(config.clients.path)
    total_clients = len(clients)
    active_clients = sum(1 for c in clients if c.enabled)
    failed_events = [e for e in events if e.get("decision") == "fail"]
    total_violations = sum(len(e.get("violations", [])) for e in failed_events)
    high_critical = sum(
        1 for e in failed_events for v in (e.get("violations") or [])
        if v.get("severity") in {"high", "critical"}
    )
    return f"""
      <div class="stats-grid">
        <div class="stat-card">
          <div class="stat-label">Total Policies</div>
          <div class="stat-value">{total_policies}</div>
          <div class="stat-sub success">{enabled_policies} enabled</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">API Keys</div>
          <div class="stat-value">{total_clients}</div>
          <div class="stat-sub success">{active_clients} active</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Violations</div>
          <div class="stat-value" style="color:{'var(--danger)' if total_violations > 0 else 'var(--text)'}">{total_violations}</div>
          <div class="stat-sub {'danger' if high_critical > 0 else 'muted'}">{high_critical} high/critical</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Failed Requests</div>
          <div class="stat-value" style="color:{'var(--warning)' if len(failed_events) > 0 else 'var(--text)'}">{len(failed_events)}</div>
          <div class="stat-sub muted">all time</div>
        </div>
      </div>
    """
```

- [ ] **Step 2: Add `_violation_stats_cards()` helper**

```python
def _violation_stats_cards(events: list) -> str:
    failed_events = [e for e in events if e.get("decision") == "fail"]
    total_violations = sum(len(e.get("violations", [])) for e in failed_events)
    high_critical = sum(
        1 for e in failed_events for v in (e.get("violations") or [])
        if v.get("severity") in {"high", "critical"}
    )
    customers = set(e.get("customer", "default") for e in failed_events)
    policies = set(
        v.get("policy_id", "unknown")
        for e in failed_events for v in (e.get("violations") or [])
    )
    return f"""
      <div class="stats-grid">
        <div class="stat-card">
          <div class="stat-label">Total Violations</div>
          <div class="stat-value" style="color:{'var(--danger)' if total_violations > 0 else 'var(--text)'}">{total_violations}</div>
          <div class="stat-sub muted">across all clients</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">High / Critical</div>
          <div class="stat-value" style="color:{'var(--danger)' if high_critical > 0 else 'var(--text)'}">{high_critical}</div>
          <div class="stat-sub {'danger' if high_critical > 0 else 'muted'}">require attention</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Customers Affected</div>
          <div class="stat-value">{len(customers)}</div>
          <div class="stat-sub muted">unique customers</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Policies Triggered</div>
          <div class="stat-value">{len(policies)}</div>
          <div class="stat-sub muted">unique policies</div>
        </div>
      </div>
    """
```

- [ ] **Step 3: Update `policies_index` to load events and include stats cards**

In the `policies_index` route handler, add event loading and inject stats cards into the body. Change the function:

```python
@router.get("/ui/policies", response_class=HTMLResponse)
async def policies_index(request: Request, message: Optional[str] = None, error: Optional[str] = None) -> HTMLResponse:
    redirect = require_ui_user(request)
    if redirect:
        audit_event(request, "ui.unauthorized", result="failure", target="/ui/policies")
        return redirect
    config = get_config()
    events = load_evaluation_events(config.tracking.log_path)
    rows = "\n".join(_policy_row(policy) for policy in config.policies)
    body = f"""
      <section class="toolbar">
        <div>
          <h1>Policies</h1>
          <p>{escape(str(get_policy_path()))}</p>
        </div>
        <a class="button primary" href="/ui/policies/new">New Policy</a>
      </section>
      {_notice(message, error)}
      {_policy_stats_cards(config, events)}
      <section class="panel">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Status</th>
              <th>Severity</th>
              <th>Category</th>
              <th>Action</th>
              <th>Checks</th>
              <th></th>
            </tr>
          </thead>
          <tbody>{rows}</tbody>
        </table>
      </section>
    """
    return HTMLResponse(_page("RAMPART Policies", body, read_session_user(request)))
```

- [ ] **Step 4: Update `violations_index` to include stats cards**

Add `{_violation_stats_cards(events)}` into the body of `violations_index`, right after the `_notice()` line (which is implicit — there's no notice on violations but it goes after the toolbar):

```python
@router.get("/ui/violations", response_class=HTMLResponse)
async def violations_index(request: Request, customer: Optional[str] = None, client_id: Optional[str] = None) -> HTMLResponse:
    redirect = require_ui_user(request)
    if redirect:
        audit_event(request, "ui.unauthorized", result="failure", target="/ui/violations")
        return redirect

    config = get_config()
    events = load_evaluation_events(config.tracking.log_path)
    customer_rows = "\n".join(_customer_summary_row(summary) for summary in summarize_customers(events))
    policy_rows = "\n".join(_policy_summary_row(summary) for summary in summarize_policies(events, customer, client_id))
    selected = ""
    if customer or client_id:
        selected = f"<p>Filtered by customer <code>{escape(customer or '*')}</code> and client <code>{escape(client_id or '*')}</code>.</p>"
    body = f"""
      <section class="toolbar">
        <div>
          <h1>Violations</h1>
          <p>{escape(config.tracking.log_path)}</p>
          {selected}
        </div>
      </section>
      {_violation_stats_cards(events)}
      <section class="panel">
        <table>
          <thead>
            <tr>
              <th>Customer</th>
              <th>Client</th>
              <th>Failed Requests</th>
              <th>Violations</th>
              <th>High/Critical</th>
              <th>Last Seen</th>
              <th></th>
            </tr>
          </thead>
          <tbody>{customer_rows or _empty_row(7, "No violation events recorded yet.")}</tbody>
        </table>
      </section>
      <section class="toolbar secondary">
        <div>
          <h1>Policy Breakdown</h1>
          <p>Counts are grouped by customer, client, policy, severity, and category.</p>
        </div>
      </section>
      <section class="panel">
        <table>
          <thead>
            <tr>
              <th>Customer</th>
              <th>Client</th>
              <th>Policy</th>
              <th>Severity</th>
              <th>Category</th>
              <th>Count</th>
              <th>Last Seen</th>
            </tr>
          </thead>
          <tbody>{policy_rows or _empty_row(7, "No policy violations match this view.")}</tbody>
        </table>
      </section>
    """
    return HTMLResponse(_page("RAMPART Violations", body, read_session_user(request)))
```

- [ ] **Step 5: Verify visually**

Reload `http://localhost:8080/ui/policies` — four stats cards should appear between the toolbar and the table. Reload `http://localhost:8080/ui/violations` — four different stats cards should appear.

- [ ] **Step 6: Commit**

```bash
git add rampart/app/ui.py
git commit -m "feat(ui): add dashboard stats cards to policies and violations pages"
```

---

### Task 5: Add inline JavaScript for confirmation dialogs and form validation

**Files:**
- Modify: `rampart/app/ui.py` — replace `_page_script()` stub with full implementation

- [ ] **Step 1: Replace the `_page_script()` stub with the full implementation**

Replace the empty `_page_script()` stub (added in Task 1) with the full JS:

```python
def _page_script() -> str:
    return """<script>
(function(){
  var overlay=document.createElement('div');
  overlay.className='modal-overlay';
  overlay.innerHTML='<div class="modal"><h2 id="modal-title"></h2><p id="modal-msg"></p><div class="actions"><button class="button" id="modal-cancel">Cancel</button><button class="button danger" id="modal-confirm">Confirm</button></div></div>';
  document.body.appendChild(overlay);
  var pendingForm=null;
  document.getElementById('modal-cancel').onclick=function(){overlay.classList.remove('active');pendingForm=null;};
  overlay.onclick=function(e){if(e.target===overlay){overlay.classList.remove('active');pendingForm=null;}};
  document.querySelectorAll('form.confirm-action').forEach(function(form){
    form.addEventListener('submit',function(e){
      e.preventDefault();
      pendingForm=form;
      document.getElementById('modal-title').textContent=form.dataset.confirmTitle||'Are you sure?';
      document.getElementById('modal-msg').textContent=form.dataset.confirmMessage||'This action cannot be undone.';
      overlay.classList.add('active');
    });
  });
  document.getElementById('modal-confirm').onclick=function(){
    overlay.classList.remove('active');
    if(pendingForm){pendingForm.classList.remove('confirm-action');pendingForm.submit();}
  };
  document.querySelectorAll('form.panel.form').forEach(function(form){
    var inputs=form.querySelectorAll('input[required],textarea[required]');
    inputs.forEach(function(input){
      input.addEventListener('blur',function(){validateField(input);});
    });
    form.addEventListener('submit',function(e){
      var valid=true;
      inputs.forEach(function(input){if(!validateField(input))valid=false;});
      if(!valid)e.preventDefault();
    });
  });
  function validateField(input){
    var err=input.parentNode.querySelector('.field-error');
    if(!input.value.trim()){
      input.classList.add('invalid');
      if(!err){err=document.createElement('div');err.className='field-error';err.textContent=input.previousElementSibling?input.previousElementSibling.textContent+' is required':'This field is required';input.parentNode.appendChild(err);}
      return false;
    }else{
      input.classList.remove('invalid');
      if(err)err.remove();
      return true;
    }
  }
})();
</script>"""
```

- [ ] **Step 2: Verify the `_page()` function includes `{_page_script()}`**

Confirm that the `_page()` function from Task 1, Step 2 includes `{_page_script()}` right before `</body>`. It should already be there from the Task 1 rewrite.

- [ ] **Step 3: Verify confirmation dialogs**

Reload `http://localhost:8080/ui/policies`. Click "Delete" on any policy — a modal should appear with "Delete Policy?" title and cancel/confirm buttons. Click cancel — modal should close. Click delete again, then confirm — form should submit.

- [ ] **Step 4: Verify form validation**

Go to `http://localhost:8080/ui/policies/new`. Clear the Policy ID field and click elsewhere — a red error message should appear below it. Try submitting with an empty required field — form should not submit and fields should highlight red.

- [ ] **Step 5: Commit**

```bash
git add rampart/app/ui.py
git commit -m "feat(ui): add confirmation dialogs and inline form validation JS"
```

---

### Task 6: Run existing tests and verify no regressions

**Files:**
- Read: `tests/test_gateway.py`, `tests/test_security.py`

- [ ] **Step 1: Run the full test suite**

Run: `python3 -m pytest tests/ -v`

Expected: All existing tests pass. The UI changes are purely cosmetic (HTML/CSS) and do not change any routing, form parsing, or backend logic. The only functional change is the addition of `events = load_evaluation_events(...)` in `policies_index`, which is a read-only call that already works in `violations_index`.

- [ ] **Step 2: Fix any failures**

If any test imports or calls UI functions directly, verify the function signatures haven't changed. The `_page()` function signature is unchanged: `_page(title: str, body: str, actor: Optional[str] = None) -> str`.

- [ ] **Step 3: Commit (if fixes were needed)**

```bash
git add -A
git commit -m "fix: resolve test regressions from UI redesign"
```

---

### Task 7: Final visual QA pass across all pages

**Files:**
- No code changes expected — this is a visual verification pass

- [ ] **Step 1: Verify Login page**

Open `http://localhost:8080/login` — dark background, cyan "RAMPART Login" title, dark inputs, primary button.

- [ ] **Step 2: Verify Policies Index**

Open `http://localhost:8080/ui/policies` — active nav link highlighted cyan, stats cards visible, severity pills color-coded, delete button triggers confirmation modal.

- [ ] **Step 3: Verify Policy Form**

Click "New Policy" or "Edit" on any policy — dark form panel, dark inputs with cyan focus glow, validation on required fields.

- [ ] **Step 4: Verify Clients Index**

Open `http://localhost:8080/ui/clients` — status pills, toggle/rotate buttons trigger confirmation modals.

- [ ] **Step 5: Verify Client Form**

Click "New API Key" or edit a client — fieldsets visible, dark inputs, backend LLM section styled.

- [ ] **Step 6: Verify Violations**

Open `http://localhost:8080/ui/violations` — stats cards, customer summary table, policy breakdown table.

- [ ] **Step 7: Verify Settings**

Open `http://localhost:8080/ui/settings` — fieldsets for LLM and upstream config, dark inputs, save button.

- [ ] **Step 8: Verify Mobile**

Resize browser to < 760px width — toolbar stacks vertically, tables scroll horizontally, stats cards reflow to 2-column then 1-column.

- [ ] **Step 9: Final commit if any touch-ups needed**

```bash
git add rampart/app/ui.py
git commit -m "fix(ui): visual QA touch-ups"
```
