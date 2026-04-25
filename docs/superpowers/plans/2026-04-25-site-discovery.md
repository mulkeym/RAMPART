# Site Configuration & Discovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add configurable AI site interception with LLM-assisted discovery mode — admins can define custom sites or let the system auto-detect conversation endpoints.

**Architecture:** New `site_store.py` for site config CRUD, new `discovery.py` for capture storage + LLM analysis + UI routes. Extension loads site configs dynamically and captures POST requests in discovery mode. The upstream LLM analyzes captures and suggests site configurations.

**Tech Stack:** Python/FastAPI (server), Chrome Extension (client), httpx for LLM calls.

**Spec:** `docs/superpowers/specs/2026-04-25-site-discovery-design.md`

---

### Task 1: Create site_store.py

**Files:**
- Create: `rampart/app/site_store.py`

- [ ] **Step 1: Create the site config store**

Create `rampart/app/site_store.py`:

```python
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field


SITE_STORE_PATH = "data/sites.json"


class SiteConfig(BaseModel):
    id: str
    name: str
    url_pattern: str
    endpoint_contains: str
    body_format: str = "json"  # "json" or "formdata"
    prompt_extraction: str = "direct"  # "direct" or "json_array_last_user"
    prompt_field: str = "message"
    prompt_user_key: str = "me"
    prompt_message_key: str = "message"
    enabled: bool = True


class SiteStore(BaseModel):
    sites: list[SiteConfig] = Field(default_factory=list)


def load_site_store(path: Optional[str] = None) -> SiteStore:
    store_path = Path(path or SITE_STORE_PATH)
    if not store_path.exists():
        return SiteStore()
    with store_path.open("r", encoding="utf-8") as f:
        return SiteStore.model_validate(json.load(f))


def save_site_store(store: SiteStore, path: Optional[str] = None) -> None:
    store_path = Path(path or SITE_STORE_PATH)
    store_path.parent.mkdir(parents=True, exist_ok=True)
    with store_path.open("w", encoding="utf-8") as f:
        json.dump(store.model_dump(), f, indent=2, sort_keys=True)
        f.write("\n")


def list_sites(path: Optional[str] = None) -> list[SiteConfig]:
    return load_site_store(path).sites


def get_site(site_id: str, path: Optional[str] = None) -> Optional[SiteConfig]:
    for site in list_sites(path):
        if site.id == site_id:
            return site
    return None


def create_site(site: SiteConfig, path: Optional[str] = None) -> SiteConfig:
    if get_site(site.id, path):
        raise ValueError(f"Site '{site.id}' already exists.")
    store = load_site_store(path)
    store.sites.append(site)
    save_site_store(store, path)
    return site


def update_site(site: SiteConfig, path: Optional[str] = None) -> None:
    store = load_site_store(path)
    updated = []
    found = False
    for existing in store.sites:
        if existing.id == site.id:
            updated.append(site)
            found = True
        else:
            updated.append(existing)
    if not found:
        raise ValueError(f"Site '{site.id}' not found.")
    store.sites = updated
    save_site_store(store, path)


def delete_site(site_id: str, path: Optional[str] = None) -> None:
    store = load_site_store(path)
    original = len(store.sites)
    store.sites = [s for s in store.sites if s.id != site_id]
    if len(store.sites) == original:
        raise ValueError(f"Site '{site_id}' not found.")
    save_site_store(store, path)
```

- [ ] **Step 2: Verify**

Run: `python3 -c "from rampart.app.site_store import SiteConfig, list_sites; print('OK')"`

- [ ] **Step 3: Commit**

```bash
git add rampart/app/site_store.py
git commit -m "feat(sites): create site config store with CRUD operations"
```

---

### Task 2: Create discovery.py — capture endpoint, LLM analysis, UI routes

**Files:**
- Create: `rampart/app/discovery.py`

- [ ] **Step 1: Create the discovery module**

Create `rampart/app/discovery.py`:

```python
from __future__ import annotations

import json
from datetime import datetime, timezone
from html import escape
from typing import Any, Optional

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse

from rampart.app.config import get_config
from rampart.app.security.auth import read_session_user, require_ui_user
from rampart.app.security.audit import audit_event
from rampart.app.site_store import SiteConfig, create_site, delete_site, get_site, list_sites, update_site
from rampart.app.ui import _page, _notice, _empty_row, _clean_policy_id

router = APIRouter()

# In-memory discovery captures: {client_id: [CapturedRequest, ...]}
_captures: dict[str, list[dict]] = {}
MAX_CAPTURES_PER_CLIENT = 100

# Last LLM analysis result
_analysis_results: dict[str, dict] = {}


# --- Extension API endpoints ---

@router.get("/v1/extension/config")
async def extension_config(request: Request) -> JSONResponse:
    """Return site configs and discovery status for the extension."""
    from rampart.app.client_store import resolve_client_from_api_key
    config = get_config()
    api_key = request.headers.get("authorization", "")
    client = resolve_client_from_api_key(api_key, config.clients.path)
    discovery = False
    if client and getattr(client, 'discovery_enabled', False):
        discovery = True
    sites = list_sites()
    return JSONResponse({
        "discovery": discovery,
        "sites": [
            {
                "url_pattern": s.url_pattern,
                "endpoint_contains": s.endpoint_contains,
                "body_format": s.body_format,
                "prompt_extraction": s.prompt_extraction,
                "prompt_field": s.prompt_field,
                "prompt_user_key": s.prompt_user_key,
                "prompt_message_key": s.prompt_message_key,
            }
            for s in sites if s.enabled
        ],
    })


@router.post("/v1/discovery/capture")
async def capture_requests(request: Request) -> JSONResponse:
    """Receive captured POST requests from the extension."""
    from rampart.app.client_store import resolve_client_from_api_key
    config = get_config()
    api_key = request.headers.get("authorization", "")
    client = resolve_client_from_api_key(api_key, config.clients.path)
    if not client:
        return JSONResponse({"status": "error", "message": "Invalid API key"}, status_code=401)
    if not getattr(client, 'discovery_enabled', False):
        return JSONResponse({"status": "error", "message": "Discovery not enabled for this client"}, status_code=403)

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"status": "error", "message": "Invalid JSON"}, status_code=400)

    captures = body.get("captures", [])
    client_captures = _captures.setdefault(client.id, [])
    for cap in captures:
        if len(client_captures) >= MAX_CAPTURES_PER_CLIENT:
            client_captures.pop(0)
        client_captures.append({
            "url": str(cap.get("url", ""))[:500],
            "body_keys": cap.get("body_keys", [])[:20],
            "body_preview": str(cap.get("body_preview", ""))[:500],
            "body_format": cap.get("body_format", "unknown"),
            "content_type": str(cap.get("content_type", ""))[:100],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
    return JSONResponse({"status": "ok", "captured": len(captures)})


# --- Sites UI ---

@router.get("/ui/sites", response_class=HTMLResponse)
async def sites_index(request: Request, message: Optional[str] = None) -> HTMLResponse:
    redirect = require_ui_user(request)
    if redirect:
        return redirect
    sites = list_sites()
    rows = "\n".join(_site_row(s) for s in sites)
    body = f"""
      <section class="toolbar">
        <div><h1>Sites</h1><p>Configure AI chat sites for the Chrome extension to monitor.</p></div>
        <a class="button primary" href="/ui/sites/new">New Site</a>
      </section>
      {_notice(message, None)}
      <section class="panel">
        <table>
          <thead><tr><th>Name</th><th>URL Pattern</th><th>Endpoint</th><th>Prompt Field</th><th>Status</th><th></th></tr></thead>
          <tbody>{rows or _empty_row(6, "No sites configured. Use discovery mode or add manually.")}</tbody>
        </table>
      </section>
    """
    return HTMLResponse(_page("RAMPART Sites", body, read_session_user(request)))


@router.get("/ui/sites/new", response_class=HTMLResponse)
async def new_site(request: Request) -> HTMLResponse:
    redirect = require_ui_user(request)
    if redirect:
        return redirect
    return HTMLResponse(_site_form(None, "Create Site", "/ui/sites/new", actor=read_session_user(request)))


@router.post("/ui/sites/new", response_class=HTMLResponse)
async def create_site_route(request: Request) -> HTMLResponse:
    redirect = require_ui_user(request)
    if redirect:
        return redirect
    from rampart.app.ui import _form_data
    form = await _form_data(request)
    site_id = _clean_policy_id(form.get("id", ""))
    if not site_id or not form.get("name", "").strip() or not form.get("url_pattern", "").strip():
        return HTMLResponse(_site_form(None, "Create Site", "/ui/sites/new", "ID, name, and URL pattern are required.", read_session_user(request)), status_code=400)
    site = SiteConfig(
        id=site_id,
        name=form.get("name", "").strip(),
        url_pattern=form.get("url_pattern", "").strip(),
        endpoint_contains=form.get("endpoint_contains", "").strip(),
        body_format=form.get("body_format", "json"),
        prompt_extraction=form.get("prompt_extraction", "direct"),
        prompt_field=form.get("prompt_field", "message").strip(),
        prompt_user_key=form.get("prompt_user_key", "me").strip(),
        prompt_message_key=form.get("prompt_message_key", "message").strip(),
        enabled=form.get("enabled") == "on",
    )
    try:
        create_site(site)
    except ValueError as e:
        return HTMLResponse(_site_form(None, "Create Site", "/ui/sites/new", str(e), read_session_user(request)), status_code=400)
    return RedirectResponse(f"/ui/sites?message=Site+{site_id}+created", status_code=303)


@router.get("/ui/sites/{site_id}", response_class=HTMLResponse)
async def edit_site(site_id: str, request: Request) -> HTMLResponse:
    redirect = require_ui_user(request)
    if redirect:
        return redirect
    site = get_site(site_id)
    if not site:
        return HTMLResponse(_page("Site Not Found", f"<p>Site <code>{escape(site_id)}</code> not found.</p>", read_session_user(request)), status_code=404)
    return HTMLResponse(_site_form(site, f"Edit {site.name}", f"/ui/sites/{site.id}", actor=read_session_user(request)))


@router.post("/ui/sites/{site_id}", response_class=HTMLResponse)
async def update_site_route(site_id: str, request: Request) -> HTMLResponse:
    redirect = require_ui_user(request)
    if redirect:
        return redirect
    site = get_site(site_id)
    if not site:
        return RedirectResponse("/ui/sites?message=Site+not+found", status_code=303)
    from rampart.app.ui import _form_data
    form = await _form_data(request)
    site.name = form.get("name", site.name).strip()
    site.url_pattern = form.get("url_pattern", site.url_pattern).strip()
    site.endpoint_contains = form.get("endpoint_contains", site.endpoint_contains).strip()
    site.body_format = form.get("body_format", site.body_format)
    site.prompt_extraction = form.get("prompt_extraction", site.prompt_extraction)
    site.prompt_field = form.get("prompt_field", site.prompt_field).strip()
    site.prompt_user_key = form.get("prompt_user_key", site.prompt_user_key).strip()
    site.prompt_message_key = form.get("prompt_message_key", site.prompt_message_key).strip()
    site.enabled = form.get("enabled") == "on"
    update_site(site)
    return RedirectResponse(f"/ui/sites?message=Site+{site_id}+saved", status_code=303)


@router.post("/ui/sites/{site_id}/delete", response_class=HTMLResponse)
async def delete_site_route(site_id: str, request: Request) -> RedirectResponse:
    redirect = require_ui_user(request)
    if redirect:
        return redirect
    try:
        delete_site(site_id)
    except ValueError:
        pass
    return RedirectResponse("/ui/sites?message=Site+deleted", status_code=303)


# --- Discovery UI ---

@router.get("/ui/discovery", response_class=HTMLResponse)
async def discovery_page(request: Request, client_id: Optional[str] = None) -> HTMLResponse:
    redirect = require_ui_user(request)
    if redirect:
        return redirect
    from rampart.app.client_store import list_clients
    config = get_config()
    clients = [c for c in list_clients(config.clients.path) if getattr(c, 'discovery_enabled', False)]

    selected = client_id or (clients[0].id if clients else "")
    captures = _captures.get(selected, [])

    # Group by domain
    capture_rows = "\n".join(_capture_row(cap) for cap in reversed(captures[-50:]))

    analysis_html = ""
    if selected in _analysis_results:
        result = _analysis_results[selected]
        analysis_html = f"""
          <div class="panel" style="padding:16px;margin-top:16px">
            <h3 style="font-size:14px;margin-bottom:8px;color:var(--text)">LLM Analysis Result</h3>
            <div class="pg-json">{escape(json.dumps(result, indent=2))}</div>
            <form method="post" action="/ui/discovery/apply" style="margin-top:12px">
              <input type="hidden" name="client_id" value="{escape(selected)}">
              <button class="button primary" type="submit">Apply as Site Config</button>
            </form>
          </div>
        """

    client_options = "".join(
        f'<option value="{escape(c.id)}" {"selected" if c.id == selected else ""}>{escape(c.id)}</option>'
        for c in clients
    )

    body = f"""
      <section class="toolbar">
        <div><h1>Discovery</h1><p>Capture and analyze POST requests from extension users to identify AI chat endpoints.</p></div>
      </section>
      <div style="display:flex;gap:12px;margin-bottom:16px;align-items:center">
        <label style="font-size:13px;color:var(--text-secondary)">Client
          <select onchange="window.location='/ui/discovery?client_id='+this.value" style="margin-left:8px">{client_options or '<option>No discovery clients</option>'}</select>
        </label>
        <span class="muted" style="font-size:12px">{len(captures)} captured requests</span>
        <form method="post" action="/ui/discovery/analyze" style="margin:0">
          <input type="hidden" name="client_id" value="{escape(selected)}">
          <button class="button small primary" type="submit">Analyze with LLM</button>
        </form>
        <form method="post" action="/ui/discovery/clear" style="margin:0">
          <input type="hidden" name="client_id" value="{escape(selected)}">
          <button class="button small danger" type="submit">Clear Captures</button>
        </form>
      </div>
      <section class="panel">
        <table>
          <thead><tr><th>URL</th><th>Format</th><th>Body Keys</th><th>Preview</th><th>Time</th></tr></thead>
          <tbody>{capture_rows or _empty_row(5, "No captures yet. Enable discovery on a client and have them browse an AI site.")}</tbody>
        </table>
      </section>
      {analysis_html}
    """
    return HTMLResponse(_page("RAMPART Discovery", body, read_session_user(request)))


@router.post("/ui/discovery/analyze", response_class=HTMLResponse)
async def analyze_captures(request: Request) -> HTMLResponse:
    redirect = require_ui_user(request)
    if redirect:
        return redirect
    from rampart.app.ui import _form_data
    from rampart.app.openai.proxy import proxy_chat_completion
    form = await _form_data(request)
    client_id = form.get("client_id", "")
    captures = _captures.get(client_id, [])
    if not captures:
        return RedirectResponse(f"/ui/discovery?client_id={client_id}&message=No+captures+to+analyze", status_code=303)

    config = get_config()
    # Build analysis prompt
    captures_json = json.dumps(captures[-30:], indent=2)
    analysis_prompt = f"""You are analyzing HTTP request captures from a web-based AI chat application.
Your job is to identify which request is the conversation/chat API endpoint
and how to extract the user's prompt from it.

Here are the captured POST requests:

{captures_json}

Analyze these requests and identify:
1. Which URL is the conversation/chat endpoint (the one that sends the user's message)
2. What format the request body uses (JSON or FormData)
3. Which field contains the user's prompt/message
4. How to extract just the user's latest message

Return ONLY valid JSON (no markdown, no explanation):
{{
    "conversation_endpoint": "the URL path pattern to match",
    "domain": "the domain name",
    "body_format": "json or formdata",
    "prompt_field": "the field name containing the prompt",
    "extraction_method": "direct or json_array_last_user",
    "user_key": "the value identifying user messages in array (if applicable)",
    "message_key": "the key within each array entry for message text (if applicable)",
    "confidence": "high, medium, or low",
    "reasoning": "brief explanation"
}}"""

    try:
        body, status = await proxy_chat_completion(config.upstream, {
            "model": config.upstream.model or "default",
            "messages": [
                {"role": "system", "content": "Return only valid JSON. No markdown fences."},
                {"role": "user", "content": analysis_prompt},
            ],
            "temperature": 0,
        })
        if status < 400 and isinstance(body, dict):
            content = body.get("choices", [{}])[0].get("message", {}).get("content", "")
            # Strip markdown fences
            content = content.strip()
            if content.startswith("```"):
                content = content.split("\n", 1)[-1]
            if content.endswith("```"):
                content = content.rsplit("```", 1)[0]
            result = json.loads(content.strip())
            _analysis_results[client_id] = result
        else:
            _analysis_results[client_id] = {"error": f"LLM returned status {status}"}
    except Exception as e:
        _analysis_results[client_id] = {"error": str(e)}

    return RedirectResponse(f"/ui/discovery?client_id={client_id}", status_code=303)


@router.post("/ui/discovery/apply", response_class=HTMLResponse)
async def apply_analysis(request: Request) -> HTMLResponse:
    redirect = require_ui_user(request)
    if redirect:
        return redirect
    from rampart.app.ui import _form_data
    form = await _form_data(request)
    client_id = form.get("client_id", "")
    result = _analysis_results.get(client_id)
    if not result or "error" in result:
        return RedirectResponse(f"/ui/discovery?client_id={client_id}", status_code=303)

    domain = result.get("domain", "unknown")
    site_id = _clean_policy_id(domain.split(".")[0] if domain else "custom")
    site = SiteConfig(
        id=site_id,
        name=domain,
        url_pattern=domain,
        endpoint_contains=result.get("conversation_endpoint", ""),
        body_format=result.get("body_format", "json"),
        prompt_extraction=result.get("extraction_method", "direct"),
        prompt_field=result.get("prompt_field", "message"),
        prompt_user_key=result.get("user_key", "me"),
        prompt_message_key=result.get("message_key", "message"),
        enabled=True,
    )
    try:
        create_site(site)
    except ValueError:
        # Already exists — update
        update_site(site)
    return RedirectResponse(f"/ui/sites?message=Site+{site_id}+created+from+discovery", status_code=303)


@router.post("/ui/discovery/clear", response_class=HTMLResponse)
async def clear_captures(request: Request) -> RedirectResponse:
    redirect = require_ui_user(request)
    if redirect:
        return redirect
    from rampart.app.ui import _form_data
    form = await _form_data(request)
    client_id = form.get("client_id", "")
    _captures.pop(client_id, None)
    _analysis_results.pop(client_id, None)
    return RedirectResponse(f"/ui/discovery?client_id={client_id}", status_code=303)


# --- Helper functions ---

def _site_row(site: SiteConfig) -> str:
    status = "enabled" if site.enabled else "disabled"
    return f"""
      <tr>
        <td><code>{escape(site.id)}</code><div class="muted">{escape(site.name)}</div></td>
        <td><code>{escape(site.url_pattern)}</code></td>
        <td><code>{escape(site.endpoint_contains)}</code></td>
        <td>{escape(site.prompt_field)} ({escape(site.prompt_extraction)})</td>
        <td><span class="pill {status}">{status}</span></td>
        <td class="row-actions">
          <a class="button small" href="/ui/sites/{escape(site.id)}">Edit</a>
          <form class="confirm-action" method="post" action="/ui/sites/{escape(site.id)}/delete" data-confirm-title="Delete Site?" data-confirm-message="Delete site config {escape(site.name)}?">
            <button class="button small danger" type="submit">Delete</button>
          </form>
        </td>
      </tr>
    """


def _site_form(site: Optional[SiteConfig], title: str, action_url: str, error: Optional[str] = None, actor: Optional[str] = None) -> str:
    sid = site.id if site else ""
    name = site.name if site else ""
    url_pattern = site.url_pattern if site else ""
    endpoint_contains = site.endpoint_contains if site else ""
    body_format = site.body_format if site else "json"
    prompt_extraction = site.prompt_extraction if site else "direct"
    prompt_field = site.prompt_field if site else "message"
    prompt_user_key = site.prompt_user_key if site else "me"
    prompt_message_key = site.prompt_message_key if site else "message"
    enabled = "checked" if (site.enabled if site else True) else ""
    readonly_id = "readonly" if site else ""

    bf_json = "selected" if body_format == "json" else ""
    bf_form = "selected" if body_format == "formdata" else ""
    pe_direct = "selected" if prompt_extraction == "direct" else ""
    pe_array = "selected" if prompt_extraction == "json_array_last_user" else ""

    array_fields_style = "" if prompt_extraction == "json_array_last_user" else "display:none"

    body = f"""
      <section class="toolbar">
        <div><h1>{escape(title)}</h1><p>Define how the extension intercepts and extracts prompts from this AI site.</p></div>
        <a class="button" href="/ui/sites">Back</a>
      </section>
      {_notice(None, error)}
      <form class="panel form" method="post" action="{escape(action_url)}">
        <label>Site ID<input name="id" value="{escape(sid)}" required {readonly_id}></label>
        <label>Name<input name="name" value="{escape(name)}" required placeholder="Internal Ask Sage"></label>
        <label>URL Pattern<input name="url_pattern" value="{escape(url_pattern)}" required placeholder="asksage.internal.mil">
          <div class="hint">The domain or URL fragment to match. The extension intercepts requests on pages matching this pattern.</div>
        </label>
        <label>Endpoint Contains<input name="endpoint_contains" value="{escape(endpoint_contains)}" required placeholder="/server/query">
          <div class="hint">The API path fragment that identifies the conversation endpoint.</div>
        </label>
        <label>Body Format
          <select name="body_format">
            <option value="json" {bf_json}>JSON</option>
            <option value="formdata" {bf_form}>FormData</option>
          </select>
        </label>
        <label>Prompt Extraction
          <select name="prompt_extraction" onchange="document.getElementById('array-fields').style.display=this.value==='json_array_last_user'?'':'none'">
            <option value="direct" {pe_direct}>Direct — field is the prompt string</option>
            <option value="json_array_last_user" {pe_array}>JSON Array — last user entry in conversation history</option>
          </select>
        </label>
        <label>Prompt Field Name<input name="prompt_field" value="{escape(prompt_field)}" placeholder="message"></label>
        <div id="array-fields" style="{array_fields_style}">
          <label>User Key<input name="prompt_user_key" value="{escape(prompt_user_key)}" placeholder="me">
            <div class="hint">The value that identifies user messages in the array (e.g. "me", "user").</div>
          </label>
          <label>Message Key<input name="prompt_message_key" value="{escape(prompt_message_key)}" placeholder="message">
            <div class="hint">The key within each array entry that contains the message text.</div>
          </label>
        </div>
        <label class="checkbox"><input type="checkbox" name="enabled" {enabled}> Enabled</label>
        <div class="actions"><button class="button primary" type="submit">Save Site</button></div>
      </form>
    """
    return _page(title, body, actor)


def _capture_row(cap: dict) -> str:
    url = cap.get("url", "")
    keys = ", ".join(cap.get("body_keys", [])[:8])
    preview = cap.get("body_preview", "")[:100]
    ts = cap.get("timestamp", "")[:19]
    fmt = cap.get("body_format", "")
    return f"""
      <tr>
        <td><code style="font-size:11px;word-break:break-all">{escape(url[:120])}</code></td>
        <td>{escape(fmt)}</td>
        <td style="font-size:11px">{escape(keys)}</td>
        <td class="muted" style="font-size:11px;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{escape(preview)}</td>
        <td style="font-size:11px"><code>{escape(ts)}</code></td>
      </tr>
    """
```

- [ ] **Step 2: Verify**

Run: `python3 -c "from rampart.app.discovery import router; print('OK')"`

- [ ] **Step 3: Commit**

```bash
git add rampart/app/discovery.py
git commit -m "feat(discovery): create discovery module with capture, LLM analysis, and site config UI"
```

---

### Task 3: Add discovery_enabled to ClientRecord + toggle in UI

**Files:**
- Modify: `rampart/app/client_store.py`
- Modify: `rampart/app/ui.py`

- [ ] **Step 1: Add discovery_enabled to ClientRecord**

In `rampart/app/client_store.py`, add after `total_violations`:

```python
    discovery_enabled: bool = False
```

- [ ] **Step 2: Add discovery toggle to client edit form**

In `rampart/app/ui.py`, find the `_client_form` function. In the form HTML, after the `<label class="checkbox"><input type="checkbox" name="enabled" {enabled}> Enabled</label>` line, add:

```python
        <label class="checkbox"><input type="checkbox" name="discovery_enabled" {"checked" if (client.discovery_enabled if client else False) else ""}> Discovery Mode</label>
        <div class="hint" style="margin-top:-8px">When enabled, the extension captures all POST requests on unknown sites for endpoint discovery.</div>
```

- [ ] **Step 3: Save discovery_enabled in the client update handler**

In the `update_client_route` function in `ui.py`, find where `existing.enabled = form.get("enabled") == "on"` is set, and add after it:

```python
    existing.discovery_enabled = form.get("discovery_enabled") == "on"
```

- [ ] **Step 4: Commit**

```bash
git add rampart/app/client_store.py rampart/app/ui.py
git commit -m "feat(discovery): add discovery_enabled toggle to clients"
```

---

### Task 4: Register router, add nav links

**Files:**
- Modify: `rampart/app/main.py`
- Modify: `rampart/app/ui.py`

- [ ] **Step 1: Register discovery router**

In `rampart/app/main.py`, add the import:

```python
from rampart.app.discovery import router as discovery_router
```

Add registration:

```python
app.include_router(discovery_router)
```

- [ ] **Step 2: Add "Sites" nav link**

In `_nav_class()`, add before `return ""`:

```python
        if label == "Sites" and ("site" in t or "discover" in t):
            return "active"
```

In `auth_nav`, add between "Extension" and "Settings":

```python
        f'<a class="{_nav_class("Sites")}" href="/ui/sites">Sites</a>'
```

- [ ] **Step 3: Commit**

```bash
git add rampart/app/main.py rampart/app/ui.py
git commit -m "feat(discovery): register discovery router and add Sites nav link"
```

---

### Task 5: Update extension — load site configs + discovery mode

**Files:**
- Modify: `extension/content.js`
- Modify: `extension/background.js`
- Modify: `extension/bridge.js`

- [ ] **Step 1: Update background.js to handle config and capture**

Replace `extension/background.js`:

```javascript
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'evaluate') {
        evaluatePrompt(message.prompt, message.images).then(sendResponse).catch(err => {
            sendResponse({ error: err.message });
        });
        return true;
    }
    if (message.type === 'getConfig') {
        getExtensionConfig().then(sendResponse).catch(err => {
            sendResponse({ discovery: false, sites: [] });
        });
        return true;
    }
    if (message.type === 'sendCaptures') {
        sendCaptures(message.captures).then(sendResponse).catch(err => {
            sendResponse({ error: err.message });
        });
        return true;
    }
});

async function getExtensionConfig() {
    const settings = await chrome.storage.sync.get(['rampartUrl', 'apiKey', 'enabled']);
    if (settings.enabled === false || !settings.rampartUrl) {
        return { discovery: false, sites: [] };
    }
    const url = (settings.rampartUrl || 'http://localhost:8080').replace(/\/+$/, '');
    const headers = {};
    if (settings.apiKey) headers['Authorization'] = 'Bearer ' + settings.apiKey;
    try {
        const resp = await fetch(url + '/v1/extension/config', { headers });
        if (resp.ok) return await resp.json();
    } catch (e) {}
    return { discovery: false, sites: [] };
}

async function sendCaptures(captures) {
    const settings = await chrome.storage.sync.get(['rampartUrl', 'apiKey']);
    const url = (settings.rampartUrl || 'http://localhost:8080').replace(/\/+$/, '');
    const headers = { 'Content-Type': 'application/json' };
    if (settings.apiKey) headers['Authorization'] = 'Bearer ' + settings.apiKey;
    try {
        const resp = await fetch(url + '/v1/discovery/capture', {
            method: 'POST', headers,
            body: JSON.stringify({ captures })
        });
        return await resp.json();
    } catch (e) {
        return { error: e.message };
    }
}

async function evaluatePrompt(prompt, images) {
    const settings = await chrome.storage.sync.get(['rampartUrl', 'apiKey', 'enabled']);
    if (settings.enabled === false) {
        return { decision: 'accept', violations: [] };
    }
    const url = (settings.rampartUrl || 'http://localhost:8080').replace(/\/+$/, '');
    const headers = { 'Content-Type': 'application/json' };
    if (settings.apiKey) headers['Authorization'] = 'Bearer ' + settings.apiKey;
    let content;
    if (images && images.length > 0) {
        content = [{ type: 'text', text: prompt || '' }];
        for (const imageUrl of images) {
            content.push({ type: 'image_url', image_url: { url: imageUrl } });
        }
    } else {
        content = prompt;
    }
    try {
        const response = await fetch(url + '/v1/rampart/evaluate', {
            method: 'POST', headers,
            body: JSON.stringify({
                request: { model: 'chatgpt', messages: [{ role: 'user', content: content }] }
            })
        });
        if (!response.ok) return { error: 'RAMPART returned HTTP ' + response.status };
        return await response.json();
    } catch (e) {
        return { error: e.message };
    }
}
```

- [ ] **Step 2: Update bridge.js to relay config and capture messages**

In `extension/bridge.js`, add these handlers after the existing `getSettings` handler:

```javascript
    if (event.data.type === 'getConfig') {
        try {
            const config = await chrome.runtime.sendMessage({ type: 'getConfig' });
            window.postMessage({ source: 'rampart-bridge', id: event.data.id, result: config }, '*');
        } catch (e) {
            window.postMessage({ source: 'rampart-bridge', id: event.data.id, result: { discovery: false, sites: [] } }, '*');
        }
    }

    if (event.data.type === 'sendCaptures') {
        try {
            const result = await chrome.runtime.sendMessage({ type: 'sendCaptures', captures: event.data.captures });
            window.postMessage({ source: 'rampart-bridge', id: event.data.id, result: result }, '*');
        } catch (e) {
            window.postMessage({ source: 'rampart-bridge', id: event.data.id, result: { error: e.message } }, '*');
        }
    }
```

- [ ] **Step 3: Update content.js to load site configs and run discovery**

In `extension/content.js`, add at the beginning (after the `pastedImages` and event listeners, before the fetch override):

```javascript
    // Load site configs and discovery mode from RAMPART
    let siteConfigs = [];
    let discoveryMode = false;
    let discoveryCaptureBuffer = [];

    sendToBridge('getConfig', {}).then(config => {
        if (config && config.sites) siteConfigs = config.sites;
        if (config && config.discovery) discoveryMode = true;
    });

    function matchesSiteConfig(url) {
        for (const site of siteConfigs) {
            if (url.includes(site.url_pattern) && url.includes(site.endpoint_contains)) {
                return site;
            }
        }
        return null;
    }

    function extractPromptFromSite(body, site) {
        const fieldValue = body[site.prompt_field];
        if (!fieldValue) return null;
        if (site.prompt_extraction === 'direct') {
            return typeof fieldValue === 'string' ? fieldValue : null;
        }
        if (site.prompt_extraction === 'json_array_last_user') {
            try {
                const arr = typeof fieldValue === 'string' ? JSON.parse(fieldValue) : fieldValue;
                if (Array.isArray(arr)) {
                    for (let i = arr.length - 1; i >= 0; i--) {
                        if (arr[i][site.prompt_user_key || 'user'] === (site.prompt_user_key || 'me') || arr[i].user === site.prompt_user_key) {
                            return arr[i][site.prompt_message_key || 'message'] || null;
                        }
                    }
                }
            } catch (e) {}
        }
        return null;
    }

    // Flush discovery captures every 30 seconds
    setInterval(() => {
        if (discoveryCaptureBuffer.length > 0) {
            const batch = discoveryCaptureBuffer.splice(0);
            sendToBridge('sendCaptures', { captures: batch });
        }
    }, 30000);
```

Then update the fetch override to use dynamic site configs and discovery:

Replace the `isConversation` detection block:

```javascript
        // Detect conversation endpoints — hardcoded + dynamic site configs
        const isConversation = typeof url === 'string' && options && options.method === 'POST' && (
            // ChatGPT (hardcoded)
            url.includes('/backend-api/conversation') ||
            url.includes('/backend-api/f/conversation') ||
            url.includes('/backend-anon/conversation') ||
            url.includes('/backend-anon/f/conversation') ||
            // Ask Sage (hardcoded)
            (url.includes('asksage.ai') && url.includes('/server/query')) ||
            // Dynamic site configs
            matchesSiteConfig(url) !== null
        );
```

After the body parsing block but before `extractPrompt`, add site config extraction:

```javascript
                // Try dynamic site config extraction first
                const matchedSite = matchesSiteConfig(url);
                let prompt;
                if (matchedSite) {
                    prompt = extractPromptFromSite(body, matchedSite);
                } else {
                    prompt = extractPrompt(body);
                }
```

At the end of the fetch override (before the final `return originalFetch.call`), add discovery capture:

```javascript
        // Discovery mode: capture all POST requests on unknown sites
        if (discoveryMode && typeof url === 'string' && options && options.method === 'POST') {
            // Skip known/internal endpoints
            if (!url.includes('rampart') && !url.includes('google') && !url.includes('analytics') && !url.includes('datadog') && !url.includes('sentry')) {
                try {
                    let bodyKeys = [];
                    let bodyPreview = '';
                    let bodyFormat = 'unknown';
                    if (options.body instanceof FormData) {
                        bodyFormat = 'formdata';
                        for (const [key] of options.body.entries()) bodyKeys.push(key);
                    } else if (typeof options.body === 'string') {
                        bodyFormat = 'json';
                        try {
                            const parsed = JSON.parse(options.body);
                            bodyKeys = Object.keys(parsed);
                            bodyPreview = options.body.substring(0, 500);
                        } catch(e) { bodyPreview = options.body.substring(0, 500); }
                    }
                    discoveryCaptureBuffer.push({
                        url: url.substring(0, 500),
                        body_keys: bodyKeys.slice(0, 20),
                        body_preview: bodyPreview,
                        body_format: bodyFormat,
                        content_type: (options.headers && options.headers['content-type']) || '',
                    });
                } catch(e) {}
            }
        }
```

- [ ] **Step 4: Commit**

```bash
git add extension/
git commit -m "feat(extension): load dynamic site configs and capture discovery data"
```

---

### Task 6: Run tests and verify

- [ ] **Step 1: Run test suite**

Run: `python3 -m pytest tests/ -v`

Expected: All existing tests pass.

- [ ] **Step 2: Verify site config UI**

Open `http://localhost:8080/ui/sites` — should show empty list with "New Site" button.

- [ ] **Step 3: Verify discovery page**

Open `http://localhost:8080/ui/discovery` — should show client selector and empty captures table.

- [ ] **Step 4: Verify extension config endpoint**

```bash
curl -s http://localhost:8080/v1/extension/config | python3 -m json.tool
```

Expected: `{"discovery": false, "sites": []}`

- [ ] **Step 5: Commit fixes if needed**

```bash
git add -A
git commit -m "fix: site discovery integration fixes"
```
