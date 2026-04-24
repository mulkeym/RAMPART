# Group Enrollment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add group-based enrollment so Chrome extension users can self-provision API keys by entering a shared group key, with Chrome identity auto-fill.

**Architecture:** New `group_store.py` for group CRUD, new `enrollment.py` for the `/v1/enroll` endpoint that auto-creates clients. Group management UI pages follow the existing pattern. Extension popup gains enrollment states with Chrome identity integration.

**Tech Stack:** Python/FastAPI (server), Chrome Extension Manifest V3 with `identity` permission (client), JSON file storage (groups).

**Spec:** `docs/superpowers/specs/2026-04-24-group-enrollment-design.md`

---

### Task 1: Create group_store.py

**Files:**
- Create: `rampart/app/group_store.py`

- [ ] **Step 1: Create the group store module**

Create `rampart/app/group_store.py`:

```python
from __future__ import annotations

import json
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field


GROUP_STORE_PATH = "data/groups.json"


class GroupRecord(BaseModel):
    id: str
    name: str
    enrollment_key: str
    policy_ids: list[str] = Field(default_factory=list)
    enabled: bool = True
    created_at: str = ""


class GroupStore(BaseModel):
    groups: list[GroupRecord] = Field(default_factory=list)


def generate_enrollment_key() -> str:
    return "grp_" + secrets.token_urlsafe(24)


def load_group_store(path: Optional[str] = None) -> GroupStore:
    store_path = Path(path or GROUP_STORE_PATH)
    if not store_path.exists():
        return GroupStore()
    with store_path.open("r", encoding="utf-8") as f:
        return GroupStore.model_validate(json.load(f))


def save_group_store(store: GroupStore, path: Optional[str] = None) -> None:
    store_path = Path(path or GROUP_STORE_PATH)
    store_path.parent.mkdir(parents=True, exist_ok=True)
    with store_path.open("w", encoding="utf-8") as f:
        json.dump(store.model_dump(), f, indent=2, sort_keys=True)
        f.write("\n")


def list_groups(path: Optional[str] = None) -> list[GroupRecord]:
    return load_group_store(path).groups


def get_group(group_id: str, path: Optional[str] = None) -> Optional[GroupRecord]:
    for group in list_groups(path):
        if group.id == group_id:
            return group
    return None


def get_group_by_enrollment_key(key: str, path: Optional[str] = None) -> Optional[GroupRecord]:
    for group in list_groups(path):
        if group.enrollment_key == key and group.enabled:
            return group
    return None


def create_group(
    group_id: str,
    name: str,
    policy_ids: Optional[list[str]] = None,
    path: Optional[str] = None,
) -> GroupRecord:
    if get_group(group_id, path):
        raise ValueError(f"Group '{group_id}' already exists.")
    group = GroupRecord(
        id=group_id,
        name=name,
        enrollment_key=generate_enrollment_key(),
        policy_ids=policy_ids or [],
        created_at=datetime.now(timezone.utc).isoformat(),
    )
    store = load_group_store(path)
    store.groups.append(group)
    save_group_store(store, path)
    return group


def update_group(group: GroupRecord, path: Optional[str] = None) -> None:
    store = load_group_store(path)
    updated = []
    found = False
    for existing in store.groups:
        if existing.id == group.id:
            updated.append(group)
            found = True
        else:
            updated.append(existing)
    if not found:
        raise ValueError(f"Group '{group.id}' not found.")
    store.groups = updated
    save_group_store(store, path)


def delete_group(group_id: str, path: Optional[str] = None) -> None:
    store = load_group_store(path)
    original = len(store.groups)
    store.groups = [g for g in store.groups if g.id != group_id]
    if len(store.groups) == original:
        raise ValueError(f"Group '{group_id}' not found.")
    save_group_store(store, path)


def regenerate_enrollment_key(group_id: str, path: Optional[str] = None) -> GroupRecord:
    group = get_group(group_id, path)
    if not group:
        raise ValueError(f"Group '{group_id}' not found.")
    group.enrollment_key = generate_enrollment_key()
    update_group(group, path)
    return group
```

- [ ] **Step 2: Verify**

Run: `python3 -c "from rampart.app.group_store import GroupRecord, create_group, list_groups; print('OK')"`

- [ ] **Step 3: Commit**

```bash
git add rampart/app/group_store.py
git commit -m "feat(groups): create group store with CRUD operations"
```

---

### Task 2: Create enrollment.py endpoint

**Files:**
- Create: `rampart/app/enrollment.py`

- [ ] **Step 1: Create the enrollment endpoint**

Create `rampart/app/enrollment.py`:

```python
from __future__ import annotations

import re
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from rampart.app.client_store import create_client, get_client, rotate_client_key
from rampart.app.config import get_config
from rampart.app.group_store import get_group_by_enrollment_key

router = APIRouter()


def _generate_client_id(email: str, device_id: str) -> str:
    name = email.split("@")[0] if email else "unknown"
    name = re.sub(r"[^a-zA-Z0-9]", "-", name)[:20]
    short_device = device_id[-8:] if device_id else "00000000"
    return f"ext-{name}-{short_device}"


@router.post("/v1/enroll")
async def enroll(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"status": "error", "message": "Invalid JSON"}, status_code=400)

    enrollment_key = body.get("enrollment_key", "").strip()
    user_name = body.get("user_name", "").strip()
    user_email = body.get("user_email", "").strip()
    device_id = body.get("device_id", "").strip()

    if not enrollment_key:
        return JSONResponse({"status": "error", "message": "Enrollment key is required"}, status_code=400)

    group = get_group_by_enrollment_key(enrollment_key)
    if not group:
        return JSONResponse({"status": "error", "message": "Invalid enrollment key"}, status_code=403)

    config = get_config()
    client_id = _generate_client_id(user_email, device_id)
    server_url = f"{request.url.scheme}://{request.headers.get('host', 'localhost:8080')}"

    existing = get_client(client_id, config.clients.path)
    if existing:
        # Re-enrollment: rotate the key
        created = rotate_client_key(client_id, config.clients.path)
        # Update policies to match current group
        existing = get_client(client_id, config.clients.path)
        if existing:
            existing.policy_ids = group.policy_ids
            existing.notes = f"Group: {group.id}"
            from rampart.app.client_store import update_client
            update_client(existing, config.clients.path)
        return JSONResponse({
            "status": "re-enrolled",
            "client_id": client_id,
            "api_key": created.api_key,
            "group_id": group.id,
            "group_name": group.name,
            "policies": group.policy_ids,
            "rampart_url": server_url,
        })

    # New enrollment
    created = create_client(
        client_id=client_id,
        customer=group.name,
        app_name="Chrome Extension",
        owner_name=user_name,
        owner_email=user_email,
        team=group.id,
        environment="extension",
        notes=f"Group: {group.id}",
        policy_ids=group.policy_ids,
        path=config.clients.path,
    )
    return JSONResponse({
        "status": "enrolled",
        "client_id": created.client.id,
        "api_key": created.api_key,
        "group_id": group.id,
        "group_name": group.name,
        "policies": group.policy_ids,
        "rampart_url": server_url,
    })
```

- [ ] **Step 2: Register in main.py**

In `rampart/app/main.py`, add the import after the extension router:

```python
from rampart.app.enrollment import router as enrollment_router
```

Add registration:

```python
app.include_router(enrollment_router)
```

- [ ] **Step 3: Verify**

Run: `python3 -c "from rampart.app.main import app; routes = [r.path for r in app.routes if hasattr(r,'path') and 'enroll' in r.path]; print(routes)"`

Expected: `['/v1/enroll']`

- [ ] **Step 4: Commit**

```bash
git add rampart/app/enrollment.py rampart/app/main.py
git commit -m "feat(groups): add /v1/enroll endpoint for group-based auto-provisioning"
```

---

### Task 3: Add Groups UI pages

**Files:**
- Modify: `rampart/app/ui.py`

- [ ] **Step 1: Add "Groups" nav link**

In `_nav_class()`, add before `return ""`:

```python
        if label == "Groups" and "group" in t:
            return "active"
```

In `auth_nav`, add between "API Keys" and "Violations":

```python
        f'<a class="{_nav_class("Groups")}" href="/ui/groups">Groups</a>'
```

- [ ] **Step 2: Add Groups routes**

Add these route handlers to `ui.py` (after the clients routes, before the policies routes). Import `group_store` at the top:

```python
from rampart.app.group_store import (
    GroupRecord, create_group as store_create_group, delete_group as store_delete_group,
    get_group, list_groups as store_list_groups, regenerate_enrollment_key, update_group as store_update_group,
)
```

Add the routes:

```python
@router.get("/ui/groups", response_class=HTMLResponse)
async def groups_index(request: Request, message: Optional[str] = None) -> HTMLResponse:
    redirect = require_ui_user(request)
    if redirect:
        return redirect
    groups = store_list_groups()
    clients = list_clients(get_config().clients.path)
    rows = "\n".join(_group_row(g, clients) for g in groups)
    body = f"""
      <section class="toolbar">
        <div><h1>Groups</h1><p>Manage enrollment groups for Chrome extension auto-provisioning.</p></div>
        <a class="button primary" href="/ui/groups/new">New Group</a>
      </section>
      {_notice(message, None)}
      <section class="panel">
        <table>
          <thead><tr><th>Name</th><th>Enrollment Key</th><th>Policies</th><th>Users</th><th>Status</th><th></th></tr></thead>
          <tbody>{rows or _empty_row(6, "No groups created yet.")}</tbody>
        </table>
      </section>
    """
    return HTMLResponse(_page("RAMPART Groups", body, read_session_user(request)))


@router.get("/ui/groups/new", response_class=HTMLResponse)
async def new_group(request: Request) -> HTMLResponse:
    redirect = require_ui_user(request)
    if redirect:
        return redirect
    return HTMLResponse(_group_form(None, "Create Group", "/ui/groups/new", actor=read_session_user(request)))


@router.post("/ui/groups/new", response_class=HTMLResponse)
async def create_group_route(request: Request) -> HTMLResponse:
    redirect = require_ui_user(request)
    if redirect:
        return redirect
    form = await _form_data(request)
    group_id = _clean_policy_id(form.get("id", ""))
    name = form.get("name", "").strip()
    if not group_id or not name:
        return HTMLResponse(_group_form(None, "Create Group", "/ui/groups/new", "Group ID and name are required.", read_session_user(request)), status_code=400)
    policy_ids = _selected_policy_ids(form)
    try:
        store_create_group(group_id=group_id, name=name, policy_ids=policy_ids)
    except ValueError as e:
        return HTMLResponse(_group_form(None, "Create Group", "/ui/groups/new", str(e), read_session_user(request)), status_code=400)
    return RedirectResponse(f"/ui/groups?message=Group+{group_id}+created", status_code=303)


@router.get("/ui/groups/{group_id}", response_class=HTMLResponse)
async def edit_group(group_id: str, request: Request) -> HTMLResponse:
    redirect = require_ui_user(request)
    if redirect:
        return redirect
    group = get_group(group_id)
    if not group:
        return HTMLResponse(_page("Group Not Found", f"<p>Group <code>{escape(group_id)}</code> not found.</p>", read_session_user(request)), status_code=404)
    return HTMLResponse(_group_form(group, f"Edit {group.name}", f"/ui/groups/{group.id}", actor=read_session_user(request)))


@router.post("/ui/groups/{group_id}", response_class=HTMLResponse)
async def update_group_route(group_id: str, request: Request) -> HTMLResponse:
    redirect = require_ui_user(request)
    if redirect:
        return redirect
    group = get_group(group_id)
    if not group:
        return RedirectResponse("/ui/groups?message=Group+not+found", status_code=303)
    form = await _form_data(request)
    group.name = form.get("name", group.name).strip()
    group.policy_ids = _selected_policy_ids(form)
    group.enabled = form.get("enabled") == "on"
    store_update_group(group)
    return RedirectResponse(f"/ui/groups?message=Group+{group_id}+saved", status_code=303)


@router.post("/ui/groups/{group_id}/delete", response_class=HTMLResponse)
async def delete_group_route(group_id: str, request: Request) -> RedirectResponse:
    redirect = require_ui_user(request)
    if redirect:
        return redirect
    try:
        store_delete_group(group_id)
    except ValueError:
        pass
    return RedirectResponse("/ui/groups?message=Group+deleted", status_code=303)


@router.post("/ui/groups/{group_id}/regenerate", response_class=HTMLResponse)
async def regenerate_key_route(group_id: str, request: Request) -> RedirectResponse:
    redirect = require_ui_user(request)
    if redirect:
        return redirect
    try:
        regenerate_enrollment_key(group_id)
    except ValueError:
        pass
    return RedirectResponse(f"/ui/groups?message=Enrollment+key+regenerated", status_code=303)
```

- [ ] **Step 3: Add helper functions for group rendering**

Add these helper functions (near the other helper functions like `_policy_row`):

```python
def _group_row(group: GroupRecord, clients: list) -> str:
    status = "enabled" if group.enabled else "disabled"
    enrolled = sum(1 for c in clients if c.team == group.id and c.environment == "extension")
    masked_key = group.enrollment_key[:8] + "..." if len(group.enrollment_key) > 8 else group.enrollment_key
    return f"""
      <tr>
        <td><code>{escape(group.id)}</code><div class="muted">{escape(group.name)}</div></td>
        <td><code title="{escape(group.enrollment_key)}" style="cursor:pointer" onclick="navigator.clipboard.writeText('{escape(group.enrollment_key)}')">{escape(masked_key)}</code></td>
        <td>{len(group.policy_ids) or "all"}</td>
        <td>{enrolled}</td>
        <td><span class="pill {status}">{status}</span></td>
        <td class="row-actions">
          <a class="button small" href="/ui/groups/{escape(group.id)}">Edit</a>
          <form class="confirm-action" method="post" action="/ui/groups/{escape(group.id)}/regenerate" data-confirm-title="Regenerate Key?" data-confirm-message="This will invalidate the current enrollment key for {escape(group.name)}.">
            <button class="button small" type="submit">Regen Key</button>
          </form>
          <form class="confirm-action" method="post" action="/ui/groups/{escape(group.id)}/delete" data-confirm-title="Delete Group?" data-confirm-message="Delete group {escape(group.name)}? Enrolled users keep their API keys.">
            <button class="button small danger" type="submit">Delete</button>
          </form>
        </td>
      </tr>
    """


def _group_form(group: Optional[GroupRecord], title: str, action_url: str, error: Optional[str] = None, actor: Optional[str] = None) -> str:
    gid = group.id if group else ""
    name = group.name if group else ""
    enabled = "checked" if (group.enabled if group else True) else ""
    readonly_id = "readonly" if group else ""
    selected = set(group.policy_ids) if group else set()
    policy_checkboxes = _policy_assignment_checkboxes(list(selected))
    enrollment_key_html = ""
    if group:
        enrollment_key_html = f"""
          <label>Enrollment Key
            <div style="display:flex;gap:8px;align-items:center">
              <input value="{escape(group.enrollment_key)}" readonly style="flex:1;font-family:monospace">
              <button type="button" class="button small" onclick="navigator.clipboard.writeText('{escape(group.enrollment_key)}')">Copy</button>
            </div>
          </label>
        """
    body = f"""
      <section class="toolbar">
        <div><h1>{escape(title)}</h1><p>Groups enable Chrome extension auto-provisioning.</p></div>
        <a class="button" href="/ui/groups">Back</a>
      </section>
      {_notice(None, error)}
      <form class="panel form" method="post" action="{escape(action_url)}">
        <label>Group ID<input name="id" value="{escape(gid)}" required {readonly_id}></label>
        <label>Name<input name="name" value="{escape(name)}" required></label>
        {enrollment_key_html}
        <label class="checkbox"><input type="checkbox" name="enabled" {enabled}> Enabled</label>
        <fieldset class="fieldset">
          <legend>Assigned Policies</legend>
          <div class="hint">Users enrolled in this group will be assigned these policies. If none selected, all enabled policies apply.</div>
          {policy_checkboxes}
        </fieldset>
        <div class="actions"><button class="button primary" type="submit">Save Group</button></div>
      </form>
    """
    return _page(title, body, actor)
```

- [ ] **Step 4: Verify**

Run: `python3 -c "from rampart.app.ui import groups_index; print('OK')"`

- [ ] **Step 5: Commit**

```bash
git add rampart/app/ui.py
git commit -m "feat(groups): add Groups UI pages — list, create, edit, delete, regenerate key"
```

---

### Task 4: Add group MCP tools

**Files:**
- Modify: `rampart/app/mcp_server.py`

- [ ] **Step 1: Add group store import**

Add to the imports at the top:

```python
from rampart.app.group_store import (
    GroupRecord, create_group as store_create_group_record, delete_group as store_delete_group_record,
    get_group, list_groups as store_list_groups, update_group as store_update_group_record,
)
```

- [ ] **Step 2: Add group management tools**

Add these tool handlers before the `_register_rest_endpoints()` call at the bottom:

```python
# --- Group Management Tools ---

@_handler(
    "list_groups",
    "List all enrollment groups for Chrome extension auto-provisioning.",
    {"type": "object", "properties": {}, "required": []},
)
def handle_list_groups() -> str:
    groups = store_list_groups()
    result = [
        {"id": g.id, "name": g.name, "enabled": g.enabled, "policy_ids": g.policy_ids, "created_at": g.created_at}
        for g in groups
    ]
    return json.dumps(result, indent=2)


@_handler(
    "create_group",
    "Create a new enrollment group for Chrome extension auto-provisioning.",
    {
        "type": "object",
        "properties": {
            "group_id": {"type": "string", "description": "Unique group identifier"},
            "name": {"type": "string", "description": "Display name"},
            "policy_ids": {"type": "array", "items": {"type": "string"}, "default": [], "description": "Policies to assign to enrolled users"},
        },
        "required": ["group_id", "name"],
    },
)
def handle_create_group(group_id: str, name: str, policy_ids: Optional[list] = None) -> str:
    try:
        group = store_create_group_record(group_id=group_id, name=name, policy_ids=policy_ids)
    except ValueError as e:
        return json.dumps({"error": str(e)})
    return json.dumps({"created": group.id, "enrollment_key": group.enrollment_key, "name": group.name})


@_handler(
    "update_group",
    "Update an existing enrollment group. Only provided fields are changed.",
    {
        "type": "object",
        "properties": {
            "group_id": {"type": "string", "description": "The group ID to update"},
            "name": {"type": "string"},
            "enabled": {"type": "boolean"},
            "policy_ids": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["group_id"],
    },
)
def handle_update_group(group_id: str, name: Optional[str] = None, enabled: Optional[bool] = None, policy_ids: Optional[list] = None) -> str:
    group = get_group(group_id)
    if not group:
        return json.dumps({"error": f"Group '{group_id}' not found."})
    if name is not None:
        group.name = name
    if enabled is not None:
        group.enabled = enabled
    if policy_ids is not None:
        group.policy_ids = [str(p) for p in policy_ids]
    store_update_group_record(group)
    return json.dumps({"updated": group_id})


@_handler(
    "delete_group",
    "Delete an enrollment group. Enrolled users keep their API keys.",
    {
        "type": "object",
        "properties": {
            "group_id": {"type": "string", "description": "The group ID to delete"},
        },
        "required": ["group_id"],
    },
)
def handle_delete_group(group_id: str) -> str:
    try:
        store_delete_group_record(group_id)
    except ValueError as e:
        return json.dumps({"error": str(e)})
    return json.dumps({"deleted": group_id})
```

Also add `"create_group", "update_group", "delete_group"` to the `WRITE_TOOLS` set.

- [ ] **Step 3: Verify**

Run: `python3 -c "from rampart.app.mcp_server import TOOLS; print(len(TOOLS), 'tools'); print([t['name'] for t in TOOLS if 'group' in t['name']])"`

- [ ] **Step 4: Commit**

```bash
git add rampart/app/mcp_server.py
git commit -m "feat(groups): add group management MCP tools"
```

---

### Task 5: Update extension for enrollment

**Files:**
- Modify: `extension/manifest.json`
- Rewrite: `extension/popup.html`
- Rewrite: `extension/popup.js`

- [ ] **Step 1: Add identity permission to manifest**

In `extension/manifest.json`, change permissions:

```json
"permissions": ["storage", "identity"],
```

- [ ] **Step 2: Rewrite popup.html with enrollment states**

Replace `extension/popup.html`:

```html
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { width: 340px; background: #0b0f14; color: #e2e8f0; font-family: -apple-system, sans-serif; font-size: 13px; padding: 16px; }
    h1 { font-size: 16px; color: #38bdf8; margin-bottom: 12px; }
    label { display: block; margin-bottom: 10px; color: #94a3b8; font-size: 12px; }
    input { width: 100%; background: #151d27; border: 1px solid rgba(255,255,255,0.08); border-radius: 4px; padding: 8px; color: #e2e8f0; font-size: 13px; margin-top: 4px; }
    input:focus { outline: none; border-color: rgba(56,189,248,0.5); }
    .actions { display: flex; gap: 8px; margin-top: 12px; }
    button { background: #38bdf8; color: #0b0f14; border: none; border-radius: 4px; padding: 8px 12px; font-size: 12px; font-weight: 600; cursor: pointer; flex: 1; }
    button.secondary { background: rgba(255,255,255,0.06); color: #94a3b8; border: 1px solid rgba(255,255,255,0.1); }
    button.danger { background: rgba(248,113,113,0.08); color: #f87171; border: 1px solid rgba(248,113,113,0.2); }
    .status { display: flex; align-items: center; gap: 6px; margin-top: 10px; font-size: 11px; color: #64748b; }
    .dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
    .dot.green { background: #4ade80; }
    .dot.red { background: #f87171; }
    .dot.gray { background: #64748b; }
    .toggle { display: flex; align-items: center; gap: 8px; margin-bottom: 12px; }
    .toggle input { width: auto; margin: 0; }
    .info { background: #151d27; border: 1px solid rgba(255,255,255,0.08); border-radius: 6px; padding: 10px; margin-bottom: 10px; font-size: 12px; }
    .info .label { color: #64748b; font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px; }
    .info .value { color: #e2e8f0; margin-top: 2px; }
    .hidden { display: none; }
    .section { margin-bottom: 12px; }
  </style>
</head>
<body>
  <h1>RAMPART</h1>

  <!-- Enrollment State -->
  <div id="enroll-view" class="hidden">
    <label>Server URL
      <input type="text" id="url" placeholder="http://localhost:8080">
    </label>
    <label>Group Key
      <input type="text" id="groupKey" placeholder="grp_...">
    </label>
    <div class="actions">
      <button id="enrollBtn">Enroll</button>
    </div>
    <div class="status" id="enroll-status">
      <span class="dot gray"></span>
      <span>Enter your group key to enroll</span>
    </div>
  </div>

  <!-- Enrolled State -->
  <div id="enrolled-view" class="hidden">
    <div class="toggle">
      <input type="checkbox" id="enabled" checked>
      <label for="enabled" style="margin:0">Enabled</label>
    </div>
    <div class="info">
      <div class="label">User</div>
      <div class="value" id="enrolled-user"></div>
    </div>
    <div class="info">
      <div class="label">Group</div>
      <div class="value" id="enrolled-group"></div>
    </div>
    <div class="info">
      <div class="label">Client ID</div>
      <div class="value" id="enrolled-client"></div>
    </div>
    <div class="status" id="enrolled-status">
      <span class="dot green"></span>
      <span>Connected</span>
    </div>
    <div class="actions">
      <button id="reenrollBtn" class="secondary">Re-enroll</button>
      <button id="settingsBtn" class="secondary">Settings</button>
    </div>
  </div>

  <!-- Settings State -->
  <div id="settings-view" class="hidden">
    <label>Server URL
      <input type="text" id="settings-url" placeholder="http://localhost:8080">
    </label>
    <label>API Key (manual)
      <input type="text" id="settings-apiKey" placeholder="rmp_live_...">
    </label>
    <div class="actions">
      <button id="saveSettingsBtn">Save</button>
      <button id="testBtn" class="secondary">Test</button>
      <button id="backBtn" class="secondary">Back</button>
    </div>
    <div class="status" id="settings-status">
      <span class="dot gray"></span>
      <span></span>
    </div>
    <div class="actions" style="margin-top:8px">
      <button id="unenrollBtn" class="danger">Reset &amp; Unenroll</button>
    </div>
  </div>

  <script src="popup.js"></script>
</body>
</html>
```

- [ ] **Step 3: Rewrite popup.js with enrollment flow**

Replace `extension/popup.js`:

```javascript
const views = {
    enroll: document.getElementById('enroll-view'),
    enrolled: document.getElementById('enrolled-view'),
    settings: document.getElementById('settings-view'),
};

function showView(name) {
    Object.values(views).forEach(v => v.classList.add('hidden'));
    views[name].classList.remove('hidden');
}

// Load state
chrome.storage.sync.get(['rampartUrl', 'apiKey', 'enabled', 'enrolled', 'clientId', 'groupName', 'userEmail'], (data) => {
    document.getElementById('url').value = data.rampartUrl || 'http://localhost:8080';
    document.getElementById('settings-url').value = data.rampartUrl || 'http://localhost:8080';
    document.getElementById('settings-apiKey').value = data.apiKey || '';

    if (data.enrolled && data.apiKey) {
        document.getElementById('enabled').checked = data.enabled !== false;
        document.getElementById('enrolled-user').textContent = data.userEmail || 'Unknown';
        document.getElementById('enrolled-group').textContent = data.groupName || 'Unknown';
        document.getElementById('enrolled-client').textContent = data.clientId || '';
        showView('enrolled');
    } else {
        showView('enroll');
    }
});

// Get Chrome identity
let userEmail = '';
let userName = '';
try {
    chrome.identity.getProfileUserInfo({accountStatus: 'ANY'}, (info) => {
        if (info && info.email) {
            userEmail = info.email;
            userName = info.email.split('@')[0];
        }
    });
} catch(e) {}

// Device ID
function getDeviceId() {
    let id = localStorage.getItem('rampart-device-id');
    if (!id) {
        id = 'chrome-' + Math.random().toString(36).substring(2, 10);
        localStorage.setItem('rampart-device-id', id);
    }
    return id;
}

// Enroll
document.getElementById('enrollBtn').addEventListener('click', async () => {
    const url = document.getElementById('url').value.replace(/\/+$/, '');
    const groupKey = document.getElementById('groupKey').value.trim();
    const status = document.getElementById('enroll-status');

    if (!url || !groupKey) {
        status.innerHTML = '<span class="dot red"></span><span>URL and group key required</span>';
        return;
    }

    status.innerHTML = '<span class="dot gray"></span><span>Enrolling...</span>';

    try {
        const resp = await fetch(url + '/v1/enroll', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                enrollment_key: groupKey,
                user_name: userName,
                user_email: userEmail,
                device_id: getDeviceId()
            })
        });
        const data = await resp.json();

        if (data.status === 'enrolled' || data.status === 're-enrolled') {
            chrome.storage.sync.set({
                rampartUrl: url,
                apiKey: data.api_key,
                clientId: data.client_id,
                groupName: data.group_name,
                groupId: data.group_id,
                userEmail: userEmail,
                enrolled: true,
                enabled: true
            }, () => {
                document.getElementById('enrolled-user').textContent = userEmail;
                document.getElementById('enrolled-group').textContent = data.group_name;
                document.getElementById('enrolled-client').textContent = data.client_id;
                document.getElementById('enabled').checked = true;
                showView('enrolled');
            });
        } else {
            status.innerHTML = '<span class="dot red"></span><span>' + (data.message || 'Enrollment failed') + '</span>';
        }
    } catch (e) {
        status.innerHTML = '<span class="dot red"></span><span>Cannot connect: ' + e.message + '</span>';
    }
});

// Re-enroll
document.getElementById('reenrollBtn').addEventListener('click', () => {
    chrome.storage.sync.get(['rampartUrl'], (data) => {
        document.getElementById('url').value = data.rampartUrl || 'http://localhost:8080';
        document.getElementById('groupKey').value = '';
        showView('enroll');
    });
});

// Enabled toggle
document.getElementById('enabled').addEventListener('change', (e) => {
    chrome.storage.sync.set({ enabled: e.target.checked });
});

// Settings
document.getElementById('settingsBtn').addEventListener('click', () => {
    chrome.storage.sync.get(['rampartUrl', 'apiKey'], (data) => {
        document.getElementById('settings-url').value = data.rampartUrl || '';
        document.getElementById('settings-apiKey').value = data.apiKey || '';
        showView('settings');
    });
});

// Save settings
document.getElementById('saveSettingsBtn').addEventListener('click', () => {
    const status = document.getElementById('settings-status');
    chrome.storage.sync.set({
        rampartUrl: document.getElementById('settings-url').value.replace(/\/+$/, ''),
        apiKey: document.getElementById('settings-apiKey').value,
    }, () => {
        status.innerHTML = '<span class="dot green"></span><span>Saved</span>';
    });
});

// Test
document.getElementById('testBtn').addEventListener('click', async () => {
    const status = document.getElementById('settings-status');
    const url = document.getElementById('settings-url').value.replace(/\/+$/, '');
    status.innerHTML = '<span class="dot gray"></span><span>Testing...</span>';
    try {
        const resp = await fetch(url + '/health');
        if (resp.ok) {
            status.innerHTML = '<span class="dot green"></span><span>Connected</span>';
        } else {
            status.innerHTML = '<span class="dot red"></span><span>HTTP ' + resp.status + '</span>';
        }
    } catch (e) {
        status.innerHTML = '<span class="dot red"></span><span>' + e.message + '</span>';
    }
});

// Back to enrolled view
document.getElementById('backBtn').addEventListener('click', () => {
    chrome.storage.sync.get(['enrolled', 'apiKey'], (data) => {
        showView(data.enrolled && data.apiKey ? 'enrolled' : 'enroll');
    });
});

// Unenroll
document.getElementById('unenrollBtn').addEventListener('click', () => {
    chrome.storage.sync.set({
        apiKey: '', enrolled: false, clientId: '', groupName: '', groupId: '', userEmail: ''
    }, () => {
        showView('enroll');
    });
});
```

- [ ] **Step 4: Commit**

```bash
git add extension/
git commit -m "feat(extension): add group enrollment UI with Chrome identity integration"
```

---

### Task 6: Run tests and verify

- [ ] **Step 1: Run test suite**

Run: `python3 -m pytest tests/ -v`

Expected: All existing tests pass.

- [ ] **Step 2: Functional test — enrollment flow**

```bash
# Create a test group
python3 -c "
from rampart.app.group_store import create_group
g = create_group('test-eng', 'Engineering', policy_ids=['no-credential-disclosure', 'harmful-content'])
print('Group created:', g.id)
print('Enrollment key:', g.enrollment_key)
"

# Test enrollment endpoint
curl -s -X POST http://localhost:8080/v1/enroll \
  -H "Content-Type: application/json" \
  -d "{\"enrollment_key\": \"$(python3 -c "from rampart.app.group_store import get_group; print(get_group('test-eng').enrollment_key)")\", \"user_name\": \"Test User\", \"user_email\": \"test@example.com\", \"device_id\": \"chrome-abcd1234\"}" | python3 -m json.tool
```

- [ ] **Step 3: Verify Groups UI**

Open `http://localhost:8080/ui/groups` — should show the test group with enrollment key and enrolled user count.

- [ ] **Step 4: Commit fixes if needed**

```bash
git add -A
git commit -m "fix: enrollment integration fixes"
```
