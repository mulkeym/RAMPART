# Group Enrollment & Auto-Provisioning

## Overview

Add group-based enrollment to RAMPART so Chrome extension users can self-provision with a shared group key. Admin creates groups with assigned policies and an enrollment key. Users enter the group key in the extension popup, which auto-creates an API key client using their Chrome profile info.

## Goals

1. **Zero-config for end users** — Enter group key + confirm identity → ready to go
2. **Group-level policy control** — Admin assigns policies per group, all enrolled users inherit them
3. **Self-service enrollment** — No admin action needed per user, just share the group key
4. **Re-enrollment** — Users can re-enroll to get a fresh API key or switch groups

## Architecture

### Server Side

**New: Group model and store** (`rampart/app/group_store.py`)

```python
class Group:
    id: str                    # e.g. "engineering"
    name: str                  # Display name
    enrollment_key: str        # Shared secret for enrollment
    policy_ids: list[str]      # Policies assigned to enrolled users
    enabled: bool              # Can new users enroll?
    created_at: str
```

Stored in `data/groups.json`.

**New: Enrollment endpoint** (`rampart/app/enrollment.py`)

```
POST /v1/enroll
{
    "enrollment_key": "grp_abc123...",
    "user_name": "John Smith",
    "user_email": "john@company.com",
    "device_id": "chrome-ext-a3f2b..."
}
→ {
    "client_id": "ext-john-a3f2b",
    "api_key": "rmp_live_...",
    "group": "engineering",
    "policies": ["no-pii", "harmful-content", ...],
    "rampart_url": "http://192.168.1.232:8080"
}
```

- Validates enrollment key against active groups
- Creates a client record with the group's policies
- Client ID format: `ext-{sanitized_email}-{short_device_id}`
- If a client with that ID already exists (re-enrollment), rotates the key instead of creating a duplicate
- No admin auth required — the enrollment key IS the auth

**New: Group management UI** (`/ui/groups`)

- List groups with enrollment key, policy count, enrolled user count
- Create/edit/delete groups
- Each group has: name, enrollment key (auto-generated), policy checkboxes, enabled toggle
- Shows the enrollment key for admin to share

**New: Group management MCP tools**

- `list_groups`, `create_group`, `update_group`, `delete_group`

### Extension Side

**Updated popup.html/popup.js:**

Three states:

1. **Not enrolled** — Shows enrollment form: Server URL, Group Key, and "Enroll" button. Chrome identity API pre-fills user name/email.
2. **Enrolled** — Shows connected status, user info, group name, "Re-enroll" and "Change Group" buttons.  
3. **Settings** — Server URL field, enable/disable toggle (accessible from both states).

**Enrollment flow in extension:**

```javascript
// 1. Get Chrome identity
chrome.identity.getProfileUserInfo({accountStatus: 'ANY'}, (info) => {
    userEmail = info.email;
    // info.id is the Google account ID
});

// 2. Generate device ID (stored locally, persistent)
let deviceId = localStorage.getItem('rampart-device-id');
if (!deviceId) {
    deviceId = 'chrome-' + crypto.randomUUID().substring(0, 8);
    localStorage.setItem('rampart-device-id', deviceId);
}

// 3. Enroll
fetch(rampartUrl + '/v1/enroll', {
    method: 'POST',
    body: JSON.stringify({
        enrollment_key: groupKey,
        user_name: userName,
        user_email: userEmail,
        device_id: deviceId
    })
});

// 4. Save returned API key
chrome.storage.sync.set({
    apiKey: response.api_key,
    clientId: response.client_id,
    group: response.group,
    enrolled: true
});
```

**Re-enrollment:**
- Calls the same `/v1/enroll` endpoint
- Server detects existing client ID and rotates the key
- Extension updates stored API key

## Enrollment Endpoint Details

### POST /v1/enroll

**No auth required** — enrollment key serves as auth.

**Request:**
```json
{
    "enrollment_key": "grp_a1b2c3...",
    "user_name": "John Smith",
    "user_email": "john@company.com",
    "device_id": "chrome-a3f2b1c0"
}
```

**Response (success):**
```json
{
    "status": "enrolled",
    "client_id": "ext-john-a3f2b1c0",
    "api_key": "rmp_live_...",
    "group_id": "engineering",
    "group_name": "Engineering",
    "policies": ["no-credential-disclosure", "harmful-content"],
    "rampart_url": "http://192.168.1.232:8080"
}
```

**Response (re-enrollment):**
```json
{
    "status": "re-enrolled",
    "client_id": "ext-john-a3f2b1c0",
    "api_key": "rmp_live_NEW...",
    "group_id": "engineering",
    "group_name": "Engineering",
    "policies": ["no-credential-disclosure", "harmful-content"],
    "rampart_url": "http://192.168.1.232:8080"
}
```

**Response (error):**
```json
{
    "status": "error",
    "message": "Invalid enrollment key"
}
```

### Client ID Generation

```python
def generate_client_id(email: str, device_id: str) -> str:
    # Sanitize email: john@company.com → john
    name = email.split("@")[0] if email else "unknown"
    name = re.sub(r'[^a-zA-Z0-9]', '-', name)[:20]
    short_device = device_id[-8:] if device_id else "00000000"
    return f"ext-{name}-{short_device}"
```

## Group Management UI

### /ui/groups — Group list page

- Nav link "Groups" added between "API Keys" and "Violations"
- Table with columns: Name, Enrollment Key (masked, click to reveal), Policies, Enrolled Users, Status, Actions
- "New Group" button

### /ui/groups/new and /ui/groups/{group_id} — Create/edit group

- Name field
- Enrollment Key — auto-generated, with "Regenerate" button
- Policy checkboxes (same pattern as client form)
- Enabled toggle
- Shows list of enrolled users (clients with matching group ID)

## Extension Popup Update

### Updated manifest.json

Add `identity` permission:
```json
"permissions": ["storage", "identity"]
```

### Popup States

**State 1: Not enrolled (default)**
```
┌─────────────────────────┐
│ RAMPART                 │
│                         │
│ Server URL              │
│ [http://192.168.1.232]  │
│                         │
│ Group Key               │
│ [grp_____________]      │
│                         │
│ [Enroll]                │
│                         │
│ ○ Not connected         │
└─────────────────────────┘
```

**State 2: Enrolled**
```
┌─────────────────────────┐
│ RAMPART            [ON] │
│                         │
│ ● Connected             │
│ john@company.com        │
│ Group: Engineering      │
│ Client: ext-john-a3f2   │
│                         │
│ [Re-enroll] [Settings]  │
│                         │
│ ○ 3 violations blocked  │
└─────────────────────────┘
```

## Implementation Scope

### New Files
1. `rampart/app/group_store.py` — Group model, CRUD operations, JSON store
2. `rampart/app/enrollment.py` — POST /v1/enroll endpoint, client auto-creation

### Modified Files
3. `rampart/app/main.py` — Register enrollment router
4. `rampart/app/ui.py` — Add "Groups" nav link, group management pages (list, create, edit)
5. `rampart/app/mcp_server.py` — Add group management tools
6. `extension/manifest.json` — Add `identity` permission
7. `extension/popup.html` — Enrollment UI states
8. `extension/popup.js` — Enrollment flow, Chrome identity, device ID

### Data
9. `data/groups.json` — Group store (created at runtime)
