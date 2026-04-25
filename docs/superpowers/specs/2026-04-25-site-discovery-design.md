# Site Configuration & Discovery Mode

## Overview

Add configurable AI site interception to RAMPART so admins can define custom AI chat sites for the Chrome extension to monitor. Includes a discovery mode that captures POST requests from a user's browsing, sends them to the configured LLM for analysis, and suggests the site configuration automatically.

## Goals

1. **Custom site configs** — Define any AI chat site's conversation endpoint, body format, and prompt field
2. **Transparent discovery** — Enable per-client, invisible to end users, captures requests automatically
3. **LLM-assisted analysis** — The configured upstream LLM analyzes captured requests and suggests the site config
4. **One-click setup** — Admin reviews LLM suggestion, clicks apply, site is live for all extension users

## Architecture

### Data Model

**SiteConfig** (`data/sites.json`):
```python
class SiteConfig:
    id: str                      # e.g. "internal-asksage"
    name: str                    # "Internal Ask Sage"
    url_pattern: str             # "asksage.internal.mil"
    endpoint_contains: str       # "/server/query"
    body_format: str             # "json" or "formdata"
    prompt_extraction: str       # "field" or "json_array_last_user"
    prompt_field: str            # "message"
    prompt_user_key: str         # "me" (for json_array_last_user)
    prompt_message_key: str      # "message" (for json_array_last_user)
    enabled: bool
```

**DiscoveryCapture** (in-memory + persisted to `data/discovery.json`):
```python
class CapturedRequest:
    client_id: str
    timestamp: str
    url: str
    body_keys: list[str]         # Top-level keys in the request body
    body_preview: str            # First 500 chars of body
    body_format: str             # "json" or "formdata"
    content_type: str
```

### Extension Changes

The extension gains two new behaviors:

1. **Load site configs** from RAMPART on page load (`GET /v1/extension/sites`)
2. **Discovery mode** — when enabled for this client, capture all POST requests on any site and send to RAMPART

### Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/v1/extension/sites` | Return active site configs for the extension |
| POST | `/v1/discovery/capture` | Extension sends captured POST requests |
| GET | `/ui/sites` | Site config management page |
| GET/POST | `/ui/sites/new` | Create site config |
| GET/POST | `/ui/sites/{id}` | Edit site config |
| POST | `/ui/sites/{id}/delete` | Delete site config |
| GET | `/ui/discovery` | View captured requests + LLM suggestions |
| POST | `/ui/discovery/analyze` | Send captures to LLM for analysis |
| POST | `/ui/discovery/apply` | Create site config from LLM suggestion |

### Discovery Flow

```
Admin enables discovery on client (checkbox on client edit page)
    ↓
Extension checks GET /v1/extension/config → {discovery: true, sites: [...]}
    ↓
Extension captures ALL POST requests (any domain, not just known sites)
    → Filters out known non-AI endpoints (analytics, tracking pixels, etc.)
    → Sends batch to POST /v1/discovery/capture every 30 seconds
    ↓
Admin opens /ui/discovery
    → Sees table of captured requests grouped by domain
    → Clicks "Analyze with LLM"
    ↓
RAMPART sends captures to upstream LLM with analysis prompt
    ↓
LLM returns structured suggestion:
{
    "conversation_endpoint": "/server/query",
    "body_format": "formdata",
    "prompt_field": "message",
    "extraction_method": "json_array_last_user",
    "user_key": "me",
    "message_key": "message",
    "confidence": "high",
    "reasoning": "The /server/query endpoint receives FormData with a 'message' field containing a JSON array of conversation history..."
}
    ↓
Admin clicks "Apply Suggestion" → site config created
```

### Client Discovery Flag

Add `discovery_enabled: bool = False` to `ClientRecord`. When True:
- Extension captures all POST requests on non-configured sites
- Captures are sent to `/v1/discovery/capture` with the client's API key
- Admin can toggle this in the client edit page

### LLM Analysis Prompt

```
You are analyzing HTTP request captures from a web-based AI chat application.
Your job is to identify which request is the conversation/chat API endpoint
and how to extract the user's prompt from it.

Here are the captured POST requests:

{captured_requests_json}

Analyze these requests and identify:
1. Which URL is the conversation/chat endpoint (the one that sends the user's message)
2. What format the request body uses (JSON or FormData)
3. Which field contains the user's prompt/message
4. How to extract just the user's latest message (is it a direct string field,
   or a JSON array of conversation history where you need the last user entry?)

Return valid JSON:
{
    "conversation_endpoint": "the URL path pattern to match",
    "domain": "the domain name",
    "body_format": "json or formdata",
    "prompt_field": "the field name containing the prompt",
    "extraction_method": "direct (field is a string) or json_array_last_user (field is a JSON array)",
    "user_key": "the value that identifies user messages in the array (e.g. 'me', 'user')",
    "message_key": "the key within each array entry that contains the message text",
    "confidence": "high, medium, or low",
    "reasoning": "brief explanation of why you chose this endpoint and extraction method"
}
```

### Extension Site Config Loading

On page load, the extension calls `GET /v1/extension/config` which returns:
```json
{
    "discovery": true,
    "sites": [
        {
            "url_pattern": "asksage.internal.mil",
            "endpoint_contains": "/server/query",
            "body_format": "formdata",
            "prompt_extraction": "json_array_last_user",
            "prompt_field": "message",
            "prompt_user_key": "me",
            "prompt_message_key": "message"
        }
    ]
}
```

The extension uses these to dynamically build its interception rules — no code changes needed for new sites.

### UI Pages

**`/ui/sites`** — List of configured sites with URL pattern, endpoint, status. Nav link "Sites" between "Extension" and "Settings".

**`/ui/discovery`** — Two panels:
- Left: Captured requests table (domain, URL, body keys, timestamp)
- Right: LLM analysis result with "Apply" button
- Top: Client selector (which client's captures to view)
- "Clear Captures" button

### Files

**New:**
- `rampart/app/site_store.py` — SiteConfig model + CRUD
- `rampart/app/discovery.py` — Discovery capture endpoint, LLM analysis, site config routes

**Modified:**
- `rampart/app/client_store.py` — Add `discovery_enabled` field
- `rampart/app/main.py` — Register discovery router
- `rampart/app/ui.py` — Add "Sites" nav link, discovery toggle on client edit page
- `extension/content.js` — Load site configs dynamically, discovery capture mode
- `extension/background.js` — Handle discovery config check + capture relay
- `extension/bridge.js` — Relay discovery captures
