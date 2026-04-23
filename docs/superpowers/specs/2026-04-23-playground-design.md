# RAMPART Playground: Policy Evaluation Simulator

## Overview

An interactive playground page in the RAMPART admin UI that lets users compose multimodal prompts, select or create ad-hoc policies, evaluate them through the real policy engine, view per-policy match/pass results and the sanitized request, and optionally send the request to the upstream LLM to see the response. All within the existing Command Center Dark theme.

## Goals

1. **Test policies before deploying** — See exactly which policies match a given prompt and why, without sending real traffic
2. **Multimodal input** — Support text + image URLs in messages to test vision-model requests
3. **Full evaluation transparency** — Per-policy pass/match breakdown with violation details, source, and path
4. **Sanitized request visibility** — Show what the request looks like after redaction and tool removal
5. **Optional upstream send** — Forward the (sanitized) request to the configured LLM and display the response

## Constraints

- New file `rampart/app/playground.py` for all playground logic (route handlers, HTML generation, helpers)
- Registered as a FastAPI router in `main.py`
- Follows the existing server-rendered HTML pattern with embedded CSS/JS in `ui.py`'s `_page()` wrapper
- JavaScript is inline, minimal, no build tools — uses `fetch()` for evaluation to avoid full page reload
- Does NOT write to the evaluation log (simulation only)
- Does NOT support streaming LLM responses
- Does NOT persist playground sessions

## Architecture

### Routes

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/ui/playground` | Render the playground form (auth required) |
| POST | `/ui/playground` | Evaluate request, return results HTML fragment (auth required) |

### Data Flow

```
User composes prompt + selects policies + clicks "Evaluate & Send"
    ↓
POST /ui/playground (form data)
    ↓
playground.py:
  1. Parse form data into messages list (text + image_url parts)
  2. Build OpenAI-compatible request dict
  3. Resolve selected policies (existing + ad-hoc)
  4. Create PolicyEngine(config, selected_policies)
  5. await engine.evaluate(request_dict)
  6. If send requested and not blocked (or force_send):
     a. Resolve upstream config (global or overrides from form)
     b. Apply sanitized request if violations exist
     c. await proxy_chat_completion(upstream, payload)
  7. Render results HTML (policy results + sanitized request + LLM response)
    ↓
JavaScript replaces #results container with returned HTML
```

### File Structure

- `rampart/app/playground.py` — All playground code: route handlers, form parsing, request building, results rendering
- `rampart/app/main.py` — Add `app.include_router(playground_router)` 
- `rampart/app/ui.py` — Add "Playground" nav link to `_page()` header, add playground-specific CSS to style block

## Input Area (Top Half)

### Message Builder (Left, ~60% width)

A dynamic list of message rows. Each row has:

- **Role dropdown** — `system`, `user`, or `assistant` (HTML `<select>`)
- **Text area** — The message content (resizable, monospace for code-friendliness)
- **"Add Image" link** — Appends an image URL input below the text area. Multiple images per message supported. Each image URL field has a remove button and shows a thumbnail preview (`<img>` with `max-height: 80px`, `object-fit: contain`).
- **Remove button** — Removes the message row (hidden if only one message remains)

Default state: one system message ("You are a helpful assistant.") and one empty user message.

An "Add Message" button below the list appends a new user message row.

Form field naming convention:
- `msg_role_0`, `msg_text_0`, `msg_img_0_0`, `msg_img_0_1`, ...
- `msg_role_1`, `msg_text_1`, `msg_img_1_0`, ...
- `msg_count` — total number of messages (hidden field, updated by JS)

### Policy Selector (Right, ~40% width)

**Existing policies section:**
- "Select All / None" toggle at top
- Checkbox list of all configured policies (both enabled and disabled from `default.yaml`)
- Each checkbox shows: policy ID (code), severity badge, description (muted)
- Checkbox name: `policy_{policy_id}` with value `on`

**Ad-hoc rules section:**
- "Add Ad-hoc Rule" button appends a temporary rule form:
  - Type dropdown: `regex` or `llm`
  - For regex: pattern input field
  - For llm: instruction textarea
  - Severity dropdown: low/medium/high/critical
  - Action dropdown: block/warn
  - Remove button
- Form field naming: `adhoc_type_0`, `adhoc_pattern_0`, `adhoc_instruction_0`, `adhoc_severity_0`, `adhoc_action_0`, `adhoc_count` (hidden)

### Controls Bar (Bottom of Input)

- **Model field** — Optional text input for model name override (placeholder shows configured upstream model)
- **Override Upstream** — Collapsible section (hidden by default, toggle link) with: Base URL, API Key, Timeout Seconds
- **Two action buttons (right-aligned):**
  - "Evaluate Only" — Runs policy evaluation, does not send to upstream. Submits with `action=evaluate`
  - "Evaluate & Send" — Runs policy evaluation, then sends to upstream if not blocked. Submits with `action=send`

## Results Area (Bottom Half)

Appears after evaluation. Three panels in a horizontal flex layout.

### Left Panel — Policy Results (~35%)

- **Decision banner** — Full-width bar at top:
  - Accepted: green background (`--success-bg`), green text, "ACCEPTED" label
  - Blocked: red background (`--danger-bg`), red text, "BLOCKED" label
  - With `animation: fadeIn 0.2s ease-out`
- **Per-policy breakdown** — Vertical list, one entry per evaluated policy:
  - Policy ID in monospace cyan
  - Severity badge (reuses `.pill.severity-*` CSS)
  - Status indicator: green "PASS" or red "MATCH"
  - For matches — expandable detail (click to toggle) showing:
    - Violation message
    - Source: "deterministic" or "llm" badge
    - Path: e.g. `messages[1].content` (if present)
    - For regex: the matched pattern
    - For LLM: the evaluator's reasoning
  - Ad-hoc rules display with "(ad-hoc)" suffix on the ID
- **Timing** — "Evaluated in {N}ms" at bottom in muted text

### Center Panel — Sanitized Request (~30%)

- **Header** — "Sanitized Request" with a subtitle: "What would be sent to the upstream LLM"
- **Content:**
  - If no modifications needed: muted text "No modifications — original request passes clean"
  - If sanitized: formatted JSON display with:
    - `[REDACTED]` tokens highlighted in amber (`--warning` color)
    - Normal text in `--text` color
    - Keys in `--primary` color
    - The JSON is rendered as a `<pre><code>` block with basic CSS syntax coloring (no library)
  - If tools were removed: a note above the JSON listing removed tool names

### Right Panel — LLM Response (~35%)

- **Header** — "LLM Response"
- **Content based on state:**
  - "Evaluate Only" was clicked: muted text "Not sent to upstream — use 'Evaluate & Send' to see LLM response"
  - Blocked and not force-sent: "Blocked by policy — not sent to upstream" with a "Force Send Anyway" button that re-submits with `action=force_send`
  - Successfully sent: 
    - Response content (the assistant message text)
    - Metadata below in muted text: model name, token usage (prompt/completion/total if available), response time
  - Upstream error: error message in red (`--danger`) with status code

## JavaScript

All inline in `playground.py`'s page rendering function (not in `_page()` since it's playground-specific). Approximately ~80 lines of vanilla JS.

### Message Builder JS
- `addMessage()` — Appends a new message row, updates `msg_count`
- `removeMessage(index)` — Removes a row, re-indexes remaining fields, updates `msg_count`
- `addImage(msgIndex)` — Appends an image URL field to a message row
- `removeImage(msgIndex, imgIndex)` — Removes an image field
- Image URL inputs trigger thumbnail preview on blur (`<img>` created/updated dynamically)

### Policy Selector JS
- `toggleAll(checked)` — Checks/unchecks all policy checkboxes
- `addAdhocRule()` — Appends ad-hoc rule form fields, updates `adhoc_count`
- `removeAdhocRule(index)` — Removes ad-hoc rule fields
- `adhocTypeChanged(index)` — Shows/hides pattern vs instruction field based on type selection

### Evaluation JS
- Form submit intercepted by JS
- `fetch()` POSTs form data to `/ui/playground`
- Response HTML replaces `#playground-results` container
- Loading state: results area shows a spinner/pulsing "Evaluating..." message
- "Force Send Anyway" button triggers another fetch with `action=force_send`

### Collapsible Sections JS
- `toggleUpstreamOverride()` — Shows/hides override upstream fields
- `togglePolicyDetail(index)` — Expands/collapses individual policy violation details
- `collapseInput()` / `expandInput()` — Accordion toggle for input area after evaluation

## CSS Additions

Added to the `_page()` style block in `ui.py` (playground-specific classes):

```css
.pg-layout { display: flex; flex-direction: column; gap: 18px; }
.pg-input { display: flex; gap: 16px; }
.pg-messages { flex: 3; display: flex; flex-direction: column; gap: 10px; }
.pg-policies { flex: 2; }
.pg-msg-row { display: flex; gap: 8px; align-items: flex-start; }
.pg-msg-role { width: 100px; flex-shrink: 0; }
.pg-msg-text { flex: 1; min-height: 60px; }
.pg-msg-images { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 6px; }
.pg-msg-images img { max-height: 80px; border-radius: 4px; border: 1px solid var(--border); object-fit: contain; }
.pg-controls { display: flex; justify-content: space-between; align-items: center; gap: 16px; }
.pg-results { display: flex; gap: 12px; min-height: 300px; }
.pg-results > div { flex: 1; background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 16px; overflow-y: auto; max-height: 500px; }
.pg-decision { padding: 8px 12px; border-radius: 6px; font-weight: 700; font-size: 13px; text-align: center; margin-bottom: 12px; }
.pg-decision.accepted { background: var(--success-bg); border: 1px solid var(--success-border); color: var(--success); }
.pg-decision.blocked { background: var(--danger-bg); border: 1px solid var(--danger-border); color: var(--danger); }
.pg-policy-item { padding: 8px 0; border-bottom: 1px solid rgba(255,255,255,0.04); }
.pg-policy-header { display: flex; justify-content: space-between; align-items: center; cursor: pointer; }
.pg-policy-detail { display: none; padding: 8px 0 0 12px; color: var(--text-secondary); font-size: 12px; }
.pg-policy-detail.open { display: block; }
.pg-json { background: var(--bg); border-radius: 6px; padding: 12px; font-family: "SFMono-Regular", Consolas, monospace; font-size: 12px; white-space: pre-wrap; word-break: break-all; overflow-x: auto; }
.pg-json .key { color: var(--primary); }
.pg-json .redacted { color: var(--warning); font-weight: 600; }
.pg-adhoc { border: 1px dashed var(--border); border-radius: 6px; padding: 10px; margin-top: 8px; }
.pg-loading { display: flex; align-items: center; justify-content: center; min-height: 200px; color: var(--muted); }
```

Mobile responsive: at `max-width: 760px`, `.pg-input` and `.pg-results` switch to `flex-direction: column`.

## Nav Link

Add "Playground" to the header nav in `_page()`. Update `_nav_class()` to detect "playground" in the title.

## Implementation Scope

### New Files
1. `rampart/app/playground.py` — Route handlers, form parsing, request construction, HTML rendering for all playground UI

### Modified Files
2. `rampart/app/main.py` — Import and include playground router
3. `rampart/app/ui.py` — Add "Playground" nav link to `_page()` header, add `.pg-*` CSS classes to style block, update `_nav_class()` 

### Not Modified
- No changes to policy engine, LLM evaluator, proxy, models, or tracking
- Playground reuses existing `PolicyEngine`, `proxy_chat_completion`, `sanitize_request` directly
