# RAMPART Chrome Extension Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Chrome extension that intercepts ChatGPT prompts, evaluates them against RAMPART policies, and blocks/sanitizes violations — plus a download page in the RAMPART GUI.

**Architecture:** Manifest V3 Chrome extension with content script (fetch override on chatgpt.com), background service worker (RAMPART API calls), and popup (settings). A new `extension.py` router serves the download page and generates a ZIP with the server URL pre-configured.

**Tech Stack:** Chrome Extension Manifest V3, vanilla JavaScript, Python/FastAPI for the download endpoint.

**Spec:** `docs/superpowers/specs/2026-04-24-chrome-extension-design.md`

---

### Task 1: Create extension directory with manifest.json and icons

**Files:**
- Create: `extension/manifest.json`
- Create: `extension/icons/` (SVG-based PNG icons)

- [ ] **Step 1: Create the manifest.json**

Create `extension/manifest.json`:

```json
{
    "manifest_version": 3,
    "name": "RAMPART - Prompt Firewall",
    "version": "0.1.0",
    "description": "Evaluate and sanitize AI prompts before submission using RAMPART policy engine",
    "permissions": ["storage"],
    "host_permissions": ["https://chatgpt.com/*", "http://*/*", "https://*/*"],
    "background": {
        "service_worker": "background.js"
    },
    "content_scripts": [{
        "matches": ["https://chatgpt.com/*"],
        "js": ["content.js"],
        "css": ["styles.css"],
        "run_at": "document_start",
        "world": "MAIN"
    }],
    "action": {
        "default_popup": "popup.html",
        "default_icon": {
            "16": "icons/icon16.png",
            "48": "icons/icon48.png",
            "128": "icons/icon128.png"
        }
    },
    "icons": {
        "16": "icons/icon16.png",
        "48": "icons/icon48.png",
        "128": "icons/icon128.png"
    }
}
```

Note: `"world": "MAIN"` is required so the content script can override `window.fetch` in the page's context. However, MAIN world scripts can't use `chrome.runtime.sendMessage`. We'll handle this with a dual-script approach in Task 3.

- [ ] **Step 2: Update manifest for dual content scripts**

Replace the content_scripts section:

```json
    "content_scripts": [{
        "matches": ["https://chatgpt.com/*"],
        "js": ["bridge.js"],
        "run_at": "document_start"
    }],
    "web_accessible_resources": [{
        "resources": ["content.js", "styles.css"],
        "matches": ["https://chatgpt.com/*"]
    }],
```

`bridge.js` runs in the isolated world (can use chrome APIs) and injects `content.js` into the MAIN world (can override fetch). They communicate via `window.postMessage`.

- [ ] **Step 3: Create placeholder icon files**

Generate simple PNG icons from the RAMPART SVG favicon. Create `extension/icons/` directory with 16x16, 48x48, 128x128 PNGs.

Since we can't render SVGs to PNGs in Python easily, create minimal 1-color PNG files programmatically:

```python
# Run this once to generate icons
import struct, zlib

def create_png(size, color=(56, 189, 248)):
    """Create a minimal solid-color PNG."""
    def chunk(chunk_type, data):
        c = chunk_type + data
        return struct.pack('>I', len(data)) + c + struct.pack('>I', zlib.crc32(c) & 0xffffffff)
    
    header = b'\x89PNG\r\n\x1a\n'
    ihdr = chunk(b'IHDR', struct.pack('>IIBBBBB', size, size, 8, 2, 0, 0, 0))
    raw = b''
    for y in range(size):
        raw += b'\x00' + bytes(color) * size
    idat = chunk(b'IDAT', zlib.compress(raw))
    iend = chunk(b'IEND', b'')
    return header + ihdr + idat + iend

import os
os.makedirs('extension/icons', exist_ok=True)
for s in [16, 48, 128]:
    with open(f'extension/icons/icon{s}.png', 'wb') as f:
        f.write(create_png(s))
```

- [ ] **Step 4: Commit**

```bash
git add extension/
git commit -m "feat(extension): create manifest.json and icon placeholders"
```

---

### Task 2: Create popup.html and popup.js (settings UI)

**Files:**
- Create: `extension/popup.html`
- Create: `extension/popup.js`

- [ ] **Step 1: Create popup.html**

```html
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { width: 320px; background: #0b0f14; color: #e2e8f0; font-family: -apple-system, sans-serif; font-size: 13px; padding: 16px; }
    h1 { font-size: 16px; color: #38bdf8; margin-bottom: 12px; display: flex; align-items: center; gap: 8px; }
    label { display: block; margin-bottom: 10px; color: #94a3b8; font-size: 12px; }
    input { width: 100%; background: #151d27; border: 1px solid rgba(255,255,255,0.08); border-radius: 4px; padding: 8px; color: #e2e8f0; font-size: 13px; margin-top: 4px; }
    input:focus { outline: none; border-color: rgba(56,189,248,0.5); }
    .actions { display: flex; gap: 8px; margin-top: 12px; }
    button { background: #38bdf8; color: #0b0f14; border: none; border-radius: 4px; padding: 8px 12px; font-size: 12px; font-weight: 600; cursor: pointer; flex: 1; }
    button.secondary { background: rgba(255,255,255,0.06); color: #94a3b8; border: 1px solid rgba(255,255,255,0.1); }
    .status { display: flex; align-items: center; gap: 6px; margin-top: 10px; font-size: 11px; color: #64748b; }
    .dot { width: 8px; height: 8px; border-radius: 50%; }
    .dot.green { background: #4ade80; }
    .dot.red { background: #f87171; }
    .dot.gray { background: #64748b; }
    .toggle { display: flex; align-items: center; gap: 8px; margin-bottom: 12px; }
    .toggle input { width: auto; margin: 0; }
  </style>
</head>
<body>
  <h1>RAMPART</h1>
  <div class="toggle">
    <input type="checkbox" id="enabled" checked>
    <label for="enabled" style="margin:0">Enabled</label>
  </div>
  <label>RAMPART Server URL
    <input type="text" id="url" placeholder="http://localhost:8080">
  </label>
  <label>API Key
    <input type="text" id="apiKey" placeholder="rmp_live_...">
  </label>
  <div class="actions">
    <button id="save">Save</button>
    <button id="test" class="secondary">Test</button>
  </div>
  <div class="status" id="status">
    <span class="dot gray"></span>
    <span>Not tested</span>
  </div>
  <script src="popup.js"></script>
</body>
</html>
```

- [ ] **Step 2: Create popup.js**

```javascript
const urlInput = document.getElementById('url');
const apiKeyInput = document.getElementById('apiKey');
const enabledInput = document.getElementById('enabled');
const statusDiv = document.getElementById('status');

// Load saved settings
chrome.storage.sync.get(['rampartUrl', 'apiKey', 'enabled'], (data) => {
    urlInput.value = data.rampartUrl || 'http://localhost:8080';
    apiKeyInput.value = data.apiKey || '';
    enabledInput.checked = data.enabled !== false;
});

// Save settings
document.getElementById('save').addEventListener('click', () => {
    chrome.storage.sync.set({
        rampartUrl: urlInput.value.replace(/\/+$/, ''),
        apiKey: apiKeyInput.value,
        enabled: enabledInput.checked
    }, () => {
        statusDiv.innerHTML = '<span class="dot green"></span><span>Saved</span>';
    });
});

// Test connection
document.getElementById('test').addEventListener('click', async () => {
    statusDiv.innerHTML = '<span class="dot gray"></span><span>Testing...</span>';
    const url = urlInput.value.replace(/\/+$/, '');
    try {
        const resp = await fetch(url + '/health', { method: 'GET' });
        if (resp.ok) {
            const body = await resp.json();
            if (body.status === 'ok') {
                statusDiv.innerHTML = '<span class="dot green"></span><span>Connected to RAMPART</span>';
            } else {
                statusDiv.innerHTML = '<span class="dot red"></span><span>Unexpected response</span>';
            }
        } else {
            statusDiv.innerHTML = '<span class="dot red"></span><span>HTTP ' + resp.status + '</span>';
        }
    } catch (e) {
        statusDiv.innerHTML = '<span class="dot red"></span><span>Cannot connect: ' + e.message + '</span>';
    }
});
```

- [ ] **Step 3: Commit**

```bash
git add extension/popup.html extension/popup.js
git commit -m "feat(extension): create settings popup with URL, API key, and test connection"
```

---

### Task 3: Create bridge.js, content.js, and styles.css

**Files:**
- Create: `extension/bridge.js`
- Create: `extension/content.js`
- Create: `extension/styles.css`

- [ ] **Step 1: Create bridge.js (isolated world — chrome API bridge)**

`bridge.js` runs in the extension's isolated world. It injects `content.js` into the MAIN world and relays messages between the page and the background service worker.

```javascript
// Inject content.js into the page's MAIN world
const script = document.createElement('script');
script.src = chrome.runtime.getURL('content.js');
script.onload = () => script.remove();
(document.head || document.documentElement).appendChild(script);

// Inject styles
const link = document.createElement('link');
link.rel = 'stylesheet';
link.href = chrome.runtime.getURL('styles.css');
(document.head || document.documentElement).appendChild(link);

// Relay messages from page (content.js) to background
window.addEventListener('message', async (event) => {
    if (event.source !== window || !event.data || event.data.source !== 'rampart-content') return;

    if (event.data.type === 'evaluate') {
        try {
            const result = await chrome.runtime.sendMessage({
                type: 'evaluate',
                prompt: event.data.prompt
            });
            window.postMessage({ source: 'rampart-bridge', id: event.data.id, result: result }, '*');
        } catch (e) {
            window.postMessage({ source: 'rampart-bridge', id: event.data.id, result: { error: e.message } }, '*');
        }
    }

    if (event.data.type === 'getSettings') {
        try {
            const settings = await chrome.storage.sync.get(['enabled']);
            window.postMessage({ source: 'rampart-bridge', id: event.data.id, result: settings }, '*');
        } catch (e) {
            window.postMessage({ source: 'rampart-bridge', id: event.data.id, result: { enabled: true } }, '*');
        }
    }
});
```

- [ ] **Step 2: Create content.js (MAIN world — fetch override + overlay)**

```javascript
(function() {
    'use strict';

    let requestId = 0;
    const pendingRequests = {};

    function sendToBridge(type, data) {
        return new Promise((resolve) => {
            const id = ++requestId;
            pendingRequests[id] = resolve;
            window.postMessage({ source: 'rampart-content', type, id, ...data }, '*');
            // Timeout after 15 seconds
            setTimeout(() => {
                if (pendingRequests[id]) {
                    delete pendingRequests[id];
                    resolve({ error: 'timeout' });
                }
            }, 15000);
        });
    }

    window.addEventListener('message', (event) => {
        if (event.source !== window || !event.data || event.data.source !== 'rampart-bridge') return;
        const resolve = pendingRequests[event.data.id];
        if (resolve) {
            delete pendingRequests[event.data.id];
            resolve(event.data.result);
        }
    });

    function extractPrompt(body) {
        try {
            const msg = body.messages && body.messages[0];
            if (msg && msg.content && msg.content.parts && msg.content.parts[0]) {
                return typeof msg.content.parts[0] === 'string' ? msg.content.parts[0] : null;
            }
        } catch (e) {}
        return null;
    }

    function extractSanitizedPrompt(result) {
        try {
            const msgs = result.sanitized_request && result.sanitized_request.messages;
            if (msgs && msgs.length > 0) {
                const content = msgs[msgs.length - 1].content;
                if (typeof content === 'string') return content;
                if (Array.isArray(content)) {
                    return content.filter(p => p.type === 'text').map(p => p.text).join('\n');
                }
            }
        } catch (e) {}
        return null;
    }

    function showViolationOverlay(result, originalPrompt) {
        return new Promise((resolve) => {
            const sanitizedPrompt = extractSanitizedPrompt(result);
            const violations = result.violations || [];

            const overlay = document.createElement('div');
            overlay.id = 'rampart-overlay';

            let violationItems = violations.map(v =>
                '<div class="rampart-violation-item">' +
                '<span class="rampart-severity rampart-severity-' + (v.severity || 'medium') + '">' + (v.severity || 'medium') + '</span> ' +
                '<strong>' + (v.policy_id || 'unknown') + '</strong>: ' +
                (v.message || 'Policy violation') +
                '</div>'
            ).join('');

            overlay.innerHTML =
                '<div class="rampart-modal">' +
                '<div class="rampart-modal-header">RAMPART Policy Violation</div>' +
                '<div class="rampart-violations">' + violationItems + '</div>' +
                '<div class="rampart-section"><div class="rampart-section-label">Original Prompt</div>' +
                '<div class="rampart-prompt-box">' + escapeHtml(originalPrompt) + '</div></div>' +
                (sanitizedPrompt ?
                    '<div class="rampart-section"><div class="rampart-section-label">Sanitized Prompt</div>' +
                    '<div class="rampart-prompt-box rampart-sanitized">' + escapeHtml(sanitizedPrompt) + '</div></div>' : '') +
                '<div class="rampart-actions">' +
                (sanitizedPrompt ? '<button class="rampart-btn rampart-btn-primary" id="rampart-send-sanitized">Send Sanitized</button>' : '') +
                '<button class="rampart-btn rampart-btn-secondary" id="rampart-cancel">Cancel</button>' +
                '</div></div>';

            document.body.appendChild(overlay);

            if (sanitizedPrompt) {
                document.getElementById('rampart-send-sanitized').onclick = () => {
                    overlay.remove();
                    resolve({ action: 'sanitize', prompt: sanitizedPrompt });
                };
            }
            document.getElementById('rampart-cancel').onclick = () => {
                overlay.remove();
                resolve({ action: 'cancel' });
            };
        });
    }

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // Override fetch
    const originalFetch = window.fetch;
    window.fetch = async function(url, options) {
        if (typeof url === 'string' && url.includes('/backend-api/conversation') && options && options.method === 'POST') {
            // Check if extension is enabled
            const settings = await sendToBridge('getSettings', {});
            if (settings && settings.enabled === false) {
                return originalFetch.call(this, url, options);
            }

            try {
                const body = JSON.parse(options.body);
                const prompt = extractPrompt(body);

                if (prompt) {
                    const result = await sendToBridge('evaluate', { prompt: prompt });

                    if (result && result.error) {
                        // RAMPART unreachable — let through with console warning
                        console.warn('[RAMPART] Evaluation failed, letting through:', result.error);
                        return originalFetch.call(this, url, options);
                    }

                    if (result && result.decision === 'fail') {
                        const userChoice = await showViolationOverlay(result, prompt);

                        if (userChoice.action === 'cancel') {
                            throw new DOMException('Request blocked by RAMPART', 'AbortError');
                        }

                        if (userChoice.action === 'sanitize') {
                            body.messages[0].content.parts[0] = userChoice.prompt;
                            options = { ...options, body: JSON.stringify(body) };
                        }
                    }
                }
            } catch (e) {
                if (e.name === 'AbortError') throw e;
                console.warn('[RAMPART] Error during evaluation:', e);
            }
        }
        return originalFetch.call(this, url, options);
    };
})();
```

- [ ] **Step 3: Create styles.css**

```css
#rampart-overlay {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.7);
    z-index: 999999;
    display: flex;
    align-items: center;
    justify-content: center;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    animation: rampart-fadein 0.15s ease-out;
}

@keyframes rampart-fadein {
    from { opacity: 0; }
    to { opacity: 1; }
}

.rampart-modal {
    background: #151d27;
    border: 1px solid rgba(255, 255, 255, 0.12);
    border-radius: 12px;
    padding: 24px;
    max-width: 560px;
    width: 90%;
    max-height: 80vh;
    overflow-y: auto;
    color: #e2e8f0;
    font-size: 14px;
}

.rampart-modal-header {
    font-size: 18px;
    font-weight: 700;
    color: #f87171;
    margin-bottom: 16px;
    display: flex;
    align-items: center;
    gap: 8px;
}

.rampart-violations {
    margin-bottom: 16px;
}

.rampart-violation-item {
    padding: 8px 10px;
    background: rgba(248, 113, 113, 0.08);
    border: 1px solid rgba(248, 113, 113, 0.2);
    border-radius: 6px;
    margin-bottom: 6px;
    font-size: 13px;
}

.rampart-severity {
    display: inline-block;
    padding: 2px 6px;
    border-radius: 999px;
    font-size: 10px;
    font-weight: 600;
    text-transform: uppercase;
}

.rampart-severity-critical { background: rgba(248, 113, 113, 0.2); color: #f87171; }
.rampart-severity-high { background: rgba(251, 191, 36, 0.2); color: #fbbf24; }
.rampart-severity-medium { background: rgba(148, 163, 184, 0.15); color: #94a3b8; }
.rampart-severity-low { background: rgba(100, 116, 139, 0.15); color: #64748b; }

.rampart-section {
    margin-bottom: 12px;
}

.rampart-section-label {
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: #64748b;
    margin-bottom: 6px;
}

.rampart-prompt-box {
    background: #0b0f14;
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 6px;
    padding: 10px;
    font-size: 13px;
    white-space: pre-wrap;
    max-height: 120px;
    overflow-y: auto;
    color: #94a3b8;
}

.rampart-prompt-box.rampart-sanitized {
    border-color: rgba(74, 222, 128, 0.2);
    color: #4ade80;
}

.rampart-actions {
    display: flex;
    gap: 8px;
    margin-top: 16px;
}

.rampart-btn {
    flex: 1;
    padding: 10px;
    border: none;
    border-radius: 6px;
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
}

.rampart-btn-primary {
    background: #38bdf8;
    color: #0b0f14;
}

.rampart-btn-secondary {
    background: rgba(255, 255, 255, 0.06);
    color: #94a3b8;
    border: 1px solid rgba(255, 255, 255, 0.1);
}
```

- [ ] **Step 4: Commit**

```bash
git add extension/bridge.js extension/content.js extension/styles.css
git commit -m "feat(extension): add fetch interception, violation overlay, and bridge for ChatGPT"
```

---

### Task 4: Create background.js (service worker)

**Files:**
- Create: `extension/background.js`

- [ ] **Step 1: Create background.js**

```javascript
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'evaluate') {
        evaluatePrompt(message.prompt).then(sendResponse).catch(err => {
            sendResponse({ error: err.message });
        });
        return true; // async response
    }
});

async function evaluatePrompt(prompt) {
    const settings = await chrome.storage.sync.get(['rampartUrl', 'apiKey', 'enabled']);

    if (settings.enabled === false) {
        return { decision: 'accept', violations: [] };
    }

    const url = (settings.rampartUrl || 'http://localhost:8080').replace(/\/+$/, '');
    const headers = { 'Content-Type': 'application/json' };
    if (settings.apiKey) {
        headers['Authorization'] = 'Bearer ' + settings.apiKey;
    }

    try {
        const response = await fetch(url + '/v1/rampart/evaluate', {
            method: 'POST',
            headers: headers,
            body: JSON.stringify({
                request: {
                    model: 'chatgpt',
                    messages: [{ role: 'user', content: prompt }]
                }
            })
        });

        if (!response.ok) {
            return { error: 'RAMPART returned HTTP ' + response.status };
        }

        return await response.json();
    } catch (e) {
        return { error: e.message };
    }
}
```

- [ ] **Step 2: Commit**

```bash
git add extension/background.js
git commit -m "feat(extension): add background service worker for RAMPART API communication"
```

---

### Task 5: Create extension download page and ZIP endpoint

**Files:**
- Create: `rampart/app/extension.py`
- Modify: `rampart/app/main.py`
- Modify: `rampart/app/ui.py`

- [ ] **Step 1: Create extension.py**

```python
from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, StreamingResponse

from rampart.app.security.auth import read_session_user, require_ui_user
from rampart.app.security.audit import audit_event
from rampart.app.ui import _page

router = APIRouter(include_in_schema=False)

EXTENSION_DIR = Path(__file__).resolve().parents[2] / "extension"


@router.get("/ui/extension", response_class=HTMLResponse)
async def extension_page(request: Request) -> HTMLResponse:
    redirect = require_ui_user(request)
    if redirect:
        audit_event(request, "ui.unauthorized", result="failure", target="/ui/extension")
        return redirect
    actor = read_session_user(request)
    server_url = f"{request.url.scheme}://{request.headers.get('host', 'localhost:8080')}"
    body = f"""
      <section class="toolbar">
        <div>
          <h1>Chrome Extension</h1>
          <p>Intercept and evaluate ChatGPT prompts with RAMPART policies.</p>
        </div>
      </section>
      <section class="panel" style="padding:24px">
        <h2 style="font-size:18px;margin-bottom:16px;color:var(--text)">Setup Instructions</h2>
        <ol style="color:var(--text-secondary);line-height:2;padding-left:20px">
          <li>Click the download button below to get the extension ZIP</li>
          <li>Unzip the downloaded file</li>
          <li>Open Chrome and go to <code>chrome://extensions</code></li>
          <li>Enable <strong>Developer mode</strong> (top right toggle)</li>
          <li>Click <strong>Load unpacked</strong> and select the unzipped folder</li>
          <li>The RAMPART icon appears in your toolbar — click it to verify the connection</li>
          <li>Visit <a href="https://chatgpt.com" target="_blank" style="color:var(--primary)">chatgpt.com</a> and your prompts will be evaluated automatically</li>
        </ol>
        <div style="margin-top:20px;display:flex;gap:12px;align-items:center">
          <a class="button primary" href="/ui/extension/download" style="text-decoration:none">Download Extension (.zip)</a>
          <span class="muted" style="font-size:12px">Pre-configured for <code>{server_url}</code></span>
        </div>
      </section>
    """
    return HTMLResponse(_page("RAMPART Extension", body, actor))


@router.get("/ui/extension/download")
async def download_extension(request: Request):
    redirect = require_ui_user(request)
    if redirect:
        return redirect

    server_url = f"{request.url.scheme}://{request.headers.get('host', 'localhost:8080')}"

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        for file_path in sorted(EXTENSION_DIR.rglob('*')):
            if file_path.is_file():
                rel_path = file_path.relative_to(EXTENSION_DIR)
                content = file_path.read_bytes()
                # Inject server URL into popup.js
                if rel_path.name == 'popup.js':
                    content = content.replace(
                        b"'http://localhost:8080'",
                        f"'{server_url}'".encode()
                    )
                zf.writestr(f"rampart-extension/{rel_path}", content)
    buf.seek(0)
    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": "attachment; filename=rampart-extension.zip"},
    )
```

- [ ] **Step 2: Register the router in main.py**

In `rampart/app/main.py`, add the import after the playground router import:

```python
from rampart.app.extension import router as extension_router
```

Add the router registration:

```python
app.include_router(extension_router)
```

- [ ] **Step 3: Add Extension nav link to ui.py**

In `_nav_class()`, add before `return ""`:

```python
        if label == "Extension" and "extension" in t:
            return "active"
```

In the `auth_nav` construction, add between Playground and Settings:

```python
        f'<a class="{_nav_class("Extension")}" href="/ui/extension">Extension</a>'
```

- [ ] **Step 4: Verify**

Run: `python3 -c "from rampart.app.extension import router; print('OK')"`

- [ ] **Step 5: Commit**

```bash
git add rampart/app/extension.py rampart/app/main.py rampart/app/ui.py
git commit -m "feat(extension): add download page with ZIP generation and nav link"
```

---

### Task 6: Test and verify

- [ ] **Step 1: Run the test suite**

Run: `python3 -m pytest tests/ -v`

Expected: All existing tests pass. No regressions.

- [ ] **Step 2: Verify extension page loads**

Open `http://localhost:8080/ui/extension` — should show setup instructions and download button.

- [ ] **Step 3: Download and verify ZIP**

Click "Download Extension (.zip)". Unzip it and verify:
- All files present: manifest.json, popup.html, popup.js, bridge.js, content.js, background.js, styles.css, icons/
- `popup.js` has the correct server URL pre-filled (not localhost if accessed from LAN)

- [ ] **Step 4: Load in Chrome**

1. Go to `chrome://extensions`
2. Enable Developer mode
3. Click "Load unpacked" and select the unzipped `rampart-extension/` folder
4. Click the extension icon — settings popup should appear with your server URL
5. Click "Test" — should show green "Connected to RAMPART"

- [ ] **Step 5: Test on ChatGPT**

1. Go to `https://chatgpt.com`
2. Type a prompt that should trigger a policy (e.g., "My SSN is 123-45-6789")
3. Click send — the RAMPART violation overlay should appear
4. Click "Send Sanitized" — the sanitized version should be submitted
5. Type a clean prompt — should go through without interruption

- [ ] **Step 6: Commit any fixes**

```bash
git add -A
git commit -m "fix(extension): testing fixes"
```
