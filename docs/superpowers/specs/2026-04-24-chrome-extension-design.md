# RAMPART Chrome Extension

## Overview

A Chrome browser extension that intercepts prompts submitted to ChatGPT, evaluates them against RAMPART policies before they're sent, and blocks/sanitizes violating prompts. Uses network-level interception (fetch override) for robustness against UI changes.

## Goals

1. **Pre-submission policy enforcement** — Evaluate every prompt against RAMPART before it reaches ChatGPT
2. **User transparency** — When a violation is detected, show the user what was flagged and the sanitized version before proceeding
3. **User control** — User can "Send Sanitized" or "Cancel" — no silent modification
4. **Simple setup** — Configure RAMPART URL and API key in the extension popup

## How It Works

1. Content script injects into `chatgpt.com` pages
2. Overrides `window.fetch` to intercept POST requests to ChatGPT's conversation API
3. When a prompt is detected, pauses the request and sends the prompt to RAMPART `/v1/rampart/evaluate`
4. If no violations: original request proceeds unchanged
5. If violations detected: shows a blocking overlay with violation details and the sanitized prompt
6. User clicks "Send Sanitized" → replaces prompt in the request body and submits
7. User clicks "Cancel" → request is aborted, original text stays in the input

## Architecture

### Extension Components

```
rampart-extension/
├── manifest.json          — Extension manifest (Manifest V3)
├── popup.html             — Settings popup (RAMPART URL, API key)
├── popup.js               — Popup logic (save/load settings)
├── content.js             — Injected into chatgpt.com (fetch override + violation UI)
├── background.js          — Service worker (handles RAMPART API calls from content script)
├── styles.css             — Violation overlay styling
└── icons/
    ├── icon16.png
    ├── icon48.png
    └── icon128.png
```

### Data Flow

```
User types prompt → Clicks Send
    ↓
content.js intercepts fetch() to /backend-api/conversation
    ↓
Sends message to background.js with prompt text
    ↓
background.js calls RAMPART /v1/rampart/evaluate
    ↓
Response: accept or fail with violations + sanitized_request
    ↓
If accept: content.js allows original fetch to proceed
If fail: content.js shows violation overlay
    ↓
User clicks "Send Sanitized": content.js replaces prompt in request body, submits
User clicks "Cancel": fetch is aborted
```

### Why background.js for API calls

Content scripts on `chatgpt.com` can't directly call RAMPART due to CORS (different origin). The background service worker can make cross-origin requests. Content script sends a message to background, background calls RAMPART, returns the result.

## Content Script — Fetch Interception

The content script overrides `window.fetch` on ChatGPT pages:

```javascript
const originalFetch = window.fetch;
window.fetch = async function(url, options) {
    // Only intercept POST to the conversation endpoint
    if (url.includes('/backend-api/conversation') && options?.method === 'POST') {
        const body = JSON.parse(options.body);
        const prompt = extractPrompt(body);
        if (prompt) {
            const result = await chrome.runtime.sendMessage({
                type: 'evaluate',
                prompt: prompt
            });
            if (result.decision === 'fail') {
                // Show violation overlay and wait for user decision
                const userChoice = await showViolationOverlay(result);
                if (userChoice === 'cancel') {
                    throw new DOMException('Request aborted by RAMPART', 'AbortError');
                }
                if (userChoice === 'sanitize' && result.sanitized_prompt) {
                    body.messages[0].content.parts[0] = result.sanitized_prompt;
                    options.body = JSON.stringify(body);
                }
            }
        }
    }
    return originalFetch.call(this, url, options);
};
```

### ChatGPT Request Body Structure

ChatGPT sends conversation requests as:
```json
{
    "action": "next",
    "messages": [{
        "author": {"role": "user"},
        "content": {"content_type": "text", "parts": ["the user prompt"]}
    }],
    "model": "gpt-4o",
    ...
}
```

The prompt text is in `messages[0].content.parts[0]`.

## Violation Overlay

When a violation is detected, an overlay appears on top of the ChatGPT interface:

- **Header:** "RAMPART Policy Violation" with the RAMPART shield icon
- **Violations list:** Each violation shows policy ID, severity badge, and message
- **Original prompt:** Shown with the flagged content highlighted
- **Sanitized prompt:** Shown below (if available) with redacted portions marked
- **Buttons:**
  - "Send Sanitized" (primary) — Submits the sanitized version
  - "Cancel" (secondary) — Aborts the request, returns to the chat input
- **Styling:** Dark theme matching RAMPART's Command Center aesthetic, semi-transparent backdrop

The overlay is injected as a shadow DOM element to avoid CSS conflicts with ChatGPT.

## Background Service Worker

Handles RAMPART API communication:

```javascript
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'evaluate') {
        evaluatePrompt(message.prompt).then(sendResponse);
        return true; // async response
    }
});

async function evaluatePrompt(prompt) {
    const settings = await chrome.storage.sync.get(['rampartUrl', 'apiKey']);
    const url = settings.rampartUrl || 'http://localhost:8080';
    const response = await fetch(`${url}/v1/rampart/evaluate`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${settings.apiKey || ''}`
        },
        body: JSON.stringify({
            request: {
                model: 'chatgpt',
                messages: [{ role: 'user', content: prompt }]
            }
        })
    });
    return response.json();
}
```

## Popup Settings

Simple form with:

- **RAMPART URL** — Text input, default `http://localhost:8080`
- **API Key** — Text input, stored in `chrome.storage.sync`
- **Test Connection** button — Calls `/health` to verify connectivity
- **Status indicator** — Green/red dot showing connection status
- **Extension toggle** — Enable/disable interception without removing the extension

## Manifest V3

```json
{
    "manifest_version": 3,
    "name": "RAMPART - Prompt Firewall",
    "version": "0.1.0",
    "description": "Evaluate and sanitize AI prompts before submission using RAMPART policy engine",
    "permissions": ["storage", "activeTab"],
    "host_permissions": ["https://chatgpt.com/*", "http://localhost:8080/*", "http://*/*"],
    "background": {
        "service_worker": "background.js"
    },
    "content_scripts": [{
        "matches": ["https://chatgpt.com/*"],
        "js": ["content.js"],
        "css": ["styles.css"],
        "run_at": "document_start"
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

## Edge Cases

- **No RAMPART connection:** If RAMPART is unreachable, let the prompt through with a warning badge on the extension icon. Don't block the user from using ChatGPT.
- **Slow evaluation:** Show a "Checking..." indicator in the chat while waiting for RAMPART response. Timeout after 10 seconds and let through with warning.
- **Image/file uploads:** Only intercept text prompts for now. File uploads pass through unchecked.
- **Streaming responses:** The fetch override only intercepts the outgoing request, not the streaming response. Post-LLM evaluation is not handled by the extension (that's the server's job if configured).

## File Structure

All extension files live in `extension/` at the project root:

```
extension/
├── manifest.json
├── popup.html
├── popup.js
├── content.js
├── background.js
├── styles.css
└── icons/
    ├── icon16.png
    ├── icon48.png
    └── icon128.png
```

## Not In Scope

- Multi-site support (Claude.ai, Gemini, etc.) — future work
- Auto-config / user provisioning — future work
- Post-LLM response checking in the extension — server handles this
- Chrome Web Store publishing — manual install for now
