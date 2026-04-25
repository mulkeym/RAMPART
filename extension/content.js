(function() {
    'use strict';

    let requestId = 0;
    const pendingRequests = {};

    function sendToBridge(type, data) {
        return new Promise((resolve) => {
            const id = ++requestId;
            pendingRequests[id] = resolve;
            window.postMessage({ source: 'rampart-content', type, id, ...data }, '*');
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
        // ChatGPT format: messages[0].content.parts[0]
        try {
            const msg = body.messages && body.messages[0];
            if (msg && msg.content && msg.content.parts) {
                const textParts = [];
                for (const part of msg.content.parts) {
                    if (typeof part === 'string') textParts.push(part);
                    else if (part && typeof part === 'object' && part.text) textParts.push(part.text);
                }
                if (textParts.length > 0) return textParts.join('\n');
            }
        } catch (e) {}

        // Ask Sage format: message field is JSON array of conversation history
        if (typeof body.message === 'string' && body.message.trim()) {
            try {
                const parsed = JSON.parse(body.message);
                if (Array.isArray(parsed)) {
                    for (let i = parsed.length - 1; i >= 0; i--) {
                        if (parsed[i].user === 'me' && parsed[i].message) {
                            return parsed[i].message;
                        }
                    }
                }
            } catch (e) {}
            return body.message;
        }
        // Generic formats
        if (typeof body.prompt === 'string' && body.prompt.trim()) return body.prompt;
        if (typeof body.query === 'string' && body.query.trim()) return body.query;
        if (typeof body.input === 'string' && body.input.trim()) return body.input;
        if (typeof body.content === 'string' && body.content.trim()) return body.content;
        // OpenAI standard messages format
        try {
            if (Array.isArray(body.messages)) {
                const last = body.messages[body.messages.length - 1];
                if (last && typeof last.content === 'string') return last.content;
            }
        } catch (e) {}

        return null;
    }

    function extractImageAssets(body) {
        try {
            const msg = body.messages && body.messages[0];
            if (!msg || !msg.content || !msg.content.parts) return [];
            const assets = [];
            for (const part of msg.content.parts) {
                if (part && typeof part === 'object' && part.content_type === 'image_asset_pointer') {
                    assets.push(part.asset_pointer || '');
                }
            }
            return assets;
        } catch (e) {}
        return [];
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
            const violations = result.violations || [];

            const dialog = document.createElement('dialog');
            dialog.style.cssText = 'border:none;background:transparent;padding:0;max-width:560px;width:90%;outline:none;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);margin:0';

            const modal = document.createElement('div');
            modal.style.cssText = 'background:#151d27;border:1px solid rgba(255,255,255,0.12);border-radius:12px;padding:24px;max-height:80vh;overflow-y:auto;color:#e2e8f0;font-size:14px';

            const iconRow = document.createElement('div');
            iconRow.style.cssText = 'display:flex;justify-content:center;margin-bottom:12px';
            const icon = document.createElement('img');
            icon.src = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADAAAAAwCAYAAABXAvmHAAAAtklEQVR4nO3UuxGAIBAEUHMDE4uxBruhAxuzFWswNMMIA8YPI3fsobszG7tvBJqGYeQzzJu32P8B2q5fLZQAdAlAlwB0CUCXAHQJQJcAdFUA4zL50PhDTyWAgC/cAQLQgOrvgGlACqIU4NX41L9g8vxbQmSNRyNExt8hNud8qPQdEB1/hdACqIw/Q2gAVMfHAPPnvjSiyHgtRNHx0gjIeCkEdHwuwsT4kNTnMy5695HqAQzD4LIDduhXDuO/4ioAAAAASUVORK5CYII=';
            icon.style.cssText = 'width:48px;height:48px;display:block';
            iconRow.appendChild(icon);
            modal.appendChild(iconRow);

            const header = document.createElement('div');
            header.style.cssText = 'font-size:18px;font-weight:700;color:#f87171;margin-bottom:16px;text-align:center';
            header.textContent = 'RAMPART Policy Violation';
            modal.appendChild(header);

            violations.forEach(v => {
                const item = document.createElement('div');
                item.style.cssText = 'padding:8px 12px;margin-bottom:6px;background:rgba(255,255,255,0.05);border-radius:6px';
                const severity = document.createElement('span');
                const sevColor = (v.severity || 'medium') === 'high' ? '#f87171' : (v.severity || 'medium') === 'low' ? '#facc15' : '#fb923c';
                severity.style.cssText = 'display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;text-transform:uppercase;margin-right:8px;background:' + sevColor + '22;color:' + sevColor;
                severity.textContent = v.severity || 'medium';
                const policyName = document.createElement('strong');
                policyName.textContent = v.policy_id || 'unknown';
                item.appendChild(severity);
                item.appendChild(policyName);
                item.appendChild(document.createTextNode(': ' + (v.message || 'Policy violation')));
                modal.appendChild(item);
            });

            const promptLabel = document.createElement('div');
            promptLabel.style.cssText = 'font-size:11px;text-transform:uppercase;color:#94a3b8;margin:16px 0 6px';
            promptLabel.textContent = 'Original Prompt';
            modal.appendChild(promptLabel);
            const promptBox = document.createElement('div');
            promptBox.style.cssText = 'background:rgba(0,0,0,0.3);border-radius:6px;padding:12px;font-family:monospace;font-size:13px;white-space:pre-wrap;max-height:120px;overflow-y:auto;color:#cbd5e1';
            // Show clean prompt text — strip any raw protocol data
            let displayPrompt = originalPrompt || '';
            // If the prompt looks like raw JSON array data, try to extract just the user text
            if (displayPrompt.startsWith('[[') || displayPrompt.startsWith('[{')) {
                try {
                    const arr = JSON.parse(displayPrompt);
                    if (Array.isArray(arr) && Array.isArray(arr[0]) && typeof arr[0][0] === 'string') {
                        displayPrompt = arr[0][0];
                    }
                } catch(e) {}
            }
            promptBox.textContent = displayPrompt.substring(0, 500);
            modal.appendChild(promptBox);

            const actions = document.createElement('div');
            actions.style.cssText = 'margin-top:20px;display:flex;gap:10px;justify-content:flex-end';
            const btn = document.createElement('button');
            btn.style.cssText = 'padding:8px 20px;border-radius:6px;border:none;font-size:13px;font-weight:600;cursor:pointer;background:#f87171;color:#fff';
            btn.textContent = 'Acknowledged';
            btn.onclick = () => { dialog.close(); dialog.remove(); resolve({ action: 'cancel' }); };
            actions.appendChild(btn);
            modal.appendChild(actions);

            dialog.appendChild(modal);

            // Add backdrop styling for faded background
            const backdropStyle = document.createElement('style');
            backdropStyle.textContent = 'dialog[open]::backdrop{background:rgba(0,0,0,0.7)}';
            dialog.appendChild(backdropStyle);

            document.body.appendChild(dialog);
            try { dialog.showModal(); } catch(e) {
                // Fallback to alert if showModal fails
                window.alert('RAMPART Policy Violation\n\n' + violations.map(v => v.message).join('\n'));
                dialog.remove();
                resolve({ action: 'cancel' });
            }
        });
    }

    // Cache pasted images from clipboard
    const pastedImages = [];

    document.addEventListener('paste', function(e) {
        if (!e.clipboardData || !e.clipboardData.items) return;
        for (const item of e.clipboardData.items) {
            if (item.type.indexOf('image') === 0) {
                const file = item.getAsFile();
                if (!file) continue;
                const reader = new FileReader();
                reader.onload = function(ev) {
                    pastedImages.push(ev.target.result);
                };
                reader.readAsDataURL(file);
            }
        }
    }, true);

    // Also intercept drag-and-drop images
    document.addEventListener('drop', function(e) {
        if (!e.dataTransfer || !e.dataTransfer.files) return;
        for (const file of e.dataTransfer.files) {
            if (!file.type.startsWith('image/')) continue;
            const reader = new FileReader();
            reader.onload = function(ev) {
                pastedImages.push(ev.target.result);
            };
            reader.readAsDataURL(file);
        }
    }, true);

    // Load site configs and discovery mode from RAMPART
    let siteConfigs = [];
    let discoveryMode = false;
    let discoveryCaptureBuffer = [];

    sendToBridge('getConfig', {}).then(config => {
        if (config && config.sites) siteConfigs = config.sites;
        if (config && config.discovery) discoveryMode = true;
        console.log('[RAMPART v3] Loaded', siteConfigs.length, 'site configs:', siteConfigs.map(s => s.url_pattern + ' / ' + s.endpoint_contains).join(', '));
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
        const extraction = site.prompt_extraction;

        // chatgpt_parts: messages[0].content.parts — ChatGPT's nested format
        if (extraction === 'chatgpt_parts') {
            try {
                const msg = body.messages && body.messages[0];
                if (msg && msg.content && msg.content.parts) {
                    const textParts = [];
                    for (const part of msg.content.parts) {
                        if (typeof part === 'string') textParts.push(part);
                        else if (part && typeof part === 'object' && part.text) textParts.push(part.text);
                    }
                    if (textParts.length > 0) return textParts.join('\n');
                }
            } catch (e) {}
            return null;
        }

        // openai_messages: last message content in messages[] array
        if (extraction === 'openai_messages') {
            try {
                if (Array.isArray(body.messages)) {
                    const last = body.messages[body.messages.length - 1];
                    if (last && typeof last.content === 'string') return last.content;
                }
            } catch (e) {}
            return null;
        }

        // For field-based extractions, get the field value
        const fieldValue = body[site.prompt_field];
        if (!fieldValue) return null;

        if (extraction === 'direct') {
            return typeof fieldValue === 'string' ? fieldValue : null;
        }

        if (extraction === 'json_array_last_user') {
            try {
                const arr = typeof fieldValue === 'string' ? JSON.parse(fieldValue) : fieldValue;
                if (Array.isArray(arr)) {
                    // Standard object-based extraction: [{user: "me", message: "hello"}, ...]
                    for (let i = arr.length - 1; i >= 0; i--) {
                        if (arr[i] && arr[i].user === site.prompt_user_key) {
                            return arr[i][site.prompt_message_key || 'message'] || null;
                        }
                    }
                    // Nested array: check arr[0][0] first (Gemini puts prompt here)
                    if (Array.isArray(arr[0]) && typeof arr[0][0] === 'string' && arr[0][0].length > 0) {
                        return arr[0][0];
                    }
                    // Fallback: deep scan
                    const found = _deepFindPrompt(arr);
                    if (found) return found;
                }
            } catch (e) {}
        }

        // deep_scan: recursively find user prompt in nested arrays
        if (extraction === 'deep_scan') {
            try {
                const data = typeof fieldValue === 'string' ? JSON.parse(fieldValue) : fieldValue;
                if (Array.isArray(data)) return _deepFindPrompt(data);
            } catch (e) {}
        }

        return null;
    }

    // Recursively search nested arrays for the user's prompt text
    function _deepFindPrompt(data) {
        if (!Array.isArray(data)) return null;
        // Recurse into sub-arrays first (prompt is nested deeper than tokens)
        for (const item of data) {
            if (Array.isArray(item)) {
                const found = _deepFindPrompt(item);
                if (found) return found;
            }
        }
        // Then check strings at this level
        for (const item of data) {
            if (typeof item === 'string' && item.length > 10
                && !item.startsWith('http') && !item.startsWith('!')
                && !item.match(/^[a-f0-9-]{20,}$/) && !item.match(/^[A-Za-z0-9_]{2,8}$/)) {
                return item;
            }
        }
        return null;
    }

    // Clean prompt text — if it's raw JSON array data, extract just the user message
    function cleanPrompt(text) {
        if (!text) return text;
        if (text.startsWith('[[') || text.startsWith('[{')) {
            try {
                const arr = JSON.parse(text);
                if (Array.isArray(arr) && Array.isArray(arr[0]) && typeof arr[0][0] === 'string') {
                    return arr[0][0];
                }
            } catch(e) {}
        }
        return text;
    }

    // Flush discovery captures every 30 seconds
    setInterval(() => {
        if (discoveryCaptureBuffer.length > 0) {
            const batch = discoveryCaptureBuffer.splice(0);
            sendToBridge('sendCaptures', { captures: batch });
        }
    }, 30000);

    // Override fetch
    const originalFetch = window.fetch;
    window.fetch = async function(url, options) {
        // If url is a Request, clone it immediately so we always have a clean copy to forward
        const isRequest = url instanceof Request;
        const fetchUrl = isRequest ? url.clone() : url;

        // Debug: log all POST fetch calls when discovery mode is active
        if (discoveryMode) {
            const dbgUrl = isRequest ? url.url : String(url);
            const dbgMethod = isRequest ? url.method : (options && options.method || 'GET');
            if (dbgMethod && dbgMethod.toUpperCase() === 'POST') {
                console.log('[RAMPART Discovery] POST fetch:', dbgUrl.substring(0, 200));
            }
        }

        // Normalize URL and method for matching
        let resolvedUrl = '';
        let resolvedMethod = '';
        let inspectBody = null;
        if (isRequest) {
            resolvedUrl = url.url;
            resolvedMethod = (url.method || 'GET').toUpperCase();
        } else {
            let rawUrl = typeof url === 'string' ? url : String(url);
            if (rawUrl.startsWith('/')) rawUrl = location.origin + rawUrl;
            resolvedUrl = rawUrl;
            resolvedMethod = (options && options.method || 'GET').toUpperCase();
            inspectBody = options && options.body;
        }

        // Detect conversation endpoints via site configs (ChatGPT, Ask Sage, Gemini, etc.)
        const isConversation = resolvedMethod === 'POST' && matchesSiteConfig(resolvedUrl) !== null;
        if (isConversation) {
            const settings = await sendToBridge('getSettings', {});
            if (settings && settings.enabled === false) {
                return originalFetch.call(this, fetchUrl, options);
            }

            try {
                // Parse body — clone Request to read body without disturbing the original
                let body;
                let rawBody = inspectBody;
                if (isRequest) {
                    try {
                        const cloned = url.clone();
                        rawBody = await cloned.text();
                    } catch(e) { rawBody = null; }
                }
                if (rawBody instanceof FormData) {
                    body = {};
                    const formImagePromises = [];
                    for (const [key, value] of rawBody.entries()) {
                        if (typeof value === 'string') {
                            body[key] = value;
                        } else if (value instanceof File) {
                            if (value.type.startsWith('image/')) {
                                formImagePromises.push(new Promise((resolve) => {
                                    const reader = new FileReader();
                                    reader.onload = function(ev) {
                                        pastedImages.push(ev.target.result);
                                        resolve();
                                    };
                                    reader.readAsDataURL(value);
                                }));
                            }
                        }
                    }
                    if (formImagePromises.length > 0) {
                        await Promise.all(formImagePromises);
                    }
                } else if (typeof rawBody === 'string') {
                    body = JSON.parse(rawBody);
                } else {
                    body = {};
                }
                const matchedSite = matchesSiteConfig(resolvedUrl);
                const prompt = matchedSite ? extractPromptFromSite(body, matchedSite) : extractPrompt(body);
                const imageAssets = extractImageAssets(body);

                // Include any captured images (from paste, drop, or FormData)
                const images = [];
                if (pastedImages.length > 0) {
                    images.push(...pastedImages);
                }

                if (prompt || images.length > 0) {
                    const cleanedPrompt = cleanPrompt(prompt || '');
                    const result = await sendToBridge('evaluate', { prompt: cleanedPrompt, images: images });

                    if (result && result.error) {
                        return originalFetch.call(this, fetchUrl, options);
                    }

                    if (result && result.decision === 'fail') {
                        const userChoice = await showViolationOverlay(result, cleanedPrompt);

                        if (userChoice.action === 'cancel') {
                            throw new DOMException('Request blocked by RAMPART', 'AbortError');
                        }
                    }
                    // Clear image cache after evaluation
                    pastedImages.length = 0;
                }
            } catch (e) {
                if (e.name === 'AbortError') throw e;
            }
        }
        // Discovery mode: capture POST requests on unknown sites
        if (discoveryMode && resolvedMethod === 'POST') {
            const noisePatterns = [
                'rampart', 'google-analytics.com', 'googletagmanager.com',
                'googleadservices.com', 'googlesyndication.com', 'doubleclick.net',
                'analytics', 'datadog', 'sentry', '/log', '/metrics', '/beacon',
                'play.google.com/log', '/pagead/', '/measurement/conversion'
            ];
            if (!noisePatterns.some(p => resolvedUrl.includes(p))) {
                try {
                    let bodyKeys = [];
                    let bodyPreview = '';
                    let bodyFormat = 'unknown';
                    let captureBody = options.body || resolvedBody;
                    // If body is a ReadableStream (e.g. from Request object), try to read it
                    if (captureBody && typeof captureBody === 'object' && typeof captureBody.getReader === 'function') {
                        try {
                            // Clone the Request so we don't consume the original body
                            if (url instanceof Request) {
                                const cloned = url.clone();
                                const text = await cloned.text();
                                captureBody = text;
                            }
                        } catch(e) { captureBody = null; }
                    }
                    if (captureBody instanceof FormData) {
                        bodyFormat = 'formdata';
                        for (const [key] of captureBody.entries()) bodyKeys.push(key);
                    } else if (typeof captureBody === 'string') {
                        bodyFormat = 'json';
                        try {
                            bodyKeys = Object.keys(JSON.parse(captureBody));
                            bodyPreview = captureBody.substring(0, 500);
                        } catch(e) { bodyPreview = captureBody.substring(0, 500); }
                    }
                    discoveryCaptureBuffer.push({
                        url: resolvedUrl.substring(0, 500),
                        body_keys: bodyKeys.slice(0, 20),
                        body_preview: bodyPreview,
                        body_format: bodyFormat,
                        content_type: (options.headers && (typeof options.headers === 'object' ? (options.headers['content-type'] || options.headers['Content-Type'] || '') : '')) || '',
                    });
                } catch(e) {}
            }
        }
        return originalFetch.call(this, fetchUrl, options);
    };

    // Override XMLHttpRequest to capture discovery data from sites that use XHR (e.g. Gemini)
    const originalXHROpen = XMLHttpRequest.prototype.open;
    const originalXHRSend = XMLHttpRequest.prototype.send;

    XMLHttpRequest.prototype.open = function(method, url, ...args) {
        this._rampartMethod = method;
        let rawUrl = typeof url === 'string' ? url : String(url);
        // Resolve relative URLs to full URLs
        if (rawUrl.startsWith('/')) {
            rawUrl = location.origin + rawUrl;
        }
        this._rampartUrl = rawUrl;
        return originalXHROpen.call(this, method, url, ...args);
    };

    XMLHttpRequest.prototype.send = function(body) {
        const xhrUrl = this._rampartUrl || '';
        const xhrMethod = (this._rampartMethod || '').toUpperCase();

        // Check if this XHR matches a site config for prompt evaluation
        if (xhrMethod === 'POST' && xhrUrl) {
            const matchedSite = matchesSiteConfig(xhrUrl);
            if (matchedSite) {
                const xhr = this;
                (async () => {
                    try {
                        const settings = await sendToBridge('getSettings', {});
                        if (settings && settings.enabled === false) {
                            originalXHRSend.call(xhr, body);
                            return;
                        }
                        // Parse body to extract prompt
                        let parsed = {};
                        if (typeof body === 'string') {
                            try { parsed = JSON.parse(body); } catch(e) {
                                // Gemini uses URL-encoded FormData-style body — parse f.req etc.
                                try {
                                    const params = new URLSearchParams(body);
                                    for (const [k, v] of params.entries()) parsed[k] = v;
                                } catch(e2) {}
                            }
                        } else if (body instanceof FormData) {
                            for (const [k, v] of body.entries()) {
                                if (typeof v === 'string') parsed[k] = v;
                            }
                        }
                        const prompt = extractPromptFromSite(parsed, matchedSite);
                        console.log('[RAMPART] XHR site match:', matchedSite.url_pattern, 'prompt:', prompt ? prompt.substring(0, 80) : '(none)', 'keys:', Object.keys(parsed).join(','));
                        const images = pastedImages.length > 0 ? [...pastedImages] : [];

                        if (prompt || images.length > 0) {
                            const cleanedPrompt = cleanPrompt(prompt || '');
                            const result = await sendToBridge('evaluate', { prompt: cleanedPrompt, images });
                            if (result && !result.error && result.decision === 'fail') {
                                const userChoice = await showViolationOverlay(result, cleanedPrompt);
                                if (userChoice.action === 'cancel') {
                                    // Abort the XHR — simulate a network error
                                    xhr.abort();
                                    pastedImages.length = 0;
                                    return;
                                }
                            }
                            pastedImages.length = 0;
                        }
                    } catch(e) {}
                    // Proceed with the original send
                    originalXHRSend.call(xhr, body);
                })();
                return; // Don't send yet — async evaluation in progress
            }
        }

        // Discovery mode: capture POST requests on unknown sites
        if (discoveryMode && xhrMethod === 'POST' && xhrUrl) {
            const noisePatterns = [
                'rampart', 'google-analytics.com', 'googletagmanager.com',
                'googleadservices.com', 'googlesyndication.com', 'doubleclick.net',
                'analytics', 'datadog', 'sentry', '/log', '/metrics', '/beacon',
                'play.google.com/log', '/pagead/', '/measurement/conversion'
            ];
            if (!noisePatterns.some(p => xhrUrl.includes(p))) {
                try {
                    let bodyKeys = [];
                    let bodyPreview = '';
                    let bodyFormat = 'unknown';
                    if (typeof body === 'string') {
                        bodyFormat = 'text';
                        try {
                            bodyKeys = Object.keys(JSON.parse(body));
                            bodyFormat = 'json';
                        } catch(e) {}
                        bodyPreview = body.substring(0, 500);
                    } else if (body instanceof FormData) {
                        bodyFormat = 'formdata';
                        for (const [key] of body.entries()) bodyKeys.push(key);
                    }
                    console.log('[RAMPART Discovery] XHR POST:', xhrUrl.substring(0, 200));
                    discoveryCaptureBuffer.push({
                        url: xhrUrl.substring(0, 500),
                        body_keys: bodyKeys.slice(0, 20),
                        body_preview: bodyPreview,
                        body_format: bodyFormat,
                        content_type: 'xhr',
                    });
                } catch(e) {}
            }
        }
        return originalXHRSend.call(this, body);
    };
})();
