(function() {
    'use strict';
    console.log('[RAMPART] Content script loaded on', window.location.href);

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
        try {
            const msg = body.messages && body.messages[0];
            if (!msg || !msg.content || !msg.content.parts) return null;
            console.log('[RAMPART] Message parts:', JSON.stringify(msg.content.parts).substring(0, 500));
            // Extract text from parts — parts can be strings or objects
            const textParts = [];
            for (const part of msg.content.parts) {
                if (typeof part === 'string') {
                    textParts.push(part);
                } else if (part && typeof part === 'object' && part.text) {
                    textParts.push(part.text);
                }
            }
            return textParts.join('\n') || null;
        } catch (e) {}
        return null;
    }

    function extractImageAssets(body) {
        // Extract image asset pointers from ChatGPT message parts
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

    // Cache uploaded images by asset pointer
    const imageCache = {};

    // Override fetch
    const originalFetch = window.fetch;
    window.fetch = async function(url, options) {
        if (typeof url === 'string' && options && options.method === 'POST') {
            // Intercept image uploads to cache them
            if (url.includes('/backend-api/files') || url.includes('/backend-api/f/files')) {
                const resp = await originalFetch.call(this, url, options);
                // Clone and read the response to get the file ID
                try {
                    const clone = resp.clone();
                    const data = await clone.json();
                    if (data && data.file_id) {
                        console.log('[RAMPART] File uploaded, caching ID:', data.file_id);
                        // Try to read the upload body as base64
                        if (options.body instanceof FormData) {
                            const file = options.body.get('file');
                            if (file && file instanceof Blob) {
                                const reader = new FileReader();
                                const dataUrl = await new Promise(resolve => {
                                    reader.onload = () => resolve(reader.result);
                                    reader.readAsDataURL(file);
                                });
                                imageCache['file-service://' + data.file_id] = dataUrl;
                                console.log('[RAMPART] Cached image for file:', data.file_id);
                            }
                        }
                    }
                } catch (e) {
                    console.warn('[RAMPART] Could not cache uploaded file:', e);
                }
                return resp;
            }
        }
        if (typeof url === 'string' && (url.includes('/backend-api/conversation') || url.includes('/backend-api/f/conversation')) && options && options.method === 'POST') {
            console.log('[RAMPART] Conversation request detected:', url);
            const settings = await sendToBridge('getSettings', {});
            if (settings && settings.enabled === false) {
                return originalFetch.call(this, url, options);
            }

            try {
                const body = JSON.parse(options.body);
                const prompt = extractPrompt(body);
                const imageAssets = extractImageAssets(body);

                // Build image URLs from cache
                const images = [];
                for (const asset of imageAssets) {
                    if (imageCache[asset]) {
                        images.push(imageCache[asset]);
                        console.log('[RAMPART] Including cached image for:', asset);
                    }
                }

                if (prompt || images.length > 0) {
                    const result = await sendToBridge('evaluate', { prompt: prompt || '', images: images });

                    if (result && result.error) {
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
