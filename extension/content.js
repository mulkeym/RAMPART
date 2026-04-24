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
        // ChatGPT format: messages[0].content.parts[0]
        try {
            const msg = body.messages && body.messages[0];
            if (msg && msg.content && msg.content.parts) {
                console.log('[RAMPART] ChatGPT parts:', JSON.stringify(msg.content.parts).substring(0, 500));
                const textParts = [];
                for (const part of msg.content.parts) {
                    if (typeof part === 'string') textParts.push(part);
                    else if (part && typeof part === 'object' && part.text) textParts.push(part.text);
                }
                if (textParts.length > 0) return textParts.join('\n');
            }
        } catch (e) {}

        // Ask Sage / generic formats
        // Try: body.message (string)
        if (typeof body.message === 'string' && body.message.trim()) return body.message;
        // Try: body.prompt (string)
        if (typeof body.prompt === 'string' && body.prompt.trim()) return body.prompt;
        // Try: body.query (string)
        if (typeof body.query === 'string' && body.query.trim()) return body.query;
        // Try: body.input (string)
        if (typeof body.input === 'string' && body.input.trim()) return body.input;
        // Try: body.content (string)
        if (typeof body.content === 'string' && body.content.trim()) return body.content;
        // Try: OpenAI standard messages format
        try {
            if (Array.isArray(body.messages)) {
                const last = body.messages[body.messages.length - 1];
                if (last && typeof last.content === 'string') return last.content;
            }
        } catch (e) {}

        return null;
    }

    // Kept for backward compat — extractPrompt now handles all formats
    function _extractPromptLegacy(body) {
        try {
            const msg = body.messages && body.messages[0];
            if (!msg || !msg.content || !msg.content.parts) return null;
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
                '<div class="rampart-actions">' +
                '<button class="rampart-btn rampart-btn-primary" id="rampart-cancel">Acknowledged</button>' +
                '</div></div>';

            document.body.appendChild(overlay);

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
                    console.log('[RAMPART] Cached pasted image from clipboard (' + Math.round(file.size/1024) + 'KB)');
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
                console.log('[RAMPART] Cached dropped image (' + Math.round(file.size/1024) + 'KB)');
            };
            reader.readAsDataURL(file);
        }
    }, true);

    // Override fetch
    const originalFetch = window.fetch;
    window.fetch = async function(url, options) {
        // Log all Ask Sage POST requests to help identify the conversation endpoint
        if (typeof url === 'string' && url.includes('asksage.ai') && options && options.method === 'POST') {
            try {
                const bodyPreview = typeof options.body === 'string' ? options.body.substring(0, 300) : '';
                console.log('[RAMPART] Ask Sage POST:', url, '| body:', bodyPreview);
            } catch(e) {}
        }
        // Detect conversation endpoints across supported AI chat sites
        const isConversation = typeof url === 'string' && options && options.method === 'POST' && (
            // ChatGPT
            url.includes('/backend-api/conversation') ||
            url.includes('/backend-api/f/conversation') ||
            url.includes('/backend-anon/conversation') ||
            url.includes('/backend-anon/f/conversation') ||
            // Ask Sage
            (url.includes('asksage.ai') && url.includes('/server/query'))
        );
        if (isConversation) {
            console.log('[RAMPART] Conversation request detected:', url);
            const settings = await sendToBridge('getSettings', {});
            if (settings && settings.enabled === false) {
                return originalFetch.call(this, url, options);
            }

            try {
                // Parse body — handle both JSON and FormData
                let body;
                let rawBody = options.body;
                if (rawBody instanceof FormData) {
                    body = {};
                    for (const [key, value] of rawBody.entries()) {
                        if (typeof value === 'string') body[key] = value;
                    }
                    console.log('[RAMPART] Parsed FormData keys:', Object.keys(body).join(', '));
                } else if (typeof rawBody === 'string') {
                    body = JSON.parse(rawBody);
                } else {
                    body = {};
                }
                const prompt = extractPrompt(body);
                const imageAssets = extractImageAssets(body);

                // Use pasted/dropped images if we have them and the message contains image assets
                const images = [];
                if (imageAssets.length > 0 && pastedImages.length > 0) {
                    images.push(...pastedImages);
                    console.log('[RAMPART] Including', images.length, 'pasted/dropped image(s) for evaluation');
                }

                if (prompt || images.length > 0) {
                    console.log('[RAMPART] Evaluating prompt:', (prompt || '').substring(0, 100), '| images:', images.length);
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
                    // Clear image cache after evaluation
                    pastedImages.length = 0;
                }
            } catch (e) {
                if (e.name === 'AbortError') throw e;
                console.warn('[RAMPART] Error during evaluation:', e);
            }
        }
        return originalFetch.call(this, url, options);
    };
})();
