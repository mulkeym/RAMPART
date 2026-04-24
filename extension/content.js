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
        if (typeof url === 'string' && (url.includes('/backend-api/conversation') || url.includes('/backend-api/f/conversation') || url.includes('/backend-anon/conversation') || url.includes('/backend-anon/f/conversation')) && options && options.method === 'POST') {
            console.log('[RAMPART] Conversation request detected:', url);
            const settings = await sendToBridge('getSettings', {});
            if (settings && settings.enabled === false) {
                return originalFetch.call(this, url, options);
            }

            try {
                const body = JSON.parse(options.body);
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
