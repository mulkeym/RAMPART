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
        if (typeof url === 'string' && options && options.method === 'POST') {
            console.log('[RAMPART] Intercepted POST to:', url);
        }
        if (typeof url === 'string' && url.includes('/backend-api/conversation') && options && options.method === 'POST') {
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
