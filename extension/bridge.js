// Load content.js and styles.css from RAMPART server (auto-updating)
// Falls back to bundled versions if server is unreachable
chrome.storage.sync.get(['rampartUrl'], (data) => {
    const serverUrl = (data.rampartUrl || '').replace(/\/+$/, '');

    // Inject styles
    const link = document.createElement('link');
    link.rel = 'stylesheet';
    if (serverUrl) {
        link.href = serverUrl + '/ui/extension/live/styles.css';
        link.onerror = () => { link.href = chrome.runtime.getURL('styles.css'); };
    } else {
        link.href = chrome.runtime.getURL('styles.css');
    }
    (document.head || document.documentElement).appendChild(link);

    // Inject content.js into the page's MAIN world
    const script = document.createElement('script');
    if (serverUrl) {
        script.src = serverUrl + '/ui/extension/live/content.js';
        script.onerror = () => {
            const fallback = document.createElement('script');
            fallback.src = chrome.runtime.getURL('content.js');
            fallback.onload = () => fallback.remove();
            (document.head || document.documentElement).appendChild(fallback);
        };
    } else {
        script.src = chrome.runtime.getURL('content.js');
    }
    script.onload = () => script.remove();
    (document.head || document.documentElement).appendChild(script);
});

// Relay messages from page (content.js) to background
window.addEventListener('message', async (event) => {
    if (event.source !== window || !event.data || event.data.source !== 'rampart-content') return;

    if (event.data.type === 'evaluate') {
        try {
            const result = await chrome.runtime.sendMessage({
                type: 'evaluate',
                prompt: event.data.prompt,
                images: event.data.images || []
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
