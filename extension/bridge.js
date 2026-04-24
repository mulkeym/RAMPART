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
