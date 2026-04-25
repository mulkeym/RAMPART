chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'evaluate') {
        evaluatePrompt(message.prompt, message.images).then(sendResponse).catch(err => {
            sendResponse({ error: err.message });
        });
        return true;
    }
    if (message.type === 'getConfig') {
        getExtensionConfig().then(sendResponse).catch(err => {
            sendResponse({ discovery: false, sites: [] });
        });
        return true;
    }
    if (message.type === 'sendCaptures') {
        sendCaptures(message.captures).then(sendResponse).catch(err => {
            sendResponse({ error: err.message });
        });
        return true;
    }
});

async function getExtensionConfig() {
    const settings = await chrome.storage.sync.get(['rampartUrl', 'apiKey', 'enabled']);
    if (settings.enabled === false || !settings.rampartUrl) {
        return { discovery: false, sites: [] };
    }
    const url = (settings.rampartUrl || 'http://localhost:8080').replace(/\/+$/, '');
    const headers = {};
    if (settings.apiKey) headers['Authorization'] = 'Bearer ' + settings.apiKey;
    try {
        const resp = await fetch(url + '/v1/extension/config', { headers });
        if (resp.ok) return await resp.json();
    } catch (e) {}
    return { discovery: false, sites: [] };
}

async function sendCaptures(captures) {
    const settings = await chrome.storage.sync.get(['rampartUrl', 'apiKey']);
    const url = (settings.rampartUrl || 'http://localhost:8080').replace(/\/+$/, '');
    const headers = { 'Content-Type': 'application/json' };
    if (settings.apiKey) headers['Authorization'] = 'Bearer ' + settings.apiKey;
    try {
        const resp = await fetch(url + '/v1/discovery/capture', {
            method: 'POST', headers,
            body: JSON.stringify({ captures })
        });
        return await resp.json();
    } catch (e) {
        return { error: e.message };
    }
}

async function evaluatePrompt(prompt, images) {
    const settings = await chrome.storage.sync.get(['rampartUrl', 'apiKey', 'enabled']);
    if (settings.enabled === false) {
        return { decision: 'accept', violations: [] };
    }
    const url = (settings.rampartUrl || 'http://localhost:8080').replace(/\/+$/, '');
    const headers = { 'Content-Type': 'application/json' };
    if (settings.apiKey) headers['Authorization'] = 'Bearer ' + settings.apiKey;
    let content;
    if (images && images.length > 0) {
        content = [{ type: 'text', text: prompt || '' }];
        for (const imageUrl of images) {
            content.push({ type: 'image_url', image_url: { url: imageUrl } });
        }
    } else {
        content = prompt;
    }
    try {
        const response = await fetch(url + '/v1/rampart/evaluate', {
            method: 'POST', headers,
            body: JSON.stringify({
                request: { model: 'chatgpt', messages: [{ role: 'user', content: content }] }
            })
        });
        if (!response.ok) return { error: 'RAMPART returned HTTP ' + response.status };
        return await response.json();
    } catch (e) {
        return { error: e.message };
    }
}
