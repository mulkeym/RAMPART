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
