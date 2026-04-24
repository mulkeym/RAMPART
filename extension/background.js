chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'evaluate') {
        evaluatePrompt(message.prompt, message.images).then(sendResponse).catch(err => {
            sendResponse({ error: err.message });
        });
        return true; // async response
    }
});

async function evaluatePrompt(prompt, images) {
    const settings = await chrome.storage.sync.get(['rampartUrl', 'apiKey', 'enabled']);

    if (settings.enabled === false) {
        return { decision: 'accept', violations: [] };
    }

    const url = (settings.rampartUrl || 'http://localhost:8080').replace(/\/+$/, '');
    const headers = { 'Content-Type': 'application/json' };
    if (settings.apiKey) {
        headers['Authorization'] = 'Bearer ' + settings.apiKey;
    }

    // Build message content — text only or multimodal
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
            method: 'POST',
            headers: headers,
            body: JSON.stringify({
                request: {
                    model: 'chatgpt',
                    messages: [{ role: 'user', content: content }]
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
