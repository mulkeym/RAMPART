const urlInput = document.getElementById('url');
const apiKeyInput = document.getElementById('apiKey');
const enabledInput = document.getElementById('enabled');
const statusDiv = document.getElementById('status');

// Load saved settings
chrome.storage.sync.get(['rampartUrl', 'apiKey', 'enabled'], (data) => {
    urlInput.value = data.rampartUrl || 'http://localhost:8080';
    apiKeyInput.value = data.apiKey || '';
    enabledInput.checked = data.enabled !== false;
});

// Save settings
document.getElementById('save').addEventListener('click', () => {
    chrome.storage.sync.set({
        rampartUrl: urlInput.value.replace(/\/+$/, ''),
        apiKey: apiKeyInput.value,
        enabled: enabledInput.checked
    }, () => {
        statusDiv.innerHTML = '<span class="dot green"></span><span>Saved</span>';
    });
});

// Test connection
document.getElementById('test').addEventListener('click', async () => {
    statusDiv.innerHTML = '<span class="dot gray"></span><span>Testing...</span>';
    const url = urlInput.value.replace(/\/+$/, '');
    try {
        const resp = await fetch(url + '/health', { method: 'GET' });
        if (resp.ok) {
            const body = await resp.json();
            if (body.status === 'ok') {
                statusDiv.innerHTML = '<span class="dot green"></span><span>Connected to RAMPART</span>';
            } else {
                statusDiv.innerHTML = '<span class="dot red"></span><span>Unexpected response</span>';
            }
        } else {
            statusDiv.innerHTML = '<span class="dot red"></span><span>HTTP ' + resp.status + '</span>';
        }
    } catch (e) {
        statusDiv.innerHTML = '<span class="dot red"></span><span>Cannot connect: ' + e.message + '</span>';
    }
});
